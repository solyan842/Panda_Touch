#!/usr/bin/env python3
"""P1S LAN diagnostics, with no modification to the printer.

Windows / Python 3.9+ (standard library only).

1. Inspect TCP/TLS only (no printer credentials):
   py -3 tools/p1s_probe.py --ip 192.168.1.50

2. Only after recognizing the TLS certificate fingerprint:
   py -3 tools/p1s_probe.py --ip 192.168.1.50 --serial YOUR_SERIAL --mqtt --pin SHA256_HEX

3. Optional read-only queries (they may be blocked by newer Cloud Mode firmware):
   ... --pushall --version --cert-list

Enter the printer's LOCAL access code when prompted. It is not stored or logged.
Never put your access code, user ID or certificate private key in a command line,
GitHub issue, screenshot or shared log.

SAFETY: This tool never enrolls certificates, signs commands, moves axes, heats
parts, starts a print, pauses or stops jobs, or changes printer configuration.
The printer's self-signed certificate cannot be verified by a public CA. MQTT
requires an explicit SHA-256 certificate pin obtained in the first probe; check
the fingerprint by an independent trusted channel when possible. The first
fingerprint observation alone is not proof of the printer's identity.
"""
import argparse
import getpass
import hashlib
import ipaddress
import json
import re
import secrets
import socket
import ssl
import struct
import sys
import time


MAX_MQTT_PACKET = 256 * 1024
RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


class ProbeError(Exception):
    pass


def mqtt_text(value):
    raw = value.encode("utf-8")
    if len(raw) > 65535:
        raise ProbeError("MQTT string is too long")
    return struct.pack("!H", len(raw)) + raw


def remaining_length(number):
    out = bytearray()
    while True:
        digit = number % 128
        number //= 128
        out.append(digit | (0x80 if number else 0))
        if not number:
            return bytes(out)


def mqtt_frame(packet_type, body):
    return bytes((packet_type,)) + remaining_length(len(body)) + body


def read_exact(stream, size):
    chunks = bytearray()
    while len(chunks) < size:
        piece = stream.recv(size - len(chunks))
        if not piece:
            raise ProbeError("Connection closed by printer")
        chunks.extend(piece)
    return bytes(chunks)


def read_packet(stream):
    first = read_exact(stream, 1)[0]
    multiplier, length = 1, 0
    for _ in range(4):
        digit = read_exact(stream, 1)[0]
        length += (digit & 0x7F) * multiplier
        if not digit & 0x80:
            break
        multiplier *= 128
    else:
        raise ProbeError("Invalid MQTT remaining length")
    if length > MAX_MQTT_PACKET:
        raise ProbeError("MQTT packet too large (safe limit 256 KiB)")
    return first, read_exact(stream, length)


def mqtt_connect(stream, access_code):
    client_id = "solyan-readonly-" + secrets.token_hex(4)
    # MQTT 3.1.1: clean session, username and password, keepalive 60 seconds.
    header = mqtt_text("MQTT") + bytes((4, 0xC2)) + struct.pack("!H", 60)
    body = header + mqtt_text(client_id) + mqtt_text("bblp") + mqtt_text(access_code)
    stream.sendall(mqtt_frame(0x10, body))
    first, payload = read_packet(stream)
    if first != 0x20 or len(payload) != 2:
        raise ProbeError("Expected MQTT CONNACK")
    if payload[1] != 0:
        codes = {
            1: "unacceptable protocol",
            2: "client identifier rejected",
            3: "broker unavailable",
            4: "bad username or password",
            5: "not authorized",
        }
        raise ProbeError("MQTT authentication rejected: " + codes.get(payload[1], str(payload[1])))


def mqtt_subscribe(stream, serial):
    topic = "device/" + serial + "/report"
    payload = struct.pack("!H", 1) + mqtt_text(topic) + bytes((0,))
    stream.sendall(mqtt_frame(0x82, payload))
    for _ in range(8):
        first, body = read_packet(stream)
        if (first >> 4) == 9:
            if len(body) < 3 or body[:2] != struct.pack("!H", 1) or body[2] == 0x80:
                raise ProbeError("MQTT SUBSCRIBE rejected")
            return
    raise ProbeError("No MQTT SUBACK received")


def mqtt_publish_readonly(stream, serial, message):
    topic = mqtt_text("device/" + serial + "/request")
    content = json.dumps(message, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    stream.sendall(mqtt_frame(0x30, topic + content))


def describe_report(packet):
    first, body = packet
    if (first >> 4) != 3 or len(body) < 2:
        return False
    topic_len = struct.unpack("!H", body[:2])[0]
    start = 2 + topic_len
    if start > len(body):
        return False
    if first & 0x06:  # QoS 1/2: packet identifier precedes payload.
        start += 2
    try:
        root = json.loads(body[start:].decode("utf-8"))
    except (UnicodeError, ValueError):
        print("Report received, but JSON could not be decoded")
        return True
    if not isinstance(root, dict):
        print("Report received (non-object JSON)")
        return True
    if isinstance(root.get("print"), dict):
        info = root["print"]
        safe = {}
        for src, dst in (("gcode_state", "state"), ("mc_percent", "progress_pct"),
                         ("layer_num", "layer"), ("nozzle_temper", "nozzle_C"),
                         ("bed_temper", "bed_C")):
            if src in info and isinstance(info[src], (str, int, float)):
                safe[dst] = info[src]
        safe["ams_reported"] = isinstance(info.get("ams"), dict)
        print("PRINT:", json.dumps(safe, ensure_ascii=True))
    if isinstance(root.get("info"), dict):
        info = root["info"]
        modules = info.get("module")
        if isinstance(modules, list):
            versions = [
                {"module": x.get("name"), "version": x.get("sw_ver")}
                for x in modules if isinstance(x, dict)
                and isinstance(x.get("name"), str) and isinstance(x.get("sw_ver"), str)
            ]
            print("VERSION:", json.dumps(versions[:12], ensure_ascii=True))
        else:
            print("INFO reply:", str(info.get("command", "unknown")))
    if isinstance(root.get("security"), dict):
        item = root["security"]
        # Do not dump certificate IDs, certificate contents or serial numbers.
        safe = {k: item[k] for k in ("command", "result", "reason", "err_code")
                if k in item and isinstance(item[k], (str, int))}
        print("SECURITY reply:", json.dumps(safe, ensure_ascii=True))
    if not any(k in root for k in ("print", "info", "security")):
        print("Other report received (details hidden)")
    return True


def verify_ip(ip_text):
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError as exc:
        raise ProbeError("Invalid IP address") from exc
    if ip.version != 4 or not any(ip in net for net in RFC1918):
        raise ProbeError("Use a private IPv4 LAN address (10.x, 172.16-31.x, 192.168.x)")
    return str(ip)


def open_tls(ip):
    tcp = socket.create_connection((ip, 8883), timeout=6)
    tcp.settimeout(6)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # identity checked separately with SHA-256 pin
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        tls = context.wrap_socket(tcp, server_hostname=None)
    except Exception:
        tcp.close()
        raise
    cert = tls.getpeercert(binary_form=True)
    if not cert:
        tls.close()
        raise ProbeError("Printer did not present a TLS certificate")
    fingerprint = hashlib.sha256(cert).hexdigest()
    return tls, fingerprint


def main():
    parser = argparse.ArgumentParser(description="Read-only P1S LAN MQTT diagnostic")
    parser.add_argument("--ip", required=True, help="P1S local IPv4 address")
    parser.add_argument("--serial", help="P1S serial: only needed for --mqtt")
    parser.add_argument("--mqtt", action="store_true", help="Subscribe to status reports")
    parser.add_argument("--pin", help="Expected SHA-256 TLS certificate fingerprint (64 hex chars)")
    parser.add_argument("--pushall", action="store_true", help="Send status request, not a control command")
    parser.add_argument("--version", action="store_true", help="Request firmware version (may be blocked)")
    parser.add_argument("--cert-list", action="store_true", help="Request cert list (never install certs)")
    parser.add_argument("--seconds", type=int, default=18, help="Listening time, 1-45 seconds")
    args = parser.parse_args()

    if not 1 <= args.seconds <= 45:
        parser.error("--seconds must be 1-45")
    if (args.pushall or args.version or args.cert_list) and not args.mqtt:
        parser.error("Read-only MQTT requests require --mqtt")
    if args.mqtt:
        if not args.serial or not re.fullmatch(r"[A-Za-z0-9]{6,40}", args.serial):
            parser.error("--serial is required for --mqtt (6-40 alphanumeric chars)")
        if not args.pin or not re.fullmatch(r"[0-9a-fA-F]{64}", args.pin):
            parser.error("--mqtt requires --pin followed by a 64-digit SHA-256 fingerprint")

    ip = verify_ip(args.ip)
    print("TCP/TLS probe: local printer, port 8883 (no printer mode changes)")
    tls, fingerprint = open_tls(ip)
    try:
        print("TCP: OPEN | TLS: " + tls.version())
        print("TLS certificate SHA256:", fingerprint)
        if not args.mqtt:
            print("DONE: TLS only; no MQTT credentials or commands sent.")
            return 0

        if not secrets.compare_digest(fingerprint, args.pin.lower()):
            raise ProbeError("TLS certificate pin mismatch; no MQTT credentials sent")
        print("Certificate pin: MATCH (does not prove first observation was authentic)")
        access_code = getpass.getpass("P1S local access code (not saved): ")
        if not access_code:
            raise ProbeError("Empty access code; nothing sent")
        mqtt_connect(tls, access_code)
        access_code = None
        print("MQTT CONNECT: OK")
        mqtt_subscribe(tls, args.serial)
        print("MQTT SUBSCRIBE: OK (report topic)")
        if args.pushall:
            mqtt_publish_readonly(tls, args.serial, {"pushing": {"sequence_id": "0", "command": "pushall"}})
            print("Status request sent; printer may ignore it in Cloud Mode")
        if args.version:
            mqtt_publish_readonly(tls, args.serial, {"info": {"sequence_id": "0", "command": "get_version"}})
            print("Version request sent; printer may ignore it in Cloud Mode")
        if args.cert_list:
            mqtt_publish_readonly(tls, args.serial, {"security": {
                "sequence_id": "0", "command": "app_cert_list",
                "timestamp": int(time.time() * 1000), "type": "app"}})
            print("Certificate LIST request sent (no enrollment)")
        deadline = time.monotonic() + args.seconds
        count = 0
        while time.monotonic() < deadline:
            tls.settimeout(min(2.0, max(0.1, deadline - time.monotonic())))
            try:
                packet = read_packet(tls)
            except socket.timeout:
                continue
            if describe_report(packet):
                count += 1
        print("DONE: received", count, "report(s); no device configuration changed.")
        if count == 0:
            print("No report is inconclusive: the printer may suppress requests in Cloud Mode.")
        return 0
    finally:
        try:
            if args.mqtt:
                tls.sendall(bytes((0xE0, 0x00)))  # MQTT DISCONNECT, not a printer command
        except OSError:
            pass
        tls.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ProbeError, OSError, ssl.SSLError, EOFError) as exc:
        print("PROBE FAILED:", exc, file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nStopped by user")
        sys.exit(130)

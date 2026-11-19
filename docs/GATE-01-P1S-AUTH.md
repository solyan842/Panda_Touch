# Gate 01 — P1S Cloud Mode authorization feasibility

**Date:** 2026-11-19  
**Target hardware:** BIGTREETECH PandaTouch, ESP32-S3, 8 MB PSRAM, 16 MB flash  
**Target printer:** Bambu Lab P1S, international firmware 01.10.x, Cloud Mode ON, Developer Mode OFF  
**Status:** **AMBER — feasible in principle; P1S-specific enrollment not verified.**  
**Scope of this step:** Public-source/code review only. No printer access, firmware flash, live network test, or credential handling.

## Objective

Establish whether PandaTouch can authenticate privileged **LAN** MQTT commands on a stock, cloud-connected P1S without any always-on intermediary. Bambu Cloud, Bambu Handy, and Bambu Studio must remain usable.

## Confirmed from public code/research

1. **P1S uses signed MQTT commands with recent authorization control.** The OpenBambuAPI X.509 notes document captured Bambu Handy ↔ P1S traffic with a `header` carrying `sign_ver`, `sign_alg=RSA_SHA256`, `sign_string`, `cert_id`, and `payload_len`. Exact firmware build of the captured P1S is not established.
2. **ESP32-S3 can perform RSA-SHA256 signing locally.** BambooSense contains an mbedTLS implementation running on an ESP32-S3; its author reports successful signed control against **P2S** in Cloud Mode. This is not proof of compatibility with P1S 01.10.x.
3. **Printer certificate enrollment and signature acceptance are separate gates.** Later reverse-engineering reports from open-bamboo-networking show that `security.app_cert_install` can return `SUCCESS` even when later signed commands fail because the printer cannot validate a complete X.509 trust chain.
4. **A genuine app certificate chain may be required.** Captured stock sessions install application leaf, intermediate, root and a CRL. Printer firmware/model differences matter. BambooSense's reported self-issued identity success on P2S and open-bamboo-networking's strict trust-chain observations on other models cannot be generalized to P1S.
5. **Tiger Touch currently blocks most Bambu Cloud control.** It offers `pause`/`resume`/`stop` through its plain LAN driver, but its `can_control` flag is true only for LAN and it has no new-auth signature implementation. It is useful for PandaTouch hardware drivers and UI, **not** a ready-made P1S Cloud Mode controller.

## What is NOT proven

- The target P1S **01.10.x** accepts a self-issued, user-provisioned app certificate without a Bambu-issued chain.
- A certificate enrolled successfully on that P1S can authenticate a harmless signed `print.*` read request.
- Control privileges persist across power cycle, reconnect, printer firmware upgrade, and certificate rotation.
- P1S 01.10.x accepts all target controls (axis jog/home, AMS load/unload, extrusion, heaters, fans, start/stop).
- The final firmware fits PandaTouch RAM/flash together with LVGL, TLS and secure key storage.

## Verification sequence (one gate at a time)

### Gate 01A — Read-only discovery (next step)

**No firmware changes and no authorization-store changes.** On the owner's P1S while Cloud/Handy are still working:

- Record **exact** printer firmware version and whether Cloud Mode is enabled and Developer Mode disabled.
- Connect by local MQTT/TLS using credentials read locally from the printer by its owner; do not put any real credentials in this repository.
- Read printer status (`pushing.pushall` / passive reports), version (`info.get_version`), and certificate list (`security.app_cert_list`) only if those requests are supported.
- Record sanitized responses: connect OK/error, version, auth-required indication, certificate-list availability, response/error codes. **Do not store serial numbers, access codes, user IDs, private keys, complete certificates, or LAN IPs in test logs.**
- **PASS** only if the P1S can be reached over LAN while Cloud/Handy remain enabled and the authorization state can be diagnosed. **FAIL/UNKNOWN** if MQTT cannot connect or the replies are inconclusive. Do not attempt motion, temperature, filament or print-job actions.

### Gate 01B — Certificate trust (requires explicit owner approval)

Only after 01A passes, and only after preparing a reversible test plan: verify whether an independently issued application certificate can be installed and then used for a **read-only signed command**. A mere `app_cert_install SUCCESS` is **not** a pass. The signed command must be accepted by the printer with a matching response. Record changes to the certificate trust store and a rollback/restart procedure.

### Gate 01C — On-device proof

Implement the minimum credential/signing driver on an ESP32-S3, then test its non-motion signed requests on the P1S. **Do not** start a full UI port or add movement/heating until 01B and 01C pass.

## Decision

- **GO**: Both certificate trust **and** a real signed read-only response are confirmed on P1S 01.10.x, with Cloud/Handy still working. Then port the smallest possible proof to PandaTouch.
- **NO-GO / REASSESS**: P1S rejects independently issued identity or needs unavailable Bambu-issued signing material. Investigate legitimate integration paths; do not bypass authentication by altering the printer firmware or downgrade the printer.

## Source links

- [OpenBambuAPI — X.509 from Bambu Handy / P1S](https://github.com/Doridian/OpenBambuAPI/blob/main/cloud-x509-auth.md)
- [BambooSense — ESP32-S3 signing firmware](https://github.com/Snail3D/bamboo-sense)
- [BambooSense — research and P2S test notes](https://github.com/Snail3D/bamboo-sense/blob/main/docs/CRACK.md)
- [open-bamboo-networking — certificate install/trust](https://github.com/ClusterM/open-bamboo-networking/blob/master/research/10.02-secrets.md)
- [open-bamboo-networking — signing behavior](https://github.com/ClusterM/open-bamboo-networking/blob/master/research/10.04-mqtt-signing.md)
- [open-bamboo-networking — observed full certificate chain](https://github.com/ClusterM/open-bamboo-networking/blob/master/research/08.04-lan.md)
- [Tiger Touch — Bambu driver](https://github.com/TigerTag-Project/Tiger-Touch/blob/main/firmware/main/drivers/drv_bambu.c)

**No third-party source code copied, no secrets stored.**

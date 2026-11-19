# SolYan Panda Touch

Independent firmware research and development for the BIGTREETECH PandaTouch (ESP32-S3), focused on **full control of a Bambu Lab P1S while keeping the printer's stock international firmware, Bambu Cloud, and Bambu Handy enabled**.

> **Status: Research / feasibility gate.** There is no working custom firmware or validated P1S compatibility in this repository yet.

## Non-negotiable requirements

- All runtime control executes **on the PandaTouch**. No always-on PC, Raspberry Pi, server, or MQTT bridge.
- Do not modify or downgrade the Bambu Lab printer firmware.
- Keep **Cloud Mode / Bambu Handy / Bambu Studio** available.
- Prioritize real printer controls rather than a monitoring-only dashboard.
- Safeguard credentials, certificates, and private keys; never commit actual device secrets.
- Back up the PandaTouch's original 16 MB flash before any replacement firmware is installed; maintain a verified recovery path.

## Target controls

- Printer status, progress, temperature, and AMS telemetry.
- Pause / resume / stop / start print (where authorized).
- X/Y/Z movement and homing.
- Extrude / retract, temperature, fan, and print-speed settings.
- AMS load / unload and filament mapping.

Support for these commands on a recent P1S firmware is **a target, not a demonstrated result**.

## First feasibility gate — before building the UI

Determine whether a **P1S on international firmware 01.10.x, with Cloud Mode enabled and Developer Mode disabled**, accepts an independently provisioned application certificate and a correctly signed **non-motion, low-risk test command** from an ESP32-S3.

Current research indicates on-device RSA-SHA256 signing is technically possible on ESP32-S3, and similar signed-command flows have been reported on other Bambu models. **P1S acceptance of this enrollment/signing route has not been verified.**

**Go / no-go:** Do not proceed with a full custom UI, motion, heating, or print-start features until the certificate and authorization path has been independently verified on the target P1S. Test only on a printer the operator owns or is authorized to control.

## References (research only)

- [Tiger Touch](https://github.com/TigerTag-Project/Tiger-Touch) — open-source PandaTouch/K-Touch board support, ESP-IDF, LVGL, Wi-Fi, MQTT, telemetry. Its Bambu Cloud driver does **not** provide full control.
- [BambooSense](https://github.com/Snail3D/bamboo-sense) — ESP32-S3 signing and certificate research, reported on P2S; not validated here on P1S.
- [BIGTREETECH PandaTouch](https://github.com/bigtreetech/PandaTouch) — original firmware releases and recovery reference.

No third-party code is copied into this repository at initialization. Review each upstream license and attribution requirements before importing code.

## Development policy

One verified step at a time. Record device model, printer firmware, PandaTouch build, test conditions, observed response, and rollback method before advancing.

No binaries, printer credentials, signing keys, or private certificates should be committed.

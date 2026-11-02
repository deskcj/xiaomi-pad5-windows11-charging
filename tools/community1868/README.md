# SK-Charging 1868 — Xiaomi Pad 5 / Windows 11 ARM64

[Русский](README.ru.md) · [Project and current status](https://github.com/deskcj/xiaomi-pad5-windows11-charging)

This archive contains the exact charging driver files tested on the project tablet. It is an experimental community package for **nabu**, not a complete Windows driver pack.

## Install

1. Have Windows 11 ARM64, the base nabu Windows drivers and **active Test Mode** already configured. [nabu boot/signing guide](https://github.com/erdilS/Port-Windows-11-Xiaomi-Pad-5/blob/main/guide/English/disable-secureboot-en.md).
2. Extract the whole ZIP to a folder on the tablet's internal Windows drive. Keep all files together; do not run it inside the ZIP.
3. Double-click **Install.cmd** and allow the Administrator prompt. It opens native Windows PowerShell; Python, an SDK and manual INF selection are not needed.
4. Wait for **Driver set staged; reboot manually**. Save your work, safely eject USB storage, and reboot manually. If it reports a failure, keep the installation record; do not interpret that as a successful installation.
5. Run **Diagnose.cmd** after reboot. The five rows should show matching versions/hashes, `Running=True` and `ProblemCode=0`.

The installer checks the model, ARM64, active Test Mode, package hashes and signatures. It saves and verifies the previous five driver packages on the internal drive before staging four updated packages for reboot. It preserves the compatible battery miniclass. It imports **only the included public development certificate** into Windows Root/TrustedPublisher if missing; no private key is included. It does not change BCD, Secure Boot, camera drivers or reboot automatically. Repeating Install on an already matching stack does nothing; automatic downgrades are refused.

The base battery miniclass must match version `1.0.1680.0` and the SYS hash in `manifest.json`. Its unchanged INF/SYS/CAT are in `reference/`, **not installed**. They are supplied to identify the tested base; do not manually install the reference. This pack is not suitable for other tablets or an incomplete base driver setup.

Optional read-only preflight:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install.ps1 -CheckOnly
```

## Diagnose or restore

**Diagnose.cmd** saves a snapshot ZIP under `%LOCALAPPDATA%\SK-Charging-Diagnostics`. It records selected driver versions/hashes/states, device problems, USB/storage topology, recent relevant System events, and documented battery telemetry. It does not install/reset devices, use private PMIC control IOCTLs, or upload reports. Review reports before sharing: USB identifiers and event messages can contain serial numbers and local paths.

For a five-minute battery sample, open PowerShell in this folder:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Diagnose.ps1 -Seconds 300
```

Battery rates/capacities are **driver telemetry, not an external USB power-meter reading**. At 100%, a capacity value may stay unchanged.

Installation records and verified backups are under `%ProgramData%\SK-Charging\Install-*`. To restore, safely eject and disconnect USB storage, then run **Restore.cmd inside the specific `Previous` backup folder** printed by Install. The main archive's Restore.cmd chooses the latest saved backup. Restore can restart USB/charging devices; it requests the saved four drivers and leaves miniclass unchanged. Reboot manually afterwards. Recovery scripts and all 15 previous INF/SYS/CAT files remain available even if the community ZIP is deleted. If Windows cannot boot, use your normal Windows recovery/offline driver-recovery procedure with those files.

## Tested status and limits

- ✅ Direct charger ↔ USB-C SSD switching; direct powerbank charging detection and OTG flash drive use in tested sequences.
- ✅ Acer HY41-T9 hub with charging and Kingston XS2000; charging resumes when the PD cable is returned.
- ⚠️ Removing the PD charger from Acer HY41-T9 briefly disconnects/reconnects the SSD. **This bug is still present.** Avoid switching hub power during disk writes; use safe removal when needed.
- ⚠️ Fixed USB PD requests up to an 18 W contract limit were observed; actual maximum input/charging power is unverified.
- ❌ PPS and a demonstrated seamless/FRS power handover are not provided by this release.
- ⚠️ This is not a guarantee for every hub, charger, OTG device, boot, sleep/resume or load condition.

`FILES-SHA256.json` lists archive file hashes. `manifest.json` identifies package versions and payload hashes. The bundle is **1868**; its component INF versions differ, and PE FileVersion can retain older values.

## Support and disclaimer

[DonationAlerts](https://www.donationalerts.com/r/deskcj) · [PayPal](https://paypal.me/vladcj)

Donations support community work and do not guarantee a feature or delivery date. This independent project is not affiliated with Xiaomi, Qualcomm or Microsoft. Original driver ownership/notices remain with their respective owners. These test-signed kernel drivers are experimental and supplied as-is, without warranty. Crashes, boot failure and data loss are possible. Keep backups and a recovery method; install at your own risk. Positive tests do not establish universal stability or maximum fast charging.

# Charging and USB-C on Xiaomi Pad 5 with Windows 11

[Русский](README.ru.md) · Xiaomi Pad 5 (`nabu`) · Windows 11 ARM64

![Status: public preview](https://img.shields.io/badge/status-public%20preview-orange?style=for-the-badge) ![Device: Xiaomi Pad 5](https://img.shields.io/badge/device-Xiaomi%20Pad%205-blue?style=for-the-badge) ![Platform: Windows 11 ARM64](https://img.shields.io/badge/platform-Windows%2011%20ARM64-0078D4?style=for-the-badge)

**SK-Charging 1869-PD013-U1** lets the tablet switch between direct charging and USB storage without rebooting in tested scenarios. Charging and an SSD also work together through a hub.

## Download

**[Download SK-Charging-1869-PD013-Universal-U1.zip](https://github.com/deskcj/xiaomi-pad5-windows11-charging/releases/download/1869-PD013-U1/SK-Charging-1869-PD013-Universal-U1.zip)**

SHA-256: `E95ED137483FC3DCBC8EC45F23E80FAC32AC72B2F6939FC162C5FF72BBDE15EC` · 307,449 bytes

U1 includes the current working drivers, a complete installer, backup and restore, **Verify.cmd**, and **Diagnose.cmd**. No SDK or manual Device Manager installation is required.

**[Download source archive](https://github.com/deskcj/xiaomi-pad5-windows11-charging/releases/download/1869-PD013-U1/SK-Charging-1869-PD013-U1-Sources.zip)** · SHA-256: `A065F70C93EEED96D362702F6EBFEEC040BEA209BBCCED4ECF4F02143698B0A5`

Sources include the custom PD filter 0.1.3, its EWDK build script and offline tests, and the U1 installer/diagnostic/rollback scripts. Full source for the base Qualcomm binary drivers is not included. Use this separate source ZIP; GitHub's automatic source archives for this tag contain the repository documentation.

## Compatibility

Use on **Xiaomi Pad 5 / nabu with Windows 11 ARM64** and existing nabu base drivers. U1 automatically recognizes two audited battery-miniclass variants: **Qualcomm 1.0.1680.0** and **Xiaomi 1.0.10730.0**, using their exact selected INF/SYS hashes. The miniclass is preserved; it is never installed or restored.

“Universal” means one installer for these two nabu baselines. Other tablets, unknown driver variants, and every modified Windows image or accessory are not covered by the test results. An unsupported baseline stops before driver installation; run **Diagnose.cmd** to obtain its details.

> [!WARNING]
> **Active Windows Test Mode is required.** The installer does not enable it or change Secure Boot/BCD. Keep a data backup and a Windows recovery method. See the [nabu setup guide](https://github.com/erdilS/Port-Windows-11-Xiaomi-Pad-5/blob/main/guide/English/disable-secureboot-en.md) if your tablet is not already configured for test-signed drivers.

## Installation

1. Extract the **entire ZIP to the internal C: drive**, for example `C:\SK-Charging-U1`. Do not run it inside the ZIP or from USB storage.
2. Double-click **Install.cmd**, approve the administrator prompt, and wait for the result.
3. At **PendingReboot**, save your work, safely eject USB storage, disconnect USB-C devices, and select **Restart** in Windows once. **PendingReboot means staging succeeded; the new drivers are not yet verified.** Do not reinstall or run Verify before this restart.
4. After Windows loads, run **Verify.cmd** and wait for **PASS**. PASS confirms driver activation and the PD filter's attachment; it does not measure charging speed.
5. Test OTG/storage → **safe removal and physical disconnection** → direct charging, then the reverse sequence. If installation, Verify, or device operation fails, run **Diagnose.cmd** and share its diagnostic ZIP after reviewing it.

U1 backs up the actual selected INF/SYS/CAT files before staging and recognizes the different original Xiaomi filenames. It records pending-restart status explicitly, so an accepted install cannot be mistaken for a verified one. The included kernel binaries are the current working set used on the project tablet.

| Component | Included version |
|---|---|
| PMIC extension | 1.0.1869.0 |
| Type-C backend | 1.0.1867.0 |
| USB-C client | 1.0.1853.0 |
| Battery manager | 1.0.10732.0 |
| Fixed PD profile filter | 0.1.3.0, mode 1 |

## What works and what remains

- ✅ Direct SSD/OTG ↔ charging switching without reboot worked on the project tablet.
- ✅ The installer automatically selects the audited Qualcomm 1680 or Xiaomi 10730 miniclass baseline and backs up the actual previous driver packages.
- ✅ Startup with a charger or SSD, followed by switching devices, worked in the recorded project-tablet tests.
- ✅ The tested power bank and mains chargers charged the project tablet.
- ✅ **Acer HY41-T9** hub + charging + SSD worked together; returning the charger resumed charging.
- ✅ Samsung accepted a fixed **9 V × 3 A USB PD contract** with filter 0.1.3.
- ❌ Removing PD power from **Acer HY41-T9** still briefly disconnects/reconnects the SSD. Avoid changing hub power during disk writes.
- ❌ Uninterrupted hub power handover and **PPS** charging are not implemented.
- ❌ Maximum actual charging power and Android-equivalent fast charging are not established; other accessories and long-term stability need more testing.

**Fast charging:** the accepted 9 V × 3 A contract raises the negotiated ceiling to **27 W** when the charger offers it. This is not a measurement of 27 W reaching the battery or the USB input. The current low-battery measurements will check actual battery energy gain and charge rate. PPS/charge-pump work remains open; there is no confirmed delivery date for full fast-charge support. An installation PASS or a charging icon alone does not establish charging speed.

## Diagnostics and recovery

**Check.cmd** runs compatibility preflight without installing drivers. **Verify.cmd** checks the selected INF/SYS, Running/Code0 state, and actual PD-filter attachment after restart.

**Diagnose.cmd** creates a local ZIP in `%LOCALAPPDATA%\SK-Charging-Diagnostics` and uploads nothing. It includes OS/build, driver identities, installation records, USB/battery state, and the five selected charging/battery INF/SYS/CAT packages with signature information. Review identifiers and local paths before sharing. If reporting a failure, include the Windows build, accessory model, connection sequence, and whether the installation restart was completed.

The installer saves previous base drivers, recognized SK PD extensions, and their prior per-device setting under `%ProgramData%\SK-Charging-Community\...\Previous`. **Restore.cmd** uses the latest backup; the copy in a particular backup selects that reserve. Safely eject and disconnect USB storage, run Restore, then restart manually. Restore requests the four saved base packages and restores the recognized PD configuration while preserving the miniclass.

The pack contains only a **public development certificate**, which may be imported if needed; no private signing key, firmware, camera, or audio update is included. The delivered ZIP's `FILES-SHA256.json` lists its files. Installer/rollback checks and read-only verification passed on the project tablet; successful testing on two audited baselines does not guarantee every configuration.

## ❤️ Help improve charging and USB-C

This is independent work on a real tablet: studying power and USB-C behavior, building ARM64 drivers, testing chargers, power banks and hubs, and investigating failures that can reboot the device. Progress takes careful experiments and repeated validation. If this project is useful to you, support helps continue the work toward more reliable charging and USB switching.

[![Support via DonationAlerts](https://img.shields.io/badge/Support-DonationAlerts-orange?style=for-the-badge)](https://www.donationalerts.com/r/deskcj) [![Support via PayPal](https://img.shields.io/badge/Support-PayPal-0070BA?style=for-the-badge&logo=paypal&logoColor=white)](https://paypal.me/vladcj)

You can also help **without donating**: star the repository, tell other nabu owners about it, and share reproducible results with your Windows version, hub or charger model, and connection sequence. That feedback helps prioritize fixes. Donations support the research, not a guaranteed result or delivery date. Thank you for helping an independent Windows on ARM project grow!

## Disclaimer

This is an independent community project, **not affiliated with or endorsed by Xiaomi, Qualcomm, or Microsoft**. Company and product names identify compatible hardware and technologies only; rights to those names belong to their owners. The underlying Qualcomm drivers and their notices remain the property of their owners; the authorship of the original `fix20` has not been established.

The drivers are experimental, test-signed kernel software provided **“as is”**, without any guarantee of stability, support, or Android-level charging speed. Crashes, boot failure, device problems, and data loss are possible. Before installing, keep a backup and a recovery method. The decision to test and the associated risks are yours. This notice does not grant permission to redistribute third-party components contrary to their licenses.

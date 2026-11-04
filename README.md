# Charging and USB-C on Xiaomi Pad 5 with Windows 11

[Русский](README.ru.md) · Xiaomi Pad 5 (`nabu`) · Windows 11 ARM64

![Build](https://img.shields.io/badge/build-1871--HQ2--U4-blue?style=for-the-badge) ![Status](https://img.shields.io/badge/status-public%20preview-orange?style=for-the-badge) ![Measured charging](https://img.shields.io/badge/accelerated%20charging-measured-brightgreen?style=for-the-badge)

**1871-HQ2-U4** is the current working charging/USB-C package. Direct charging ↔ SSD/OTG switching and charging + SSD through a hub work in the recorded tests. **Real accelerated charging is measured on compatible chargers.** Removing charger power from the hub still briefly disconnects the SSD; full 33 W and PPS remain unconfirmed.

## Download

**[Download Xiaomi-Pad5-Charging-1871-HQ2-U4.zip](https://github.com/deskcj/xiaomi-pad5-windows11-charging/raw/refs/heads/main/downloads/Xiaomi-Pad5-Charging-1871-HQ2-U4.zip)** · 314,150 bytes

SHA-256: `C4491C15E814E4A5840C93FA668941C75E6C47BE1B60EBA52D923CC2F6261386`

**[Download development sources](https://github.com/deskcj/xiaomi-pad5-windows11-charging/raw/refs/heads/main/downloads/Xiaomi-Pad5-Charging-1871-HQ2-U4-Sources.zip)** · 346,211 bytes · 165 files

SHA-256: `A7642A0A3735B2C30643088F9BC9789BA6E8A64A7E2BE6C0A63357D41B714AF5`

The driver ZIP includes **Install.cmd**, compatibility check, verification, backup/restore and local diagnostics. No Python, SDK or manual Device Manager installation is needed.

The separate source ZIP includes exact U4 installer scripts, the custom PD filter 0.1.3 and EWDK build, current C/assembly patch additions and offline tests, and PD/PPS/LN8000/FRS research components. **Full Qualcomm source is unavailable:** the source ZIP cannot rebuild every base driver from scratch. The research components are not installed by U4. Use this separate ZIP; GitHub's automatic source archives contain the repository documentation. See [the development handoff](docs/CONTINUE-DEVELOPMENT.md).

## What works and what remains

- ✅ Direct SSD/OTG ↔ charger switching worked without rebooting in recorded tests.
- ✅ Startup with a charger or SSD and subsequent device switching worked in recorded tests.
- ✅ The tested mains chargers and power bank delivered real battery charge.
- ✅ Hub, charging and SSD work together; returning charger power resumes charging.
- ✅ Fixed **USB PD 9 V / 3 A** is confirmed; a sustained 1871 test averaged **13.8 W net battery power**.
- ✅ A **33 W-rated charger** produced about **8.6 V at the USB input** and **16–17.4 W average net battery power** across separate recorded runs.
- ✅ Actual **Install.cmd → restart → Verify.cmd PASS**, plus diagnostics and an already-installed no-op, were verified on the project tablet.
- ❌ An **Acer hub** and **another tested hub** showed a brief SSD disconnect/reconnect when charger power was removed, including after safe ejection. Other tested functions worked correctly. Avoid changing hub power during disk writes.
- ❌ Seamless hub power handover is unresolved; **PPS is not implemented in the installed package**.
- ⏳ Full **33 W input power**, Android-equivalent maximum speed and compatibility with every modified Windows/driver set remain unconfirmed.

## Fast charging: what the measurements prove

**Accelerated charging is already supported by the measured elevated input voltage and positive battery energy gain.** The 33 W-rated charger runs averaged about 16–17.4 W into the battery; the 180-second follow-up peaked at 17.68 W. A separate voltage capture measured 8.55–8.63 V at the USB input. These figures come from separate captures, not a claimed continuous maximum-power test.

A tested charger negotiated fixed 9 V / 3 A. Its **27 W contract is a ceiling**, not a measurement of 27 W input or battery power. Net battery watts exclude tablet consumption and conversion losses; the 33 W-rated charger test did not capture USB input current or identify the charging protocol. **A 33 W charger rating does not prove 33 W delivery.** PPS and the charge-pump path remain development work. Installer PASS and the charging icon do not measure speed. [Measurement details](docs/FAST-CHARGING.md).

## Compatibility

For **Xiaomi Pad 5 / nabu, Windows 11 ARM64**, with compatible nabu base drivers. The installer recognizes audited Qualcomm **1.0.1680.0** and Xiaomi **1.0.10730.0** battery-miniclass baselines by exact selected INF/SYS identity. The miniclass is preserved and never installed or restored.

U4 also recognizes one audited **qcpmicext 23.5.57.553** source set using complete pinned identities and supporting transport drivers. This migration has not been verified on hardware. Unknown higher-version sets or PD extensions stop installation. A separately installed **NabuTypeC** package can outrank the requested Type-C backend, leaving a partial set after staging. **Require Verify PASS after reboot; staging success alone is insufficient.** No universal compatibility with all modified Windows images is claimed.

> [!WARNING]
> **Active Windows Test Mode is required.** Install does not enable it or change Secure Boot/BCD. Keep a backup and a Windows recovery method. [nabu setup guide](https://github.com/erdilS/Port-Windows-11-Xiaomi-Pad-5/blob/main/guide/English/disable-secureboot-en.md).

## Installation

1. Extract the **entire ZIP to internal C:**, for example `C:\Xiaomi-Pad5-Charging`. Do not run inside the ZIP or from USB storage.
2. Double-click **Install.cmd**, approve the administrator prompt when requested, and wait.
3. At **PendingReboot**, save work, safely eject storage, disconnect USB-C devices, and select **Restart** once. This status means Windows accepted staging; activation is still unverified. The installer never restarts automatically.
4. After Windows loads, run **Verify.cmd** and require **PASS**. If Install reports **Verified** for the exact already-active set, no additional installation/reboot is needed.
5. Test direct SSD/OTG → safe ejection and physical disconnection → direct charging, then reverse. If installation, Verify or operation fails, run **Diagnose.cmd** and review its local ZIP.

| Component | Included version |
|---|---|
| PMIC extension | 1.0.1871.0 |
| Type-C backend | 1.0.1867.0 |
| USB-C client | 1.0.1853.0 |
| Battery manager | 1.0.10732.0 |
| Fixed PD profile filter | 0.1.3.0, installer mode 1 |
| Battery miniclass | Audited 1680 or 10730 baseline; preserved |

## What changed in U4

Compared with the older public U1, PMIC is updated from 1869 to **1871**. U4 fixes PowerShell module startup, SHA256 collection without module autoload, empty-event-log handling and diagnostic export-error reporting. **U4's driver INF/SYS/CAT files are unchanged from U3.** A charging-speed or seamless-hub improvement over U1 has not been demonstrated; this package provides the current verified set and a more reliable installer/diagnostic workflow.

The delivered ZIP is exactly the archive installed and verified on the project tablet, including its file index. The custom filter in the source ZIP was rebuilt with EWDK and passed 4,672 ARM64 parser executions, 40 callback and 22 lifecycle executions in emulation. These are offline checks, not proof of new PPS/FRS hardware support.

## Diagnostics and recovery

**Check.cmd** checks compatibility/package integrity without installing. **Verify.cmd** checks the full selected INF/SYS identities, Running/Code0 state and actual PD-filter attachment after restart.

**Diagnose.cmd** creates a ZIP under `%LOCALAPPDATA%\SK-Charging-Diagnostics` and uploads nothing. It contains OS/build, driver identities, installation records, USB/battery state and copies of the five selected charging/battery INF/SYS/CAT packages. Review device identifiers and local paths before sharing.

Before an update, Install verifies and saves selected packages, recognized PD extensions and their previous configuration under `%ProgramData%\SK-Charging-Community\...\Previous`. **Restore.cmd** uses the latest reserve; the copy within a specific reserve selects that backup. Safely eject/disconnect USB storage, run Restore, then restart manually. The miniclass stays preserved. Unknown intervening changes or incomplete backups are refused.

Only a **public development certificate** is supplied; the installer may import it into LocalMachine Root/TrustedPublisher. No private signing key, firmware, camera or audio update is included. `FILES-SHA256.json` and `manifest.json` identify the package. Long-term stability and all accessories are not covered by the recorded tests.

## ❤️ Help improve charging and USB-C

This is independent work on a real tablet: studying power and USB-C behavior, building ARM64 drivers, testing chargers, power banks and hubs, and investigating failures that can reboot the device. Progress takes careful experiments and repeated validation. If this project is useful to you, support helps continue the work toward more reliable charging and USB switching.

[![Support via DonationAlerts](https://img.shields.io/badge/Support-DonationAlerts-orange?style=for-the-badge)](https://www.donationalerts.com/r/deskcj) [![Support via PayPal](https://img.shields.io/badge/Support-PayPal-0070BA?style=for-the-badge&logo=paypal&logoColor=white)](https://paypal.me/vladcj)

You can also help **without donating**: star the repository, tell other nabu owners about it, and share reproducible results with your Windows version, hub or charger model, and connection sequence. That feedback helps prioritize fixes. Donations support the research, not a guaranteed result or delivery date. Thank you for helping an independent Windows on ARM project grow!

## Disclaimer

This is an independent community project, **not affiliated with or endorsed by Xiaomi, Qualcomm, or Microsoft**. Company and product names identify compatible hardware and technologies only; rights to those names belong to their owners. The underlying Qualcomm drivers and their notices remain the property of their owners; the authorship of the original `fix20` has not been established.

The drivers are experimental, test-signed kernel software provided **“as is”**, without any guarantee of stability, support, or Android-level charging speed. Crashes, boot failure, device problems, and data loss are possible. Before installing, keep a backup and a recovery method. The decision to test and the associated risks are yours. This notice does not grant permission to redistribute third-party components contrary to their licenses.

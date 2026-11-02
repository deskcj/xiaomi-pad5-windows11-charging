# Charging and USB-C on Xiaomi Pad 5 with Windows 11

[Русский](README.ru.md) · Xiaomi Pad 5 (`nabu`) · Windows 11 ARM64

![Status: public preview](https://img.shields.io/badge/status-public%20preview-orange?style=for-the-badge) ![Device: Xiaomi Pad 5](https://img.shields.io/badge/device-Xiaomi%20Pad%205-blue?style=for-the-badge) ![Platform: Windows 11 ARM64](https://img.shields.io/badge/platform-Windows%2011%20ARM64-0078D4?style=for-the-badge)

**SK-Charging 1868** is an experimental community driver pack. In tested scenarios, the tablet switches between charging and USB storage without rebooting Windows; charging and an SSD also work together through a hub. This is not an official driver or a guarantee of compatibility with every accessory.

## Download

**[Download SK-Charging-1868.zip](https://github.com/deskcj/xiaomi-pad5-windows11-charging/raw/7998b94957dbd4d9da0689191bd7ef8948ac94e1/downloads/SK-Charging-1868.zip)** · SHA-256: `F2A2EEBC8BF730BCFE58E5AD671176D286284B05804A968C0C37AA5C555E5432`

The archive contains four updated `INF/SYS/CAT` driver packages; an unchanged battery miniclass reference used for compatibility checks (**not installed**); a public test certificate; `Install.cmd`, `Diagnose.cmd`, and `Restore.cmd`; instructions; and file hashes. It contains no private signing keys. Before updating drivers, the installer verifies the files and backs up the previous drivers to the tablet's internal drive.

> [!WARNING]
> Use this pack only on a Xiaomi Pad 5 (`nabu`) running Windows 11 ARM64 with the base nabu drivers and **Test Mode already enabled**. Back up your data and keep a Windows recovery method before installing.

## Installation

1. Disable Secure Boot and enable Windows **Test Mode** by following [this guide](https://github.com/erdilS/Port-Windows-11-Xiaomi-Pad-5/blob/main/guide/English/disable-secureboot-en.md).
2. Extract the entire ZIP to a folder on the tablet's internal drive.
3. Double-click `Install.cmd` and approve the administrator prompt. If a compatibility check fails, do not assume the drivers were installed.
4. After `Driver set staged; reboot manually`, safely eject USB storage and reboot Windows yourself.
5. Run `Diagnose.cmd` from the archive. Check that versions and hashes match, `Running=True`, and `ProblemCode=0`.

The installer does not change Secure Boot, BCD, or camera drivers and does not reboot the tablet automatically.

## What was tested

- ✅ Direct charging from a USB-C wall charger and a power bank is detected; charging returns after safely ejecting an SSD, without rebooting.
- ✅ A USB-C SSD and an OTG flash drive work in the tested connection sequences.
- ✅ With an **Acer HY41-T9** hub, charging and an SSD worked together; charging resumed after reconnecting the power cable.
- ⚠️ **Removing power from that hub** briefly disconnects and reconnects the SSD. Do not change hub power during disk writes.
- ❌ Seamless hub power handover and **PPS** fast charging are not implemented. Long-term stability with every hub and charger has not been established.

**Charging speed:** build 1868 negotiated fixed USB PD profiles up to **18 W** (9 V × 2 A or 12 V × 1.5 A). This is a negotiated contract limit, **not measured battery power**. In an earlier eight-minute build 1867 test, battery telemetry showed an energy gain of about 0.91–0.95 Wh, but the maximum speed of build 1868 has not been checked with an external power meter. Android-equivalent fast charging and PPS are not promised.

## Diagnostics and recovery

`Diagnose.cmd` creates a local report in `%LOCALAPPDATA%\SK-Charging-Diagnostics` and uploads nothing. Review the report before sharing it: it may contain USB identifiers and local paths. Previous drivers and installation records are saved under `%ProgramData%\SK-Charging\Install-*`. To roll back, use `Restore.cmd` from the archive or the `Previous` folder of the appropriate backup; safely eject and disconnect USB storage first. Reboot Windows manually after restoring.

## ❤️ Help improve charging and USB-C

This is independent work on a real tablet: studying power and USB-C behavior, building ARM64 drivers, testing chargers, power banks and hubs, and investigating failures that can reboot the device. Progress takes careful experiments and repeated validation. If this project is useful to you, support helps continue the work toward more reliable charging and USB switching.

[![Support via DonationAlerts](https://img.shields.io/badge/Support-DonationAlerts-orange?style=for-the-badge)](https://www.donationalerts.com/r/deskcj) [![Support via PayPal](https://img.shields.io/badge/Support-PayPal-0070BA?style=for-the-badge&logo=paypal&logoColor=white)](https://paypal.me/vladcj)

You can also help **without donating**: star the repository, tell other nabu owners about it, and share reproducible results with your Windows version, hub or charger model, and connection sequence. That feedback helps prioritize fixes. Donations support the research, not a guaranteed result or delivery date. Thank you for helping an independent Windows on ARM project grow!

## Disclaimer

This is an independent community project, **not affiliated with or endorsed by Xiaomi, Qualcomm, or Microsoft**. Company and product names identify compatible hardware and technologies only; rights to those names belong to their owners. The underlying Qualcomm drivers and their notices remain the property of their owners; the authorship of the original `fix20` has not been established.

The drivers are experimental, test-signed kernel software provided **“as is”**, without any guarantee of stability, support, or Android-level charging speed. Crashes, boot failure, device problems, and data loss are possible. Before installing, keep a backup and a recovery method. The decision to test and the associated risks are yours. This notice does not grant permission to redistribute third-party components contrary to their licenses.

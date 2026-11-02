<h1 align="center">SK-Charging · Xiaomi Pad 5</h1>
<p align="center"><strong>Charging and USB-C switching for Windows 11 ARM64</strong><br>Community driver pack · build 1868 · tested on nabu</p>

<p align="center">
  <img src="https://img.shields.io/badge/device-Xiaomi_Pad_5-ff6900" alt="Xiaomi Pad 5">
  <img src="https://img.shields.io/badge/platform-Windows_11_ARM64-0078d4" alt="Windows 11 ARM64">
  <img src="https://img.shields.io/badge/build-1868-2ea44f" alt="Build 1868">
  <img src="https://img.shields.io/badge/status-public_preview-orange" alt="Experimental public preview">
</p>

<p align="center"><strong>English</strong> · <a href="README.ru.md">Русский</a><br><a href="#download-and-install">Download & install</a> · <a href="#what-works">Test results</a> · <a href="#known-hub-bug">Known bug</a> · <a href="#diagnostics-and-recovery">Diagnostics</a> · <a href="#support-the-project">Support</a></p>

The goal is practical: plug in a charger and charge; replace it with an SSD or an OTG device and use USB; switch back to charging without rebooting Windows. **Build 1868 gives good results in the tested connection sequences**, including direct USB-C storage, an OTG flash drive, a powerbank, and a powered hub.

This download contains the **exact driver bytes currently working on the project tablet**, with a double-click installer, verified backup, and diagnostic script. It is a community preview for **Xiaomi Pad 5 / nabu**, not an official or universally stable driver release.

> **Remaining bug:** removing the charger from an Acer HY41-T9 hub briefly disconnects and reconnects the SSD. Returning the charger resumes charging. Seamless USB continuity during that power change is **not fixed** in this release.

## Download and install

### [⬇ Download SK-Charging 1868 — ZIP](https://github.com/deskcj/xiaomi-pad5-windows11-charging/raw/refs/heads/main/downloads/SK-Charging-1868.zip)

[SHA-256 file](downloads/SK-Charging-1868.zip.sha256) · [English archive instructions](tools/community1868/README.md) · [Русская инструкция](tools/community1868/README.ru.md)

```text
F2A2EEBC8BF730BCFE58E5AD671176D286284B05804A968C0C37AA5C555E5432
```

**Prerequisites:** Xiaomi Pad 5 (nabu), Windows 11 ARM64, the base nabu Windows driver set, and **already active Test Mode**. The pack checks the compatible battery miniclass version/hash; it is not a replacement for the complete base driver pack. See the [nabu Windows boot/signing guide](https://github.com/erdilS/Port-Windows-11-Xiaomi-Pad-5/blob/main/guide/English/disable-secureboot-en.md) if your installation is not prepared.

1. Download and **extract the entire ZIP** to a folder on the tablet's internal Windows drive.
2. Double-click **`Install.cmd`** and allow the Administrator prompt. It uses native Windows PowerShell; no Python, SDK or manual INF selection is needed.
3. Wait for **“Driver set staged; reboot manually”**. Save your work, safely eject USB storage, and reboot manually.
4. Run **`Diagnose.cmd`** after reboot. The five driver rows should show matching versions and hashes, `Running=True`, and `ProblemCode=0`.

If Install reports an error, keep its record and run diagnostics; do not treat a failed run as installed. Repeating Install on the matching stack makes no changes. The installer refuses other models, incomplete payloads, an incompatible base miniclass and automatic driver downgrades.

Before staging the four updated packages, Install saves **all five previous INF/SYS/CAT packages** to the internal Windows drive and verifies their hashes. Windows activates the updated set after a manual reboot. The installer imports only the included **public** development certificate into Root/TrustedPublisher when needed. It does not change BCD/Secure Boot, modify camera drivers, or reboot automatically.

Optional preflight, without installing or changing certificates:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install.ps1 -CheckOnly
```

## What works

✅ means **observed in the project tests**, not a promise for every peripheral or Windows configuration. Latest hardware checks: **2 November 2026, build 1868**.

| Status | Scenario | Observed result |
|:--:|---|---|
| ✅ | Direct Samsung-labelled charger | Power detected; fixed PD contract confirmed; positive battery telemetry |
| ✅ | Direct powerbank | Power detected after SSD removal; fixed PD contract and positive telemetry |
| ✅ | Direct iPhone-labelled charging block | Power detected after the powerbank; fixed PD contract and positive telemetry |
| ✅ | Charger → direct Kingston XS2000 USB-C SSD | SSD appears without a Windows reboot |
| ✅ | Safely ejected SSD → direct charger/powerbank | Charging detection returns without a Windows reboot |
| ✅ | Kingston DataTraveler 3.0 through OTG | USB storage and volume appear; read-only directory check succeeded |
| ✅ | OTG flash drive → direct Samsung charger | Charging detection returns |
| ✅ | Acer HY41-T9 + charger + Kingston XS2000 | Charging and SSD both work in the tested setup |
| ✅ | Return the PD charger to the hub | Charging resumes; user reported SSD stayed connected on return in recent cycles |
| ⚠️ | Remove the PD charger from the hub | SSD briefly disconnects/reconnects — still reproducible |
| ⚠️ | Every boot, sleep/resume, load and cable orientation | Full coverage is pending; earlier boot checks were promising |
| ❌ | PPS / demonstrated seamless FRS handover | Not provided by this release |
| ⚠️ | Maximum fast-charge wattage | Not established with an external input-power measurement |

The short version of the current progress:

- [x] Tested direct charging, USB-C SSD and OTG flash-drive switching.
- [x] Tested simultaneous charging and SSD operation through Acer HY41-T9.
- [x] Charging returns after the hub's PD cable is reconnected.
- [x] One-click launchers, read-only diagnostics and verified previous-driver backup.
- [ ] Keep SSD continuously connected while the hub's charger is removed.
- [ ] Enable and validate PPS / maximum fast charging.
- [ ] Complete broader boot, suspend/resume, peripheral and sustained-load testing.

## Is it really charging? What about fast charging?

The investigation uses **USB PD negotiation records plus documented battery-driver telemetry**, rather than the battery icon alone. In the latest build 1868 tests, the battery was already at 100%: power was reported online and battery rates were positive, but capacity was capped at full. Those tests support charging/top-up; they cannot demonstrate a fresh capacity gain or maximum charge rate.

Earlier completed **8-minute tests on build 1867** reported actual battery-energy gains:

| Source | Reported energy gain | Mean battery rate |
|---|---:|---:|
| Powerbank | 0.911 Wh | 8.04 W |
| iPhone-labelled block | 0.945 Wh | 8.43 W |
| Samsung-labelled block | 0.911 Wh | 8.19 W |

These are battery-driver measurements, **not external USB input-power measurements**, and are not a maximum-speed benchmark for 1868.

In the 1868 traces, the tested powerbank negotiated **9 V × 2 A**; the iPhone-labelled and Samsung-labelled blocks negotiated **12 V × 1.5 A**. Each is an **18 W contract/request limit**, not a claim that 18 W reaches the battery. Tablet load, battery state, thermal policy, the cable and the hub all matter.

The tested Samsung source and powerbank advertised PPS, but **Windows did not request PPS**. A generic Windows charging indication does not establish the charging speed, and an Android “fast charging” label cannot be used as proof of the Windows contract or rate. This release does not promise Android-equivalent maximum fast charging.

## Known hub bug

With **Acer HY41-T9 + Kingston XS2000**, removing only the hub's PD charging cable causes a brief SSD disappearance and reappearance. Returning the cable restores charging; recent user cycles did not show another SSD interruption on return.

The required next improvement is to keep the USB session alive while hub power changes. The interruption is reproduced, but the exact division between hub power handover and the Windows USB-C/role sequence still needs proof. **It is not established that a driver-only change can eliminate it for this hub.** Build 1868 does not add a validated FRS/seamless handover mechanism.

Avoid changing hub power during disk writes; use safe removal when appropriate. A disappearing volume can interrupt an application even when it returns quickly. A possible reconnect on initial hub insertion was also reported, but its exact event sequence has not yet been established.

## What's in build 1868?

The bundle number is **1868**; individual component versions differ:

| Component | INF version | Archive action |
|---|---|---|
| `qcpmicext` | 1.0.1866.0 | Install |
| `qcpmictcc` | 1.0.1867.0 | Install |
| `qcusbctcpm` | 1.0.1853.0 | Install |
| `qcbattmngr` | 1.0.10732.0 | Install |
| `qcbattminiclass` | 1.0.1680.0 | Preserve installed driver; exact files in `reference/` |

The unchanged miniclass keeps its original community signing identity and is not re-signed or installed. Its exact SYS hash is required as the tested base. The four modified packages carry a development/test signature, not WHQL production signing. The public certificate's historical name contains `NabuCameraDev`; using it here does not install or modify camera drivers.

Compared with 1867, **1868 changes the battery manager's handling of a voltage/power update when the current limit remains unchanged**. That update could previously be ignored. The focused repair preserves the existing special cases and adds no PMIC register writes, new protocol commands, timers or threads. Offline checks passed **1,728 ARM64 callback executions and 563 native unwind cases**, with no failures. The specific unchanged-current voltage transition still needs hardware validation; this is not a hub-disconnect fix.

The published pack also passed Windows PowerShell 5.1 preflight, a real diagnostic snapshot, eight SYS/INF catalog-membership checks, and twelve packaging/backup/guard checks. The tests did **not** reinstall drivers on the working tablet. [Version hashes and validation details](docs/BUILD1868.md).

## Diagnostics and recovery

**`Diagnose.cmd`** creates a local ZIP under `%LOCALAPPDATA%\SK-Charging-Diagnostics`. It collects driver versions/hashes/states, PnP problems, USB/storage topology, recent relevant System events, and standard battery telemetry. It does not install/reset devices, use private PMIC control IOCTLs, or upload data.

For five minutes of battery samples:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Diagnose.ps1 -Seconds 300
```

Review a diagnostic ZIP before sharing it: USB identifiers/event messages can include serial numbers and local paths. When [reporting an issue](https://github.com/deskcj/xiaomi-pad5-windows11-charging/issues), include the bundle number, Windows build, hub/charger/device models and the connection sequence. Share diagnostic evidence you have reviewed; raw memory dumps are not required.

Install records and verified backups are under `%ProgramData%\SK-Charging\Install-*`. To return to a specific saved stack, safely eject/disconnect USB storage and run **`Restore.cmd` inside that backup's `Previous` folder**. The main archive's Restore launcher chooses the latest backup. Restore may restart the USB/charging stack; reboot manually afterwards. Keep the printed backup path and your normal Windows recovery method in case Windows cannot start. [Full instructions](tools/community1868/README.md).

## Support the project

If this work helps your tablet, you can support continued investigation and testing:

- [💜 DonationAlerts](https://www.donationalerts.com/r/deskcj)
- [💙 PayPal](https://paypal.me/vladcj)

Donations are optional and do not guarantee a feature, compatibility or a delivery date. Testing reports and clear reproduction steps are also valuable.

Related project: [Xiaomi Pad 5 Windows 11 camera drivers](https://github.com/deskcj/xiaomi-pad5-windows11-camera). The charging installer does not modify that stack.

## Disclaimer and attribution

This independent community project is not affiliated with **Xiaomi, Qualcomm or Microsoft**. Original driver ownership and copyright notices remain with their respective owners; see [NOTICE.md](NOTICE.md). These experimental test-signed kernel drivers are supplied **as-is, without warranty**. Crashes, boot failure and data loss are possible. Keep backups and a recovery method, and install at your own risk. Good results on the project tablet do not guarantee every device, absence of BSODs, seamless hub power changes or maximum fast charging.

Earlier reports and experiments remain in the repository as research history. They describe older builds, not the current downloadable pack; the [previous README](https://github.com/deskcj/xiaomi-pad5-windows11-charging/blob/8166f9350a8de12fd8f0b519e1a9a64fa80cc2d4/README.md) is preserved in Git history.

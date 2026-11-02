# Build 1868 — package identity and validation

Date: 2 November 2026. Target: Xiaomi Pad 5 (nabu), Windows 11 ARM64.

The downloadable ZIP is a copy of the tested, selected driver packages on the project tablet. **No driver was recompiled or re-signed for this publication.** Component INF versions, rather than retained PE FileVersion strings, identify the bundle together with the following SYS hashes.

| Service | INF version | SYS SHA-256 |
|---|---|---|
| qcpmicext | 1.0.1866.0 | `AC79E695D905015908E3853E6A35DCFC16B22A81E99D1FD35BE08AED99A8E2BA` |
| qcpmictcc | 1.0.1867.0 | `7EE5593BB2FA79CB6F223C7F48F3320B36754609D3E3426671B4E10A079E4B5A` |
| qcusbctcpm | 1.0.1853.0 | `0A48C1493F03DF07D11EEF85DDBE0187D3FD3C86EBC903C5D761D9363B3C4109` |
| qcbattmngr | 1.0.10732.0 | `FA04E5BD5A17C8F09E752F5C177ABE90C89FCC34F335019BECDA6ABA6406DC22` |
| qcbattminiclass | 1.0.1680.0 | `7F7ECE18BF7ED43827E9E331274C4DA15A765B615B886DB8BE3209B9144FF4C4` |

## Payload and signatures

- Four installable packages: 12 INF/SYS/CAT files under `packages/`.
- Unmodified battery miniclass reference: 3 INF/SYS/CAT files under `reference/`, excluded from installation. Its original INF prints the equivalent version `1.0.1680.0000`.
- Four modified SYS/CAT pairs report **Valid** Authenticode signatures on the prepared test tablet. All eight SYS/INF catalog-membership checks passed with Windows SDK SignTool (`verify /pa /c`). This is test/development signing, not a WHQL claim.
- Public development certificate thumbprint: `F38EDD5C105095C8342556158CE66253F045965D`.
- Public certificate SHA-256: `1C655BB59BEF778420AB5E47BAE06A6FB8FF9178AA5881D99FCFC32904642D3B`.
- The reference miniclass keeps its original Windows On Andromeda signing identity. Its certificate chain could not be built to a trusted root on the project installation. It is not re-signed, imported as a new trusted signer, or reinstalled by this pack. The installer requires the already installed compatible SYS version/hash.
- No private signing keys, registry exports, user machine backups, serial-bearing diagnostic logs, memory dumps or raw ETW captures are published in this pack.

`manifest.json` lists exact payload file sizes/hashes. `FILES-SHA256.json` lists all other archive files; it excludes itself. The ZIP contains one `SK-Charging-1868/` folder with 28 files. [Archive checksum](../downloads/SK-Charging-1868.zip.sha256).

## Focused battery-manager repair

The event-5 callback could suppress a voltage/power update when the current limit stayed the same. Build 1868 changes the comparison path to handle that update. The patch replaces one comparison at RVA `0x7654` with a branch to a 64-byte leaf at RVA `0x30000`.

It preserves unknown current `-1`, true duplicates, the existing 900 mA special case and unrelated events/sources. It adds no PMIC register writes, new protocol commands, timers or threads.

Offline execution results:

- 1,728 executions of the actual ARM64 callback.
- 64 reproductions of the original defect.
- 563 native Windows unwind checks.
- Zero failures; signed mapped sections identical to the QA candidate.

**The specific unchanged-current voltage-transition fix still needs hardware acceptance.** Successful charging and storage tests after installation do not by themselves prove that branch was exercised. PPS is not implemented, and hub continuity is not fixed.

## Installer and diagnostic validation

Native Windows PowerShell 5.1 was used for parsing, `Install.ps1 -CheckOnly`, the documented battery-query helper and a real diagnostic snapshot. The preflight reported the release already selected. The snapshot showed all five versions/hashes matching, five drivers Running, PnP problem codes zero and no diagnostic errors. Battery was full; online/charging state and positive battery rate were reported. No new capacity gain was claimed.

The [12 packaging checks](../tests/community1868-package-checks.json) covered release hashes/trust, compatibility, rejection of corrupted/missing/extra payload files, a newer installed version, an incompatible miniclass, a USB backup destination and a non-ARM64 environment, plus a real 15-file DriverStore backup, rejection of a damaged backup and an unchanged final live baseline. To reproduce on an already matching prepared tablet, keep the checkout on the internal Windows drive and pass the extracted archive folder explicitly to [Test-Community1868Package.ps1](../tests/Test-Community1868Package.ps1) with `-Root`.

These publication checks **did not call driver installation, change certificates or reboot**. Administrator/UAC installation and recovery launchers were reviewed and parsed; this packaging exercise did not reinstall the working tablet or perform a fresh install on another community member's tablet. No universal installation/stability guarantee follows from it.

Installation uses `DiInstallDriverW` with `DIIRFLAG_INSTALL_AS_SET` (`0x40`) for deferred activation at reboot. Explicit restore uses `DIIRFLAG_FORCE_INF` (`0x2`) and can restart devices, so USB storage must be disconnected. There are no historical OEM-number deletion commands. Previous packages and recovery launchers are retained on the internal drive before Windows installation is requested; no automatic rollback/reboot or device reset is performed by the normal Install action.

## Hardware evidence and open work

Build 1868 tests covered direct Samsung charger, charger to Kingston XS2000, safely ejected SSD to powerbank, powerbank to iPhone-labelled block, iPhone block to Kingston DataTraveler 3.0 through OTG, OTG to Samsung charger, powered Acer HY41-T9 with SSD, and hub PD-cable removal/return. Direct charging/storage scenarios worked in those runs. The flash drive's disk/volume relationship and a read-only root-directory query were checked; 16 topology samples showed it present without device errors.

Removing PD charging from the hub still briefly disconnects/reconnects the SSD. Returning PD restores charging; the cycle's ETW capture was finalized with zero lost events. A possible reconnect at initial powered-hub insertion is user-reported and still needs exact event analysis. All physical-test captures are stopped; this release deliberately retains the known hub limitation.

Fixed PD contracts were confirmed at 9 V/2 A for the tested powerbank and 12 V/1.5 A for the tested iPhone-labelled and Samsung-labelled blocks. These are request/contract limits, not externally measured input power. PPS was advertised by the tested Samsung source and powerbank but not requested. See the [English results](../README.md) or [Russian results](../README.ru.md) for the earlier build 1867 energy-gain measurements and their limits.

Broader boot, sleep/resume, sustained load, different peripherals/chargers/cables and maximum fast charging remain open. A complete Android-equivalent power policy or a seamless handover mechanism is not claimed.

# Hardware trial — 26 October 2026

**FAILED charger-removal transition:** removing only the charger from the attached hub caused both hub and SSD to disappear. First boot and charging with the adapter connected succeeded, but functional acceptance failed. No new driver installed or automatic device reset attempted in response.

The first Windows restart completed with PMIC 1.0.1843.0 / oem50.inf. The service is running, device problem codes are 0, and the battery miniclass remains 1680. The owner connected the hub after Windows loaded. Short charging/storage checks passed; more scenarios remain open.

## Earlier installation checkpoint

The installation returned 3010 and required a restart; that restart has now been completed once.

The signed SYS again passed 1,624 ARM64 emulation cases and 93 native unwind cases. A fresh compilation and patch build reproduced the exact audited unsigned SYS. No kernel binary changed in installer/recovery revision 2.

Full SYSTEM/BCD and baseline/new packages were copied and verified externally before activation. Revision 2 preserves the pre-stage SYSTEM hive for restoration after removal of the experimental package. Four preview/selection guards passed. Microsoft OROpenHive validated the real saved SYSTEM, and an independent parser read 56,197 keys and confirmed the original binding. A separate live reg.exe load check failed with ERROR_FILENAME_EXCED_RANGE; its cause remains unresolved. Actual offline Apply and failed-boot recovery have not been exercised.

At the initial installation checkpoint, boot, charging, hotplug and sleep/wake were pending. The first boot result below supersedes that checkpoint. Pre-reboot power observations cannot validate the new driver because Windows requires the restart. No absence-of-BSOD guarantee is made.

## First boot result

One Windows restart completed with PMIC 1.0.1843.0 / oem50.inf and the expected SYS hash. The service is running, PMIC and battery problem codes are 0, and the battery miniclass remains 1680. The owner reports connecting the hub after Windows loaded.

During the initial three-minute post-boot observation, reported battery SOC rose from 96% to 97%, reported remaining energy rose, and charge/discharge flags stayed consistent (Charging=1, Discharging=0). Reported charging rate was about 7 W; no external input-power measurement was taken. The hub and SSD stayed enumerated. Three uncached 32 KiB reads matched the internal reference without writing to the SSD.

No new System bugcheck 1001, Kernel-Power 41 or disk 11/153/157 events were found within this boot at the checkpoint. The same three WUDFRd 219 warnings were also present before the experiment and remain recorded. The RunOnce collector did not execute automatically; collection was started manually.

This proves one successful startup and a short post-boot observation. Hub hotplug, direct charging, startup with the hub already attached, cold boot and sleep/wake remain open. See [first-boot evidence](../evidence/first-boot.json).

## Failed external-power removal

The owner disconnected only the charger from the hub. The log recorded AC offline / Charging=0 / Discharging=1 at 17:55:23, then hub and SSD removal at 17:55:25 (CM return 13). PMIC, Type-C, host and dual-role controllers retained problem code 0. Windows stayed alive. The external project volume was unavailable, so evidence and work remained on the internal disk. Additional stress tests were paused while capturing the state and asking for the charger to be restored without moving the hub or rebooting.

The root cause is not proven: no Windows PMIC-register readback or physical VBUS-voltage capture was taken at this edge. A missing power-source handover is a hypothesis, not a measured register state. The r1 helper retains fix20's policy heuristic and has no newly implemented event-driven recovery of VBUS.

In the [official Android implementation](https://github.com/MiCode/Xiaomi_Kernel_OpenSource/blob/71b6effd2dfa8f703dd1ea17acd1323b2fd3cf6c/drivers/power/supply/qcom/smb5-lib.c), USB-host notification enables OTG VBUS separately from the Type-C role configuration; the regulator enable/disable routines explicitly update the OTG bit. The [register definitions](https://github.com/MiCode/Xiaomi_Kernel_OpenSource/blob/71b6effd2dfa8f703dd1ea17acd1323b2fd3cf6c/drivers/power/supply/qcom/smb5-reg.h) separate 0x1140 OTG control from 0x1544 Type-C role configuration. This supports examining that boundary, but does not prove Windows failed at that exact write or authorize blindly enabling OTG into an externally powered link.

Next analysis must locate Windows' existing VBUS-enable/disable callbacks and their role-transition notifications, compare them with saved Android measurements, and establish external-VBUS/CC state and error paths before changing the policy. Do not call this release Android-equivalent or fully stable.

## Charger return and direct connection

Returning only the charger restored the hub at 18:05:56, external-power indication at 18:05:57 and SSD at 18:06:00 without a restart. The charger-removal failure remains unresolved. See [return evidence](../evidence/charger-return.json).

The owner then safely ejected the external storage and connected the same charger directly. External power was first recorded at 18:32:05. The log subsequently recorded three offline/online cycles, last returning online at 18:32:47. The first of these drops was about 24 seconds after initial direct AC detection. The owner subsequently reported no further cable actions after insertion, while giving the initial hub-to-cable swap as the possible explanation. Exact physical insertion time was not independently captured. This is evidence of AC-status instability after connection, not proof of a physical VBUS dropout or of its root cause. As of 2026-10-26T18:40:04.8483579+05:00, it had remained online for 437.1 seconds. Direct charging is not marked as a stable pass.

SOC was 100% throughout this observation, so it cannot establish battery energy gain. No PMIC, Type-C or host problem codes were observed, and uptime remained continuous. The active SYS hash was rechecked and no driver changed for this test. Logging and working notes are on the internal disk, independent of the disconnected hub. See [direct observation](../evidence/direct-charger-observation.json).

The [nabu-charger comparison](NABU-CHARGER-REVIEW.md) records why its LN8000/Quick Charge driver is useful research but cannot be installed as a validated combined fix on this ACPI/PMIC configuration.

## Return after the direct-charger trial

The owner restored the powered hub and SSD without reboot. AC and hub returned at 18:42:27, SSD at 18:42:31; a matching 32 KiB uncached read passed. The logger completed at 18:58:25 with both present. [Evidence](../evidence/powered-hub-return-after-direct.json). Static investigation then identified and emulated a separate Type-C readiness-lock defect; its unsigned research candidate has not been installed. See [power handover analysis](POWER-HANDOVER.md).

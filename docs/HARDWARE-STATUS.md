# Hardware trial — 26 October 2026

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

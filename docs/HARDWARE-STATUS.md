# Hardware trial — 26 October 2026

Windows accepted PMIC 1.0.1843.0 as oem50.inf, replacing the oem92.inf binding. PnP reported problem code 0, but pnputil returned **3010: reboot required**. The battery miniclass remains 1680. This is an installation checkpoint, not a passed boot or charging test.

The signed SYS again passed 1,624 ARM64 emulation cases and 93 native unwind cases. A fresh compilation and patch build reproduced the exact audited unsigned SYS. No kernel binary changed in installer/recovery revision 2.

Full SYSTEM/BCD and baseline/new packages were copied and verified externally before activation. Revision 2 preserves the pre-stage SYSTEM hive for restoration after removal of the experimental package. Four preview/selection guards passed. Microsoft OROpenHive validated the real saved SYSTEM, and an independent parser read 56,197 keys and confirmed the original binding. A separate live reg.exe load check failed with ERROR_FILENAME_EXCED_RANGE; its cause remains unresolved. Actual offline Apply and failed-boot recovery have not been exercised.

Boot without the hub, boot with the hub, direct charging, battery reporting, hub/storage hotplug and sleep/wake remain **pending**. Pre-reboot power observations cannot validate the new driver because Windows requires the restart. No absence-of-BSOD guarantee is made.

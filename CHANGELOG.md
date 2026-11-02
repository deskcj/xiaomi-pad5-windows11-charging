# 2026-11-02 — SK-Charging 1868 public preview

- Publish the exact tested installed four-package charging stack, with the unchanged battery miniclass as reference.
- Add double-click Install/Diagnose/Restore launchers, model/hash/signature checks and verified internal-drive backups.
- Replace the landing page with English/Russian current results, direct ZIP download, donations and disclaimer.
- Document the focused same-current voltage/power battery-manager repair and its offline QA; specific hardware acceptance remains pending.
- Record successful direct charging, SSD/OTG and powered-hub scenarios. Preserve the known SSD reconnect on hub PD-power removal; PPS and maximum fast charging remain unproven.

# 2026-10-26 — experimental fix20r1

- Restore PMIC scaling constants overwritten by fix20.
- Replace the handwritten role trampoline with MSVC ARM64 C code and compiler unwind metadata.
- Check initialization for all roles and preserve transport error results.
- Keep the legacy role heuristic explicitly experimental.
- Add 1 624 ARM64 execution cases and 93 native Windows unwind contexts.
- Package a separately labeled legacy fix20 with unchanged section contents, updated test signature/catalog and corrected installer.
- Replace device-removal/pending-rename/automatic-reboot installation with Inspect / Stage / explicit Activate and full pre-experiment backups.
- Hardware boot, charging, hub and hotplug validation remains pending.

## Installer/recovery revision 2 and first installation

Restore the verified pre-stage SYSTEM after removing the experiment; include the recovery helper in the external Activate rescue before touching the live binding. Four snapshot guards pass. Kernel binaries unchanged. Installation selected oem50.inf and requires reboot (3010); boot/functional tests pending.

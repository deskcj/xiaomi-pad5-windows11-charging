# 2026-10-26 — experimental fix20r1

- Restore PMIC scaling constants overwritten by fix20.
- Replace the handwritten role trampoline with MSVC ARM64 C code and compiler unwind metadata.
- Check initialization for all roles and preserve transport error results.
- Keep the legacy role heuristic explicitly experimental.
- Add 1 624 ARM64 execution cases and 93 native Windows unwind contexts.
- Package a separately labeled legacy fix20 with unchanged section contents, updated test signature/catalog and corrected installer.
- Replace device-removal/pending-rename/automatic-reboot installation with Inspect / Stage / explicit Activate and full pre-experiment backups.
- Hardware boot, charging, hub and hotplug validation remains pending.

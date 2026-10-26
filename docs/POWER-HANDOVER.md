# Power handover and the Type-C lock finding

## Acceptance requirement

The owner requires uninterrupted USB storage operation when only the charger is removed from or returned to the hub. The hub remains attached to the tablet. Successful re-enumeration after a disconnect does not meet this requirement. A restart, controller reset or automatic device removal would interrupt an active copy operation and cannot be counted as the solution.

The current 1843 trial fails the removal transition. Returning charger power restores the devices, and a later powered-hub reconnection after direct charging also succeeded with a matching uncached read. Neither result establishes storage continuity through removal. Asked specifically about Android, the owner reports that removing only the charger also made the storage disappear there while the hub stayed physically connected. This is an uninstrumented owner report: whether the hub remained enumerated, supply-voltage timing and any I/O interruption duration were not captured. The exact hub's power handover remains a hardware/control-test question, and uninterrupted operation cannot be assumed to be a demonstrated Android baseline. [Owner report](../evidence/android-hub-removal-user-report.json).

## Verified Windows paths

These RVAs refer to the exact original binaries identified in [static evidence](../evidence/handover-static-analysis.json), not arbitrary releases.

* Original PMIC `0x7dd0` handles request `0x801c0fac`: a four-byte enable input controls masked write of bit 0 in `0x1140`. This is an existing OTG path.
* Original PMIC `0x8ac0` sets Type-C role through `0x1544`, mask 7. The experimental fix20/r1 changes this path and adds an OTG-disable decision based on the full `0x1509` byte. The order of those calls during the failing edge has not been captured.
* Original Type-C `0x6b40` processes control requests and dispatches writes to virtual TCPCI control registers. `0x7090` forwards commands to virtual register `0x50`. Both go through the shared register-access helpers described below.
* The Type-C binary searches device interface `8e863b1d-b0a2-4044-89a8-ea31318e3229` and queries protocol `151cc35b-90e7-4798-a7ed-e156de92a049`. The live interface registry identifies its backend as `qcpmictcc8150.sys`, ACPI `QCOM0582`, version 1680. That exact backend was also imported into Ghidra: helper `0xaf20` sends `0x801c0fac` on one branch. Helper `0xab48` sends role request `0x802a0fac` with logical index 1. Helper `0xa910` sends configuration request `0x802a0fa8`, which reaches the PMIC `0x1546` handler and is distinct from the role-setting request. [Backend manifest](../evidence/typec-backend-manifest.json).

Microsoft describes the [UcmTcpciCx policy/client boundary](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/write-a-usb-type-c-port-controller-driver), and the separate [control](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ucmtcpciportcontrollerrequests/ni-ucmtcpciportcontrollerrequests-ioctl_ucmtcpci_port_controller_set_control) and [command](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ucmtcpciportcontrollerrequests/ni-ucmtcpciportcontrollerrequests-ioctl_ucmtcpci_port_controller_set_command) requests. Register role configuration cannot be treated as the whole power policy. The official Android nabu implementation also distinguishes attached state, source/sink mode and OTG control.

## R1 logical-port readiness limitation

R1 checks the context pointer for slot 0 before delegating other indices to the legacy path. A four-case ARM64 check of the exact installed signed SYS reproduces a conditional defect: if slot 0 is absent while slot 1 is ready, a valid slot-1 request returns `0x61` without reaching the legacy role write. Whether slot 0 was absent in the live failing session is unknown; this is not yet a proven explanation of the hardware failure. The earlier 1,624 tests used uniform context readiness and did not cover this mixed-readiness case. Before another PMIC release, readiness must be validated for the selected supported slot, and mixed states added to the tests. Moving the Chinese full-byte state heuristic onto index 1 is not justified by this finding. [Counterexample](../evidence/r1-port-guard-counterexample.json).

## Reproduced lock leak in the Type-C binary

In `qcusbctcpm8150.sys` SHA-256 `7c63f4a4b8a9ee0f49b427b6ac94867d2475e02f85d92d5fbcfe4a8aa1804067`, helper `0x8e38` acquires lock state 1 for a read and `0x8fc8` acquires state 2 for a write at context offset `0x118`. Both then test readiness at `0xf0`. The normal callback path releases the lock. The not-ready path returns an error without releasing the acquired lock.

Actual ARM64 instruction emulation reproduces a later request remaining busy even after readiness becomes 1. Other lifecycle paths can reset the lock; this finding does not establish an irreversible lock under every execution order, nor prove that this path occurred during our observed hub failure. The callbacks also appear to log a nonzero underlying status while returning success; that behavior has been recorded and is outside the narrow lock repair.

## Offline research candidate

`typec-lockfix1` changes six existing instructions: for each helper it loads the same error directly into its preserved status register, uses the freed instruction to release its acquired lock, and preserves the existing error argument sent to tracing. It leaves an already-busy owner's lock intact. No sections, imports, prologues, epilogues or unwind tables were added or changed. It changes no PMIC register, USB role or charge profile.

Validation: 576 input scenarios compared original and candidate, eight retry sequences covered both first/retry method combinations, and three image bases were used. Stack, nonvolatile registers, x18, error returns and tracing arguments were checked. The real Windows ARM64 unwinder passed 318 captured contexts for the original and 318 for the candidate. The first native harness needed rebasing of emulated frame pointers; the corrected harness passed both. Ghidra independently decompiled both patched helpers and confirmed the missing releases were added.

This candidate is **unsigned, not installed, not boot-tested and not a demonstrated fix for loss of the hub**. There is no installation package for it. Current PMIC 1843 and Type-C 1680 remain installed. [Machine-readable results](../evidence/typec-lockfix1.json) and the [offline builder/emulator](../tools/build-test-typec-lockfix.py) are published; the proprietary source binary and experimental unsigned SYS are not included in the public downloads.

To reproduce offline, provide the exact audited Type-C SYS in a separate research folder and install `pefile`, `capstone` and `unicorn` in an isolated Python environment. Run `python tools/build-test-typec-lockfix.py --research-folder <folder>`; `--python-deps <directory>` is available for isolated modules. The builder refuses a different input hash. The native [unwind checker](../tests/native_unwind_typec.c) is a user-mode ARM64 program; it maps the SYS as non-executable data.

## Readback limit and next investigation

The installed SPMI binary was audited: READ uses `0x85b5240c` with three 32-bit header fields and a one-byte output for our bounded request. A hash-bound helper validated six header vectors and rejected an unlisted register. The existing device refused a read-access open with Win32 error 31, so **no PMIC read IOCTL was sent and no register value was obtained**. The cause of the open failure is not established. No peripheral grant, access-table change, register write or device reset was attempted.

Next work must observe the actual ownership and ordering of OTG, Type-C role and external-power changes, and instrument the same physical hub's transition if uninterrupted I/O is to be established. The owner-reported Android storage loss makes a Windows-only explanation insufficient. A driver cannot be assumed to hide a physical hub power reset or safely enable OTG into an externally powered connection. The Android snapshots distinguish historical QC charging directly from PD through the hub, but do not identify the current Apple adapter's model or prove its negotiated protocol.

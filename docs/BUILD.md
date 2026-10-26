# Build / reproduce

The original Qualcomm driver is proprietary binary input. The repair is an audited, hash-bound modification, not a rebuild of its unavailable full source. New code is in `src/role_repair.c`.

Inputs must match the two SHA-256 values in [INVESTIGATION](INVESTIGATION.md). Install the pinned Python dependencies in an isolated environment. Use MSVC ARM64 from EWDK/WDK; this build used compiler 19.44.35209.

```powershell
cl.exe /nologo /c /O2 /GS- /Zl /Gy- /GF- /guard:cf- /kernel /W4 /WX /Forole_repair.obj src\role_repair.c
python tools\build_patch.py --fix20 original-fix20.sys --stock stock-qcpmicext8150.sys --object role_repair.obj --output candidate-unsigned.sys
python tests\test_candidate.py candidate-unsigned.sys
```

New direct calls are resolved against the audited image; there are no new indirect call targets or imports. The constrained COFF linker accepts only the used ARM64 relocations and fails on unknown symbols/relocations. It adds separate RX code / R metadata sections, preserves existing exception entries, imports, load config and base relocations, and strips the old invalid signature. Microsoft ARM64 unwind records come from the compiled object, not handwritten guesses.

`test_candidate.py` executes actual mapped ARM64 instructions with mocked SPMI results and emits boundary fixtures. Build `tests/native_unwind.c` as an ordinary **native ARM64 user-mode console application**, linked with the SDK/kernel32/ntdll and normal CRT. It loads the candidate as non-executable data and calls RtlVirtualUnwind; it does not start a driver/service.

```powershell
native_unwind.exe candidate-unsigned.sys build\unwind-fixtures.bin
```

After signing with an existing trusted development certificate and rebuilding Inf2Cat for `10_GE_ARM64`, verify catalog membership with `signtool verify /pa /c package.cat package.sys`. Then compare every mapped section of the signed and tested images, verify PE checksum, and repeat native unwind against the signed file. Test signing is not Microsoft production signing; `/kp` production trust fails for this development certificate.

The public CER contains no private key. No certificate import, BCD changes or signing-key export is part of the installer. Do not distribute or commit a private signing key.

The 1 624 emulation / 93 unwind checks establish properties of this candidate's software implementation. They do not establish USB-PD policy correctness, measured charging power, boot compatibility or hotplug success on hardware.

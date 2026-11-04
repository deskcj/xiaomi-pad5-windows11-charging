# Continue development from U4

## Installed implementation

The release driver ZIP is the exact verified U4 package. U4 updates PowerShell launch, hashing and diagnostic behavior; its driver INF/SYS/CAT files are identical to U3. Compared with the older public U1, the PMIC is 1871. A higher version alone has not demonstrated better charging speed or seamless USB.

The `installer` folder contains exact U4 scripts and its pinned driver manifest. To use those scripts, take the packages, reference files, public certificate and complete file index from the driver ZIP. Run the delivered driver package to install; this source archive is not an installer.

`fixed-pd-profile-013` contains the custom KMDF filter source and portable EWDK build. It changes the offered fixed PD sink profile through the existing owner. It is not a PD3/PPS owner. Default source mode is 0; the released installer opts the supported device into mode 1. Private signing keys are deliberately absent.

`patches` contains the preserved C/assembly additions, constrained binary binders and offline tests for current driver development. Original Qualcomm source is unavailable. These patchers require exact prerequisite binaries, layout and build artifacts; hashes are listed in each `REFERENCE-IDENTITIES.json`. Input binaries are omitted from this source ZIP. The PMIC chain includes earlier repairs not fully reconstructible from this archive alone. The battery-manager vendor implementation is also unavailable. Do not remove hash, layout, unwind or lifetime checks to use a different baseline.

## Offline PPS/LN8000 work

`research/pd-next-core` contains PD session/wire handling, fixed/PPS exchanges, guarded LN8000 charge-path/ADC/protection code and FRS coordinator tests. These are offline components, not code installed by U4. They use mocked system/power boundaries. Historical compiler paths refer to H:\Vlad\EWDK; adjust them to your local EWDK. Python dependencies are in the root requirements file. Build.ps1 emits a component DLL for emulated ARM64 tests; it does not load a kernel driver.

Remaining PPS prerequisites: exclusive native PD3 ownership and quiescence of the current owner; reviewed LN8000 SPB/I2C endpoint; validated ADC/protection mappings; board-specific power sequencing and fault rollback. The ACPI audit found I2C5 started but no validated LN8000 endpoint. No pump probe/ACPI override has been installed. Selecting an APDO or raising a limit without these bindings is not a complete implementation.

## Hub link interruption

Removing charger power from a tested Acer hub interrupts the upstream link for about 229–231 ms. Another tested hub also showed the SSD interruption. Re-inserting power usually resumes charging without another SSD interruption. A safely ejected SSD can re-enumerate after loss of the upstream hub session.

The measured root link loss precedes PMIC queued work (~0.84 ms), switcher-power-ok work (~0.93 ms), CC DPC (~11.13 ms), and later power enable (~175.33 ms). No earlier PEP disable was observed, but XHCI WPP coverage was absent, so an early controller/PHY reset is not excluded. Current IRQ storm handling and late CC events do not explain or prove a fix for the initial loss. HS PHY VBUS override initialization already matches the reviewed Android behavior. Windows autonomous FRS detector/route, isolation and boost bindings remain unproven. Android switcher-power-ok boost-back handling is not FRS. Masking PnP removal would not preserve a lost physical USB session.

## Installation conflict

An independently installed `nabutypec.inf` 1.0.13.2 can outrank the requested Type-C backend: observed rank 00FE0001 versus 00FF0001. Complete-set staging may be accepted while Windows retains the old backend. Always require post-reboot Verify PASS for the full selected set. A date/version bump does not beat a better rank. No arbitrary FeatureScore, unknown OEM deletion or forced live reset is implemented. Complete identity and usage review is required before a safe migration for that configuration.

## References and reporting

- Xiaomi kernel sources: https://github.com/MiCode/Xiaomi_Kernel_OpenSource (nabu branches; drivers/power/supply/qcom/smb5-lib.c, ti/pd_policy_manager.c, ln8000_charger.c).
- Microsoft DiInstallDriverW: https://learn.microsoft.com/en-us/windows/win32/api/newdev/nf-newdev-diinstalldriverw
- Microsoft FeatureScore: https://learn.microsoft.com/en-us/windows-hardware/drivers/install/inf-featurescore-directive

Preserve reference hashes and distinguish component tests, installation verification and hardware observations. Hardware changes need explicit power-path proof; mock replays alone do not validate PPS, FRS or USB continuity. Review diagnostics for local paths/device identifiers before sharing.

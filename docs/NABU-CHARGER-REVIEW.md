# FerrisMind/nabu-charger: comparison with this tablet

Source snapshot: [4aed0960c7315f3c34ca92d4763df572e05a2059](https://github.com/FerrisMind/nabu-charger/tree/4aed0960c7315f3c34ca92d4763df572e05a2059), reviewed on 26 October 2026. The source was downloaded and inspected; its installers, register probes, build and test suite were not executed on this tablet.

## What is relevant

The project implements a Windows ARM64 KMDF driver for the LN8000 charge pump, charger classification, HVDCP/Quick Charge negotiation and pump protection/telemetry. It is useful evidence for how the nabu charging path can be implemented on Windows. Its tests and hardware measurements belong to that project; they are not validation of this tablet or of a combined installation.

The [README](https://github.com/FerrisMind/nabu-charger/blob/4aed0960c7315f3c34ca92d4763df572e05a2059/README.md) leaves PD voltage negotiation with the platform Type-C implementation. The [findings](https://github.com/FerrisMind/nabu-charger/blob/4aed0960c7315f3c34ca92d4763df572e05a2059/docs/FINDINGS.md) qualify the PD results: adapter detection alone did not establish reliable battery capacity growth in their setup. This tablet previously showed reported SOC 96% to 100% with the powered hub; the setups and measurements must not be conflated.

The current owner describes the adapter as an original Apple USB-C charger. Model, rating and cable endpoints are unverified. No particular PD profile or Quick Charge capability has been established for that adapter.

## Installation blockers and interactions

* The LN8000 driver targets ACPI `PEIC` / `QCOM057E`. This tablet has no enumerated `ACPI\\QCOM057E` device. Its live DSDT does not contain the `PEIC` name or the `QCOM057E` string. This does not prove that the physical chip is absent or audit every possible SSDT; it does mean the expected driver target is currently missing. No ACPI/UEFI change was made.
* The README explicitly says the combination with fix20/usbfix has not been measured, and warns that both drivers can write the same charger registers. Our active PMIC is the modified 1.0.1843.0 build; it is not their tested stock binary.
* The driver can publish its own battery class. Our existing miniclass 1680 already supplies the battery meter. Any future integration must explicitly resolve publication and ownership rather than assume two battery providers are harmless.
* The [HVDCP source](https://github.com/FerrisMind/nabu-charger/blob/4aed0960c7315f3c34ca92d4763df572e05a2059/crates/ln8000-kmdf/src/hvdcp.rs) discusses releasing D+/D- through USBFn/URS for Quick Charge. That is a separate requirement from preserving a working USB data host and powering an attached hub.

## Relation to the reproduced hub failure

On our 1843 build, removing only the adapter from the attached hub removed both the hub and SSD. Returning only the adapter restored the hub, external-power indication and SSD without a Windows restart. PMIC and host PnP problem codes stayed zero. No PMIC-register or physical VBUS measurement was captured at the failing edge.

Consequently the charge-pump project is not a demonstrated fix for this USB power-source transition. The next policy investigation must establish external-VBUS state, Type-C role, existing Windows OTG callbacks and register ownership. Register constants or the ability to open an SPMI device are not sufficient justification to write live registers. No new PMIC reads/writes or LN8000 driver installation were performed for this comparison.

The foreign source is GPL-2.0-or-later; its provenance and license remain with the downloaded snapshot. This review links to it and does not incorporate its code into the experimental PMIC package.

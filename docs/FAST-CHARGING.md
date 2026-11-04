# Measured charging behavior

These measurements establish real accelerated battery charging in the tested configurations. They do not establish full 33 W input power, PPS, or an Android-equivalent maximum.

| Charger and connection | Evidence | Limit of the conclusion |
|---|---|---|
| Samsung, directly connected, PMIC 1871 | PD Request → Accept → PS_RDY, fixed 9 V / 3 A; 46 positive samples over 232.361 s; 13.8015 W mean net battery power; +945 mWh | 27 W is the contract ceiling, not measured input power. Windows selected fixed PD, not PPS. |
| Xiaomi MDY-11-EZ rated 33 W, USB-A → USB-C, directly connected | Initial five-minute trace: 17.435 W mean net battery power. Follow-up: 37 samples / 180 s, 16.049 W mean, 17.682 W peak. Input-voltage follow-up: 13/13 successful ADC2 channel 2 reads, 8.549–8.631 V, 8.604 V mean; about 16.0 W mean net battery power | Input current and protocol were not measured. Battery SOC around 80–82% and temperature around 40°C may affect speed, but neither is a proven limiter. |
| Tested iPhone mains adapter and power bank | Positive battery charge and successful switching in recorded local tests | Results apply to those accessories; no universal fast-charge claim. |

Net battery watts exclude tablet consumption and conversion losses. A valid negotiated limit, a high-wattage charger label, a Windows icon, or installer PASS alone does not establish input watts. A compatible inline meter that preserves the cable/charger protocol is needed for independent input V/A/W measurement.

For controlled comparisons, use direct connections, similar load/temperature and roughly 30–70% SOC; record at least five minutes. The supplied raw participant diagnostics are not public source artifacts. No continuous trace is inferred from isolated screenshots.

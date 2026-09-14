# Suricata detections

`local.rules` contains the local signatures modelled by the SentinelSwitch sensor. The synthetic
`data/suricata/eve.json` dataset only ever references signature IDs defined here; the generator reads
this file so the `alert.signature`, `alert.category` and `alert.severity` fields always agree with the
rule text.

Severity mapping used by the correlation layer (`metadata: sentinel_severity`):

| sentinel_severity | Suricata `alert.severity` |
| --- | --- |
| high | 1 |
| medium | 2 |
| low | 3 |

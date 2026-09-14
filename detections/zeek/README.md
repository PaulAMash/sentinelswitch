# Zeek detections

Scripts loaded on the SPAN-fed sensor (`SEC-TP01`, `eth1`). The twin models the notices these scripts
produce; `data/zeek/notice.log` only contains notice types defined here or in the stock Zeek scan policy:

| notice | source |
| --- | --- |
| `Scan::Address_Scan` | policy/misc/scan (thresholds lowered in `sentinel-scan.zeek`) |
| `Scan::Port_Scan` | policy/misc/scan |
| `SentinelDNS::NXDomain_Burst` | `sentinel-dns.zeek` |
| `SentinelDNS::High_Query_Rate` | `sentinel-dns.zeek` |

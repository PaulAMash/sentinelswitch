# Detection engineering

SentinelSwitch treats detection as three layers that build on each other:

1. **Sensor signatures** — Suricata rules (`detections/suricata/local.rules`) and Zeek policy
   (`detections/zeek/*.zeek`) that fire on traffic characteristics.
2. **Switch-native events** — RADIUS results and IOS syslog from DAI, DHCP snooping, port security
   and BPDU Guard, which are detections in their own right.
3. **Correlation rules** — declarative YAML (`detections/correlation/*.yaml`) that turn one or more
   of the above into a scored detection for a specific actor.

## Normalization

Every source is reduced to one event shape (`backend/sentinelswitch/detection/normalize.py`):

| field | meaning |
| --- | --- |
| `ts` | ISO-8601 UTC, millisecond precision |
| `source` / `kind` | `suricata` alert, `zeek` notice, `radius` auth, `syslog` message |
| `severity` | `high` / `medium` / `low` / `info` |
| `actor_ip`, `mac`, `interface` | whichever actor keys the source can supply |
| enrichment | `port_class` from the port intent, `claims_gateway` for DAI messages, parsed Zeek notice fields (`ports_scanned`, `nxdomain_ratio`, `dga_like`, …) |

Suricata signatures that track by destination (the NXDOMAIN response burst) are mapped so that
`actor_ip` is the *client*, not the DNS server.

## Correlation rules

A rule declares a trigger, an aggregation window, a base confidence and a list of evidence
features. When a trigger fires for an actor, the engine waits `aggregate_window` seconds (on the
scenario's simulated clock), gathers everything it knows about that actor, and scores:

```
confidence = clamp(base + Σ weight(feature matched), 0.05, 0.99)
```

Severity can depend on which features matched (for example, a port scan from an authorized
scanner is `medium`, from anything else `high`).

| rule | trigger | window | base | features (weight) | severity |
| --- | --- | --- | --- | --- | --- |
| `lateral-reconnaissance` | sid 1000021/1000022 | 1.5 s | 0.75 | Zeek `Scan::Address_Scan` +0.10, prior ICMP sweep +0.07, PTR burst +0.05, authorized scanner −0.35 | high |
| `port-scan` | sid 1000011/1000012 | 1.2 s | 0.70 | Zeek `Scan::Port_Scan` +0.12, ≥100 ports +0.08, server targets +0.06, authorized scanner −0.35 | high, medium if authorized |
| `dns-anomaly` | sid 1000030/1000031 | 45 s | 0.60 | NXDOMAIN ≥0.5 +0.12, DGA-like +0.15, ≥100 qpm +0.08, ≥200 domains +0.05 | high if DGA-like |
| `arp-spoofing` | `%SW_DAI-4-*` | 5 s | 0.65 | ≥3 denials +0.10, ≥20 denials +0.10, claims gateway +0.12, guest VLAN +0.03 | high if gateway / many |
| `rogue-dhcp` | `%DHCP_SNOOPING-5-…UNTRUSTED_PORT` | 3 s | 0.80 | ≥3 drops +0.08, Suricata sid 1000040 +0.07, unknown MAC +0.05 | high |
| `mac-address-change` | `%PORT_SECURITY-2-PSECURE_VIOLATION` | 5 s | 0.65 | unknown MAC +0.12, MAC belongs to another asset +0.20, AAA reject +0.10, after hours +0.05 | high if impersonation |
| `unauthorized-endpoint` | RADIUS MAB reject | 0 | 0.70 | workstation-class port +0.20, unknown MAC +0.06, port-security case −0.25 | high on corporate ports |
| `bpdu-violation` | `%SPANTREE-2-BLOCK_BPDUGUARD` | 0.05 s | 0.90 | `%PM-4-ERR_DISABLE` +0.06 | high |
| `auth-failure-burst` | RADIUS reject (EAP) | 120 s | 0.30 | ≥3 rejects +0.25, no later accept +0.15 (emit ≥0.50) | low |
| `certificate-failure` | RADIUS reject, reason contains "certificate" | 0 | 0.35 | unknown MAC +0.30 | low |
| `ntp-policy-violation` | sid 1000050 | 0 | 0.40 | — | low |

### Why the same behaviour scores differently

The dataset contains two instances of several scenarios. On the dataset day a port scan from the
authorized scanner IT-LT-037 scores 0.61 and is only logged; the validation instance of the same
traffic from MKT-WS-021 scores 0.96 and is quarantined. A guest laptop that emits three stale ARP
replies scores 0.78 (review); forty replies claiming the gateway score 0.99 (containment). Context
is part of the rule, not an analyst afterthought.

## Corroboration

The flagship rule needs two independent sources before it reaches the automatic tier: Suricata's
fan-out signature (base 0.75) plus Zeek's address-scan notice (+0.10). Prior discovery activity
adds the remaining confidence. Without the Zeek notice the detection would score 0.87 and land in
manual review.

## Confidence and severity in the policy

| tier | condition |
| --- | --- |
| automatic containment | confidence ≥ 0.95 **and** severity high |
| manual review | confidence ≥ 0.75 |
| monitor | anything else |

Guards can only lower the tier. See [containment.md](containment.md).

## Sensor signatures

`detections/suricata/local.rules` holds twelve local signatures in the 1000000 range. The dataset
generator reads the file, so an alert's `signature`, `category` and `severity` always match the rule
text. Thresholds are written for a small segment (for example, the ICMP sweep fires on 200 echo
requests in five seconds; the SMB fan-out on eight distinct hosts on 445 in five seconds).

`detections/zeek/` lowers the stock scan thresholds for a /24 and adds `SentinelDNS`, a SumStats-based
notice that reports queries per minute, NXDOMAIN ratio, unique domains and a DGA-likeness flag in its
`sub` field — exactly the fields the `dns-anomaly` rule consumes.

## Testing detections

* `backend/tests/test_detection.py` — scoring, windows, severity overrides, actor mapping, emit thresholds.
* `backend/tests/test_scenarios.py` — every scenario through the full pipeline.
* `make validate-security` — the eight-scenario harness with timing metrics.

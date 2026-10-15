# Demo guide

Exact commands to demonstrate SentinelSwitch from a fresh clone. Everything runs locally and offline
once dependencies are installed.

## 1. Set up

```bash
git clone <your fork> sentinelswitch && cd sentinelswitch
make setup        # venv, Python deps, Node deps, headless Chromium (~2 min)
make seed         # generate the dataset and load the baseline into SQLite
```

`make seed` ends with the validation summary:

```
✓ seeded data/generated/sentinelswitch.db: 36 devices, 44 alerts, 3 incidents, 136 auth events
✓ validation: 9/9 scenarios met their expected outcome (8 contained, 1 withheld by policy)  MTTD 10.446s  MTTA 0.533s  MTTC 1.214s
baseline state: Gi1/0/23 in VLAN 20, flagship incident not yet replayed
```

## 2. Terminal demo (about 15 seconds)

```bash
make demo
```

The replay resets the baseline, then prints the flagship incident phase by phase, paced by the
simulated timestamps:

```
[21:14:31.284] telemetry   unusual ICMP echo fan-out from 10.20.0.47: 507 addresses across 10.20.0.0/24, 10.30.0.0/24
[21:14:33.507] detect      Suricata sid 1000010 (medium): SENTINELSWITCH RECON ICMP echo sweep from internal host
[21:14:38.198] detect      Suricata sid 1000021 (high): SENTINELSWITCH LATERAL SMB probe fan-out to multiple internal hosts
[21:14:39.649] detect      Zeek notice Scan::Address_Scan: 10.20.0.47 scanned at least 15 unique hosts on port 445/tcp in 0m2s
[21:14:39.867] detection   Rule lateral-reconnaissance matched: severity high, confidence 0.97 (base 0.75; zeek_address_scan+0.10, prior_icmp_sweep+0.07, ptr_burst+0.05)
[21:14:40.092] correlate   dhcp_binding [resolved] 10.20.0.47 -> A4:83:E7:12:34:56 (dhcp-snooping, VLAN 20, Gi1/0/23, 23841s remaining)
[21:14:40.346] correlate   mac_table [resolved] A4:83:E7:12:34:56 -> SW01 Gi1/0/23 (VLAN 20, DYNAMIC)
[21:14:40.439] correlate   identity [resolved] ENG-LT-047 (laptop, Lenovo, Ubuntu 24.04 LTS) criticality=standard user=jchen (Jia Chen, Engineering)
[21:14:40.585] policy      Disposition automatic_containment: Automatic containment approved (severity=high confidence=0.97); action=quarantine_vlan
[21:14:41.000] contain     SW01 Gi1/0/23: switchport access vlan 20 → 50 (workflow WF-2026-0042-01)
[21:14:41.125] verify      Verification succeeded: Access Mode VLAN: 50
[21:14:41.464] evidence    Evidence bundle INC-2026-0042 finalized (895 related connections, 254 DNS records)
```

Then verify on the twin exactly as you would on the switch:

```bash
.venv/bin/python -m sentinelswitch show "show interfaces Gi1/0/23 switchport"
.venv/bin/python -m sentinelswitch show "show mac address-table interface Gi1/0/23"
.venv/bin/python -m sentinelswitch show "show vlan id 50"
ls data/incidents/INC-2026-0042/
```

## 3. Dashboard

```bash
make dev          # builds the React app and serves http://127.0.0.1:8000
```

Suggested walk-through:

1. **SOC Overview** (`/operations`; the dashboard opens on the 2.0 *Posture* page) — KPIs, alert timeline, network activity. Use *Replay flagship incident* / *Reset to
   baseline* to run the incident from the UI; every view refreshes over Server-Sent Events.
2. **Incidents → INC-2026-0042** — correlation chain, resolution steps, timeline, source detections,
   containment decision (factors and guards), *Switch verification* tab, evidence artifacts.
3. **Network / Switch** — the 48-port front panel with `Gi1/0/23` in red; click ports for intent and
   IOS output; run `show` commands in the console.
4. **Detection Coverage** — the validation matrix; click a row for its timeline and evidence features.
5. **Configuration Drift** — three open findings (`Gi1/0/22` description, `Gi1/0/35` storm control,
   `Gi1/0/41` enabled unused port) and the quarantine reported as an approved deviation.
6. **Evidence** — browse the bundle files in place.
7. Release containment from the incident page and watch `Gi1/0/23` return to VLAN 20.

## 4. Validation and drift from the CLI

```bash
make validate-security
make drift
```

## 5. Reset

```bash
make reset        # baseline again: Gi1/0/23 in VLAN 20, INC-2026-0042 bundle removed
```

## 6. Regenerate media

```bash
make screenshots  # diagrams + dashboard screenshots + LinkedIn cards + GitHub images
```

## 7. SentinelSwitch 2.0 workflow

```bash
make demo-2       # or: .venv/bin/python -m sentinelswitch demo2 --no-pdf
```

One command runs the evidence-driven sequence end to end on the simulated clock and prints one
numbered line per step:

```
 1. reset + baseline       seeded 36 devices; baseline assessment ASR-20260317T211400-baseline-seed: {'PASS': 200, 'FAIL': 4, 'UNKNOWN': 1, 'STALE': 1}
 2. flagship incident      INC-2026-0042 detected 21:14:39.867Z conf 0.97 → Gi1/0/23 VLAN 20→50 verified 21:14:41.125Z (TTD 8.583s, TTC 1.258s)
 3. post-containment       ASR-20260317T211441-post-containment: {'PASS': 203, 'FAIL': 4, 'UNKNOWN': 1, 'STALE': 1}
 4. negative path          1 detection(s) withheld from automation by policy guards; 1 awaiting analyst decision
 5. analyst decision       DET-20260317T20371618-PORT (Critical Asset Scan — SRV-GIT01): containment rejected by tlee
 6. remediate              FND-CONFIG-BASELINE-Gi1-0-22 → verified
 7. remediate              FND-CONFIG-BASELINE-Gi1-0-35 → verified
 8. remediate              FND-ENDPOINT-IDENTITY-Gi1-0-30 → verified
 9. remediate              FND-SENSOR-COVERAGE-vlan-50 → verified
10. remediate              FND-UNUSED-PORTS-Gi1-0-41 → verified
11. restore + recovery     INC-2026-0042 resolved; recovery assessment ASR-20260317T214936-recovery-INC-2026-0042: {'PASS': 208, 'FAIL': 0, 'UNKNOWN': 1, 'STALE': 0}
12. export                 security-posture-report.json, security-posture-report.html, security-posture-report.pdf
```

(Step 12 prints `(PDF skipped)` instead of the `.pdf` name when Playwright Chromium is not installed.)

It ends with the final posture (209 assessments: 208 pass, 0 fail, 1 unknown, 0 stale, one retired
row excluded; coverage 99.5 %, determinate pass rate 100 %) and the artifact paths. What each step does, and why the
remaining unknown cannot be resolved, is in [workflow-2.0.md](workflow-2.0.md).

Artifacts land in `artifacts/sentinelswitch-2.0/`:

```bash
ls artifacts/sentinelswitch-2.0/reports/      # security-posture-report.{json,html,pdf}
jq '.final_posture, .remediated' artifacts/sentinelswitch-2.0/validation/demo-results.json
jq '.posture.totals, .framework_mapping.subcategories[0]' artifacts/sentinelswitch-2.0/reports/security-posture-report.json
open artifacts/sentinelswitch-2.0/reports/security-posture-report.html
```

The individual pieces are available on their own:

```bash
make assess       # one assessment run against the current twin; lists every non-passing result
make findings     # open findings (sentinelswitch findings --all includes verified ones)
make remediate    # request → execute → re-assess → verify every open finding with an executable action
make report       # export JSON + HTML (+ PDF when Chromium is installed)
.venv/bin/python -m sentinelswitch remediate FND-SENSOR-COVERAGE-vlan-50 --actor tlee --note "mirror the quarantine VLAN"
```

In the dashboard (`make dev`), the 2.0 pages are the first group in the navigation: **Posture**
(`/`), **Controls**, **Findings & Remediation** (with a *Remediate* action per finding), **Incidents**
(authorization record, approve/reject for reviewed detections) and **Evidence & Reports** (generate
and open the reports). `make screenshots-2` captures them into `artifacts/sentinelswitch-2.0/screenshots/`.

The validation harness now replays nine scenarios: the ninth, `critical-asset-scan`, is the negative
path in which the `critical_assets` guard withholds automatic containment.

## Docker

```bash
docker compose up --build     # http://localhost:8000 with the flagship incident already applied
```

## Useful API calls

```bash
curl -s localhost:8000/api/overview | jq .kpis
curl -s localhost:8000/api/incidents/INC-2026-0042 | jq .incident.chain
curl -s "localhost:8000/api/switch/show?cmd=show%20interfaces%20Gi1/0/23%20switchport"
curl -s -X POST localhost:8000/api/incidents/INC-2026-0042/restore -H 'content-type: application/json' -d '{"actor":"tlee","note":"re-imaged"}'
```

SentinelSwitch 2.0 routes ([workflow-2.0.md](workflow-2.0.md#api)):

```bash
curl -s localhost:8000/api/posture | jq .totals
curl -s localhost:8000/api/controls | jq '.status[] | {control_id, status, open_findings}'
curl -s -X POST localhost:8000/api/assessments/run -H 'content-type: application/json' -d '{"actor":"tlee"}' | jq .counts
curl -s 'localhost:8000/api/findings?open_only=true' | jq '.[] | {id, status, result, severity}'
curl -s -X POST localhost:8000/api/findings/FND-SENSOR-COVERAGE-vlan-50/remediate -H 'content-type: application/json' -d '{"actor":"tlee","note":"mirror VLAN 50"}' | jq '.finding.status, .run.counts'
curl -s -X POST localhost:8000/api/reviews/DET-20260317T20371618-PORT/reject -H 'content-type: application/json' -d '{"actor":"tlee","note":"benign CI scanner"}' | jq .review.authorization
curl -s -X POST localhost:8000/api/reports/generate | jq .
curl -s localhost:8000/api/reports/posture.json | jq .schema_version
```

Interactive API docs are at `http://127.0.0.1:8000/docs`.

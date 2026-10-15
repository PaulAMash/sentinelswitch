# Data model

## Canonical sources (edit these)

| file | contents |
| --- | --- |
| `simulator/fixtures/environment.yaml` | organization, dataset day and seed, switch identity, VLANs, DHCP scopes, port profiles and per-port intent, deliberate drift |
| `simulator/fixtures/inventory.yaml` | 36 devices with MAC, IP, VLAN, port, owner, criticality, authentication method, attach schedule; 4 unregistered devices; OUI hints |
| `simulator/fixtures/users.yaml` | 22 fictional users with department and EAP method |
| `simulator/fixtures/external.yaml` | external services on RFC 5737 documentation ranges, internal service names |
| `simulator/scenarios/*.yaml` | nine scenarios: actor, `day` and `validation` instances, traffic parameters, expected outcome, resolution, engine timing |
| `detections/**` | Suricata rules, Zeek scripts, correlation rules |
| `automation/policies/containment-policy.yaml` | tiers, guards, actions |

Everything else in `data/`, `cisco/show-output/` and `cisco/configs/` is generated from these by
`make seed` (`simulator/generators/run.py`).

## Normalized event

```json
{
  "ts": "2026-03-17T21:14:38.198Z",
  "source": "suricata", "kind": "alert", "severity": "high",
  "signature_id": 1000021, "signature": "SENTINELSWITCH LATERAL SMB probe fan-out to multiple internal hosts",
  "category": "Attempted Information Leak", "sentinel_class": "lateral",
  "src_ip": "10.20.0.47", "actor_ip": "10.20.0.47", "dest_ip": "10.30.0.10", "dest_port": 445, "proto": "TCP",
  "mac": "A4:83:E7:12:34:56", "interface": "Gi1/0/23", "device": "ENG-LT-047",
  "summary": "…", "scenario": "lateral-reconnaissance", "raw": { "…": "original EVE record" }
}
```

`data/generated/events.jsonl` holds the whole day (512 events before the flagship incident);
`data/generated/flagship-events.jsonl` the seven events the demo replays.

## Relationships

```
Device ──(mac, interface)──▶ Interface ──(access/oper vlan)──▶ VLAN
   │                              │
   └──(ip, mac)──▶ DhcpBinding    └──▶ MacEntry (mac, vlan, interface)

Alert ──detection_id──▶ Detection ──incident_id──▶ Incident ──▶ ContainmentAction (workflow_id)
                                   └──review────▶ Review                 └──▶ Timeline entries
Incident ──▶ data/incidents/<id>/ (11 artifacts)
ValidationResult (scenario_id) ──▶ Scenario

AssessmentRun (ASR-…) ──▶ AssessmentHistory rows (one per control × scope per run)
Control (CTL-…) ──▶ Assessment (ASM-<control>-<scope>, latest result) ──finding_id──▶ Finding (FND-<control>-<scope>)
                                                                                        └──▶ FindingEvent (append-only)
Assessment.related_incidents ──▶ Incident;  ContainmentAction.authorization / Incident.authorization / Review.authorization ──▶ Authorization record
```

## SQLite tables

| table | key | document |
| --- | --- | --- |
| `kv` | `twin`, `twin_baseline`, `demo`, `validation_metrics`, `dataset`, `last_assessment_run` | switch twin JSON and application state |
| `devices`, `unknown_devices`, `users` | hostname / mac / username | inventory joined with schedule and tags |
| `alerts` | `ALT-nnnnn` | every alert-worthy raw event with status, detection and incident links |
| `detections` | `DET-…` | scored correlation detections with features and event references |
| `incidents` | `INC-2026-nnnn` | incident record, attribution chain, decision, current/original VLAN |
| `reviews` | detection id | manual-review queue entries with analyst closure |
| `timelines` | incident or detection id | ordered phases |
| `containment_actions` | `WF-…` | action, commands, transcript, verification, restore |
| `auth_events` | `RAD-nnnnn` | RADIUS results |
| `traffic_buckets` | 15-minute timestamp | connections, bytes, DNS queries, alerts, hosts |
| `validation_results` | scenario id | harness rows |
| `scenarios` | scenario id | scenario definitions for the UI |
| `assessment_runs` | `run_id` (`ASR-…`); columns `assessed_at`, `trigger` | run summary: counts per state, `findings_open`, actor |
| `assessments` | `id` (`ASM-<control>-<scope>`); columns `control_id` (indexed), `scope_id`, `status`, `severity`, `assessed_at`, `finding_id` | the **latest** result per (control, scope); `status` becomes `RETIRED` once the scope stops existing (excluded from posture totals) |
| `assessment_history` | `seq` (autoincrement); columns `run_id` (indexed), `assessment_id`, `status`, `assessed_at` | every result of every run, append-only |
| `findings` | `id` (`FND-<control>-<scope>`); columns `control_id`, `scope_id`, `status`, `severity`, `opened_at`, `updated_at` | finding record with remediation and verification blocks; never deleted |
| `finding_events` | `seq` (autoincrement); columns `finding_id` (indexed), `ts`, `event`, `actor` | lifecycle events (`opened`, `reopened`, `remediation_requested`, `remediation_executed`, `remediation_refused`, `verification_failed`, `verified`, `scope_retired`) |

Documents are stored as JSON text with a few indexed columns; the access layer is
`backend/sentinelswitch/services/store.py`.

## Assurance records (2.0)

`seed_database()` recreates every table, so the assurance tables start empty and are filled by the
baseline assessment at the end of seeding. `containment_actions`, `incidents` and `reviews`
documents gained an `authorization` object (see [containment.md](containment.md#authorization-record)).

| document | produced by | shape |
| --- | --- | --- |
| assessment run | `AssessmentEngine.run()` | `run_id`, `assessed_at`, `trigger`, `actor`, `controls`, `assessments`, `counts{PASS,FAIL,UNKNOWN,STALE}`, `findings_open`, `clock` |
| assessment | `AssessmentEngine._finalize()` | `id`, `run_id`, control fields, `framework.nist_csf_2_0`, `scope{type,id,asset,interface,vlan,switch}`, `expected`, `observed`, `status`, `severity`, `explanation`, `evidence[]`, `freshness`, `related_incidents`, `remediation{guidance,commands,action}`, `finding_id` |
| finding | `AssessmentEngine._reconcile()`, updated by `RemediationService` | assessment fields plus `status`, `result`, `opened_at`, `updated_at`, `first_run_id`, `last_run_id`, `occurrences`, `remediation{…,status,requested_at,requested_by,executed_at,executed_by,transcript,note}`, `verification{outcome,at,run_id,after_remediation}`, `resolved_at` |
| finding event | engine and remediation service | `ts`, `event`, `actor`, `detail`, optional `transcript` |

`assessments` keeps one row per assessment id (the latest result); the per-run rows live in
`assessment_history`. Scopes that stop being evaluated (an incident that was resolved) keep their
last row, which is why the posture total can exceed the last run's count. Field-by-field types are
in [export-schema.md](export-schema.md); the id scheme and lifecycle in [controls.md](controls.md).

## Switch twin

`SwitchTwin.to_dict()` serialises: identity, VLAN table, SPAN session, snooping/DAI VLANs, 50
interfaces (configuration settings, operational state, quarantine/hold flags, counters, port
security), MAC table, DHCP snooping bindings (with lease start/expiry, static bindings for servers),
MAC observation history, configuration changes, audit entries and the logging buffer.

## Evidence bundle

| file | contents |
| --- | --- |
| `incident.json` | incident, detection (features), metrics, attribution chain |
| `timeline.json` | telemetry → alert → detection → correlation → policy → containment → verification → evidence |
| `alerts.json` | source detections with raw records |
| `network-context.json` | attribution, VLANs, SPAN session, port intent, sensor |
| `dhcp-binding.json`, `mac-table.json` | the exact lookups used |
| `switch-port.json` | before/after state with `show` output |
| `containment.json` | decision factors, guards, action, transcript, verification |
| `related-connections.json`, `related-dns.json` | Zeek records for the actor from two minutes before the first event until the bundle was finalized |
| `README.md` | generated report |

## Telemetry files

| file | records | format |
| --- | --- | --- |
| `data/zeek/conn.log` | 9,924 | Zeek JSON (`ts`, `uid`, `id.*`, `proto`, `service`, `conn_state`, byte and packet counts) |
| `data/zeek/dns.log` | 4,102 | Zeek JSON |
| `data/zeek/ssl.log`, `http.log` | 2,925 / 103 | Zeek JSON |
| `data/zeek/notice.log`, `weird.log` | 3 / 26 | Zeek JSON |
| `data/suricata/eve.json` | 12 alerts + 1,922 flow events (pre-flagship) | Suricata EVE |
| `data/radius/auth-events.jsonl`, `radius.log` | 136 | JSONL and FreeRADIUS-style text |
| `data/cisco/SW01-syslog.log`, `.jsonl` | 368 | `<PRI>seq: SW01: Mon DD HH:MM:SS.mmm UTC: %FAC-SEV-MNEMONIC: text` |
| `cisco/show-output/{pre,post}-quarantine/` | 20 transcripts each | IOS |

`data/generated/manifest.json` records SHA-256 hashes of every generated file; two runs of the
generator produce identical hashes.

# Data model

## Canonical sources (edit these)

| file | contents |
| --- | --- |
| `simulator/fixtures/environment.yaml` | organization, dataset day and seed, switch identity, VLANs, DHCP scopes, port profiles and per-port intent, deliberate drift |
| `simulator/fixtures/inventory.yaml` | 36 devices with MAC, IP, VLAN, port, owner, criticality, authentication method, attach schedule; 4 unregistered devices; OUI hints |
| `simulator/fixtures/users.yaml` | 22 fictional users with department and EAP method |
| `simulator/fixtures/external.yaml` | external services on RFC 5737 documentation ranges, internal service names |
| `simulator/scenarios/*.yaml` | eight scenarios: actor, `day` and `validation` instances, traffic parameters, expected outcome, resolution, engine timing |
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
```

## SQLite tables

| table | key | document |
| --- | --- | --- |
| `kv` | `twin`, `twin_baseline`, `demo`, `validation_metrics`, `dataset` | switch twin JSON and application state |
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

Documents are stored as JSON text with a few indexed columns; the access layer is
`backend/sentinelswitch/services/store.py`.

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

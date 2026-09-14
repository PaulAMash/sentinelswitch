# Correlation detections

Each YAML file in this directory is a SentinelSwitch correlation rule. Rules consume the normalized
event stream (Suricata alerts, Zeek notices, RADIUS results, Cisco syslog) and produce a scored
*detection* for one actor (an IP, a MAC, or a physical interface).

Rule schema:

| key | meaning |
| --- | --- |
| `trigger` | event filter that starts an evaluation for an actor |
| `actor_key` | which trigger field identifies the actor (`actor_ip` for flow-based sources, `mac`, `interface`) |
| `aggregate_window` | seconds to keep collecting corroborating events after the first trigger before scoring |
| `base_confidence` | starting confidence |
| `features` | additive evidence features (positive or negative weights), each with a type |
| `severity` | `high`, or a list of `{when: <feature id>, severity: ...}` overrides evaluated in order |
| `class` | actor class used by the policy engine to select the containment action |
| `emit_threshold` | optional; detections scoring below it are discarded instead of recorded |

Feature types: `event_match`, `event_count`, `event_field`, `asset_tag`, `asset_unknown`,
`asset_mac_belongs_elsewhere`, `asset_in_vlan`, `outside_business_hours`.
Confidence is clamped to `[0.05, 0.99]`.

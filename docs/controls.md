# Control assessment

SentinelSwitch 2.0 adds an evidence-backed control-assessment layer on top of the detection and
response pipeline. `backend/sentinelswitch/assurance/` evaluates thirteen controls against the switch
twin and the application store, persists every result, opens findings for failures, drives
remediation through the same switch adapter the containment controller uses, and exports the
outcome ([export-schema.md](export-schema.md)).

## Scope

The assessments are **simulated checks against the SentinelSwitch digital twin**. Every control
reads a named source of truth inside the twin (`SwitchTwin`), the SQLite store or the evidence
bundles on disk, and compares it with the port intent in `simulator/fixtures/environment.yaml`.
Nothing is read from a physical switch, no RADIUS server or sensor is queried, and the NIST CSF 2.0
references are an orientation aid, not a framework audit or certification. All timestamps are taken
from the simulated clock (the twin's `now`), so every run is reproducible.

## States

An assessment has exactly one of four live states (`assurance/engine.py`, `export.py`), plus one
bookkeeping state for results whose scope has disappeared:

| state | meaning | finding | counted as |
| --- | --- | --- | --- |
| `PASS` | available evidence demonstrates the condition is satisfied | closes an open finding (`verified`) | determinate |
| `FAIL` | available evidence demonstrates the condition is not satisfied | opens or re-opens a finding | determinate |
| `UNKNOWN` | evidence is insufficient to decide; never counted as a pass | none; listed under `unverified` | indeterminate |
| `STALE` | evidence is older than the control's freshness window at the assessment clock; never counted as a pass | opens or re-opens a finding (`result: STALE`) | indeterminate |
| `RETIRED` | the scope no longer exists at the latest run (a resolved incident, a MAC that left its port); the last result is kept in history and in the export with `retired_at` / `retired_by_run` | an open finding on a retired scope is `closed` (event `scope_retired`) | excluded from every total (`totals.retired` reports how many) |

`posture.py` reports the counts with explicit denominators and no composite score:

| metric | definition |
| --- | --- |
| `coverage_pct` | (PASS + FAIL) / all assessments; UNKNOWN and STALE are excluded from the numerator |
| `pass_rate_of_determinate_pct` | PASS / (PASS + FAIL) — effectiveness among determinate results, not overall compliance |
| `pass_rate_of_all_pct` | PASS / all assessments; UNKNOWN and STALE count against it |

A control's rolled-up status in `by_control` is `FAIL` if any assessment failed, else `STALE`, else
`UNKNOWN`, else `PASS`, or `NOT_ASSESSED` when the control produced no assessment.

## Freshness policy

Only event-derived evidence ages. State-based evidence (interface settings, VLAN membership, SPAN
sources, MAC table, containment records, bundle files) is read live from the twin at the assessment
clock and has no window (`freshness_window: None`).

| evidence | window | source of the number |
| --- | --- | --- |
| RADIUS result backing an endpoint identity (`CTL-ENDPOINT-IDENTITY`) | 15 300 s = 4 h 15 m | RADIUS `Session-Timeout` 14 400 s (re-authentication timer) + 15 min grace |
| Zeek `conn` feed (`CTL-TELEMETRY-FRESH`, source `zeek-conn`) | 900 s = 15 min | one traffic bucket; age is measured from the end of the last populated 15-minute bucket |
| RADIUS feed (`CTL-TELEMETRY-FRESH`, source `radius`) | 15 300 s = 4 h 15 m | one re-authentication period |
| IOS syslog (`CTL-TELEMETRY-FRESH`, source `syslog`) | 8 100 s = 2 h 15 m | controller health-check cadence + 15 min grace |
| Suricata (`CTL-TELEMETRY-FRESH`, source `suricata`) | — | the dataset has no EVE `stats` events, so liveness is always `UNKNOWN` |

Two code paths produce `STALE`:

1. `AssessmentEngine._finalize()` — for a control with a `freshness_window`, if the oldest
   freshness-relevant evidence item of a `PASS`/`FAIL` draft is older than the window, the status
   becomes `STALE` and the explanation gains `Evidence is Xh Ym old, older than the N-minute
   freshness window; result is not current.`
2. The `CTL-TELEMETRY-FRESH` evaluator sets `STALE` directly when a source's last record is older
   than its window.

A `STALE` assessment carries severity `low`, or `medium` when the control's severity is `high`.
Guest-VLAN sessions have no periodic re-authentication, so their identity evidence ages until the
port is bounced; that is the one `STALE` result in the committed baseline (`Gi1/0/30`).

## Control catalog

Thirteen controls, grouped by category. "Scope" is what the evaluator enumerates; each (control,
scope) pair yields one assessment. "Action" is the executable remediation type handed to
`RemediationService` when the control fails; `—` means guidance only (the API answers `409 … manual
follow-up required`).

| id | name | category | scope | source of truth | states | severity | action | NIST CSF 2.0 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `CTL-VLAN-INTENT` | Access port carries its intended VLAN | Segmentation | interface: every access-mode port in the intent that is not class `unused` | port intent vs `SwitchTwin.interfaces[*].access_vlan`, quarantine flags and `containment_actions` | PASS, FAIL | high | `apply_config` (`switchport access vlan <intent>`) | PR.IR-01, ID.AM-03 |
| `CTL-DOT1X-ENFORCED` | 802.1X / MAB enforced on user ports | Access control | interface: every port whose intent sets `dot1x` | port intent (`dot1x`/`mab`) vs `interfaces[*].settings` | PASS, FAIL | high | `apply_config` (`dot1x`, `mab`) | PR.AA-03, PR.IR-01 |
| `CTL-ENDPOINT-IDENTITY` | Connected endpoints have a verified identity | Identity | interface: every connected non-trunk, non-SPAN port with learned MACs (one assessment covers every MAC on the port) | `SwitchTwin.mac_table` + `devices` inventory + the latest RADIUS result per MAC in `auth_events`¹ | PASS, FAIL, UNKNOWN, STALE | medium | `reauthenticate` (`clear authentication sessions interface …`) | ID.AM-01, PR.AA-03 |
| `CTL-PORT-SECURITY` | Port security matches the port profile | Access control | interface: every port whose intent enables port security | intent `port_security` vs `interfaces[*].settings.port_security` (enabled, maximum, violation, sticky) | PASS, FAIL | medium | `apply_config` (`port_security`) | PR.IR-01, PR.AA-03 |
| `CTL-CONFIG-BASELINE` | Interface configuration matches the baseline | Configuration | interface: every port in the intent | `DriftEngine` (desired intent vs observed twin settings); approved deviations do not fail; settings owned by a dedicated control (`access_vlan`, `dot1x`, `mab`, `port_security`, the trust flags, and `admin_status` on unused ports) are left to that control so one deviation yields one finding | PASS, FAIL | medium² | `apply_config` (the drifted settings) | PR.PS-01 |
| `CTL-UNUSED-PORTS` | Unused ports are shut down and parked | Hardening | interface: every port of intent class `unused` | intent class `unused` vs `admin_status` / `access_vlan` 999 | PASS, FAIL | medium | `shutdown_unused` | PR.IR-01, PR.PS-01 |
| `CTL-TRUST-BOUNDARY` | DHCP snooping / DAI trust limited to infrastructure trunks | Segmentation | global (`trust-boundary`) | `dhcp_snooping_trust` / `dai_trust` on every interface vs protected trunks in the intent | PASS, FAIL | high | `fix_trust`³ | PR.IR-01 |
| `CTL-TELEMETRY-FRESH` | Required telemetry sources are current | Monitoring | source: `zeek-conn`, `radius`, `syslog`, `suricata` | `traffic_buckets`, `auth_events`, `SwitchTwin.log`; Suricata has no liveness signal | PASS, STALE, UNKNOWN | medium | — | DE.CM-01 |
| `CTL-SENSOR-COVERAGE` | Endpoint VLANs are mirrored to the sensor | Monitoring | vlan: 20, 30, 40, 50 (`vlan-<n>`) | `SwitchTwin.span.source_vlans` | PASS, FAIL | medium | `add_span_source` | DE.CM-01, ID.AM-03 |
| `CTL-RESPONSE-AUTHORIZED` | Containment actions were authorized before execution | Response | incident: every containment action with status `verified`, `restored` or `failed` and an `applied_at` | `containment_actions[*].authorization` vs `applied_at` | PASS, FAIL, UNKNOWN | high | — | RS.MA-01, RS.AN-06 |
| `CTL-QUARANTINE-VERIFIED` | Containment state independently verified | Response | incident: every incident with status `contained` or `containment_failed` | last action's `verification.ok` **and** live interface state (access VLAN + learned MACs, or admin down + no MACs) | PASS, FAIL, UNKNOWN | high | — (original commands repeated as guidance) | RS.MI-01, RS.AN-06 |
| `CTL-RECOVERY-VERIFIED` | Restored interfaces returned to their expected state | Recovery | incident: every `resolved` incident with a `restored` action | `restored_at` + intent VLAN + live interface (`access_vlan`, `admin_status`, no quarantine/hold flags) | PASS, FAIL | high | — | RC.RP-01, RC.RP-04 |
| `CTL-EVIDENCE-COMPLETE` | Incident evidence bundle is complete | Evidence | incident: every incident | `data/incidents/<id>/` vs `evidence.bundle.BUNDLE_FILES` (11 artifacts); a missing bundle directory is a `FAIL`, not an unknown | PASS, FAIL | low | — | RS.AN-06, DE.AE-03 |

¹ Per MAC: `PASS` for an inventoried asset whose latest result is `Access-Accept` or `Guest-VLAN`, or
for a statically addressed asset (the static `ip source binding` is cited only when the twin actually
holds one; otherwise the record says the identity rests on the inventory alone); `FAIL` when a MAC
is forwarding although its latest RADIUS result is anything other than `Access-Accept` or
`Guest-VLAN` (in the dataset, an `Access-Reject`); `UNKNOWN` when the MAC is not in the inventory or
a non-static asset has no RADIUS result. The interface takes the worst of its MACs, and `STALE`
applies when the oldest cited RADIUS result is older than the window. The `reauthenticate` action
is offered only when at least one MAC on the port has a RADIUS result; otherwise the finding is
guidance-only.
² The severity of a `CTL-CONFIG-BASELINE` finding is the worst open drift item's severity
(`info` maps to `low`).
³ `RemediationService` executes `fix_trust` only for the unexpected trusted ports (`extra`); adding
trust to a missing protected trunk is reported but not executed.

Every assessment records `expected`, `observed`, an `explanation`, the evidence rows it was decided
on (`source`, `ref`, `collected_at`, `detail`), the `source_of_truth` string from the catalog, the
control's `limitations`, `related_incidents`, and the remediation `guidance`, `commands` and
`action`. Details of the shape are in [export-schema.md](export-schema.md).

## Finding lifecycle

A finding is opened by the first `FAIL` or `STALE` assessment of a (control, scope) pair and is
never deleted. Every state change is appended to `finding_events`.

```
            FAIL/STALE                     POST /findings/{id}/remediate
assessment ──────────▶ open ──────────────▶ remediation_requested ──▶ remediated
                        ▲                        │ adapter refuses        │ re-assessment
                        │                        ▼ (ProtectedInterface)   ▼
                        │                  remediation_failed ◀── FAIL ───┤
                        │                                                 │ PASS
   FAIL/STALE again     │                                                 ▼
reopened ◀──────────────┴──────────────────────────────────────────── verified
```

| status | set by | meaning |
| --- | --- | --- |
| `open` | engine | first `FAIL`/`STALE`; `result` holds which |
| `remediation_requested` | `RemediationService` | an analyst asked for the executable action; `remediation.requested_by` / `requested_at` recorded |
| `remediated` | `RemediationService` | the action was applied through the adapter; `remediation.commands`, `transcript`, `executed_at`, `executed_by: sentinel` recorded |
| `verified` | engine | a later run reports `PASS`; `verification.outcome = PASS`, `resolved_at` set, `after_remediation` true when the finding was `remediated` |
| `remediation_failed` | `RemediationService` / engine | the adapter refused the change (`remediation.status: refused`, event `remediation_refused`) or the re-assessment still fails (`verification.outcome = FAIL`, event `verification_failed`) |
| `reopened` | engine | a `verified` or `closed` finding fails again; `resolved_at` cleared, `occurrences` incremented |
| `closed` | engine (`_retire`) | the finding's scope no longer exists (for example the incident was resolved); `resolved_at` set, `verification` untouched, event `scope_retired` |

Open states (`FINDING_OPEN_STATES`): `open`, `reopened`, `remediation_requested`, `remediated`,
`remediation_failed`. `verified` and `closed` are the two closed states the engine writes
(`FINDING_TERMINAL_STATES`); remediation of a closed finding, or of one that is already requested or
executed and awaiting verification, is refused with HTTP 409. While a finding stays open across runs, `occurrences`,
`last_run_id`, `observed`, `explanation`, `result` and `severity` follow the latest assessment.

Finding events: `opened`, `reopened`, `remediation_requested`, `remediation_executed`,
`remediation_refused`, `verification_failed`, `verified`, `scope_retired`. Each carries `ts`, `event`, `actor`,
`detail` and, for executions, the IOS `transcript`.

Remediation runs through four separately recorded steps (`assurance/remediation.py`):

| step | clock offset | what is recorded |
| --- | --- | --- |
| requested | twin `now` + 60 s | status, actor, note; event `remediation_requested` |
| executed | + 4.2 s | adapter transcript and command list; event `remediation_executed` (actor `sentinel`) |
| assessed | + 12 s | `AssessmentEngine.run("remediation-<finding id>")` |
| verified | same run | the engine marks the finding `verified` or `remediation_failed` |

`remediate` refuses (`RemediationError`, HTTP 409) a finding that is already `verified`, already
`remediation_requested`, or has no executable `remediation.action`. `--no-reassess` (CLI) stops after
the execution step.

## Identifier scheme

| prefix | pattern | example |
| --- | --- | --- |
| `ASR-` | `ASR-<YYYYMMDDTHHMMSS of the simulated clock>-<trigger slug>`, with `-2`, `-3` … appended when another run already used the same clock second and trigger | `ASR-20260317T211400-baseline-seed` |
| `ASM-` | `ASM-<control id without CTL->-<slug(scope id)>` | `ASM-CONFIG-BASELINE-Gi1-0-22` |
| `FND-` | `FND-<control id without CTL->-<slug(scope id)>` | `FND-SENSOR-COVERAGE-vlan-50` |

`slug()` replaces every run of non-alphanumeric characters with `-`. Scope ids are the interface
name (`Gi1/0/22`), the incident id (`INC-2026-0042`), the telemetry source (`radius`), `vlan-<n>`,
or the global name `trust-boundary`. Because the id depends only on control and
scope, the same condition always maps to the same assessment and finding across runs; the full
per-run result stays in `assessment_history`.

Triggers used by the code: `baseline-seed` (seed), `post-containment` (flagship replay),
`post-containment-<incident id>` (`POST /api/reviews/{id}/approve`), `remediation-<finding id>`,
`recovery-<incident id>` (restore), `api` (`POST /api/assessments/run`)
and `cli` (`sentinelswitch assess`, overridable with `--trigger`).

## NIST CSF 2.0 mapping

**Verification note.** On 2026-10-15 the twelve identifiers and texts in `assurance/controls.py`
were compared programmatically against the CSF 2.0 Core in NIST CSWP 29 (February 26, 2024), retrieved
from `https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf`. All twelve identifiers exist and
every subcategory text matches the published wording, ignoring whitespace. No other identifier is used.

The identifiers below are NIST Cybersecurity Framework 2.0 subcategory ids (NIST CSWP 29, February
2024). The texts are reproduced from the `CSF` dictionary in `assurance/controls.py`. The mapping is
illustrative: it shows which simulated check is related to which subcategory so a reader can
orient the results; it is not a conformance claim.

| subcategory | text | controls |
| --- | --- | --- |
| `ID.AM-01` | Inventories of hardware managed by the organization are maintained | CTL-ENDPOINT-IDENTITY |
| `ID.AM-03` | Representations of the organization's authorized network communication and internal and external network data flows are maintained | CTL-VLAN-INTENT, CTL-SENSOR-COVERAGE |
| `PR.AA-03` | Users, services, and hardware are authenticated | CTL-DOT1X-ENFORCED, CTL-ENDPOINT-IDENTITY, CTL-PORT-SECURITY |
| `PR.IR-01` | Networks and environments are protected from unauthorized logical access and usage | CTL-VLAN-INTENT, CTL-DOT1X-ENFORCED, CTL-PORT-SECURITY, CTL-UNUSED-PORTS, CTL-TRUST-BOUNDARY |
| `PR.PS-01` | Configuration management practices are established and applied | CTL-CONFIG-BASELINE, CTL-UNUSED-PORTS |
| `DE.CM-01` | Networks and network services are monitored to find potentially adverse events | CTL-TELEMETRY-FRESH, CTL-SENSOR-COVERAGE |
| `DE.AE-03` | Information is correlated from multiple sources | CTL-EVIDENCE-COMPLETE |
| `RS.MA-01` | The incident response plan is executed in coordination with relevant third parties once an incident is declared | CTL-RESPONSE-AUTHORIZED |
| `RS.AN-06` | Actions performed during an investigation are recorded, and the records' integrity and provenance are preserved | CTL-RESPONSE-AUTHORIZED, CTL-QUARANTINE-VERIFIED, CTL-EVIDENCE-COMPLETE |
| `RS.MI-01` | Incidents are contained | CTL-QUARANTINE-VERIFIED |
| `RC.RP-01` | The recovery portion of the incident response plan is executed once initiated from the incident response process | CTL-RECOVERY-VERIFIED |
| `RC.RP-04` | Critical mission functions and cybersecurity risk management are considered to establish post-incident operational norms | CTL-RECOVERY-VERIFIED |

The posture summary (`posture.csf`) and the export's `framework_mapping.subcategories` roll the
assessment counts up per subcategory (`pass`, `fail`, `unknown`, `stale`, contributing `controls`,
and the CSF `function` prefix).

## Surfaces

| surface | where |
| --- | --- |
| API | `GET /api/controls`, `GET /api/controls/{id}`, `GET /api/assessments`, `GET /api/findings`, `POST /api/assessments/run`, `POST /api/findings/{id}/remediate` — see [workflow-2.0.md](workflow-2.0.md) |
| CLI | `sentinelswitch assess`, `findings`, `remediate` |
| Dashboard | *Overview* (`/`), *Posture* (`/posture`), *Controls* (`/controls`, `/controls/:id`), *Findings* (`/findings`, `/findings/:id`) |
| Export | `controls`, `assessments`, `findings`, `framework_mapping` in the JSON report; sections 2, 3 and 9 of the HTML report |

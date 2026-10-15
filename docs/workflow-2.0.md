# SentinelSwitch 2.0 workflow

`python -m sentinelswitch demo2` (`make demo-2`) runs the complete evidence-driven workflow against
the digital twin, deterministically, in one command: baseline assessment → flagship incident →
post-containment assessment → negative path and analyst decision → remediation of every open
finding → restore and recovery assessment → export. It is implemented in `cli.cmd_demo2` and uses
the same services as the API and the dashboard; the only difference is sequencing.

```bash
make seed      # once: generate the dataset and load the baseline
make demo-2    # the workflow below; add --no-pdf via `.venv/bin/python -m sentinelswitch demo2 --no-pdf`
```

## Vocabulary

The workflow keeps eight activities apart because each is recorded by a different component and
can fail independently:

| activity | component | record |
| --- | --- | --- |
| **Detection** | Suricata / Zeek / RADIUS / syslog events, correlation rules (`detection/engine.py`) | detection with confidence, severity and matched features |
| **Correlation** | `correlation/engine.py` | attribution chain IP → DHCP binding → MAC → interface → identity, with flags |
| **Identification** | attribution + inventory | device, user, port class, criticality |
| **Recommendation (policy)** | `containment/policy.py` | decision: disposition tier, action, factors, guards that fired, `tier_before_guards` |
| **Authorization** | `containment/controller.authorization_record()`, `services/response.py` | authorization record: `automatic` (policy tier) or `analyst` approval; or `rejected` |
| **Execution** | `ContainmentController` → `SimulatedCisco2960XAdapter` | containment action with commands and transcript |
| **Verification (read-back)** | adapter `verify_vlan` / `verify_shutdown` | `verification.ok`, expected string, transcript |
| **Recovery assessment** | `AssessmentEngine` after restore | `CTL-RECOVERY-VERIFIED` and the full control set re-run |

The policy *recommends*; the authorization record states who *allowed* execution and when. A
disposition of `automatic_containment` is itself the authorization (mode `automatic`, authorizer
`policy-engine`). Anything the guards downgrade to `manual_review` stays `pending` until an analyst
approves or rejects it, and the controller refuses to execute an action whose authorization is not
`authorized` (status `not_applicable`). `CTL-RESPONSE-AUTHORIZED` later checks that
`authorized_at` precedes `applied_at` for every executed action.

## The twelve steps

Step numbers are what `demo2` prints. Steps 5 and 6–10 repeat per open review and per open
finding; with the committed dataset there is one open review and five open findings, giving twelve
steps. Clock values below are the simulated clock produced from the committed dataset.

| # | step | what happens | code |
| --- | --- | --- | --- |
| 1 | `reset + baseline` | `seed_database()` drops and recreates the schema, loads `data/seed/*.json`, removes a stale flagship bundle, runs the **baseline assessment** (trigger `baseline-seed`, clock 21:14:00) and the validation harness (9 scenarios) | `services/seed.py` |
| 2 | `flagship incident` | `run_flagship()` replays `lateral-reconnaissance` (day instance): detection 21:14:39.867 at confidence 0.97, attribution to `Gi1/0/23`, policy `automatic_containment`, authorization `automatic` by `policy-engine` at 21:14:40.585, quarantine VLAN 20 → 50 applied 21:14:41.000, read-back verified 21:14:41.125, evidence bundle `INC-2026-0042` finalized (TTD 8.583 s, TTC 1.258 s) | `services/demo.py`, `simulator/scenario.py` |
| 3 | `post-containment` | the assessment run that `run_flagship()` triggers at the evidence-finalized time (trigger `post-containment`): three new incident-scoped assessments for INC-2026-0042 (`CTL-RESPONSE-AUTHORIZED`, `CTL-QUARANTINE-VERIFIED`, `CTL-EVIDENCE-COMPLETE`); `Gi1/0/23` in VLAN 50 passes `CTL-VLAN-INTENT` because a verified workflow explains the deviation | `assurance/engine.py` |
| 4 | `negative path` | counts the reviews whose policy decision has `guards_triggered` and those still in status `review`: the `critical-asset-scan` detection (`DET-20260317T20371618-PORT`, port sweep from `SRV-GIT01`, confidence 0.96, severity high) was scored for `automatic_containment` but the `critical_assets` guard downgraded it to `manual_review`; nothing changed on the switch and its authorization is `pending` | `containment/policy.py` |
| 5 | `analyst decision` | `reject_review()` for every open review as analyst `tlee` with the note `Containment declined: critical_assets; investigated and closed as benign after review.`: authorization becomes mode `rejected`, status `rejected`, `authorized_at` 21:16:31.284; review status `closed`; timeline gains a `resolution` entry; linked alerts are closed | `services/response.py` |
| 6–10 | `remediate` | for every open finding with an executable action, in `opened_at, id` order: `FND-CONFIG-BASELINE-Gi1-0-22` (description), `FND-CONFIG-BASELINE-Gi1-0-35` (storm control), `FND-ENDPOINT-IDENTITY-Gi1-0-30` (stale guest-VLAN identity), `FND-SENSOR-COVERAGE-vlan-50` (quarantine VLAN not mirrored), `FND-UNUSED-PORTS-Gi1-0-41` (unused port enabled). Each goes requested → executed → re-assessed → verified (see below); the verification run is attributed to `sentinel-assurance`, not to the analyst who asked | `assurance/remediation.py` |
| 11 | `restore + recovery` | `restore_incident()` releases containment 1 800 s after the later of the verification time and the twin's current clock (21:49:31.284 with the committed dataset: `Gi1/0/23` back to VLAN 20, actor `tlee`, note `Endpoint re-imaged and cleared by IT; returning to production VLAN.`), marks the incident `resolved`, then runs the **recovery assessment** (trigger `recovery-INC-2026-0042`, 5 s later): `CTL-RECOVERY-VERIFIED` passes for the incident and the incident's `CTL-QUARANTINE-VERIFIED` row, whose scope no longer exists, is retired (kept in history, excluded from totals) | `services/demo.py` |
| 12 | `export` | `build_export()` → `security-posture-report.json`, `.html` and `.pdf` (unless `--no-pdf` or Chromium is unavailable) | `assurance/export.py` |

Finally `demo2` writes `validation/demo-results.json` and prints the final posture. With the
committed dataset: 209 assessments, 208 pass, 0 fail, 1 unknown (Suricata liveness), 0 stale, plus
one retired row; coverage 99.5 %, determinate pass rate 100 %; all five findings `verified`.

### Baseline findings (step 1)

The baseline run assesses 206 (control, scope) pairs: 200 pass, 4 fail, 1 unknown, 1 stale. The
non-passing results are deliberate properties of the dataset:

| finding | control | cause | fixture |
| --- | --- | --- | --- |
| `FND-CONFIG-BASELINE-Gi1-0-22` | CTL-CONFIG-BASELINE | description `MKT-WS-022 loaner` instead of `MKT-WS-022` | `drift_injections` in `environment.yaml` |
| `FND-CONFIG-BASELINE-Gi1-0-35` | CTL-CONFIG-BASELINE | storm-control lines missing | same |
| `FND-UNUSED-PORTS-Gi1-0-41` | CTL-UNUSED-PORTS | unused port left `no shutdown` (the drift engine reports the same deviation; `CTL-CONFIG-BASELINE` leaves it to this control so it is counted once) | same |
| `FND-SENSOR-COVERAGE-vlan-50` | CTL-SENSOR-COVERAGE | the intent mirrors VLANs 20, 30, 40, 50 but the session on the twin carries 20, 30, 40 only; quarantined hosts are invisible to the sensor | `drift_injections` (`span_session`) |
| `FND-ENDPOINT-IDENTITY-Gi1-0-30` | CTL-ENDPOINT-IDENTITY (`STALE`) | `CONF-A-TV01` sits in the guest VLAN; its last `Guest-VLAN` result is older than 4 h 15 m | guest VLAN has no re-authentication |
| `ASM-TELEMETRY-FRESH-suricata` | CTL-TELEMETRY-FRESH (`UNKNOWN`, no finding) | no EVE `stats` heartbeat in the dataset | — |

### Remediation (steps 6–10)

`RemediationService.remediate()` performs four recorded steps per finding and refuses anything
that is already verified or closed, already requested or executed and awaiting verification, or has
no executable action:

| step | clock | record |
| --- | --- | --- |
| requested | twin `now` + 60 s | `remediation.status = requested`, `requested_by`, note; event `remediation_requested` |
| executed | + 4.2 s | adapter call by action type; IOS transcript and command list; event `remediation_executed` (actor `sentinel`); finding `remediated` |
| assessed | + 12 s | `AssessmentEngine.run("remediation-<finding id>")` — the full control set, not just the one control |
| verified | same run | the finding becomes `verified` (`verification.after_remediation = true`) or `remediation_failed` (event `verification_failed`) |

| action type | adapter call | twin change |
| --- | --- | --- |
| `apply_config` | `apply_baseline(interface, lines, intent)` | re-applies the named settings from the port intent (`description`, `storm_control`, `admin_status`, `access_vlan`, `port_security`, `dot1x`, `mab`, …) |
| `shutdown_unused` | `apply_baseline(…, ["admin_status", "access_vlan"])` per port | `shutdown` + VLAN 999 |
| `add_span_source` | `add_span_source(vlan)` | `monitor session 1 source vlan … both` |
| `reauthenticate` | `reauthenticate(interface)` | `clear authentication sessions interface …`; the twin emits fresh RADIUS results (and a `%DOT1X-5-SUCCESS` / `%AUTHMGR-5-VLANASSIGN` syslog) that are persisted to `auth_events` |
| `fix_trust` | `apply_baseline(…, ["dhcp_snooping_trust", "dai_trust"])` for each unexpected trusted port | removes trust |

The adapter's `_guard()` still protects `Gi1/0/1`, `Gi1/0/48` and the SPAN destination: a
remediation that targets them is recorded as `remediation_failed` with `remediation.status =
refused` and an event `remediation_refused` by `switch-adapter`, and nothing changes on the twin.
The reassessment waits 12 s because guest-VLAN fallback after a re-authentication takes about 7 s on
the twin's clock.

## Negative path

Two things are demonstrated on the `critical-asset-scan` scenario:

1. **The guard withholds automation.** The port sweep from `SRV-GIT01` (criticality high) scores
   0.96 / high, which meets the `automatic_containment` tier, but the `critical_assets` guard
   downgrades the disposition to `manual_review`. The decision keeps `tier_before_guards =
   automatic_containment` and `guards_triggered = [critical_assets]`; the authorization record is
   `pending`; the controller returns `not_applicable`; the timeline carries `Automatic containment
   NOT authorized: guard(s) critical_assets require analyst approval`. The validation harness checks
   this instance for disposition, action `none` and the expected guard.
2. **The analyst rejects.** `demo2` calls `reject_review()`; in the dashboard or API the same
   detection could instead be approved (`POST /api/reviews/{id}/approve`), which would execute the
   quarantine through the normal controller with an `analyst` authorization and open
   `INC-2026-0043`. See [containment.md](containment.md#analyst-decisions).

The four historical reviews from the dataset day (ARP spoofing, MAC change, port scan from the
authorized scanner, DNS anomaly) were closed during generation with the same record shape
(`status: rejected`, mode `analyst`).

## Artifacts

Written under `SENTINEL_ARTIFACTS_DIR` (default `artifacts/sentinelswitch-2.0/`):

| path | producer | content |
| --- | --- | --- |
| `reports/security-posture-report.json` | step 12, `make report`, `POST /api/reports/generate` | the schema 2.0 document ([export-schema.md](export-schema.md)) |
| `reports/security-posture-report.html` | same | the ten-section report |
| `reports/security-posture-report.pdf` | same, when Playwright Chromium is available | A4 print of the HTML |
| `validation/demo-results.json` | step 12 | `steps` (step, detail and the data of each step), `final_posture` (totals), `findings` (by status), `validation` (harness metrics), `incident`, `generated_at`, `remediated` |
| `screenshots/` | `make screenshots-2` (not part of `demo2`) | dashboard captures of the 2.0 pages |

`demo-results.json` is the machine-readable record of the run; its `steps[*].authorization`
entries show the automatic authorization of step 2 and the rejection of step 5 side by side.

## API

All routes are in `backend/sentinelswitch/api/assurance_routes.py` (prefix `/api`). POST bodies are
`{"actor": "<username>", "note": "<text>"}` (defaults `tlee`, empty; max 64 / 500 characters).
Mutating routes publish Server-Sent Events (`assessment`, `finding`, `incident`, `state`) so the
dashboard refreshes.

| method and path | returns |
| --- | --- |
| `GET /api/posture` | `posture.summary()` |
| `GET /api/controls` | `{catalog, status (by_control), last_run}` |
| `GET /api/controls/{control_id}` | `{control, assessments, findings}`; 404 if unknown |
| `GET /api/assessments?status=&control_id=` | latest assessments, filtered |
| `GET /api/assessments/runs` | runs, newest first |
| `GET /api/assessments/runs/{run_id}` | `{run, assessments}` from `assessment_history` |
| `GET /api/assessments/{assessment_id}` | `{assessment, history, finding, control}` |
| `POST /api/assessments/run` | runs the engine (trigger `api`); returns the run |
| `GET /api/findings?status=&open_only=true` | findings |
| `GET /api/findings/{finding_id}` | `{finding, events, assessment, history, control}` |
| `POST /api/findings/{finding_id}/remediate` | `{finding, executed, transcript, commands, run}` or `{finding, executed: false, refused}`; 404 unknown, 409 `RemediationError` |
| `GET /api/reviews/{detection_id}` | the review record |
| `POST /api/reviews/{detection_id}/approve` | `{incident, action, review}`; 409 if not open or not containable |
| `POST /api/reviews/{detection_id}/reject` | `{review}`; 409 if not open |
| `GET /api/reports/posture.json` | the export document, built on request |
| `GET /api/reports/posture.html` | the HTML report, rendered on request |
| `POST /api/reports/generate` | writes JSON, HTML and PDF; `{json, html, pdf, assessments, findings}` |
| `GET /api/reports/posture.pdf` | the last generated PDF; 404 until generated |

The 1.x routes that the workflow also uses: `POST /api/demo/run` (flagship replay, which now ends
with the post-containment assessment) and `POST /api/incidents/{id}/restore` (which now ends with
the recovery assessment).

## CLI

| command | what it does |
| --- | --- |
| `sentinelswitch assess [--trigger cli] [--actor tlee] [--json]` | one assessment run; prints the run summary and every non-passing assessment (seeds first if the database is empty) |
| `sentinelswitch findings [--all]` | open findings (or all, including verified) |
| `sentinelswitch remediate [FND-… …] [--all] [--actor tlee] [--note …] [--no-reassess]` | request, execute and verify remediation for the named findings or every open finding with an executable action; prints the transcript; exit 1 if any finding is unknown, refused by the service or refused by the switch adapter |
| `sentinelswitch report [--out DIR] [--no-pdf]` | export JSON, HTML and PDF; validates the required top-level keys |
| `sentinelswitch demo2 [--no-pdf]` | the twelve steps above |
| `sentinelswitch status` | includes `assessments`, `findings`, `findings_open`, `assessment_runs`, `reviews_open` counts |

Make targets: `make demo-2`, `make assess`, `make findings`, `make remediate` (`--all`), `make report`.

## Dashboard

| page | route | shows |
| --- | --- | --- |
| Posture | `/` | totals with denominators, by control / category / CSF, open findings, unverified assessments, recent runs |
| Controls | `/controls`, `/controls/:id` | catalog, rolled-up status, per-control assessments and findings |
| Findings & Remediation | `/findings`, `/findings/:id` | lifecycle, evidence, remediation transcript and events, *Remediate* action |
| Incidents | `/incidents`, `/incidents/:id` | review queue with *Approve containment* / *Reject* for detections in manual review (`/incidents`); authorization record, verification and restore on the incident page |
| Evidence & Reports | `/reports` | generate and open the JSON / HTML / PDF reports |

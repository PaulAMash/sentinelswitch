# Export schema

`backend/sentinelswitch/assurance/export.py` produces one machine-readable document
(`schema_version` **`2.0`**) and renders a human-readable HTML report from it. Everything in both is
read from SQLite and the evidence bundles at export time; nothing is computed only for the export.

| output | produced by | path |
| --- | --- | --- |
| JSON document | `build_export()` + `write_json()`; `GET /api/reports/posture.json` | `artifacts/sentinelswitch-2.0/reports/security-posture-report.json` |
| HTML report | `render_html()` + `write_html()`; `GET /api/reports/posture.html` | `artifacts/sentinelswitch-2.0/reports/security-posture-report.html` |
| PDF report | `write_pdf()` (Playwright, optional); `GET /api/reports/posture.pdf` | `artifacts/sentinelswitch-2.0/reports/security-posture-report.pdf` |

`sentinelswitch report [--out DIR] [--no-pdf]`, `POST /api/reports/generate` and `sentinelswitch demo2`
write the JSON and the HTML, and the PDF when Playwright Chromium is available. The CLI additionally reloads the JSON and fails (exit 1) if any of
`schema_version`, `generated_at`, `posture`, `controls`, `assessments`, `findings`, `incidents`,
`containment_actions`, `framework_mapping`, `limitations` is missing. The artifacts directory is
`SENTINEL_ARTIFACTS_DIR` (default `artifacts/sentinelswitch-2.0`).

## JSON document

Timestamps are ISO-8601 UTC strings with millisecond precision on the **simulated** clock unless
stated otherwise. Keys appear in this order.

### Top level

| key | type | meaning |
| --- | --- | --- |
| `schema_version` | string | `"2.0"` |
| `generator` | object | `name` (`SentinelSwitch`), `version` (`sentinelswitch.__version__`), `component` (`assurance.export`) |
| `generated_at` | string | simulated clock of the export: the twin's `now` unless a time is passed in |
| `clock_basis` | string | `simulated switch-twin clock (dataset day <YYYY-MM-DD>)` |
| `simulation_notice` | string | statement that assets, telemetry, incidents and assessments are synthetic |
| `scope` | object | `organization` (from `environment.yaml`), `switch` {`hostname`, `model`, `ios_version`, `management_ip`}, `vlans` [{`id`, `name`, `subnet`, `purpose`}] (VLAN 999 excluded), `assets_in_scope` (devices in inventory), `controls_in_scope` (13) |
| `methodology` | object | `states` (PASS/FAIL/UNKNOWN/STALE definitions), `freshness` (policy sentence), `metrics` (the posture metric definitions) |
| `posture` | object | see [Posture](#posture) |
| `controls` | array | the control catalog ([Control](#control)) |
| `assessments` | array | the latest result of every assessment id ([Assessment](#assessment)) |
| `findings` | array | every finding ever opened, each with its `events` ([Finding](#finding)) |
| `assets_with_open_findings` | array | {`asset`, `interface`, `findings`, `worst`, `controls`} per asset, worst severity first |
| `unverified` | array | {`id`, `control_id`, `scope`, `status`, `explanation`} for every `UNKNOWN`/`STALE` assessment |
| `assessment_runs` | array | every run, newest first ([Assessment run](#assessment-run)) |
| `incidents` | array | one item per incident ([Incident item](#incident-item)) |
| `manual_reviews` | array | review-queue entries without their `timeline` and `attribution`; `attribution_chain` holds the attribution flags ([Manual review](#manual-review)) |
| `containment_actions` | array | every containment action, newest first ([Containment action](#containment-action)) |
| `validation` | object | `metrics` (harness totals from the `validation_metrics` kv entry) and `results` (one row per scenario without `timeline`, `features`, `derived`) |
| `framework_mapping` | object | `framework` (`NIST CSF 2.0`), `note` (illustrative-mapping disclaimer), `subcategories` ([CSF rollup](#csf-rollup)) |
| `limitations` | array of strings | twin not hardware; synthesized telemetry; no Suricata liveness; simulated timestamps |
| `reproducibility` | object | `commands` (`make seed`, `make demo-2`, `make report`), `dataset_manifest` (`data/generated/manifest.json`), `deterministic` (`true`) |

### Posture

`posture` is `assurance/posture.summary()` minus the list-valued keys that are exported at top level
(`findings`, `assets_with_open_findings`, `unverified`, `recent_runs`, `last_run`), plus four
finding counters.

| key | type | meaning |
| --- | --- | --- |
| `generated_for` | string | dataset day |
| `clock` | string / null | `assessed_at` of the most recent run |
| `runs` | integer | number of assessment runs |
| `totals` | object | `assessments`, `controls`, `pass`, `fail`, `unknown`, `stale`, `determinate` (pass + fail), `retired` (latest results whose scope no longer exists; excluded from every other number here), `coverage_pct`, `pass_rate_of_determinate_pct`, `pass_rate_of_all_pct` (percentages rounded to 0.1; `null` when the denominator is 0) |
| `definitions` | object | one sentence per metric, plus `open_findings` |
| `by_control` | array | per control: `control_id`, `name`, `category`, `severity`, `scope_type`, `csf`, `assessments`, `pass`, `fail`, `unknown`, `stale`, `open_findings`, rolled-up `status` (`FAIL` > `STALE` > `UNKNOWN` > `PASS`, or `NOT_ASSESSED`) |
| `by_category` | array | {`category`, `pass`, `fail`, `unknown`, `stale`} |
| `csf` | array | the [CSF rollup](#csf-rollup) |
| `incidents` | object | `total`, `open` (`contained`, `open`, `containment_failed`), `resolved` |
| `scope_note` | string | simulation disclaimer |
| `findings_open` / `findings_closed` | integer | findings in / not in the open states |
| `findings_by_severity` | object | open findings per `high` / `medium` / `low` |
| `findings_by_status` | object | all findings per lifecycle status |

`totals` counts the non-retired rows of the `assessments` table, which after any run equals that
run's `assessments`. A row whose scope disappeared (for example `CTL-QUARANTINE-VERIFIED` for an
incident that was later resolved) becomes `RETIRED`: it is counted only in `totals.retired`, and it
stays in `assessment_history` and in the top-level `assessments` array with status `RETIRED`.

### Control

One entry per catalog control (`Control.to_dict()`).

| key | type | meaning |
| --- | --- | --- |
| `id`, `name`, `description` | string | catalog identity |
| `category` | string | Segmentation, Access control, Identity, Configuration, Hardening, Monitoring, Response, Recovery, Evidence |
| `severity` | string | severity of a `FAIL` finding: `high` / `medium` / `low` |
| `scope_type` | string | `interface` / `incident` / `source` / `vlan` / `global` |
| `source_of_truth` | string | what the evaluator reads |
| `csf` | array | [{`id`, `text`}] NIST CSF 2.0 subcategories |
| `freshness_window` | integer / null | seconds; `null` for state-based evidence |
| `states` | array | states the control can reach |
| `remediation` | string | remediation guidance |
| `limitations` | string | known limitation of the check (may be empty) |

### Assessment

| key | type | meaning |
| --- | --- | --- |
| `id` | string | `ASM-<control>-<scope slug>` (stable across runs) |
| `run_id` | string | run that produced this result |
| `control_id`, `control_name`, `category` | string | from the catalog |
| `framework` | object | `nist_csf_2_0`: [{`id`, `text`}] |
| `scope` | object | `type`, `id`, `asset` (hostname, device, VLAN label or switch), `interface`, `vlan`, `switch`, and `description` for interface scopes |
| `assessed_at` | string | the run's clock |
| `expected` / `observed` | any | string, object or list, as the evaluator produced them |
| `status` | string | `PASS` / `FAIL` / `UNKNOWN` / `STALE`, or `RETIRED` for a kept-but-uncounted result (then `retired_at` and `retired_by_run` are present; `GET /api/assessments` omits these rows unless `include_retired=true`) |
| `severity` | string | catalog severity, per-finding override for drift, downgraded for `STALE` |
| `explanation` | string | one or two sentences |
| `evidence` | array | [{`source`, `ref`, `collected_at`, `detail`}]; sources: `switch-twin`, `inventory`, `radius`, `zeek`, `syslog`, `suricata`, `drift-engine`, `containment-action`, `policy-decision`, `evidence-bundle` |
| `evidence_collected_at` | string | newest `collected_at` (or the run clock when there is no evidence) |
| `freshness` | object | `window_seconds`, `applied`; when applied also `oldest_evidence_at`, `age_seconds`, `fresh` |
| `related_incidents` | array | incident ids |
| `detector` | string | `sentinelswitch-assurance` |
| `source_of_truth` | string | from the catalog |
| `remediation` | object | `guidance`, `commands` (IOS lines), `action` (executable descriptor or `null`) |
| `finding_id` | string / null | finding opened or closed by this assessment |
| `limitations` | string / null | from the catalog |

Remediation `action` descriptors: `{"type": "apply_config", "interface", "lines"}`,
`{"type": "shutdown_unused", "interfaces"}`, `{"type": "add_span_source", "vlan"}`,
`{"type": "reauthenticate", "interface"}`, `{"type": "fix_trust", "extra", "missing"}`.

### Finding

| key | type | meaning |
| --- | --- | --- |
| `id` | string | `FND-<control>-<scope slug>` |
| `control_id`, `control_name`, `category` | string | from the catalog |
| `scope` | object | as in the assessment |
| `asset` | string / null | `scope.asset` |
| `severity` | string | follows the latest assessment |
| `status` | string | `open`, `reopened`, `remediation_requested`, `remediated`, `remediation_failed`, `verified`, or `closed` (the scope was retired before verification) |
| `result` | string | latest non-passing result: `FAIL` or `STALE` |
| `opened_at`, `updated_at`, `resolved_at` | string / null | lifecycle timestamps |
| `first_run_id`, `last_run_id` | string | runs that opened / last touched it |
| `occurrences` | integer | number of runs that reported it non-passing |
| `assessment_id` | string | the assessment that last touched it |
| `expected`, `observed`, `explanation`, `related_incidents` | | copied from the assessment |
| `remediation` | object | `guidance`, `commands`, `action`, `status` (`not_started` / `requested` / `executed` / `refused`), `requested_at`, `requested_by`, `executed_at`, `executed_by`, `transcript`, `note` |
| `verification` | object | `outcome` (`PASS` / `FAIL` / `null`), `at`, `run_id`, `after_remediation` (present once a run has decided the outcome) |
| `events` | array | [{`ts`, `event`, `actor`, `detail`, optional `transcript`}] — `opened`, `reopened`, `remediation_requested`, `remediation_executed`, `remediation_refused`, `verification_failed`, `scope_retired`, `verified` |

### Assessment run

| key | type | meaning |
| --- | --- | --- |
| `run_id` | string | `ASR-<clock>-<trigger>` |
| `assessed_at` | string | simulated clock |
| `trigger` | string | `baseline-seed`, `post-containment`, `remediation-<finding>`, `recovery-<incident>`, `api`, `cli` |
| `actor` | string | `sentinel-assurance` (seed, replay, remediation verification), the requesting analyst, or `api` when `POST /api/assessments/run` has no body |
| `controls`, `assessments` | integer | 13; number of assessments in the run |
| `retired` | integer | latest-result rows this run retired because their scope no longer exists |
| `counts` | object | `PASS`, `FAIL`, `UNKNOWN`, `STALE` |
| `findings_open` | integer | open findings after reconciliation |
| `clock` | string | `simulated (switch twin)` |

### Incident item

| key | type | meaning |
| --- | --- | --- |
| `incident` | object | the incident record: `id`, `title`, `severity`, `confidence`, `status`, `opened_at`, `closed_at`, `rule`, `rule_name`, `class`, `mitre`, `scenario`, `instance`, `detection_id`, `device`, `user`, `department`, `ip`, `mac`, `vendor`, `switch`, `interface`, `original_vlan`, `current_vlan`, `port_class`, `chain`, `summary`, `disposition`, `action`, `attribution_confidence`, `flags`, `impersonated_device`, `authorization` ([Authorization](#authorization)), `workflow_id`, `mechanism`, `contained_at`, plus `evidence_finalized_at`, `evidence_path`, `closed_by`, `resolution_note` where applicable |
| `timeline` | array | [{`ts`, `phase`, `actor`, `message`, `details`}]; phases include `authorization`, `containment`, `verification`, `evidence`, `resolution` |
| `actions` | array | the incident's [containment actions](#containment-action) |
| `evidence_bundle` | object | `path` (`data/incidents/<id>`, repository-relative) and `present` (file names found on disk; empty when the directory does not exist) |

### Containment action

`ContainmentAction.to_dict()` from `containment/controller.py`.

| key | type | meaning |
| --- | --- | --- |
| `workflow_id` | string | `WF-<incident number>-<nn>` |
| `incident_id` | string / null | |
| `action` | string | `quarantine_vlan` / `port_shutdown` / `none` |
| `mechanism` | string | human label of the mechanism |
| `interface`, `switch`, `from_vlan`, `to_vlan` | | target |
| `reason`, `initiating_detection`, `actor` | string | summary, detection id, `sentinel` |
| `requested_at`, `applied_at`, `verified_at` | string / null | |
| `status` | string | `pending`, `not_applicable`, `applied`, `verified`, `failed`, `refused`, `restored` |
| `commands` | array | IOS commands sent |
| `transcript` | string | IOS-style transcript |
| `verification` | object | `ok`, `expected`, `transcript`, `checked_at` |
| `restored_at`, `restored_by`, `restore_note`, `restore_transcript` | | set by rollback |
| `notes` | array | adapter / controller notes |
| `authorization` | object / null | [Authorization](#authorization) |

### Authorization

`authorization_record()` in `containment/controller.py`; attached to incidents, containment actions
and reviews.

| key | type | meaning |
| --- | --- | --- |
| `mode` | string | `automatic` (policy tier), `analyst` (an analyst decision), `rejected` (declined through `POST /api/reviews/{id}/reject`). Historical reviews generated with the dataset carry `mode: analyst` with `status: rejected`; reviews declined at runtime carry `mode: rejected` |
| `status` | string | `authorized`, `pending`, `rejected` |
| `authorized_by` | string | `policy-engine` or the analyst username |
| `authorized_at` | string / null | set when authorized or rejected; `null` while pending |
| `basis` | string | `policy tier <disposition>` plus `(before guards: <tier>)` when a guard downgraded it |
| `reason` | string | the policy decision's reason text |
| `guards` | array | guards that fired (`critical_assets`, `protected_ports`, `trunk_ports`, `span_destination`, `unresolved_attribution`, `no_action_for_class`) |
| `action` | string | the action the decision selected |
| `note` | string / null | analyst note |

### Manual review

| key | type | meaning |
| --- | --- | --- |
| `authorization` | object | [Authorization](#authorization) |
| `detection_id`, `status` | string | `review` (open), `approved`, `closed`, `monitor` |
| `opened_at`, `closed_at`, `closed_by`, `note` | | analyst closure |
| `scenario`, `rule`, `actor`, `severity`, `confidence`, `title` | | detection context |
| `decision` | object | the policy decision (`disposition`, `action`, `reason`, `factors`, `guards_triggered`, `quarantine_vlan`, `tier_before_guards`) |
| `attribution_chain` | array / null | the attribution flags |
| `incident_id` | string | present when the review was approved |

### CSF rollup

One entry per NIST CSF 2.0 subcategory referenced by any assessment:
`id`, `text`, `function` (`ID`, `PR`, `DE`, `RS`, `RC`), `controls` (sorted ids), `pass`, `fail`,
`unknown`, `stale`.

## HTML report

`render_html()` renders the JSON document as a single self-contained page (inline CSS, inline SVG
logo, no external resources) with a header (title, `generated_at`, `clock_basis`, schema and
generator version, scope and simulation notice) and ten numbered sections:

| # | section | content |
| --- | --- | --- |
| 1 | Executive summary | one paragraph of counts, the five most significant open findings, six KPI tiles (assessments, pass, fail, unknown, stale, open findings) |
| 2 | Assessment counts and methodology | metric table with definitions, state definitions, freshness sentence, results-by-control table with CSF ids |
| 3 | Control findings | every open finding (asset, expected, observed, explanation, opened/run/occurrences, guidance and commands) worst severity first; table of verified/closed findings with their verification run |
| 4 | Affected assets | assets with open findings; table of unverified (UNKNOWN/STALE) assessments |
| 5 | Supporting evidence | evidence rows for every non-passing assessment and for every incident-scoped assessment (detail truncated to 220 characters; the JSON holds the full lists) |
| 6 | Incident timeline | per incident: chain, open/close, phase-by-phase timeline |
| 7 | Containment authorization and verification | per workflow: authorization mode, authorizer, basis, authorized/applied/verified times, read-back result, status; table of detections routed to manual review with guards and outcome |
| 8 | Outstanding remediation | open findings with remediation status and times; full remediation event history |
| 9 | Framework mapping (NIST CSF 2.0) | the CSF rollup with the illustrative-mapping note |
| 10 | Limitations and reproducibility | limitation list, reproduce commands, dataset manifest, validation harness totals (scenarios passed, MTTD, MTTC); a footer that repeats the simulated `generated_at` and states that no wall-clock time is embedded, so the HTML is byte-reproducible for the same state |

Print styles (`@media print`) keep headings with their tables and avoid page breaks inside rows.

## PDF generation

`write_pdf(html_path, pdf_path)` opens the written HTML file (`file://` URI) in headless Chromium
through Playwright (`playwright.sync_api`) and prints it with `page.pdf(format="A4",
print_background=True, margin top/bottom 12 mm, left/right 10 mm)`. It returns `None` without
raising when Playwright is not installed or Chromium cannot launch; the CLI then prints `PDF skipped
(Playwright Chromium not available)` and `POST /api/reports/generate` returns `"pdf": null`.
`GET /api/reports/posture.pdf` serves the last generated file and answers 404 until one exists.
`make setup` installs Chromium with `playwright install chromium`.

## Deliberately excluded

* **Secrets.** No credentials, RADIUS shared secrets, certificates or API tokens exist in the store,
  and none are modelled in the twin; the export contains none.
* **Personal data beyond the fictional inventory.** Identities are the synthetic users and hostnames
  from `simulator/fixtures/`. Review entries are exported without their full `attribution` and
  `timeline`; validation rows without `timeline`, `features` and `derived`.
* **Host paths.** The document refers to files only by repository-relative paths
  (`data/incidents/<id>`, `data/generated/manifest.json`). The local file names of the written
  reports are returned by `POST /api/reports/generate` and printed by the CLI, but are not part of
  the document.
* **Wall-clock time.** Neither the JSON nor the HTML carries a wall-clock timestamp; every timestamp
  is on the simulated clock, as `clock_basis` states, so repeated exports of the same state are
  identical.

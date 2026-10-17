# SentinelSwitch 2.0 — portfolio package

Everything in this file is written to be posted as-is. Every number below is taken from an executed
run of the repository (`make demo-2`, `scripts/test.sh`, `make validate-security`) and can be
reproduced from a fresh clone. The project is a **simulation**: a digital twin of a Cisco Catalyst
2960-X, synthetic deterministic telemetry, no physical attacks, no real switch, no production network.
SentinelSwitch is an independent personal project. It is **not** affiliated with, endorsed by, or
built for any employer, vendor, league or customer, and no third-party logos or names are used in
the media.

## Contents of `artifacts/sentinelswitch-2.0/`

| path | what it is |
| --- | --- |
| `screenshots/sentinelswitch-2.0-overview.png` | the Overview home page (`/`) after the flagship incident was contained: attention strip, alert stream, response ledger, control status (1600 × 1000 CSS px at 2×) |
| `screenshots/sentinelswitch-2.0-dashboard.png` | the posture dashboard (`/posture`) after the flagship incident was contained (1600 × 1000 CSS px at 2×) |
| `screenshots/sentinelswitch-2.0-review-dialog.png` | the analyst authorization dialog for the detection that policy routed to manual review |
| `screenshots/sentinelswitch-2.0-dashboard-full.png` | the same view, full page |
| `screenshots/sentinelswitch-2.0-incident.png`, `-incident-full.png` | INC-2026-0042 with detection → correlation → identification → recommendation → authorization → execution → verification |
| `screenshots/sentinelswitch-2.0-findings-open.png`, `-findings-open-full.png` | the six open findings before remediation |
| `screenshots/sentinelswitch-2.0-controls.png`, `-controls-full.png` | the thirteen controls with their status counts |
| `screenshots/sentinelswitch-2.0-findings-verified.png` | all findings after executed and verified remediation |
| `screenshots/sentinelswitch-2.0-finding-detail.png` | one finding's full record: expected vs observed, the IOS transcript of the remediation, and the verifying assessment run |
| `screenshots/sentinelswitch-2.0-reports.png` | the reports page after export |
| `screenshots/sentinelswitch-2.0-dashboard-after-remediation.png` | the posture dashboard after remediation and recovery |
| `screenshots/sentinelswitch-2.0-report-preview.png` | the HTML report rendered in the browser |
| `reports/security-posture-report.json` | the JSON export (schema 2.0, see `docs/export-schema.md`) |
| `reports/security-posture-report.html` | the HTML report |
| `reports/security-posture-report.pdf` | the PDF report |
| `validation/demo-results.json` | every step of the 2.0 workflow with the observed counts |
| `validation/test-results.md` | the executed test, lint and validation run |

All screenshots were captured by `scripts/screenshots.py --only-2` from the running application
with headless Chromium. None were edited.

## Verified metrics (from the executed run)

| metric | value | source |
| --- | --- | --- |
| controls assessed | 13 | `GET /api/controls`, `docs/controls.md` |
| baseline assessment | 206 assessments: 200 PASS, 4 FAIL, 1 UNKNOWN, 1 STALE → 5 findings | `validation/demo-results.json` step `reset + baseline` |
| flagship incident | detected 21:14:39.867 Z at confidence 0.97; VLAN 20 → 50 verified 21:14:41.125 Z; TTD 8.583 s, TTA 0.572 s, TTC 1.258 s (simulated clock) | `validation/demo-results.json` step `flagship incident` |
| negative path | 1 detection withheld by the `critical_assets` guard; analyst rejected containment; switch untouched | steps `negative path`, `analyst decision` |
| remediation | 5 findings → `verified` by re-assessment | steps `remediate` |
| recovery | INC-2026-0042 restored; recovery assessment confirms Gi1/0/23 back in VLAN 20 | step `restore + recovery` |
| final posture | 209 assessments, 208 PASS, 1 UNKNOWN (Suricata liveness, not counted as a pass), 1 retired row excluded; coverage 99.5 %, determinate pass rate 100 % | `final_posture` |
| validation harness | 9 / 9 scenarios met their expected outcome: 8 contained and verified, 1 withheld by policy for analyst review; MTTD 10.446 s and MTTA 0.533 s over all 9, MTTC 1.214 s over the 8 contained (simulated clock) | `validation/test-results.md`, `docs/validation.md` |
| automated tests | 82 backend tests passing, frontend type-check and lint clean | `validation/test-results.md` |

## LinkedIn post (long form)

> Last month I built a digital twin of a Cisco access layer to practise one hard thing: getting from a
> suspicious flow to a physical switch port and containing it with evidence. SentinelSwitch 2.0 adds
> the question I kept being asked afterwards — *how do you know the controls you are relying on are
> actually in place right now?*

**SentinelSwitch 2.0 — Evidence-Driven Network Security & Response Lab**

The lab models a Catalyst 2960-X (WS-C2960X-48FPD-L) and a Linux ThinkPad running Zeek, Suricata and
FreeRADIUS, framed as the venue network of a fictional esports league. Everything is simulated and
deterministic — no real switch, no real traffic, no production network — but the detection,
attribution, policy, containment, assessment and reporting code is real and tested.

What 2.0 adds:

• **Control assessments with evidence.** Thirteen controls (VLAN intent, 802.1X/MAB, endpoint
identity, port security, configuration baseline, unused ports, DHCP-snooping trust boundary,
telemetry freshness, sensor coverage, response authorization, verified quarantine, verified recovery,
evidence completeness) are evaluated against the switch twin, the port intent, RADIUS results, the
SPAN session and the containment records. Each assessment stores what it expected, what it observed
and where it looked, and reports PASS / FAIL / UNKNOWN / STALE under a declared freshness policy.
UNKNOWN and STALE never count as a pass.

• **A posture view without a risk score.** Every number is *n of N*: coverage (determinate
assessments over all assessments) and determinate pass rate are shown separately, so a control that
cannot be evaluated is never hidden inside a percentage.

• **Findings that have to be proven fixed.** A failed assessment opens a finding. Remediation is
executed through the same switch adapter as containment, and only a re-assessment that passes moves
the finding to *verified*. The full history stays attached.

• **Authorization as a first-class step.** Every containment action carries an authorization
record — the policy engine for the automatic tier, a named analyst for reviews — that must precede
execution. A new negative scenario (a critical server scanning the server segment) is detected and
attributed, then withheld by the critical-asset guard until an analyst decides. In the demo the
analyst rejects containment, and the assessment layer confirms nothing executed without authorization.

• **Reports you can hand to someone.** JSON with a documented schema, a self-contained HTML report
and a PDF, generated from the same data the dashboard shows.

The flagship incident is unchanged: an authenticated engineering laptop sweeps two subnets, bursts
reverse DNS and fans out SMB/RDP probes; Suricata and Zeek corroborate, a correlation rule scores
0.97, attribution walks DHCP snooping → MAC table → Gi1/0/23, policy authorizes, the port moves to the
quarantine VLAN, the switch is read back to verify — 1.26 s from detection to verified containment on
the simulated clock — and the recovery is verified the same way when the port is restored.

Numbers from the executed run: 9 of 9 validation scenarios pass (MTTD 10.4 s, MTTA 0.53 s, MTTC 1.21 s
on the simulated clock), 82 automated tests, 206 assessments at the baseline with 5 findings,
all 5 verified remediated, 208 of 209 passing after recovery with one honest UNKNOWN.

What I learned this time: "verified" is a stronger word than "done". Making the remediation flow
re-run the assessment instead of trusting the action that was just executed caught a timing bug in
my own re-authentication logic that a simple status flip would have hidden.

Stack: Python 3 · FastAPI · Pydantic · SQLite · React 19 · TypeScript · Vite · Recharts · Playwright ·
Cisco IOS configuration-as-code with drift detection · Zeek and Suricata rule sources · MITRE ATT&CK
and a limited NIST CSF 2.0 mapping.

Repository, screenshots, reports and a deterministic terminal demo are on GitHub.

#NetworkSecurity #Cisco #Zeek #Suricata #DetectionEngineering #IncidentResponse #SecurityAssurance
#Python #FastAPI #React #SOC #NIST

## LinkedIn post (short form)

> SentinelSwitch 2.0 is out: my Cisco access-layer digital twin now assesses its own controls.
> 13 controls evaluated against the switch twin, the port intent and the telemetry, each with
> expected vs observed evidence and PASS / FAIL / UNKNOWN / STALE — where UNKNOWN and STALE never
> count as a pass. Findings are remediated through the switch adapter and only marked verified when a
> re-assessment passes. Every containment action carries an authorization record, and a new scenario
> shows automation being withheld for a critical asset until an analyst decides. JSON / HTML / PDF
> reports with a documented schema. Simulated, deterministic, no real hardware — 9/9 validation
> scenarios, 82 tests, all reproducible from a fresh clone.
> #NetworkSecurity #Cisco #DetectionEngineering #SecurityAssurance

## Suggested images for the post

1. `screenshots/sentinelswitch-2.0-dashboard.png` — alt text: "SentinelSwitch 2.0 posture dashboard:
   13 controls, assessment counts with denominators, open findings by severity, active incident."
2. `screenshots/sentinelswitch-2.0-incident.png` — alt text: "Incident INC-2026-0042 with the
   detection, correlation, identification, recommendation, authorization, execution and verification
   stages."
3. `screenshots/sentinelswitch-2.0-findings-verified.png` — alt text: "Findings after executed
   remediation, each verified by a re-assessment run."
4. `screenshots/sentinelswitch-2.0-report-preview.png` — alt text: "The exported HTML security
   posture report."

Add "Simulated lab — synthetic data" to the first image's caption.

## Direct-message drafts

**To a hiring manager or team lead (network security / SOC)**

> Hi <name>, I saw <team> is working on <topic from their post or job description>. I recently
> finished SentinelSwitch 2.0, a self-contained lab that models a Cisco 2960-X access layer with
> Zeek/Suricata/RADIUS telemetry, automated attribution to the switch port, authorized containment
> with read-back verification, and a control-assessment layer that reports evidence-backed
> PASS / FAIL / UNKNOWN / STALE for thirteen controls. It is a simulation rather than production work,
> but the pipeline, the tests and the reports are real and reproducible from a clone. If it is
> relevant to what you are building, I would value fifteen minutes to hear how your team approaches
> evidence for network controls. Repository: <link>.

**To a peer engineer (asking for feedback)**

> Hi <name>, your write-up on <their topic> was the clearest thing I have read on <aspect>. I have
> been building a lab that assesses network controls against a switch digital twin — expected vs
> observed evidence, freshness windows, findings that have to be re-assessed before they count as
> fixed. I would really like a critical read from someone who has run this in production: what would
> you distrust first? Repository: <link>. Happy to return the favour on anything you are working on.

**To a recruiter (reply to an outreach)**

> Thanks for reaching out, <name>. Before we talk, here is the most representative thing I have
> built recently: SentinelSwitch 2.0, a network detection, response and assurance lab (Cisco access
> layer twin, Python/FastAPI backend, React dashboard, deterministic validation, exported posture
> reports). It is simulated, not a production deployment, and I say so in the README. The repository
> link is <link>; the two-minute version is the dashboard screenshot and the demo results file in
> `artifacts/sentinelswitch-2.0/`. I am interested in <role type> roles where network security and
> automation meet.

**Follow-up after a connection accepts**

> Thanks for connecting, <name>. No agenda — if you ever want to compare notes on automated
> containment and how to evidence that network controls are actually in place, I have a lab with a
> reproducible demo and would enjoy the conversation.

## Resume bullet (2.0)

* Extended SentinelSwitch, a Cisco Catalyst 2960-X digital twin with synthetic Zeek / Suricata /
  802.1X / IOS telemetry, into an evidence-driven assurance lab: 13 control assessments with
  expected-vs-observed evidence and a PASS / FAIL / UNKNOWN / STALE freshness policy, a finding
  lifecycle whose remediation executes through the switch adapter and is verified by re-assessment,
  explicit authorization records on every containment action with a negative (withheld) scenario,
  and JSON / HTML / PDF posture reports with a documented schema — validated by 9 / 9 replayed
  adversary scenarios and 82 automated tests.

## Statements to avoid

* Do not describe the lab as a production deployment, a customer engagement or a live network.
* Do not attribute the project to, or imply endorsement by, any employer, vendor, event organiser or
  league; the esports framing is fictional.
* Do not quote a composite "security score" — the project deliberately does not compute one.
* Do not present the NIST CSF 2.0 citations as a framework assessment or a compliance result.

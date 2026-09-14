# LinkedIn media assets

All images in `assets/linkedin/` are rendered by `make screenshots` from the running application
(`/media/<slug>` routes in the dashboard) with headless Chromium at 1080 × 1350 CSS pixels and a
2× device scale factor (2160 × 2700 px files). Every number in every image comes from the API; none
of them are hand-edited. The physical hardware photo is supplied separately and is **not** part of
this set.

| # | file | what it shows | data source |
| --- | --- | --- | --- |
| 01 | `01-architecture.png` | portrait architecture diagram: endpoints → twin → telemetry → controller → quarantine | `diagrams/svg/architecture-portrait.svg` |
| 01b | `01-architecture-landscape.png` | landscape version of the same diagram (1600 × 900 @2×) | `diagrams/png/architecture.png` |
| 02 | `02-soc-overview.png` | KPI tiles, alert timeline, recent alerts | `/api/overview` |
| 03 | `03-incident-detected.png` | the seven source detections of INC-2026-0042 and the scored correlation rule (0.97) | `/api/incidents/INC-2026-0042` |
| 04 | `04-correlation.png` | IP → MAC → SW01 → Gi1/0/23 → VLAN 20 → VLAN 50 chain with every resolution step | attribution from the evidence bundle |
| 05 | `05-auto-quarantine.png` | VLAN 20 → VLAN 50, time to contain, front panel with Gi1/0/23 highlighted, decision/action/verification timeline | `/api/incidents/…`, `/api/switch` |
| 06 | `06-cisco-verification.png` | `show interfaces Gi1/0/23 switchport`, `show mac address-table interface Gi1/0/23`, `show vlan id 50` from the twin after containment | `/api/switch/show` |
| 07 | `07-validation-results.png` | validation matrix (8 × PASS) with MTTD / MTTA / MTTC | `/api/validation` |

Recommended carousel order is 01 → 07. Each card tells one step of the story:

1. **Architecture** — what was built.
2. **SOC overview** — the environment at a glance.
3. **Incident detected** — telemetry becomes a scored detection.
4. **Correlation** — the detection becomes a physical switch port.
5. **Auto-quarantine** — the policy acts and verifies.
6. **Cisco verification** — proof on the switch.
7. **Validation** — the same pipeline against eight scenarios.

## GitHub images (`assets/github/`)

| file | use |
| --- | --- |
| `hero.png` | README hero (1600 × 800 @2×), also copied to `assets/branding/social-card.png` |
| `architecture.png` | README architecture section |
| `dashboard-overview.png`, `incident-detail.png`, `switch-panel.png`, `validation-results.png` | README screenshots (1440 × 900 @2×) |

## Dashboard screenshots (`assets/screenshots/`)

`01-overview` … `11-architecture`, one per view, captured at 1440 × 900 @2× (full page for the
overview, incident and switch views).

## Branding (`assets/branding/`)

`logo.svg` / `logo.png` (512 px), `wordmark.svg` / `wordmark.png`, `favicon.svg`, `social-card.png`.

## Regenerating

```bash
make screenshots
```

The script starts its own API server on a temporary database, seeds it, applies the flagship
incident, captures everything, and shuts the server down. Because the dataset and the incident are
deterministic, re-running it produces the same images (modulo font rendering on the host).

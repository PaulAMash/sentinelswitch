# Signature visual redesign — QA report

Scope: frontend only (`frontend/src`), plus README text and regenerated screenshots. Starting point:
commit `04d57a5` (clean tree). Every check below was run on 2026-10-19 against a local build; all
state-changing interaction tests ran on an isolated server with a temporary database, never on the
shared deployment.

## 1. Summary of visual changes

- **Network signal field** (new, `components/signal/`): the Overview's centerpiece. One hexagon per
  SW01 interface (50), in colonies by operational VLAN around a switch core, on a faint decorative
  lattice with a radial fade, coordinate rings and an instrument frame.
- **Overview rebuilt around it**: scoped status rail (DAY / NOW / RUN on every number), the field with
  its timeline, inspector and event stream, then numbered sections — 02 Telemetry, 03 Detection and
  response, 04 Assurance and access.
- **Design system v2**: deeper blue-charcoal surfaces, hairline separators, an edge highlight on
  panels, atmospheric top glow instead of the square grid, a three-step severity scale, a source
  category scale, motion tokens (`--t-fast/base/slow/reveal/travel`, `--ease-out`, `--ease-in-out`).
  Green is reserved for confirmed outcomes (PASS, verified, resolved, Access-Accept): `online`,
  `closed` and "connected" became neutral.
- **Analytics suite** (`charts/viz.tsx`, `charts/index.tsx`): eight distinct visual forms (below).
- **Other routes upgraded**: Posture (category bars, CSF wheel, run ledger, balanced layout),
  Coverage (stage-timing matrix), Findings (lifecycle strip), Alerts (brushable timeline filter +
  severity ring), Incident detail (focused signal field beside a vertical attribution trace), Switch
  (`?port=` deep link used by the field's inspector).
- **Motion**: route fade/rise keyed by section, staged reveals, one-shot node arrival, pulses,
  flow draw, colony migration, bar/arc/ribbon entrances — all disabled by `prefers-reduced-motion`.

## 2. Hexagonal field: approach and why it fits the data

The data describes one monitored access switch, not Internet traffic, so the field is a **schematic
topology of SW01**, not a map. There is no trustworthy geolocation in the API (external destinations
are documentation ranges such as 192.0.2.123), so no world map was drawn.

| visual element | source | meaning |
| --- | --- | --- |
| hexagon | `/api/switch` `interfaces[]` | one switch interface; label = port number |
| colony | `oper_vlan` (trunks and VLAN 999 grouped) | operational VLAN; layout positions are fixed schematic anchors |
| fill (low / medium / high, 3 intensities) | `/api/alerts` with `interface`, in the selected window and filters | alert count (1, 2–3, 4+) tinted by the highest severity |
| outline style | `state` | connected, not connected (dashed), shut/unused (dotted), trunk, SPAN destination |
| ring + hatch | `quarantined`, `hold`, open `/api/reviews` (attribution interface), open `/api/incidents` | contained (hatched), held, awaiting authorization (dashed), open incident |
| arc | alert `src` port → `dest_ip` resolved through the DHCP snooping table (inventory as fallback) | a source→destination pair recorded in an alert; unresolved destinations are labelled stubs |
| "SPAN" / "not mirrored" tag | `span.source_vlans`; `CTL-SENSOR-COVERAGE` assessment | "not mirrored" only where that control returned FAIL |
| vacated slot (dashed) | `quarantined` + `original_vlan` | where a quarantined port normally sits |

Rendering: SVG (≈50 interactive nodes; the lattice is one path). Chosen over Canvas for exact hit
testing, focusable nodes and CSS transitions without per-frame React work. No dependency added.

Honesty rules implemented: the lattice is labelled decorative; the field says "SNAPSHOT · dataset day
· simulated clock" and switches to "REPLAY hh:mm" only during replay; nothing moves unless data or the
user changed it; response rings are current state and are never inferred from the time window.

## 3. Charts and their data

| chart | where | data source | notes |
| --- | --- | --- | --- |
| Alert timeline scrubber (15-min stacked bins + SPAN connections backdrop on its own scale) | Overview field, Alerts | `/api/alerts`, `/api/overview.traffic` | brushable window, empty bins kept at zero |
| Severity ring | Overview, Alerts | `/api/alerts` | counts and percentages always shown |
| Detection sources (stacked by severity) | Overview | `/api/alerts.source` | all four sensors listed even at zero |
| Alert classes | Overview | `/api/overview.alerts_by_category` | backend categories verbatim |
| SPAN traffic + DNS small multiples | Overview | `/api/overview.traffic` (`connections`/`bytes`, `dns`) | separate panels, no dual axis; bytes/connections toggle kept |
| Endpoint activity ranking | Overview | `/api/alerts.device` / `interface` | links to `/devices/:hostname`; unregistered ports labelled |
| Response outcomes flow | Overview | `/api/detections` + incidents + containment actions + reviews | outcome via `responseStateOf` (needs verification) or review record; "declined by analyst" from a rejected authorization |
| ATT&CK technique tiles | Overview | `/api/detections.mitre` | counts tags, explicitly "not framework coverage"; names/tactics from `lib/mitre.ts` |
| Response stage timing (TTD / TTA / TTC) | Coverage | `/api/validation.results` | per-column scale; withheld scenario shows "withheld by policy", no time |
| Category stack, CSF wheel, run ledger | Posture | `/api/posture` (`by_category`, `csf`, `recent_runs`) | wheel colours the worst result per subcategory; ledger only shows runs that exist (2) |
| Findings lifecycle strip | Findings | `/api/posture.findings.by_status` | every state shown, zeros dimmed |

## 4. Interactions and motion (verified with Playwright scripts)

- Select a port (click / Enter): attribution hops (DHCP binding → MAC table → port → VLAN → inventory),
  window activity, response links; peers by recorded flows stay lit, others dim, related arcs animate.
- Select an event in the stream: inspector shows the alert, its source port pulses, its arc is drawn.
- Colony focus (click a VLAN label), severity and source filters, Day / 4 h / 1 h presets (relative to
  the switch clock), brush, Field ↔ List view (accessible table alternative).
- Replay: walks the recorded timestamps of the window in ~16 s per day; checked mid-run at 09:02 that
  only earlier alerts are lit (`heat-0` on Gi1/0/23, ring still current-state).
- Server events: reset → replay through the real pipeline produced 44 → 51 alerts, 7 "new" stream rows
  and 7 pulses within ~250–500 ms, and Gi1/0/23 travelled from VLAN 20 to VLAN 50 leaving its slot
  outlined; no other port moved.
- Keyboard: one tab stop for the field (roving), arrows move by geometry, Enter selects, Escape clears;
  timeline keys ←/→, Shift+←/→, Home.
- Reduced motion: zero running animations (`document.getAnimations().length === 0`); arcs that would
  "draw in" are shown immediately.

## 5. Routes and capabilities preserved

All routes from the previous route contract resolve, including `/operations` → `/`, `/posture`,
`/findings?view=all`, `/evidence/:id?file=`, `/media/:slug`. Preserved: replay/reset demo dialogs,
review approve/reject dialogs, release containment, remediate, run assessment, generate reports,
console `show` restriction (checked earlier in this redesign line; unchanged code path), response-state
derivation (single `responseStateOf`), UNKNOWN / STALE / RETIRED / withheld semantics. Overview still
has recent alerts (event stream), containment ledger and recent authentication with links.

## 6. Screenshots

- Before (commit `04d57a5`): `artifacts/ui-redesign-2/before/` — 76 captures, 4 viewports × 19 routes, plus `metrics.json`.
- After: `artifacts/ui-redesign-2/after/` — same matrix, `metrics.json`, log `after-audit.log`.
- Interactions: `artifacts/ui-redesign-2/interactions/01…11` (snapshot, port selected, event selected,
  colony focus, replay, list view, baseline → server event → contained, phone field, phone incident).
- Repository screenshots and media cards regenerated by `scripts/screenshots.py` (log `screenshots-run.log`, exit 0).

## 7. Checks

| check | result |
| --- | --- |
| `scripts/ui_audit.py artifacts/ui-redesign-2/after` (1920×1080, 1440×900, 1024×768, 390×844; 19 routes) | 76 measured, **0 failing**, no hex literals in TSX; overflow 0, past-viewport 0, sub-11 px text 0, console 0, failed requests 0, non-focusable rows 0, radii {4px, 6px, 50%}, ≤ 7 font sizes per route |
| `pytest` (via `scripts/test.sh`) | 82 passed |
| `ruff` | all checks passed |
| `tsc -b` | ok |
| `oxlint` | ok (only the existing "fast refresh only-export-components" warnings) |
| validation harness | 9/9 (8 contained, 1 withheld) |
| `vite build` | ok |
| frontend unit tests | none exist in the project; not run |
| backend / simulator / data / detections diff | 0 lines |

## 8. Not implemented because the data does not support it

- Geographic map of external sources (no trustworthy geolocation).
- A "live" feed: the dataset is one recorded day; the UI updates on server events and offers replay.
- DNS query distribution by domain (only per-bucket DNS counts are served).
- Historical posture or findings trends beyond the run ledger (two runs exist; nothing interpolated).

## 9. Known limitations

- ATT&CK names/tactics come from a small static table (`lib/mitre.ts`) for the ids the rules emit.
- Hexagons on a 390 px phone are about 24 px wide, below a 40 px touch target; the List view is the
  touch-friendly alternative.
- The incident page's mini field does not fetch the sensor-coverage assessment, so it omits the
  "not mirrored" tag that the Overview shows.
- Bundle grew from 822 kB to 888 kB (gzip 257 kB); Vite's > 500 kB chunk warning predates this work.
- `scripts/test.sh` rewrote `artifacts/sentinelswitch-2.0/validation/test-results.md` (timestamp only).

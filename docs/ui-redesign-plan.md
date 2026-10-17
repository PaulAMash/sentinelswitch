# SentinelSwitch 2.0 — dashboard visual redesign: audit and implementation plan

Status: **planning only**. Nothing in `frontend/`, `backend/`, `scripts/` or `assets/` was changed to
produce this document. It is written for the implementation session (Opus) and for the owner's
review. Every statement below is tagged:

- **[source]** verified by reading the repository at commit `197f2a6` (HEAD, working tree clean).
- **[rendered]** observed by running the application locally (built `frontend/dist`, temporary SQLite,
  `SENTINEL_AUTO_DEMO=1`) and rendering every route with headless Chromium at four viewports
  (1920×1080, 1440×900, 1024×768, 390×844), plus the hosted instance's `/api/meta`.
- **[assumption]** a judgement call; the recommendation is stated and the plan proceeds on it.

---

## 0. Implementation guardrails (read first)

These rules bind every phase in F. Where a later section seems to allow more, this section wins.

1. **Frontend only.** No file under `backend/`, `simulator/`, `data/`, `cisco/`, `detections/`,
   `automation/` changes. `frontend/src/lib/api.ts` keeps every endpoint path, method, body and
   response type; new TypeScript fields may be *added* to types only when the backend already
   returns them (verify with `curl` against `/api/...` before typing them). Backend tests stay at 82.
2. **Every existing route keeps working.** The route table in D.0 is the contract: nothing is removed,
   `/operations` stays as a redirect to `/`, and every page keeps the capabilities listed in the
   capability inventory (D.0). A feature may move or collapse; it may not disappear.
3. **Nothing is fabricated.** Every value on screen comes from an `endpoints.*` response or from the
   two client-side computations that exist today (`diff()` deltas between two server timestamps on
   the incident page; filter/sort of fetched rows). No client-side "health", "liveness", "last seen"
   or counters that the API does not provide. Timestamps are the server's simulated-clock values.
4. **Response and assessment semantics are rendered, never inferred.** The derivation rules in D.3
   and D.4 are exhaustive: a response is "contained · verified" only when the backend says the
   action is `verified` with `verification.ok === true`; an executed-but-unverified action is shown
   as exactly that; "withheld" and "rejected" stay visibly distinct from both success and failure;
   UNKNOWN, STALE and RETIRED keep the meanings in `docs/controls.md`; "not recorded" is shown when a
   record is absent, never a guessed state.
5. **The console only shows.** The IOS console sends the typed string unchanged to the existing
   `GET /api/switch/show`, which already rejects anything that does not start with `show`. Suggestions
   are built only from the server-provided `commands` list and the interface-scoped `show …
   interface <port>` templates the page offers today. No client-side interpretation, no new
   endpoint, no change to `cli_render.SHOW_COMMANDS`.
6. **Confirmation only where it changes state.** Dialogs are required for approve, reject, release
   containment, remediate, reset to baseline and replay flagship incident (D.4). Navigation, filters,
   tabs, drawers, port selection, console commands, run assessment, re-run validation, generate
   reports and report links get no dialog.
7. **Demo identity is shown where it is recorded, not everywhere.** The hard-coded analyst `tlee`
   appears in the four dialogs whose request carries an `actor` (approve, reject, release, remediate)
   as "Recorded as analyst tlee (demo identity, no sign-in)", and wherever the backend already
   displays an actor. It does not appear in the topbar, the sidebar or other dialogs.
8. **Dependencies: at most the two self-hosted font packages in E.5**, and only after the owner's
   decision. Framework, router, charts and the plain-CSS architecture stay.
9. **Visual verification is a gate, not a report.** H.0 defines the mandatory baseline, final
   screenshot sets, viewports, human inspection and pass criteria; a phase is not complete until it
   passes them.

---

## A. Executive design direction

**Identity: an operations terminal, not a dashboard.** SentinelSwitch should read as the console an
analyst keeps open on a second monitor: near-black blue-charcoal surfaces separated by hairlines
rather than floating cards, one signal-cyan accent reserved for interaction and selection, and a
strict split between two typefaces — a humanist UI face for prose and labels, a monospace face for
every identifier, address, timestamp, interface and transcript. Severity and response state are
carried by a small, fixed vocabulary of chips that always pair a colour with a word and, for the
response ledger, an icon.

**Why it suits the product.** The distinctive data in SentinelSwitch is *technical and chained*: IP →
DHCP binding → MAC → MAC table → port → VLAN → identity, and detect → authorize → execute → verify →
restore. A terminal-inspired treatment makes those chains the hero: monospace tokens line up, hairline
rails connect stages, and the switch front panel and IOS console stop looking like guests from
another product. The 2.0 assurance layer (PASS / FAIL / UNKNOWN / STALE with explicit denominators)
is served by the same discipline: counts are typeset as ratios, never as decorative gauges.

**What will make it distinctive rather than generic.**

1. A *response ledger* on every incident: seven fixed stages with timestamps and the authorization
   record in the middle, so "who allowed this and when" is the centre of the page.
2. The *attribution trace*: the chain is drawn as connected evidence with explicit
   confirmed / fallback / conflict / missing states (data already exists in `attribution.steps`).
3. A real *IOS console* with a prompt, command history and completion of the allowed `show`
   commands, replacing today's `<select>`.
4. Flat surfaces and hairlines instead of bordered, shadowed, rounded cards; one radius for
   controls (4 px) and one for panels (6 px); a faint 24 px engineering grid on the canvas only.
5. A header that reports *connection state honestly* (connected / stale / unavailable) from the
   SSE stream and the last successful fetch, with no fake "LIVE" badge.

What it deliberately is not: no neon outlines, no scanlines, no typing animations, no counters that
tick, no glassmorphism, no gradients beyond a single area-chart fill.

---

## B. Current-state audit

### B.1 Framework and styling architecture [source]

| item | fact |
| --- | --- |
| Framework | React 19.2, TypeScript ~6.0, Vite 8.3, react-router-dom 7, Recharts 3; linted with oxlint; built with `tsc -b && vite build` (`frontend/package.json`) |
| Entry | `frontend/src/main.tsx` imports `styles/base.css` and `styles/components.css`; `App.tsx` mounts `/media/:slug` (standalone media cards) and `/*` → `Shell` |
| Styling | three plain CSS files: `styles/tokens.css` (32 lines of custom properties), `styles/base.css` (177 lines: reset, shell, chips, grids, cards, tables, controls, drawer, misc), `styles/components.css` (170 lines: chain, timeline, switch panel, features, matrix, media cards, assurance chips). No CSS modules, no utility framework |
| Dead file | `frontend/src/index.css` is the untouched Vite template (light theme, purple accent, `#root { width: 1126px; text-align: center }`). It is not imported anywhere; delete it |
| Design tokens | colours, two font stacks (system; no bundled fonts, `frontend/public` holds only `favicon.svg`), two radii (6 / 10 px), one shadow, `--sidebar-w: 224px`, `--topbar-h: 52px`. No spacing, type-scale or z-index tokens |
| Token bug | `components.css:146` uses `var(--text-3)`, which is not defined in `tokens.css`; `.chip.RETIRED` therefore falls back to inherited colour |
| Data access | `lib/api.ts` (743 lines): typed `endpoints.*` over `fetch`; `lib/hooks.ts`: `useApi(loader, deps)` with request sequencing and a `fresh` flag, refetch on SSE events of kinds `state`, `incident`, `alert`, `validation`, `assessment`, `finding` (matches the backend publishers in `api/routes.py` and `api/assurance_routes.py`). `useLocalState` for per-viewer preferences |
| Shared components | `components/ui.tsx`: `Card`, `Kpi`, `Chip`, `Sev`, `Ts`, `Empty`, `Loading`, `Term`, `KV`, `Tabs`, `Drawer`; `Chain`/`Steps`, `Timeline`, `Features`/`Confidence`, `SwitchPanel`/`PortLegend`, `Logo` (`Mark`, `Wordmark`), `Icons` (15 inline SVG icons), `charts/index.tsx` (4 Recharts wrappers + `Legend`) |
| Pages (16) | Posture `/`, Controls `/controls[/:id]`, Findings `/findings[/:id]`, Incidents `/incidents`, IncidentDetail `/incidents/:id`, Reports `/reports`, Overview `/operations`, Alerts, Devices `/devices[/:hostname]`, Switch, Authentication, Coverage, Drift, Evidence `/evidence[/:id]`, About, Media `/media/:slug` |
| Tests | backend: 82 pytest tests (`backend/tests`), none render the frontend. Frontend: no test runner is installed; `tsc -b` and `oxlint` are the only checks |
| Screenshot workflows | `scripts/screenshots.py` starts its own server on a temp DB and captures: 11 dashboard views (`assets/screenshots`), 4 README images and the hero (`assets/github`), 7 LinkedIn cards from `/media/<slug>` (`assets/linkedin`), branding, and the 2.0 artifact set (`artifacts/sentinelswitch-2.0/screenshots`, 13 files, viewport 1600×1000 @2×). It waits on the selector `.content` and on `#media-root:not([data-loading])`; `make screenshots` / `make screenshots-2` wrap it |
| Behavioural docs | `docs/containment.md` (authorization record, analyst decisions, verification failure), `docs/controls.md` (states, freshness, lifecycle), `docs/workflow-2.0.md`, `docs/demo-guide.md`, README "The dashboard" (names the Assurance / Operations groups) |
| Hosted vs local | `https://sentinelswitch.onrender.com/api/meta` reports version 2.0.0, demo stage `baseline`; Render deploys `main` at `197f2a6`, the same commit audited here. No divergence found. The hosted instance sleeps when idle and all visitors share one state |

### B.2 Specific visual and structural defects

Metrics come from the audit script in Appendix 1 (also what produced the numbers below).

**Shell and responsiveness [rendered]**

1. Every route overflows horizontally on a 390 px phone by 261–319 px (`document.scrollWidth − clientWidth`). Cause [source]: `.topbar` (`base.css:54–62`) is a non-wrapping flex row holding crumbs, the simulation chip, the stage chip, "SW01 reachable" and the clock; plus tables with `white-space: nowrap`.
2. Below 900 px the sidebar is simply made `position: relative` (`base.css:173–177`), so the full 14-item navigation renders *above* the content: on the phone the first page content starts about 700 px down (see `mobile__*` captures).
3. Between 900 and 1100 px the 224 px sidebar stays fixed and two-column grids collapse, leaving a 776 px content column where 10–13 column tables (`/controls`, `/incidents` review queue, `/alerts`, `/authentication`) scroll inside their card: 287, 125, 467 and 691 px of hidden width respectively at 1024 px.
4. At 1440 px `/alerts` is still 219 px wider than the viewport (9 columns, `minWidth: 300` on the signature column, `Alerts.tsx:81`); `/controls` 85 px (13 columns, `Controls.tsx:81`).
5. Focus is the browser default only (`outline: auto 1px` observed); there is no `:focus-visible` rule, no `prefers-reduced-motion` rule, and `@keyframes pulse` (`base.css:170`) has no selector that uses it, so the `pulse` class set by `SwitchPanel.tsx:28` does nothing.

**Typography [rendered + source]**

6. 18 distinct font sizes are in use at 1440 px (6.5, 7, 8.5, 9.24, 9.52, 10, 10.5, 11, 11.5, 12, 12.5, 13, 14, 15, 15.4, 20, 22, 26 px). The switch front panel labels are 6.5 px (`components.css:71`), the sidebar subtitle computes to 9.5 px (`Logo.tsx:22`), nav section labels and badges are 10 px (`base.css:42,50`), KPI hints 11 px on `--faint` (contrast ≈ 2.9:1).
7. Hierarchy is flat: page `h1` is 20 px, card titles 13 px, and `h3` is redefined as an 11 px uppercase label (`base.css:21`, which also declares `font-size` twice). The result is that the page title, a card title and a column header differ by a few pixels and weight only.
8. Every page opens with 2–3 lines of explanatory prose under the title (`page-head p`), which reads as documentation embedded in the tool and pushes the first data below 120 px on every screen.

**Surfaces and components [source + rendered]**

9. Seven border radii in use (2, 3, 4, 5, 6, 10 px, 50 %); cards are 10 px with a drop shadow (`base.css:91`), chips 4 px, buttons 6 px, ports 2.5 px, status bars 5 px.
10. Hard-coded colours bypass the tokens: in CSS `#ff8a80` ×12, `#f0c36b` ×10, `#7ee2a8` ×7, plus 20 other literals; in TSX `Posture.tsx` (`SWATCH`, `INK`), `Controls.tsx` (`Count` tones), `Incidents.tsx:107`, `Overview.tsx:70`, `Authentication.tsx:27`, `charts/index.tsx` (21 literals), `SwitchPanel.tsx` (23 literals), `About.tsx:19,66`.
11. Inline `style={{…}}` is the primary layout mechanism on the new pages: 41 sites in `Posture.tsx` producing 416 inline-styled DOM nodes on `/`, 25 in `Controls.tsx`, 24 in `Findings.tsx`, 12 in `IncidentDetail.tsx`. Grid templates (`Posture.tsx:181,195,229,377`), clamps, ellipsis and colours all live in page code, so the same pattern is re-implemented per page.
12. The chip vocabulary is overloaded and inconsistently cased: `.chip.open` and `.chip.contained` are both red, `.chip.closed` green, `automatic_containment` red (looks like an error), `rejected` neutral; labels render as `PASS`, `Verified`, `review`, `Access-Accept` side by side (`ui.tsx:38–44`, `base.css:68–80`, `components.css:142–152`).
13. KPI tiles dominate the first screen with low information density: 9 tiles on `/operations` (`grid kpis nine`), 6 on `/reports` and `/controls`, 5 on `/authentication` and `/coverage`, 4 on `/drift`; each tile is a bordered, shadowed card ~110 px tall.
14. `Kpi` on `/operations` colours "802.1X success" green unconditionally (`Overview.tsx:62`) and `Posture` colours the determinate pass rate green at 100 % even when coverage is low (fixed partially in `Posture.tsx:184`); tone rules are per page, not per component.
15. `Loading` is the bare text "Loading…" and the error copy says "Is the API running? (make dev)" (`ui.tsx:61–62`): developer-facing text that visitors of the hosted demo can see.
16. `Drawer` (`ui.tsx:109–120`): fixed 520 px, no Escape handling, no focus trap, close button is a literal `✕`; drawers are used for alerts, devices, assessments and validation rows.
17. Clickable table rows are `<tr onClick>` with no `tabIndex`, `role` or key handler (`Alerts.tsx:78`, `Controls.tsx:87,188`, `Findings.tsx:107`, `Devices.tsx:59`, `Coverage.tsx:50`): not reachable by keyboard.
18. Consequential actions execute on a single click with a hard-coded actor and note: "Approve containment" / "Reject" (`Incidents.tsx:99–100`), "Release containment" (`IncidentDetail.tsx:59`), "Remediate" (`Findings.tsx:289`), "Reset to baseline" and "Replay flagship incident" (`Overview.tsx:46–52`), "Run assessment", "Re-run validation". There is no confirmation dialog component in the codebase.
19. The incident header is six equal KV cards in an `auto-fit minmax(150px)` grid (`IncidentDetail.tsx:68–75`): endpoint, addresses, switch, VLANs, times and authorization all carry the same visual weight, exactly the pattern the brief rules out.
20. The IOS console is a `<select>` plus a "run" button (`Switch.tsx:48–53`); output is a `pre.term` without a prompt line, scroll region or history.
21. `/evidence` shows `README.md` and JSON artifacts as raw text in `pre.term` inside a 220 px + 1fr grid of ad-hoc buttons (`Evidence.tsx:48–60`).
22. `/reports` leads with a paragraph of prose, six KPI tiles and a 720 px iframe; the actions (Generate, Open HTML, JSON, PDF) are in the page header but their result lives in a separate "Generated artifacts" card.
23. The header's "SW01 reachable" is true whenever `/api/meta` succeeded once (`App.tsx:97–104`); SSE connection state is never surfaced, so a dropped stream or a sleeping Render instance is indistinguishable from "connected".
24. `.media` card styles (`components.css:97–138`) share every component with the dashboard; any component change alters the seven LinkedIn cards, the README images and the hero. They must be regenerated and re-reviewed as part of the redesign.

**Things that are already right and must be kept [source]**

- One SSE stream, request sequencing with the `fresh` flag, and per-filter loading rows (the stale-rows bug is fixed).
- No console errors and no failed requests on any route at any viewport [rendered].
- Posture semantics: UNKNOWN / STALE never counted as a pass, retired rows excluded, explicit denominators (`Posture.tsx`, backend `posture.py`).
- The switch front panel is accurate (48 + 2 ports, state classes, protected lock glyph) and clickable.
- Chip CSS exists for every lifecycle value the backend emits.

### B.3 Functional and technical risks

| risk | why it matters | mitigation in this plan |
| --- | --- | --- |
| Media cards regress silently | `/media/<slug>` reuses dashboard components; `make screenshots` would commit changed PNGs under `assets/` | Phase 5 regenerates and reviews all media; media CSS moves to its own file and keeps its own density overrides |
| `scripts/screenshots.py` depends on `.content` and `#media-root` | a shell rewrite that renames `.content` breaks `make screenshots` | keep `.content` on the main element (or update the script in the same commit) |
| Route change for the home page | README, `docs/demo-guide.md`, `scripts/screenshots.py` and the portfolio package name `/` as Posture and `/operations` as SOC Overview | treated as an explicit decision in A/I; all four places are updated together |
| Behaviour must not change | authorization, policy, assessment and remediation live in the backend; the UI only calls `endpoints.*` | the preservation checklist (G) and the existing 82 tests; no `api.ts` endpoint signature changes |
| Font bundling | the only proposed dependency | optional; the system stack remains the fallback |

### B.4 Limitations of this inspection

- Rendering was Chromium-only (Playwright). Safari and Firefox were not exercised.
- The 390 px run used viewport emulation, not a device; touch targets were measured geometrically (`< 44 px` tall buttons counted) but not tapped.
- Keyboard checks were limited to tabbing three times on `/` and reading the focused element's computed outline; a full tab-order walk is part of the QA plan, not of this audit.
- The hosted instance was checked through its API only; its rendered UI is the same build as local and was not screenshotted separately.
- Baseline ("before") screenshots exist only in the session scratchpad; they are reproducible from this commit with Appendix 1.

---

## C. Proposed design system

All values are concrete and are meant to land in `tokens.css` as custom properties. Names are new;
existing names are kept as aliases during migration (see E).

### C.1 Colour

Dark, cool-neutral, flat. One accent. Semantic colours are the only saturated surfaces besides the accent.

| token | value | role |
| --- | --- | --- |
| `--bg-0` | `#0a0d12` | application canvas (behind everything; carries the faint grid) |
| `--bg-1` | `#0e1218` | sidebar, topbar, drawers, dialogs |
| `--surface-1` | `#121820` | panels (default work surface) |
| `--surface-2` | `#171f29` | inset areas: table headers, inputs, terminal backdrops, nested rows |
| `--surface-3` | `#1d2733` | hover, selected row, active segment |
| `--line-1` | `#1f2a36` | hairlines between panels and rows |
| `--line-2` | `#2e3b4b` | control borders, focused panel edge |
| `--text-1` | `#e6edf3` | primary text (contrast on surface-1 ≈ 13:1) |
| `--text-2` | `#b3c0cf` | secondary text (≈ 8:1) |
| `--text-3` | `#8391a3` | muted labels, hints (≈ 5.2:1; this also fixes the missing `--text-3`) |
| `--text-4` | `#56657a` | decorative only: tick marks, rules, disabled (≈ 2.9:1; never for information) |
| `--accent` | `#39c5d6` | links, active nav, primary buttons, selection rails, SPAN state. Kept from the existing brand mark so the logo, favicon and media stay coherent |
| `--accent-strong` | `#5fd8e6` | hover/active accent, focus ring (2 px, offset 2 px) |
| `--accent-dim` | `rgba(57,197,214,.12)` | selected-row and primary-button fills |
| `--ok` / `--ok-ink` | `#3fb950` / `#7ee2a8` | pass, verified, contained-and-verified, Access-Accept |
| `--warn` / `--warn-ink` | `#d29922` / `#f0c36b` | stale, review, pending authorization, medium severity |
| `--danger` / `--danger-ink` | `#f85149` / `#ff8a80` | fail, high/critical severity, quarantined, containment failed |
| `--info` / `--info-ink` | `#58a6ff` / `#8ec3ff` | low severity, trunk/protected, informational |
| `--withheld` / `--withheld-ink` | `#a371f7` / `#c9a8ff` | "withheld by policy" and analyst-rejected: deliberately not green (nothing was contained) and not red (nothing failed) |
| chart series | `--chart-1 #3987e5`, `--chart-2 #2f9e4f`, `--chart-3 #e05a5a`, `--chart-4 #c99420`, `--chart-5 #31a0b0`, `--chart-grid #263241`, `--chart-axis #7d8b9c` | read by `charts/index.tsx` through `getComputedStyle` once at module load, so Recharts stops carrying hex literals |

Rules: severity and response status are never colour-only — every chip carries its word, and the
response ledger adds a glyph (✓ verified, ◌ pending, ⊘ withheld, ✕ failed) rendered as inline SVG,
not emoji. `--text-4` is reserved for ornament. No gradients except the single area-chart fill
(`--chart-1` at 22 % → 2 %). No glass, no blur.

### C.2 Typography

- UI face: `--font-ui: "Inter Variable", Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif`.
- Mono face: `--font-mono: "JetBrains Mono Variable", "JetBrains Mono", "SF Mono", ui-monospace, Menlo, Consolas, monospace`.
- **Dependency decision [assumption]:** self-host both faces with `@fontsource-variable/inter` and
  `@fontsource-variable/jetbrains-mono` (two npm packages, ≈ 330 KB of woff2 shipped from the app's
  own origin, no network calls, no icon fonts). Justification: the hosted demo runs on Linux Chromium
  where the current stack falls back to Liberation/DejaVu, so the portfolio and the live link do not
  look alike. If the owner declines, the stacks above degrade to system fonts with no other change.
- Type scale (px / line-height / weight), exactly eight sizes, exposed as `--fs-*`:

| token | size | use |
| --- | --- | --- |
| `--fs-xs` | 11 / 1.4 / 500 | eyebrow labels, column headers, chip text. Minimum size for any informational text; nothing below 11 px outside the switch SVG |
| `--fs-sm` | 12 / 1.45 / 400 | dense table cells, hints, mono identifiers in tables |
| `--fs-md` | 13 / 1.5 / 400 | body, KV values, nav items |
| `--fs-lg` | 14 / 1.4 / 600 | panel titles, drawer titles, tab labels |
| `--fs-xl` | 16 / 1.35 / 600 | section titles inside a page, incident title on tablet |
| `--fs-2xl` | 20 / 1.25 / 600 | page title |
| `--fs-3xl` | 28 / 1.1 / 600, tabular-nums | metric values |
| `--fs-4xl` | 36 / 1.05 / 600, tabular-nums | hero ratio on Posture and Overview only |

- Mono sizes: 12 px in tables and KV, 12.5 px in terminals (line-height 1.55), 11 px only inside
  chips. Timestamps are always mono with `font-variant-numeric: tabular-nums`.
- Uppercase is allowed only at `--fs-xs` with `letter-spacing: .06em` for eyebrow labels and column
  headers. Never uppercase data, chip values that are identifiers, or anything above 12 px.
- Sidebar subtitle, nav section labels and badges move to 11 px; the switch SVG keeps its own
  internal scale but port numbers rise from 6.5 px to 8 px in a 1000-unit viewBox and the panel is
  given more width (D.9).

### C.3 Layout and spacing

- Spacing scale `--sp-1…--sp-8` = 4, 8, 12, 16, 20, 24, 32, 40 px. No other margins/paddings.
- Shell: sidebar `--sidebar-w: 232px` (expanded), `--rail-w: 56px` (icon rail), topbar `--topbar-h: 48px`.
- Content gutter `--gutter: 24px` ≥ 1200 px, 16 px at 900–1199, 12 px < 900. Content max width 1760 px, centred (no stretched tables on 4K).
- Panel padding 12 px 16 px; panel header 40 px tall; table cells 8 px 12 px (default) / 6 px 10 px (compact density, a per-viewer preference stored with `useLocalState`).
- Grid primitives (classes, not inline styles): `.grid-2`, `.grid-3`, `.grid-main-rail` (`minmax(0,1fr) 340px`), `.grid-rail-main`, `.grid-metrics` (`repeat(auto-fit, minmax(140px, 1fr))`), each with its ≤ 1199 px and ≤ 899 px collapse rules in `base.css`.
- Alignment rules: page title, toolbar buttons, metric labels and the first table column share the same left edge (the gutter); panel headers are 40 px with title left and controls right; section eyebrows sit on a 24 px rhythm; numbers right-align in `.num` cells; chips inside tables are vertically centred at 20 px height.
- Radii: `--r-ctl: 4px` (chips, inputs, buttons, ports, tooltips), `--r-panel: 6px` (panels, drawers, dialogs, terminal). Nothing else.
- Elevation: panels are flat (`1px solid var(--line-1)`, no shadow). Shadow only on drawers, dialogs and menus: `0 12px 40px rgba(0,0,0,.55)`.
- Canvas texture: `--bg-0` with a 24 px grid drawn by two `linear-gradient`s at 3 % white, applied to `.content` only (not to panels, drawers, media cards or print).

### C.4 Component system (shared, one implementation each)

| component | file (new unless noted) | specification |
| --- | --- | --- |
| `Shell`, `Sidebar`, `Topbar` | `components/layout.tsx` | persistent sidebar with brand, two nav groups, attention badges, footer; rail mode and off-canvas mode; topbar with page title/crumbs, environment identity, connection state, simulated clock, stage chip |
| `PageHeader` | `layout.tsx` | title (`--fs-2xl`), optional identifier row (chips), one-line subtitle, right-aligned toolbar; the long explanatory paragraphs move into an `Info` popover (an "i" icon button) so the first data starts within 88 px of the topbar |
| `Section` | `layout.tsx` | eyebrow label (`--fs-xs` uppercase with a 2 px accent tick), optional count and right slot; replaces ad-hoc `h3 style={{marginBottom}}` |
| `Panel` | `ui.tsx` (replaces `Card`) | flat surface; `title`, `sub`, `right`, `padding: 'default' \| 'none'`; variants `inset` (surface-2) and `rail` (for the context rail). `Card` stays exported as an alias during migration |
| `Metric`, `Ratio` | `components/metric.tsx` (replaces `Kpi`) | `Metric`: label, value (`--fs-3xl`), unit, hint, `tone` resolved from a rule passed by the page (`good \| warn \| danger \| neutral`). `Ratio`: numerator / denominator with the denominator always visible and a 6 px status bar; used for coverage and pass rate so no percentage appears without its fraction |
| `StatusChip`, `SeverityChip`, `ResponseChip`, `AssessChip` | `components/status.tsx` | one `Chip` primitive with explicit `tone` + text + optional glyph; four thin wrappers map backend vocabularies to tones: severity (high/critical → danger, medium → warn, low/info → info); assessment (PASS ok, FAIL danger, UNKNOWN neutral, STALE warn, RETIRED outline-dashed, NOT_ASSESSED outline); finding lifecycle (open/reopened/remediation_failed danger, remediation_requested/remediated warn, verified ok, closed neutral); response (see D.4). Labels are rendered as given by the backend, lower-case for lifecycle words, upper-case only for PASS/FAIL/UNKNOWN/STALE and the response ledger states |
| `Id`, `Mono` | `status.tsx` | `Id` renders identifiers (INC-, FND-, ASM-, ASR-, WF-, DET-, DRIFT-) in mono with consistent size and an optional link; `Mono` for MACs, IPs, interfaces, commands |
| `Button`, `IconButton` | `ui.tsx` | tones `primary` (accent fill), `secondary` (surface-2 + line-2), `consequential` (warn outline; opens a dialog), `destructive` (danger outline; opens a dialog), `ghost`; sizes `md` 32 px and `sm` 26 px; always `:focus-visible` ring |
| `Tabs` | `ui.tsx` (existing) | keyboard arrows, `role="tablist"`, underline in accent |
| `SearchInput`, `Select`, `Segmented` | `ui.tsx` | 32 px tall, surface-2, line-2; `Segmented` gets `role="radiogroup"` |
| `DataTable` | `components/table.tsx` | wraps `table.data`: sticky header, `density`, `rowLink`/`onRowActivate` with `tabIndex=0`, Enter/Space activation and `aria-selected`; built-in loading row, error row, empty row; column definitions carry `minWidth`, `align`, `wrap`, `priority` (columns with priority ≥ 2 are hidden below 1200 px and moved into the row's drawer) |
| `Timeline` | existing, restyled | 92 px mono time column, 2 px rail, phase dots use tokens; optional date divider rows |
| `Trace` (attribution) | `components/trace.tsx` (replaces `Chain` + `Steps`) | horizontal on ≥ 1200 px, vertical below; each node has label, mono value, source line and a state glyph (confirmed / fallback / conflict / missing / skipped from `Step.status`) so inferred data is visibly different from confirmed |
| `ResponseLedger` | `components/ledger.tsx` | seven fixed stages with timestamp and state (D.4); drives the incident header |
| `ConfirmDialog` | `components/dialog.tsx` | `<dialog>`-based modal: title, consequence summary (what changes on which port/VLAN), optional editable note, an actor line only for actions that record an actor, Cancel + confirm button in the tone of the action; focus trapped, initial focus and Escape/Enter rules per D.4, focus restored to the opener on close |
| `Drawer` | `ui.tsx` (existing, fixed) | widths 520 / 100 vw on mobile, Escape closes, focus moves in and returns, close icon from `Icons` |
| `Terminal`, `Console` | `components/terminal.tsx` | `Terminal`: output block with prompt colouring, highlights, max height + scroll, copy button. `Console`: prompt input with history (↑/↓, kept in component memory for the session only), completion limited to `data.commands` from `/api/switch` (the server's `SHOW_COMMANDS`) plus the interface-scoped `show … interface <selected port>` templates the page already offers; the typed string is sent unchanged through `endpoints.show` to the existing `GET /api/switch/show`, which enforces the `show` prefix; the client never interprets, rewrites or executes commands and no new endpoint is added; errors (HTTP 400 for non-`show` input) print in the terminal, not as a toast |
| `Toast` | `components/toast.tsx` | bottom-right, 4 s, used for "report generated", "assessment run", action results; never for errors that belong inline |
| `Loading`, `Skeleton`, `ErrorState`, `Empty` | `ui.tsx` | skeleton rows for tables/panels; `ErrorState` copy without developer hints ("The API did not respond. Retry.") with a Retry button; `Empty` with a one-line reason |
| `Charts` | `charts/index.tsx` (existing) | colours from tokens; a shared `ChartFrame` with fixed heights 180/220; axis font 11 px |
| `SwitchPanel` | existing | state colours via CSS classes only (remove the 23 literals), port label 8 units, `aria-label` per port, keyboard focusable ports (`tabIndex`, Enter) |

### C.5 Motion and interaction

- Durations: 120 ms (hover/focus), 180 ms (drawer/dialog open, tab underline), 240 ms (sidebar collapse). Easing `cubic-bezier(.2,.8,.2,1)`.
- `@media (prefers-reduced-motion: reduce)`: all transitions and the single pulse animation are disabled; the design must read identically.
- The only animation on data: a port whose state just changed pulses its LED **once** (600 ms) after an SSE `incident`/`state` event; no continuous blinking anywhere.
- No typing effects, no counters, no fake activity. Loading states are skeletons, not spinners that imply traffic.
- Focus ring: 2 px `--accent-strong` with 2 px offset on every interactive element, including table rows and ports.

---

## D. Page-by-page redesign

Format per page: purpose · existing problems · hierarchy · arrangement · prominent / secondary ·
responsive · states · preserved interactions · dependencies and risks.

### D.0 Information architecture and shell [assumption, recommended]

- **Sidebar, persistent.** Fourteen destinations in two groups do not fit a top bar, and the existing
  mental model (Assurance vs Operations) is documented in the README. Keep a left sidebar: expanded at
  ≥ 1200 px, an icon rail with tooltips at 900–1199 px, and an off-canvas drawer opened by a menu
  button below 900 px.
- **Home route.** Make `/` the operational **Overview** (today's `/operations` redesigned, D.1) and
  move the assurance **Posture** page to `/posture`. `/operations` redirects to `/`. Rationale: the
  first screen should answer "what needs me now" (open review, contained incidents, failing controls)
  and then let the analyst drill into posture; the current home is a GRC summary with no alert
  stream. Update together: `App.tsx` routes and `NAV`, `scripts/screenshots.py` (the 2.0 capture named
  `sentinelswitch-2.0-dashboard` must point at `/posture`, the 1.0 `01-overview`/`dashboard-overview`
  captures at `/`), README "The dashboard" and quick-start text, `docs/demo-guide.md`,
  `artifacts/sentinelswitch-2.0/PORTFOLIO-PACKAGE.md`, and `backend/tests/test_api.py` is unaffected
  (it tests the API only).
- **Navigation labels** stay explicit: Overview, Posture, Controls, Findings, Incidents, Reports |
  Alerts, Assets, Switch, Authentication, Coverage, Drift, Evidence, Architecture. "Findings &
  Remediation" becomes "Findings" with the badge; the description moves to the page info popover.
- **Topbar content (left → right):** page title with crumb for detail routes · environment identity
  (`org.name · SW01`) · stage chip (baseline / INC-2026-0042 contained / resolved, from `meta.demo`) ·
  connection state · simulated clock. The "Simulation · synthetic telemetry" chip moves into the
  sidebar footer and the info popover; it stays visible on every screen but stops competing with
  operational status.
- **Connection state** (frontend-only, `hooks.ts`): expose `{status: 'connected'|'stale'|'unavailable', lastEventAt, lastFetchAt}`. Connected = EventSource `OPEN` and a successful fetch in the last 60 s; stale = EventSource `CONNECTING` or no successful fetch for 60 s; unavailable = the last fetch failed. Shown as dot + word; never "LIVE".
- **Attention badges** in the sidebar: Incidents = contained count, Findings = open findings, Reports none. Add a review-queue badge on Incidents when `meta.counts.reviews_open > 0` (the field exists in `/api/meta`, served from `store.counts()`).

**Route contract (required).** Every route below must resolve after the redesign; the "renders" column is the page it must show.

| route | renders | note |
| --- | --- | --- |
| `/` | Overview (D.1) | new home; `NavLink` for it must use `end` so it is not active on every path |
| `/posture` | Posture (D.2), the complete current `/` page | sidebar entry "Posture"; also linked from the Overview control-status rail |
| `/operations` | redirect to `/` (`<Navigate replace>`) | kept permanently for existing links and docs |
| `/controls`, `/controls/:id`, `/findings`, `/findings/:id` (+ `?view=all`), `/incidents`, `/incidents/:id`, `/reports`, `/alerts`, `/devices`, `/devices/:hostname`, `/switch`, `/authentication`, `/coverage`, `/drift`, `/evidence`, `/evidence/:id` (+ `?file=`), `/about`, `/media/:slug` | unchanged | query parameters keep their meaning |

Links and active states to update with the route change: `App.tsx` `NAV` and the topbar `current` lookup (it uses `startsWith`; `/` needs an exact match); in-app links that point at `/` meaning Posture (`Posture.tsx` has none, but `Reports.tsx`, `Controls.tsx`, `Findings.tsx` link to `/findings`, `/controls` and `/evidence` — unchanged); README "The dashboard" and "Quick start"; `docs/demo-guide.md` walkthrough; `artifacts/sentinelswitch-2.0/PORTFOLIO-PACKAGE.md`; `scripts/screenshots.py` (`PAGES`, the README set and `capture_2` route list). The screenshot named `sentinelswitch-2.0-dashboard.png` keeps showing the Posture page (captured from `/posture`) so the portfolio package stays truthful.

**Capability inventory (every item must survive, possibly relocated).**

| page | capabilities that must remain |
| --- | --- |
| Overview | replay flagship incident; reset to baseline; alert timeline; bytes/connections toggle; recent alerts, recent authentication and containment activity tables with their links |
| Posture | run assessment; ratios with definitions; four-state counts and status bar; outcomes by category; open findings table with "more" link; control status rail with links; assets with open findings; unverified assessments; recent runs; recently closed; CSF mapping with caveat; scope note; retired-results note |
| Controls | run assessment; catalog table with freshness, CSF ids, outcome counts, status, row navigation; control detail with definition, remediation, limitations, current result, assessments table, findings table; assessment drawer with expected/observed, evidence, freshness, source of truth, related incidents, remediation, history |
| Findings | open-only/all segmented control (`?view=all`), severity and status filters, fresh-flag loading row; detail with facts, expected/observed, evidence, freshness, related incidents, framework mapping, remediation guidance and commands, request/execute/verify record, transcript, Remediate action, result notice, events timeline with transcripts, assessment history |
| Incidents | incidents table; manual review queue with approve/reject and per-row errors; links to incidents and devices |
| Incident detail | release containment; evidence bundle link; header chips; correlation chain and steps; five tabs with all their content including the policy-evaluation read of `containment.json` |
| Reports | generate; open HTML; JSON; PDF (disabled until generated); artifact paths and counts; document facts; preview iframe; schema table; evidence bundle list; limitations |
| Evidence | bundle list; per-file viewer selected by `?file=`; open-incident link |
| Alerts | search; severity/source/status filters; row drawer with detection features and raw record |
| Assets | search; VLAN filter; unregistered devices table; device drawer with interface, incidents, alerts, authentication |
| Switch | front panel with port selection; port detail with running-config; IOS console (show commands); VLANs; configuration changes; logging buffer |
| Authentication, Coverage, Drift, Architecture | all current tables, charts, re-run validation, validation row drawer |
| Media | every `/media/<slug>` card and the hero render and are captured by `scripts/screenshots.py` |

**Overview data mapping (every number on the new home, with its exact meaning).**

| element | source field | meaning as served |
| --- | --- | --- |
| awaiting authorization | `/api/reviews` rows with `status === 'review'` | detections policy routed to manual review and no analyst decision yet |
| contained hosts | `/api/overview.kpis.quarantined_hosts` | ports in VLAN 50 or under administrative hold on the twin |
| open incidents | `/api/overview.kpis.open_incidents` | incidents in `contained` or `containment_failed` |
| open findings | `/api/posture.findings.open` | lifecycle states `open`, `reopened`, `remediation_requested`, `remediated`, `remediation_failed` |
| unverified assessments | `/api/posture.totals.unknown + .stale` | UNKNOWN plus STALE; labelled "unverified", never "failing" |
| coverage, determinate pass | `/api/posture.totals.*` with `definitions.*` as hints | as computed by the backend; never recomputed client-side |
| telemetry freshness | `/api/assessments?control_id=CTL-TELEMETRY-FRESH` | the latest assessment per source; labelled "as of run <run_id> at <assessed_at>"; `suricata` shows UNKNOWN with its explanation |
| response rows | `/api/overview.containment_activity` | `ResponseChip` from `status` + `verification` per D.4 |
| metrics band | `/api/overview.kpis` | same hints as today, "simulated clock" stated on MTTD/MTTC |

### D.1 Overview (`/`, today's SOC Overview)

- **Purpose.** The analyst's first screen: what needs a decision, what is contained, what the telemetry looks like, and how healthy the controls are.
- **Problems [rendered/source].** Nine equal KPI tiles; the review queue (the one thing waiting for a human) is not on the page at all; posture is absent; the demo controls ("Replay flagship incident") sit in the page header like ordinary actions (`Overview.tsx:44–54`).
- **Hierarchy.** (1) Attention strip → (2) incident and alert stream → (3) posture and telemetry health → (4) activity.
- **Arrangement.**
  - Row 1, *Attention strip* (full width, surface-2 inset): four compact cells with counts and a verb: "1 detection awaiting authorization → Review", "1 host contained → Incident", "5 open findings → Findings", "2 unverified assessments → Posture". Sources: `/api/reviews` (status `review`), `/api/overview.kpis.quarantined_hosts`/`open_incidents`, `/api/posture.findings.open`, `/api/posture.totals.unknown+stale`. Cells with 0 render muted, never hidden.
  - Row 2, `.grid-main-rail`: left *Security activity* panel with the alert timeline (keep `AlertTimeline`) over a compact "Recent alerts" table (time · severity · signature · source · incident link); right rail: *Response* (containment activity rows with `ResponseChip`), then *Devices by VLAN* bars.
  - Row 3, `.grid-main-rail`: left *Network activity* (traffic area with bytes/connections segmented control, kept); right *Control status* mini: `Ratio` coverage, `Ratio` determinate pass, a 6 px status bar, and the top three non-PASS controls as rows linking to `/controls/:id`; below it *Telemetry freshness*: zeek-conn / radius / syslog / suricata with their assessment state (from `/api/assessments?control_id=CTL-TELEMETRY-FRESH`), which is the honest replacement for any "live" indicator. It is a snapshot, not monitoring: the panel eyebrow reads "as of run <run_id> · <assessed_at>", and it is empty with "no assessment run yet" when there is none.
  - Row 4: `Metric` strip (devices online x/36, alerts, high severity, 802.1X success with explicit accepts/rejects, mean time to detect/contain with "simulated clock" in the hint) as a single-height band, not nine cards.
  - Demo controls ("Replay flagship incident", "Reset to baseline") move to a *Demo* control in the topbar's overflow menu and to the Overview toolbar as `consequential`/`destructive` buttons with confirmation dialogs stating what will change.
- **Prominent / secondary.** Attention strip and activity stream are prominent; the metric band and the VLAN bars are secondary; the dataset-day prose goes to the info popover.
- **Responsive.** ≥ 1200: as above. 900–1199: rails stack under their main panels; attention strip 2×2. < 900: attention strip as a vertical list, charts at 160 px height, tables with priority ≥ 2 columns hidden.
- **States.** Loading: skeleton strip + skeleton chart. Baseline (no incident): attention strip shows "0 contained"; response panel shows "No containment actions since the last reset". Error: `ErrorState` with retry. Stale: topbar state only; panels keep data.
- **Preserved.** Replay/reset (same endpoints), bytes/connections toggle, links to alerts, incidents, authentication.
- **Dependencies/risks.** None backend-side; all fields exist. Risk: four requests on one page (overview, posture, reviews, assessments) — acceptable, all cached by the browser and refreshed by SSE.

### D.2 Posture (`/posture`)

- **Purpose.** Evidence-driven control assessment summary: what passed, what failed, what could not be decided, and what is open.
- **Problems.** 416 inline-styled nodes; three grid templates declared in page code; the "Assessment outcomes" panel repeats the KPI tiles; the control list is 12 px text with 10.5 px uppercase category lines; run chip truncates the run id at 320 px.
- **Hierarchy.** (1) Outcome ratio hero → (2) open findings and control status → (3) assets and unverified → (4) history and framework.
- **Arrangement.** Hero band: left, one `Ratio` at `--fs-4xl` for determinate pass (`pass / determinate`) and one for coverage (`determinate / assessments`), each with its definition as hint; right, the four-count row PASS / FAIL / UNKNOWN / STALE on one 10 px status bar with the "1 retired result excluded" note. Below, `.grid-main-rail`: *Open findings* table (DataTable: severity · finding id · scope · result→status · opened · explanation, priority columns) and the *Control status* rail (13 rows: name, category eyebrow, 4-count mono, `AssessChip`). Then `.grid-2`: *Assets with open findings* and *Unverified assessments*. Then *Recent runs* (DataTable) with *Recently closed* beside it, and *NIST CSF 2.0 mapping* collapsed by default under a `Section` with the "documentation aid" caveat visible in the eyebrow.
- **Prominent / secondary.** Ratios, status bar and open findings prominent; CSF and runs secondary; scope note stays as the last line.
- **Responsive.** Rail stacks below 1200; hero becomes two rows below 900.
- **States.** `t.assessments === 0` → empty hero with "Run assessment" primary; run failure inline error (kept); STALE chips always amber with the clock glyph; RETIRED never in totals (kept).
- **Preserved.** "Run assessment" (no dialog: it is a routine, non-destructive workflow step; show a busy state and a toast with the run id and counts, errors inline as today), links to findings/controls, all computed fields and definitions text.
- **Risks.** Must not re-derive any metric in the UI: use `totals`, `definitions`, `by_control` as served.

### D.3 Incident investigation (`/incidents/:id`)

- **Purpose.** Understand one incident quickly: what fired, why, where it is on the network, what the system was allowed to do, what it did, and what the switch says now.
- **Problems.** Six equal KV cards; the correlation chain is above the tabs but the authorization is split between a header card and a tab; response status is a lowercase chip; "Release containment" is an ordinary button.
- **Hierarchy.** (1) Identity line and response ledger → (2) attribution trace → (3) investigation tabs with a context rail.
- **Arrangement.**
  - *Header*: `Id` + title, `SeverityChip`, `ResponseChip`, disposition chip, MITRE technique chips (mono, info tone); toolbar: `Release containment` (consequential → dialog), `Evidence bundle` (secondary).
  - *Response ledger* (full width): Detected `det.ts` → Correlated `att.completed_at` → Identified (device/user) → Recommended (`decision.disposition`) → Authorized (`auth.authorized_at`, `auth.authorized_by`, mode) → Executed (`action.applied_at`) → Verified (`action.verified_at`, read-back ok) → Restored (`action.restored_at`, when present). Each stage shows its timestamp in mono and a state glyph; the elapsed TTD/TTA/TTC appear between stages as small mono deltas (computed exactly as today's `diff()` in `IncidentDetail.tsx:281`).
  - *Ledger derivation rules (exhaustive).* Each stage is driven only by its own field and never by a later stage: Detected ← `detection.ts`; Correlated ← `attribution.completed_at`; Identified ← `incident.device`/`user` (shows "unknown device" or "impersonating <device>" exactly as the incident record says); Recommended ← `incident.disposition` (`automatic_containment` / `manual_review` / `monitor`, plus `analyst_approved`); Authorized ← `incident.authorization ?? action.authorization` — status `authorized` with `authorized_by` and `authorized_at`, `rejected` shown as "declined by <actor>", `pending` as "awaiting decision", and **"not recorded"** when absent; Executed ← `action.applied_at` (absent → "not executed", including `not_applicable` and `refused`, whose `notes` are shown); Verified ← `action.verified_at` **and** `action.verification.ok === true` (`ok === false` → "read-back failed" in danger; `verified_at` absent → "not verified"); Restored ← `action.restored_at` with `restored_by`, shown only when present. A later stage being present never marks an earlier stage complete.
  - *Attribution trace* (`Trace`): IP → DHCP binding → MAC → MAC table → port → VLAN → endpoint, with `Step.status` glyphs; the existing `chainFromAttribution` output feeds it.
  - *Workspace*: `.grid-main-rail`. Main: tabs Timeline · Detections · Decision & authorization · Switch verification · Evidence. Rail (sticky on ≥ 1200): *Endpoint* (device link, user, vendor, OS from `/api/devices/:hostname` is not fetched here — use incident fields only), *Network location* (switch, interface, port class, original → current VLAN with `vlanName`), *Authorization* card (status chip, mode, by, at, basis with soft wrap, guards), *Addresses* (ip, mac, attribution confidence + flags).
  - Decision tab: policy evaluation (factors as KV) left; containment action (workflow, mechanism, VLAN change, requested/applied/verified timestamps, actor, `Terminal` transcript) right — unchanged data, restyled.
  - Switch verification tab: four `Terminal` blocks with the `show` command as the eyebrow (kept).
- **Prominent / secondary.** Ledger and trace prominent; addresses and MITRE secondary; the long summary paragraph becomes two lines with "more" expansion.
- **Responsive.** Ledger scrolls horizontally inside its panel below 1200 with a visible scroll shadow; trace goes vertical; rail stacks under the tabs.
- **States.** `containment_failed`: ledger shows Executed ✓ then Verified ✕ in danger, and the header `ResponseChip` reads "verification failed"; resolved: Restored stage present and header chip "restored". Missing authorization record: ledger stage reads "not recorded" (never implies authorization).
- **Preserved.** Restore endpoint and note semantics, all five tabs, evidence file links, `DecisionView` reading `containment.json`.
- **Risks.** Ledger timestamps must come from the same fields the timeline uses; no new computed metrics.

### D.4 Containment and response safeguards (Incidents `/incidents`, review queue, dialogs)

- **Vocabulary → `ResponseChip` tones (frontend mapping only, data unchanged):**

| state shown | derived from | tone, glyph |
| --- | --- | --- |
| suggested | review `decision.disposition = manual_review`, `authorization.status = pending` | warn, ◌ |
| awaiting authorization | same, listed in the queue with actions | warn, ◌ (also an attention-strip item) |
| authorized | `authorization.status = authorized` and no `applied_at` yet | accent, ● |
| in progress | client-side `busy` while an approve / release / remediate request is in flight; cleared on response | neutral, animated ring only if motion allowed |
| executed · unverified | `action.applied_at` present, `verified_at` absent (`status = applied`) | warn, ◌ — never shown as contained |
| contained · verified | incident `contained`, action `verified`, `verification.ok === true` | ok, ✓ |
| withheld by policy | review rejected or guards withheld automation (`guards_triggered` non-empty, status `closed`/`rejected`) | withheld (purple), ⊘ |
| failed | incident `containment_failed` or `verification.ok = false` | danger, ✕ |
| restored · verified | action `restored` and recovery assessment PASS (incident `resolved`) | ok outline, ✓ |

- **Review queue** (`/incidents`): becomes the top panel ("Awaiting authorization" when any row is `review`), DataTable with: opened · severity · detection · rule · confidence · policy disposition · guards (mono) · authorization · actions. Actions are `Approve containment` (consequential) and `Reject` (secondary) and both open `ConfirmDialog`:
  - Approve: "Quarantine SRV-GIT01 on Gi1/0/12: VLAN 30 → 50. Policy withheld automation because: critical_assets. You are authorizing this as analyst tlee." Note field prefilled with today's default text, editable; confirm button labelled "Authorize and contain".
  - Reject: "Record that containment was declined for DET-…. The switch is not touched." Note prefilled.
  - Errors from the API (409 "no executable containment action") render inside the dialog.
- **Incidents table** below: id · opened · severity · title · endpoint · port · VLAN change · confidence · `ResponseChip`.
- **Precedence when deriving the chip** (first match wins): client `busy` → in progress; `incident.status = containment_failed` or `verification.ok === false` → failed; `action.status = restored` → restored · verified only if the incident is `resolved`, else "restored" (ok outline, no "verified" word); `action.status = verified && verification.ok === true` → contained · verified; `action.status = applied` → executed · unverified; `action.status in (refused, not_applicable)` with guards or a rejected authorization → withheld by policy; `authorization.status = authorized` → authorized; `authorization.status = pending` → awaiting authorization; otherwise → suggested. The helper `responseStateOf(incident, action, review?)` in `ledger.tsx` implements exactly this list and nothing else.
- **Other consequential actions** get the same dialog: Release containment ("Gi1/0/23 returns to VLAN 20; a recovery assessment will run"), Remediate ("These IOS commands will be applied to SW01 through the adapter, then re-assessed" with the command list), Reset to baseline ("Re-seeds the dataset; the current incident and findings history are discarded" — destructive tone), Replay flagship incident ("Replays INC-2026-0042 through the real pipeline; Gi1/0/23 will be quarantined if policy authorizes it").
- **No dialog** for: run assessment, re-run validation, generate reports (busy state + toast + inline error), console commands, drawers, tabs, filters, segmented controls, port selection, report links, "Reload preview", navigation.
- **Dialog behaviour (all dialogs):** native `<dialog>` with `aria-modal="true"` and `aria-labelledby` the title; focus moves to the Cancel button for destructive dialogs and to the note field (or confirm button when there is no note) for consequential ones; Tab cycles inside; Escape cancels and never confirms; Enter submits only non-destructive dialogs; on close, focus returns to the element that opened it; the confirm button is disabled while the request is in flight; the API error renders inside the dialog and the dialog stays open so the user can read it.
- **Never weakened.** The dialog is UI only; the backend still refuses unauthorized execution, protected interfaces and non-review states. The hard-coded demo analyst `tlee` stays (the API requires an actor; there is no identity system). It is displayed only where it becomes part of a record: a single line "Recorded as analyst tlee (demo identity, no sign-in)" in the approve, reject, release and remediate dialogs, and in the existing actor fields of authorization records, finding events and timeline entries. The reset and replay dialogs, the topbar and the sidebar do not mention it.
- **Responsive.** Queue rows below 900 px collapse to a card row: title, chips, two full-width buttons.
- **States.** Empty queue: "No detections are waiting for a decision"; busy row: buttons disabled with the in-progress chip; error per row kept.

### D.5 Network and endpoint attribution (Trace component, Assets, Switch)

- The trace is the product's signature view, so it appears in three places with one implementation: the incident page (horizontal), the alert drawer when a detection has attribution (vertical, compact), and the device drawer (port → VLAN only).
- Each node: eyebrow (SOURCE IP, DHCP BINDING, MAC ADDRESS, MAC TABLE, INTERFACE, VLAN, ENDPOINT, then CONTAINMENT), mono value, source line in `--text-3` mono ("show ip dhcp snooping binding · 21:14:40.092"), state glyph and word from `Step.status` (resolved = confirmed ✓ ok; fallback = inferred ◌ warn; conflict = conflict ! warn; missing = missing ✕ danger; skipped = — neutral). The containment node is danger when quarantined, neutral when none.
- Assets page (`/devices`): DataTable with VLAN filter and search (kept), quarantined devices show `StatusChip quarantined`; the device drawer gains the mini trace and keeps alerts/auth tables.

### D.6 Security posture and GRC (Controls, Findings)

- **Controls catalog** (`/controls`): replace six KPI tiles with the hero band from D.2 in compact form (one `Ratio` + status bar + "13 controls · 209 scopes"). The catalog table drops the 13-column layout: columns control (name + id) · category · scope · severity · freshness · outcomes (status bar + 4 mono counts in one cell) · open · status; CSF ids move into the row's expansion/drawer. Row click → `/controls/:id` (kept).
- **Control detail**: header with id chips (kept); `.grid-main-rail`: assessments DataTable (scope · status · expected · observed · assessed · evidence · finding) main; rail: definition, remediation guidance, limitations, current result bar, CSF list. Assessment drawer kept (Escape/focus fixed), sections become `Section`s rather than nested `Card`s.
- **Findings list**: open-only/all segmented control, severity and status selects (kept, including the `fresh` loading behaviour); DataTable with priority columns; the explanation column wraps at 2 lines with title tooltip.
- **Finding detail**: `.grid-main-rail` where the *Remediation* panel is the main element (guidance, proposed commands `Terminal`, request/execute/verify timeline, transcript, the `Remediate` consequential button → dialog) and the rail holds Finding facts, Expected vs observed, Evidence (with freshness), Related incidents, Framework mapping; events timeline and assessment history below. Verification outcome chip in the header next to the lifecycle chip.
- **Semantics preserved verbatim:** UNKNOWN and STALE are never green or counted; STALE always shows the age ("11 h 38 m old, window 255 min") from `freshness`; RETIRED rows stay dashed-outline and out of totals; failed controls are never hidden by a default filter (the catalog has no filter; findings default to open-only, which is the correct default for a queue).

### D.7 Evidence and reporting (`/reports`, `/evidence`)

- **Reports**: header toolbar = `Generate reports` (consequential dialog: "Writes JSON and HTML under the artifacts directory and renders the PDF when Chromium is available") + `Open HTML` + `JSON` + `PDF` (disabled with reason until generated). Below: an *Artifacts* panel with three rows (JSON · HTML · PDF) each with endpoint, availability chip and, after generation, the path and counts exactly as `POST /api/reports/generate` returns them (`json`, `html`, `pdf`, `assessments`, `findings`) — file sizes and modification times are not provided by the API and are not shown; a *Document facts* KV (generated at, clock basis, generator, scope, reproduce commands); the preview iframe collapsed by default under a `Section` ("Preview") with Open in new tab; the schema table and limitations under collapsed sections. Success/failure of generation as an inline notice in the Artifacts panel plus a toast.
- **Evidence**: left list of bundles as compact rows (id, severity, response chip, artifact count, size); main viewer with a file tab strip (the 11 artifacts) and a `Terminal`-style viewer with wrap toggle and copy; `README.md` rendered as *light* Markdown (headings, lists, code fences, tables) by a ~60-line in-repo renderer rather than a dependency — only the subset the generator emits (`evidence/bundle.py::render_report`); JSON artifacts pretty-printed with the same highlight rules as today. The distinction between original evidence (bundle files), analyst actions (timeline `authorization`/`resolution` entries), remediation evidence (finding transcripts), assessment results and exported reports is made by labelling each panel's source in its eyebrow (e.g., "ORIGINAL EVIDENCE · data/incidents/INC-2026-0042").

### D.8 Alerts, Authentication, Coverage, Drift, Architecture

- **Alerts**: toolbar = search + three selects (kept); DataTable with priority columns (signature and status always visible; dst, device/port hidden < 1200), max height to viewport; drawer restyled with the trace.
- **Authentication**: one metric band (success rate with accepts/rejects, guest fallbacks, events) replacing five tiles; `.grid-main-rail`: results per hour + recent records table main; methods, VLAN assignments, most rejected identities as three small bar panels in the rail. Colours from tokens.
- **Coverage**: metric band (9/9 with "8 contained · 1 withheld by policy", MTTD, MTTA, MTTC, end-to-end); validation DataTable with `ResponseChip` in the Response column (CONTAINED ok / WITHHELD purple / FAIL danger) so the withheld scenario is never shown as a containment; rules tables below; drawer kept.
- **Drift**: metric band; findings DataTable where `recommendation` renders in a `Terminal` cell with a copy button; approved deviations shown with an ok outline chip and the note.
- **Architecture**: unchanged content; diagram panel flat; component table and VLAN plan as DataTables.

### D.9 Switch, terminal and specialised screens

- **Switch page**: hero = the front panel at full content width in a flat chassis panel (surface-2, 6 px radius), legend as a row of chip-like swatches under it; summary counts in the header toolbar (kept). `.grid-main-rail`: main = `Console` (prompt `SW01#`, input with history and completion from `data.commands`, output `Terminal` 360 px tall, "clear" button); rail = *Interface Gi1/0/x* panel (state chips, KV, running-config `Terminal`), selected from the panel. Below: VLANs, recent configuration changes, logging buffer as three panels (kept).
- **SwitchPanel SVG**: keep geometry; move every colour to CSS classes; port number 8 units; `tabIndex` and `aria-label` per port; selected port gets the accent ring; a one-shot LED pulse after state change (reduced-motion aware).
- **Terminal output** everywhere (`Term` call sites: incident decision/verification tabs, finding transcripts, drift recommendations, evidence viewer, switch logging buffer): 12.5 px mono, 1.55 line height, surface `#0b0f14` → `--surface-2` with a 1 px line, max height with internal scroll, horizontal scroll inside the block (never the page).

---

## E. Code-level implementation map

### E.1 Styling architecture

| file | action |
| --- | --- |
| `frontend/src/styles/tokens.css` | rewrite: colour, type, spacing, radius, z-index, motion tokens; keep legacy names (`--panel`, `--panel-2`, `--muted`, `--faint`, `--accent-2`, `--radius`, `--radius-lg`, `--green/amber/red/purple`, `--chart-*`) as aliases of the new tokens during migration; delete aliases in Phase 4 |
| `frontend/src/styles/base.css` | rewrite: reset, typography scale, shell layout (sidebar/rail/off-canvas, topbar), grid primitives, responsive rules, canvas grid texture, focus-visible, reduced-motion |
| `frontend/src/styles/components.css` | rewrite: chip, button, inputs, segmented, tabs, panel, metric, table, drawer, dialog, terminal, toast, timeline, trace, ledger, switch panel, evidence item |
| `frontend/src/styles/pages.css` (new) | the few page-specific layout classes (posture hero, incident ledger grid, switch hero), replacing inline grid templates |
| `frontend/src/styles/media.css` (new) | the existing `.media` rules moved verbatim from `components.css`, then re-tuned once components change; imported only by `Media.tsx` |
| `frontend/src/index.css` | delete (dead Vite template) |
| `frontend/src/main.tsx` | import `tokens.css`, `base.css`, `components.css`, `pages.css` |

Rule for the implementer: no `style={{…}}` in pages except for values computed from data (bar widths, chart heights). Target ≤ 10 inline style sites per page file; today `Posture.tsx` has 41.

### E.2 Components

| component | change |
| --- | --- |
| `components/layout.tsx` (new) | `Shell`, `Sidebar`, `Topbar`, `PageHeader`, `Section`, `Toolbar`; `App.tsx` shrinks to routes + `Shell` |
| `components/ui.tsx` (edit) | `Panel` (+ `Card` alias), `Button`, `IconButton`, inputs, `Segmented`, `Tabs` (keyboard), `Drawer` (Escape, focus), `Loading`/`Skeleton`/`ErrorState`/`Empty`, `KV` (wrap rules), remove `Kpi`/`Chip`/`Sev`/`Term` after migration |
| `components/status.tsx` (new) | `Chip`, `SeverityChip`, `AssessChip`, `LifecycleChip`, `ResponseChip`, `Id`, `Mono`, plus the pure mapping functions (unit-testable without a renderer) |
| `components/metric.tsx` (new) | `Metric`, `Ratio`, `MetricBand` |
| `components/table.tsx` (new) | `DataTable` with column priority, density, keyboard rows, built-in states |
| `components/trace.tsx` (new) | `Trace` (replaces `Chain.tsx` + `Steps`); `lib/chain.ts` stays as the data adapter |
| `components/ledger.tsx` (new) | `ResponseLedger` + `responseStateOf(incident, action)` helper used by `ResponseChip` |
| `components/dialog.tsx` (new) | `ConfirmDialog` on the native `<dialog>` element |
| `components/terminal.tsx` (new) | `Terminal` (replaces `Term`), `Console` |
| `components/toast.tsx` (new) | `ToastProvider`, `useToast` |
| `components/Timeline.tsx` (edit) | tokens, date dividers, label map unchanged |
| `components/SwitchPanel.tsx` (edit) | classes instead of literals, label size, a11y, one-shot pulse |
| `components/Icons.tsx` (edit) | add: menu, chevron, info, check, pending, withheld, fail, copy, external, terminal, clock; keep existing |
| `components/Logo.tsx` (edit) | sizes from tokens; mark unchanged |
| `charts/index.tsx` (edit) | colours from CSS variables; `ChartFrame` |
| `lib/hooks.ts` (edit) | export `useConnection()`; `useApi` unchanged in behaviour |
| `lib/format.ts` (edit) | add `fmtDelta(seconds)` for ledger gaps; nothing removed |
| `lib/api.ts` | **no endpoint changes**; add two optional type fields only if needed for typing (`Review.decision.guards_triggered` already exists) |

Retire after migration: `Kpi`, `Chip` (ui), `Sev`, `Term`, `Chain`, `Steps`, `Card` alias.

### E.3 Pages

All 16 page files change (they consume the components above). Order and depth are in F. `Media.tsx`
is touched only to import `media.css` and to swap component names; its cards are re-tuned in Phase 5.

### E.4 Scripts, docs and tests

- `scripts/screenshots.py`: update the route list for the home-route change (D.0) and add two 2.0 captures: `sentinelswitch-2.0-overview.png` (`/`) and `sentinelswitch-2.0-review-dialog.png` (approve dialog open). Keep `.content` as the awaited selector.
- `scripts/ui_audit.py` (new, from Appendix 1): the objective-metrics gate used by the QA plan; `make ui-audit` target.
- README "The dashboard", `docs/demo-guide.md`, `artifacts/sentinelswitch-2.0/PORTFOLIO-PACKAGE.md`: route names and the walkthrough order; regenerate `artifacts/sentinelswitch-2.0/screenshots`, `assets/screenshots`, `assets/github`, `assets/linkedin`, `assets/branding/social-card.png` with `make screenshots`.
- Backend: untouched. `backend/tests`: untouched (82 tests must still pass).

### E.5 Dependencies

Facts checked before proposing anything [source, 2026-10-17]: `frontend/package.json` has four
runtime dependencies (react, react-dom, react-router-dom, recharts) and no font or icon packages;
`frontend/public` contains only `favicon.svg`; `frontend/package-lock.json` has no font entries; the
Docker frontend stage runs `npm ci`, so the lockfile must be updated in the same commit as
`package.json`; the committed branding and diagram SVGs reference the system stack with `'Inter'`
as an optional name, so bundling Inter in the app does not change them (they are rendered outside
the app and are out of scope).

- Required: none.
- Recommended, pending the owner's decision (C.2): `@fontsource-variable/inter` and
  `@fontsource-variable/jetbrains-mono`, both version 5.3.0 on npm, licence **OFL-1.1** (SIL Open
  Font License; compatible with this MIT project, attribution kept in `node_modules` and surfaced in
  `docs/architecture.md`'s stack list). Unpacked package sizes are 1.9 MB and 0.2 MB because they
  ship every script subset and axis; import only the `index.css` entry (Latin subsets are the only
  ones the browser fetches, via `unicode-range`), expect roughly 150–250 KB of woff2 transferred
  per first visit, and record the real numbers from `vite build` output in the QA notes. Fonts are
  served from the app's own origin (works offline and on Render; no CDN, no network at build time
  beyond `npm ci`). `font-display: swap` is the package default; the token stacks keep the system
  fallbacks so nothing breaks if the packages are removed.
- Explicitly rejected: UI kits, icon fonts, animation libraries, Markdown libraries (the light
  renderer is in-repo), state libraries, CSS frameworks. Nothing is added for decoration.

### E.6 Backend changes required: none

The redesign reads only existing endpoints. Ideas that were considered and **excluded** because they
would need backend work; if the owner wants them, they are separate tickets, not part of this plan:

- file size and modification time of generated reports on the Reports page (`POST /api/reports/generate` returns paths and counts only);
- a live sensor-liveness signal (the dataset has no Suricata stats events; the assessment layer reports it UNKNOWN by design);
- a real analyst identity or sign-in (the API takes an `actor` string; the demo uses `tlee`);
- server-side console history or any non-`show` command;
- per-incident evidence integrity hashes.

---

## F. Implementation sequence

Each phase ends with the checkpoint commands in H.1 passing and a screenshot sweep; the application
must render every route at every checkpoint (no half-migrated state is committed).

| phase | work | depends on | checkpoint |
| --- | --- | --- | --- |
| 0 — baseline | add `scripts/ui_audit.py` (Appendix 1) and a `make ui-audit` target; run it on the **clean starting revision before any other file changes** (`git status` must be clean apart from the script); store the laptop and mobile sets plus `metrics.json` under `artifacts/ui-redesign/before/`; note the commit hash in `artifacts/ui-redesign/QA.md` | — | `before/` exists, reproducible from the noted commit; the gate is expected to fail on the baseline (that is the point) |
| 1 — tokens and shell | new `tokens.css` with aliases, `base.css` shell (sidebar/rail/off-canvas, topbar with connection state), `layout.tsx`, `useConnection`, delete `index.css`, add fonts (if accepted), focus/reduced-motion rules | 0 | all routes render; mobile overflow = 0 on every route (the topbar and sidebar fixes alone remove the global overflow); media cards unchanged in pixels except font if bundled |
| 2 — primitives | `status.tsx`, `metric.tsx`, `table.tsx`, `dialog.tsx`, `terminal.tsx`, `toast.tsx`, `Panel`, `Button`, `Drawer` fix; chart tokens; SwitchPanel classes | 1 | storybook-free check: a temporary `/dev/components` route is **not** added; instead each primitive is exercised on the first page that adopts it (phase 3a) |
| 3a — flagship workflow pages | Overview (`/`), Posture (`/posture`), Incidents + review queue with dialogs, Incident detail with ledger and trace | 2 | demo walkthrough works end to end in the browser (replay → review → approve/reject → release → report); `scripts/screenshots.py --only-2` runs |
| 3b — assurance pages | Controls catalog/detail/drawer, Findings list/detail with Remediate dialog, Reports, Evidence | 3a | `make demo-2` then screenshots; pytest unchanged |
| 3c — operations pages | Switch + Console, Alerts, Assets, Authentication, Coverage, Drift, Architecture | 2 | audit script: no route wider than viewport at 1024 and 1440; inline-style count ≤ 10 per page |
| 4 — responsive and accessibility | rail/off-canvas behaviour on every page, column priorities, card rows for queues on phones, keyboard rows, dialog/drawer focus, remove token aliases, delete retired components | 3a–3c | full matrix at 4 viewports; tab-order walk on 6 key pages; reduced-motion run |
| 5 — media, docs, artifacts | `media.css` re-tune, `make screenshots`, README/docs/portfolio updates, `artifacts/sentinelswitch-2.0` regeneration, final QA report | 4 | H.4 acceptance criteria all met; `bash scripts/test.sh` green |

Avoiding inconsistency between phases: token aliases keep old class names working until Phase 4;
`Card`/`Kpi`/`Chip`/`Term` remain exported (delegating to the new primitives) until every page has
migrated; pages are migrated whole, never half.

---

## G. Functional preservation checklist

| invariant | where enforced | protected by |
| --- | --- | --- |
| Containment executes only with an `authorized` authorization record; the controller never mints one | `containment/controller.py` | `test_containment.py`, `test_scenarios.py`, `test_response.py` |
| Guards only downgrade; protected ports, trunks, SPAN destination and critical assets are never acted on automatically | `containment/policy.py`, adapter `_guard` | `test_policy.py`, `test_containment.py` |
| Analyst approve/reject only for reviews in status `review`; approve writes an evidence bundle and runs an assessment | `services/response.py`, `api/assurance_routes.py` | `test_response.py`, `test_assurance_api.py` |
| UNKNOWN and STALE never count as a pass; RETIRED excluded from totals; coverage and pass rate keep explicit denominators; no composite score | `assurance/posture.py`, `engine.py` | `test_assurance.py::test_posture_summary_math`, `_deterministic_workflow…` |
| Remediation goes requested → executed → re-assessed → verified; refused on protected interfaces | `assurance/remediation.py` | `test_assurance.py` (remediation tests) |
| Validation reports CONTAINED vs WITHHELD; withheld is never a containment | `validation/harness.py` | `test_scenarios.py` |
| Exports (JSON/HTML/PDF) unchanged | `assurance/export.py` | `test_assurance.py::test_export_document_html_and_files`, `test_assurance_api.py` |
| No fabricated data in the UI: every number comes from `endpoints.*`; no client-side metrics beyond the existing `diff()` deltas | frontend | review rule + the audit script's "no hard-coded numbers" grep (Appendix 1) |
| `make screenshots`, `make screenshots-2`, `scripts/test.sh`, `make demo-2` keep working | `scripts/` | run at every checkpoint |
| Media cards (`/media/*`) keep rendering and regenerate | `Media.tsx`, `media.css` | `make screenshots` |
| SSE-driven refresh and the `fresh`-flag loading rows keep working | `hooks.ts` | manual check in H.3 (switch filters with throttled network) |

Risks needing particular attention: the home-route change (every doc and the screenshot script
reference it); the `ResponseChip` mapping (must be derived from backend fields, not guessed);
dialog default notes (must remain truthful about who acts: analyst `tlee`).

---

## H. Visual QA plan

### H.0 Verification gate (mandatory, every phase)

1. **Baseline first.** Before the first UI edit, run `scripts/ui_audit.py` against the clean starting
   revision with the baseline route list (`UI_AUDIT_ROUTES` set so that `/operations` is captured and
   `/posture` is not; see Appendix 1) and store `artifacts/ui-redesign/before/` (laptop + mobile PNGs,
   `metrics.json`, commit hash in `QA.md`). Desktop and tablet baselines are regenerated on demand
   from that commit rather than stored.
2. **Final set.** After Phase 5, run the same script on the final build for all four viewports and
   store `artifacts/ui-redesign/after/` with the same file names, plus the interaction, baseline-stage,
   post-workflow, degraded and reduced-motion sets from H.2.
3. **Look at the pictures.** Automated metrics do not pass a phase. The implementer must open every
   `after/` screenshot (contact sheets are acceptable for a first pass, full-size for anything
   flagged) and record in `artifacts/ui-redesign/QA.md`, per route and viewport: overflow,
   misalignment, inconsistent spacing, unreadable or clipped text, broken dialogs/drawers,
   components that differ from the shared implementation. Each entry gets a fix commit or an
   explicit "accepted, because …".
4. **Checks that must pass before a phase is called done:** `npx tsc -b`, `npm run lint`,
   `npm run build`, `./.venv/bin/python -m pytest -q` (82 passed), `bash scripts/test.sh`,
   `scripts/ui_audit.py` exit 0 on the final build, `scripts/screenshots.py --only-2` and
   `make screenshots` completing, and the manual walkthrough in H.3 at 1440×900 and 390×844.
5. **Honesty rule.** If Playwright/Chromium is unavailable in the implementation environment, the
   QA notes say so, list which checks were not run, and the phase is reported as unverified; no
   screenshot or "visually checked" claim is made without the file to show for it.

### H.1 Commands (all exist today unless marked new)

```bash
cd frontend && npx tsc -b            # type check
cd frontend && npm run lint          # oxlint
cd frontend && npm run build         # production build (tsc + vite)
./.venv/bin/python -m pytest -q      # 82 backend tests (must stay green; UI work does not touch them)
bash scripts/test.sh                 # the above + ruff + validation harness, writes test-results.md
./.venv/bin/python scripts/ui_audit.py artifacts/ui-redesign/after   # new: metrics + screenshots (Appendix 1)
./.venv/bin/python scripts/screenshots.py --only-2                    # 2.0 artifact captures
make screenshots                                                       # full media regeneration
```

There is no frontend unit-test runner; adding one is out of scope for a visual redesign. The pure
mapping functions in `status.tsx` and `ledger.tsx` are written so they could be tested by a future
Vitest setup, but the gate for this work is the audit script plus browser inspection.

### H.2 Screenshot matrix

| set | routes | viewports | states |
| --- | --- | --- | --- |
| core | `/`, `/posture`, `/controls`, `/controls/CTL-ENDPOINT-IDENTITY`, `/findings`, `/findings/FND-SENSOR-COVERAGE-vlan-50`, `/incidents`, `/incidents/INC-2026-0042`, `/reports`, `/alerts`, `/devices`, `/switch`, `/authentication`, `/coverage`, `/drift`, `/evidence/INC-2026-0042`, `/about` | 1920×1080, 1440×900, 1024×768, 390×844 | contained stage (`SENTINEL_AUTO_DEMO=1`) |
| interactions | incident tabs ×4, controls drawer, alert drawer, device drawer, switch port selected + console after a command, approve dialog, release dialog, remediate dialog, off-canvas nav open | 1440×900 and 390×844 | contained stage |
| baseline | `/`, `/posture`, `/incidents`, `/findings`, `/switch` | 1440×900 | `SENTINEL_AUTO_DEMO=0` (empty queue, no containment) |
| post-workflow | `/`, `/posture`, `/findings?view=all`, `/incidents/INC-2026-0042`, `/reports` | 1440×900 | after `make demo-2` (resolved, all verified) |
| degraded | `/`, `/incidents` | 1440×900 | API stopped after first load (stale → unavailable in the topbar; panels show `ErrorState` on refetch) |
| motion | `/switch` | 1440×900 | `prefers-reduced-motion: reduce` emulated |

Before and after sets live side by side under `artifacts/ui-redesign/{before,after}/` with the same
file names so they can be diffed visually; the before set is produced from commit `197f2a6`.

### H.3 Responsive and interaction checks (manual, in the browser, recorded in the QA notes)

- Tab through `/`, `/incidents`, `/incidents/INC-2026-0042`, `/findings/:id`, `/switch`, `/reports`: every interactive element reachable in reading order, visible ring, Enter/Space activate rows and ports, Escape closes drawers and dialogs, focus returns to the opener.
- Resize 1920 → 390 continuously: no element crosses the viewport edge; tables scroll inside their panel; dialogs stay within the viewport; sticky topbar never covers content; the off-canvas nav traps focus and closes on route change.
- Throttle the network (Slow 3G) and switch the findings filter: loading row appears; no stale rows.
- Stop the API: topbar moves to stale within 60 s, then unavailable on the next failed fetch; restart: connected again without reload.
- Console: zero errors and zero warnings on every route; network: zero failed requests.

### H.4 Acceptance criteria (objective; measured by `scripts/ui_audit.py` unless noted)

1. Horizontal document overflow = 0 px on every route at 1920, 1440, 1024 and 390 (today: 261–319 px on all 19 routes at 390).
2. No element extends past the viewport outside an element with `overflow: auto` (the `wide` metric counts only such elements) — target 0 at 1440 and 1024 (today: up to 219 and 691).
3. Zero console errors/warnings and zero failed requests on all routes (today: already 0; must stay 0).
4. No informational text below 11 px outside the switch SVG; at most 8 distinct font sizes per route (today: 18).
5. Border radii used: only 4 px, 6 px and 50 % (today: 7 values).
6. Inline `style` DOM nodes per route ≤ 60, and ≤ 10 `style={{` sites per page file (today: 416 nodes on `/`, 41 sites in `Posture.tsx`).
7. No hex colour literals in `*.tsx` except `Logo.tsx` and `SwitchPanel.tsx` gradient stops (grep gate in the audit script; today: 9 files).
8. Every clickable table row and every port is keyboard focusable and activatable (audit counts `tr.clickable` without `tabindex`; target 0).
9. Every state-changing action in guardrail 6 (approve, reject, release containment, remediate, reset to baseline, replay flagship incident) opens a `ConfirmDialog` before any request is sent, and none of the routine actions (run assessment, re-run validation, generate reports, console commands, navigation) does (manual + network tab).
10. `:focus-visible` rings present on buttons, links, inputs, rows, ports; `prefers-reduced-motion` disables all animation (manual, H.3).
11. Severity, assessment, lifecycle and response states always render a word with the colour (audit: no `.chip` without text content).
12. UNKNOWN/STALE never use `--ok` colours; RETIRED is excluded from every total shown (manual against `/api/posture`).
13. `bash scripts/test.sh` exits 0 with 82 passed; `scripts/screenshots.py` and `make screenshots` complete; media cards reviewed.
14. Buttons ≥ 32 px tall on desktop, ≥ 40 px tap targets on phones for primary actions (audit `buttons` metric at 390).

Findings during QA are logged in `artifacts/ui-redesign/QA.md` with route, viewport, screenshot
name, cause, fix commit; a criterion that cannot be met is reported as such, never relaxed silently.

---

## I. Open questions and assumptions

**Verified from source:** everything in B.1, the invariants in G, the endpoint inventory used by D
(`/api/overview`, `/api/posture`, `/api/reviews`, `/api/assessments?control_id=…`, `/api/switch`,
`/api/switch/show` accepting only `show …` commands listed in `cli_render.SHOW_COMMANDS`).

**Observed in the rendered UI:** every number in B.2 items 1–7, 9, 11, 13; the contact-sheet
observations (sidebar-above-content on phones, equal-weight incident header, raw README in the evidence
viewer, select-based console).

**Assumptions (recommendation made, not blocking):**

1. Home route becomes the operational Overview (`/`) with Posture at `/posture`. If the owner prefers Posture as home, keep today's routes and still build the attention strip on the Overview; nothing else in the plan changes.
2. Fonts are self-hosted via two `@fontsource` packages. If declined, the token stacks fall back to system fonts.
3. The demo analyst identity stays hard-coded as `tlee`; it is shown only in the four dialogs that record an actor and in existing audit fields (guardrail 7); no identity system is added.
4. Dark theme only; no light theme is designed (the app has never had one).
5. The light Markdown renderer for `README.md` covers only what `render_report` emits (headings, paragraphs, bullet lists, fenced code, pipe tables); anything else falls back to the raw view.

No question blocks implementation.

---

## Appendix 1 — `scripts/ui_audit.py` (gate for H.4; same script produced the numbers in B.2)

```python
"""Render every route at four viewports against a temporary server; record overflow, font sizes,
radii, inline styles, console errors, failed requests; save screenshots. Usage: ui_audit.py OUT_DIR"""
import json, os, re, shutil, socket, subprocess, sys, tempfile, time, urllib.request
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; OUT = Path(sys.argv[1]); OUT.mkdir(parents=True, exist_ok=True)
s = socket.socket(); s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]; s.close()
tmp = Path(tempfile.mkdtemp(prefix='ui-audit-')); inc = tmp / 'incidents'; shutil.copytree(ROOT / 'data' / 'incidents', inc)
env = dict(os.environ, SENTINEL_DB=str(tmp / 'a.db'), SENTINEL_INCIDENTS_DIR=str(inc), SENTINEL_ARTIFACTS_DIR=str(tmp / 'art'),
           SENTINEL_AUTO_SEED='1', SENTINEL_AUTO_DEMO=os.environ.get('SENTINEL_AUTO_DEMO', '1'))
proc = subprocess.Popen([sys.executable, '-m', 'sentinelswitch', 'serve', '--port', str(port)], env=env, cwd=ROOT,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
base = f'http://127.0.0.1:{port}'
for _ in range(60):
    try: urllib.request.urlopen(base + '/api/meta', timeout=2); break
    except Exception: time.sleep(1)
DEFAULT_ROUTES = ['/', '/posture', '/controls', '/controls/CTL-ENDPOINT-IDENTITY', '/findings', '/findings/FND-SENSOR-COVERAGE-vlan-50',
          '/incidents', '/incidents/INC-2026-0042', '/reports', '/alerts', '/devices', '/devices/ENG-LT-047', '/switch',
          '/authentication', '/coverage', '/drift', '/evidence', '/evidence/INC-2026-0042', '/about']
# Baseline run on the starting revision (no /posture yet, SOC Overview at /operations):
#   UI_AUDIT_ROUTES="/,/operations,/controls,...,/about" python scripts/ui_audit.py artifacts/ui-redesign/before
ROUTES = [r for r in os.environ.get('UI_AUDIT_ROUTES', ','.join(DEFAULT_ROUTES)).split(',') if r]
VIEWPORTS = {'desktop': (1920, 1080), 'laptop': (1440, 900), 'tablet': (1024, 768), 'mobile': (390, 844)}
METRICS_JS = """() => {
  const vw = document.documentElement.clientWidth;
  const all = [...document.querySelectorAll('body *')];
  const vis = all.filter(e => { const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0; });
  const inScroller = e => !!e.closest('[style*="overflow"], .table-wrap, pre, .chain, .ledger, .trace');
  const fonts = {}; let tiny = 0;
  for (const e of vis) {
    if (![...e.childNodes].some(n => n.nodeType === 3 && n.textContent.trim())) continue;
    const fs = parseFloat(getComputedStyle(e).fontSize); fonts[fs] = (fonts[fs] || 0) + 1;
    if (fs < 11 && !e.closest('svg')) tiny++;
  }
  const radii = {}; for (const e of vis) { const r = getComputedStyle(e).borderTopLeftRadius; if (r !== '0px') radii[r] = (radii[r] || 0) + 1; }
  return {
    hOverflow: document.documentElement.scrollWidth - vw,
    wide: vis.filter(e => e.getBoundingClientRect().right > vw + 1 && !inScroller(e)).length,
    fonts, tiny, radii,
    inlineStyled: document.querySelectorAll('[style]').length,
    rowsNotFocusable: document.querySelectorAll('tr.clickable:not([tabindex])').length,
    chipsWithoutText: [...document.querySelectorAll('.chip')].filter(c => !c.textContent.trim()).length,
    smallButtons: [...document.querySelectorAll('button,a.btn')].filter(b => { const r = b.getBoundingClientRect(); return r.width > 0 && r.height > 0 && r.height < (vw < 600 ? 40 : 32); }).length,
    docHeight: document.documentElement.scrollHeight,
  };
}"""
from playwright.sync_api import sync_playwright
report = {}
with sync_playwright() as p:
    browser = p.chromium.launch()
    for vname, (w, h) in VIEWPORTS.items():
        ctx = browser.new_context(viewport={'width': w, 'height': h}, color_scheme='dark'); page = ctx.new_page()
        errors, failed = [], []
        page.on('console', lambda m: errors.append(m.text) if m.type in ('error', 'warning') else None)
        page.on('requestfailed', lambda r: failed.append(r.url))
        page.on('response', lambda r: failed.append(f'{r.status} {r.url}') if r.status >= 400 else None)
        for route in ROUTES:
            errors.clear(); failed.clear()
            page.goto(base + route, wait_until='networkidle'); page.wait_for_timeout(600)
            m = page.evaluate(METRICS_JS); m['console'] = list(errors); m['failed'] = list(failed)
            name = (route.strip('/') or 'home').replace('/', '_')
            page.screenshot(path=str(OUT / f'{vname}__{name}.png'))
            report[f'{vname} {route}'] = m
        ctx.close()
    browser.close()
proc.terminate(); shutil.rmtree(tmp, ignore_errors=True)
(OUT / 'metrics.json').write_text(json.dumps(report, indent=1))
hex_in_tsx = [str(f.relative_to(ROOT)) for f in (ROOT / 'frontend' / 'src').rglob('*.tsx')
              if f.name not in ('Logo.tsx', 'SwitchPanel.tsx') and re.search(r'#[0-9a-fA-F]{6}\b', f.read_text())]
bad = [k for k, m in report.items() if m['hOverflow'] > 0 or m['console'] or m['failed'] or m['tiny'] or m['rowsNotFocusable'] or m['chipsWithoutText']
       or len(set(float(x) for x in m['fonts'])) > 8 or (set(m['radii']) - {'4px', '6px', '50%'})]
print('routes failing a criterion:', len(bad)); [print(' ', b) for b in bad]
print('tsx files with hex literals:', hex_in_tsx)
sys.exit(1 if bad or hex_in_tsx else 0)
```

The baseline numbers in B.2 came from the same measurements on commit `197f2a6` (with today's
routes: `/` = Posture, `/operations` = SOC Overview). The script exits non-zero when any criterion
fails; on the baseline that is expected. Screenshot file names are derived from the route, so the
`before/` and `after/` sets line up except for `operations` (before only) and `posture` (after only).

# UI redesign — visual QA record

Plan: `docs/ui-redesign-plan.md`. Gate: `python scripts/ui_audit.py <out>` (section H.0/H.4).

## Baseline

- Captured from commit `197f2a6` (working tree clean apart from `docs/ui-redesign-plan.md` and the new `scripts/ui_audit.py`), before any UI change.
- Command: `UI_AUDIT_ROUTES="/,/operations,…,/about" python scripts/ui_audit.py artifacts/ui-redesign/before` with `SENTINEL_AUTO_DEMO=1` (contained stage).
- Stored: laptop (1440×900) and mobile (390×844) viewport captures for 19 routes plus `metrics.json` (which also holds the desktop and tablet measurements).
- Result: gate FAILED as expected — every route overflows on mobile (261–319 px), 11–15 font sizes per route, sub-11 px text on every route, 10 px and 2 px radii, non-focusable clickable rows, hex literals in 8 TSX files.

## After (implementation complete)

- Command: `python scripts/ui_audit.py artifacts/ui-redesign/after` (temporary database, copied evidence bundles, `SENTINEL_AUTO_DEMO=1`), run three times during the work; the numbers below are from the final run on the final build.
- Stored: 76 screenshots (`{desktop,laptop,tablet,mobile}__<route>.png`, 1920×1080 / 1440×900 / 1024×768 / 390×844) and `metrics.json` in `artifacts/ui-redesign/after/`; the run log is `artifacts/ui-redesign/after-audit.log`.
- Result: see the "Final audit" section at the end of this file.
- One change to the audit script itself: `.tabs`, `.console`, `.md table` were added to the list of intentional horizontal scroll containers (next to `.table-wrap`, `pre`, `.ledger`, `.trace`), so tab strips, the IOS console output and the README tables in the evidence viewer are measured the same way as the other scrollers. Nothing else in the criteria changed.

## Findings log (route · viewport · defect · resolution)

| # | route · viewport | defect found | resolution |
| --- | --- | --- | --- |
| 1 | `/` · all | first audit run: metric band rendered as one column (`.grid-metrics` had no `display: grid`) | added `display: grid` to `.grid-metrics` |
| 2 | `/incidents` · laptop | an open review whose guards withheld automation showed "withheld by policy" instead of "awaiting authorization" | `responseStateOf` only returns *withheld* for a rejected authorization / rejected review, or a closed review without an incident; an open review is *awaiting* (plan D.4) |
| 3 | all routes · all viewports | radii outside {4px, 6px, 50%}: 10 px (`.nav-badge`), 3 px (`.counts span`, `.skeleton span`, `.bar-track`, `.md code`), 2 px (legend and port-legend swatches, tooltip swatch) | all moved to 4 px / 6 px |
| 4 | `/alerts`, `/switch`, `/posture`, `/reports`, `/findings` · mobile | page overflow 11–215 px: the page-header toolbar (`flex: none`) kept its content width, so search fields, selects and buttons pushed the page wider | `.page-head .toolbar` gets `max-width: 100%` and, below 900 px, `flex: 1 1 100%` so controls wrap under the title |
| 5 | `/incidents/INC-2026-0042` · mobile | tab buttons counted as past the viewport although the tab strip scrolls; same for console output lines on `/switch` and README table cells on `/evidence` (laptop/tablet) | audit script now treats `.tabs`, `.console` and `.md table` as scroll containers (they already had `overflow: auto`) |
| 6 | `/incidents/INC-2026-0042` · all | header chips rendered uppercase because the identity row reused the `eyebrow` class | identity row uses its own `.ident-row` class |
| 7 | `/incidents/INC-2026-0042` · mobile | ledger "+572 ms" deltas clipped at the top of the scroll box; panel subtitle wrapped into a narrow column beside the trace legend | `.ledger` padding-top 12 px; below 600 px panel heads wrap and the right-hand controls take a full row |
| 8 | `/` · desktop | menu button visible at desktop width (`.btn` from components.css overrode `.menu-btn { display: none }` at equal specificity) | `.topbar .menu-btn` / `.brand-row .menu-btn` selectors |
| 9 | mobile drawer | brand text ran into "2.0EVIDENCE…" when the drawer opened (`display: initial` made it inline) | `.shell.nav-open .brand-text { display: flex }` |
| 10 | `/` · all | off-scale font sizes: 12.5 px (terminal, console prompt), 10.5 px (`.chip.sim`, ledger delta), 18/22 px (ratios, outcome counts, attention counts), 15 px (brand), 18 px (h1 on phones) | all mapped to the eight-size scale (11/12/13/14/16/20/28/36) |
| 11 | rail mode (900–1199) | nav badges overlapped the icons | badge pinned to the top-right corner with a 15 px minimum width |
| 12 | `/media/05-auto-quarantine` | wordmark text hidden on the 1080 px media canvas (rail-mode rule), chassis showed the model twice | `.media .brand-text { display: flex }`; chassis shows the family ("Catalyst 2960-X") and the model string once |

## Interaction checks (browser pane, isolated server with a temporary database, 1440×900 and 375×812)

- Off-canvas navigation (375 px): opens from the menu button, closes on Escape and after navigation; focus and labels visible.
- Approve-containment dialog (`/incidents`): opens with focus in the note field, states port/VLAN/guards, carries "Recorded as analyst tlee (demo identity, no sign-in)", Escape cancels, focus returns to the "Approve containment" button, no request is sent on cancel.
- IOS console (`/switch`): typing `show vl` lists completions from `/api/switch`.commands, Tab accepts, Enter runs `show vlan brief` on the twin; `configure terminal` is sent unchanged and the server's `400 only show commands are supported` is printed in the terminal.
- Keyboard: table rows with an action are focusable (Tab) and activate on Enter/Space; front-panel ports are buttons with arrow-key navigation.
- No console errors or failed requests on any route (audit `console` / `failed` arrays empty).

## Final audit

Final run (2026-10-17, final build, after `scripts/screenshots.py` regenerated every capture):

```
76 route/viewport combinations measured; screenshots in artifacts/ui-redesign/after
routes failing a criterion: 0
tsx files with hex colour literals: none
exit 0
```

Aggregated from `metrics.json`: horizontal overflow 0 px on every route and viewport; 0 elements past the viewport outside scroll containers; 0 text nodes below 11 px outside SVG (the front-panel port numbers are 8 px SVG text by design); font sizes in use 11/12/13/14/16/20/28/36 px; radii 4 px / 6 px / 50 % only; 0 clickable rows without `tabindex`; 0 chips without text; 0 console errors or warnings; 0 failed requests. Remaining inline styles (≤ 23 per route, 416 on Posture before) are data-driven widths (status bars, confidence bar, skeleton rows) and CSS custom-property heights for the terminal/console.

Before/after captures: `artifacts/ui-redesign/before/` (laptop + mobile, 19 routes) and `artifacts/ui-redesign/after/` (four viewports, 19 routes).


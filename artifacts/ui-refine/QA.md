# SentinelSwitch 2.0 refinement pass: QA record

Starting revision: `f702691` (clean tree). Baseline captures: `before/` (audit log `before-audit.log`).
Final captures: `after/` (audit log `after-audit.log`), interaction captures: `interactions/`.
All browser checks ran against isolated local servers with temporary databases. The deployed site
was only read with GET requests; nothing was written to it. Nothing has been committed.

## Results on the final build

| Check | Result |
| --- | --- |
| Backend tests (`pytest`) | 82 passed |
| Python lint (`ruff check backend simulator scripts diagrams/source`) | all checks passed |
| Frontend type-check (`tsc -b`) | passed |
| Frontend lint (`oxlint`) | 0 errors; 11 `only-export-components` warnings, the same 11 as at `f702691` |
| Production build (`vite build`) | passed (existing chunk-size warning) |
| Validation harness | 9/9 scenarios met their expected outcome |
| Visual-QA gate (`scripts/ui_audit.py artifacts/ui-refine/after`) | 76 route/viewport combinations, 0 failing, no hex literals |
| Playback check (`scripts/playback_check.py`, new) | 15/15 |
| Table fit sweep (every table, 18 routes, plus tabs, list view and drawers) | no table wider than its container at 1920, 1600, 1440, 1366, 1280, 1200, 1100, 1024, 900, 768, 720, 680, 600, 390 and 360 px |

`scripts/test.sh` itself was not run because it rewrites the tracked
`artifacts/sentinelswitch-2.0/validation/test-results.md` with a wall-clock date; its five commands
were run individually instead (rows 1 to 4 and the validation harness above).

## Playback checks (scripts/playback_check.py)

| Check | Observed |
| --- | --- |
| autoplay on load | playing from the window start |
| 1× rate | 17.1 simulated min/s for the 21.25 h day window (expected 17.0: window / 75 s) |
| pause freezes | clock unchanged after 1.5 s |
| click on the timeline seeks and pauses | 00:43 to 12:01, held |
| drag on the timeline scrubs and pauses | 12:01 to 10:04, held |
| Play resumes from the playhead | 10:04 to 10:21 after 1 s |
| 4× | 68.1 simulated min/s (3.99×) |
| 4 h window | 17:15 to 21:15 UTC at 3.2 simulated min/s |
| loop | 20:59 wrapped to the window start, indicator "loop 2" |
| a full pass at 4× | 0 requests of any kind (no write, no data read) |
| navigation away 3 s and back | playhead kept, one clock (rate unchanged after repeated round trips) |
| hidden tab | clock held while hidden, resumed without a jump |
| reload | autoplays |
| console | no errors |
| reduced motion | playback still runs; 0 running CSS animations (normal motion runs 9 named animations) |

Earlier scratch runs also verified: keyboard control of the timeline (End, arrows, Space), the
empty-dataset state ("no data", Play disabled, "NO RECORDED EVENTS"), the loading skeleton, and the
field reconstruction at a given playhead (Gi1/0/23 in VLAN 20 before 21:14:41, contained in VLAN 50
at 21:15 with its vacated slot outlined).

## Connection status checks

| Situation | Top bar |
| --- | --- |
| healthy | API reachable, events live |
| one endpoint returns HTTP 503 | API errors (tooltip carries the status), events live; the page shows its error state with Retry |
| browser offline, then a view loads | API unreachable; the page shows "Could not load data" |
| server hard-stopped | events reconnecting and API unreachable within 4 s, without user action |
| server back | events live and API reachable without user action; mounted views re-read once |

A graceful server stop keeps open event-stream connections alive while it drains, so the stream
correctly stays "live" until the process exits; the hard-stop case above is the realistic outage.

## Fixes made during QA

- Tables now shed columns by their own container width (container queries) instead of the viewport.
  The previous viewport rule hid source and destination addresses on the Alerts table below 1500 px
  and still overflowed between 1200 and 1440 px, where the full sidebar and side-by-side panels
  leave tables narrowest.
- Queue-style tables (review queue, drift) become label/value cards below 900 px of container width;
  long lists opt in to cards on viewports below 720 px. Cards keep the same hidden columns as the
  table, so a phone alert card is five lines; the row drawer keeps every field.
- About components, Switch VLANs and the Overview containment ledger fold a secondary value under the
  primary one instead of spending a column on it.
- The event stream now re-checks the API when it drops or reconnects, and views re-read their data
  after a reconnect, so the top bar and the page recover on their own.
- `scripts/screenshots.py` pauses the Overview at the end of the record before capturing, because the
  page now autoplays from the start of the day; README images were regenerated from the final build.

## Limitations from the data and architecture

- Port link state and administrative state are not recorded over time; outlines show the twin's
  current state at every playhead. Only VLAN moves and holds are time-derived, from each containment
  action's applied and restored times.
- Attribution in the port inspector reads the current switch tables and says so.
- Flows are drawn only for alerts that recorded a source and a destination; destinations outside SW01
  are drawn as labelled stubs.
- The replay window ends at the last recorded instant rounded up to 15 minutes.
- Playwright cannot emulate a dropped event stream while offline; the stream checks used a real
  server stop and restart instead.
- The refinement is local and uncommitted; the deployed site still runs the previous build.

## Remaining issues (not fixed)

- The copy button of wide terminal blocks (Switch logging buffer) overlaps the first line's tail
  while the block is scrolled horizontally.
- The main JavaScript chunk exceeds Vite's 900 kB warning size (unchanged by this pass).

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

# Pass 2: the recorded wire, auto pace, motion across pages, formatting sweep

Requested after the first pass was deployed: no dead time after load, a timeline filled with
activity that still means something, more life on the other pages, and the small formatting mistakes
fixed. Captures for this pass: `pass-2/`. Audit captures were refreshed in `after/` (demo state) and
added in `after-baseline/` (baseline state).

## What changed

- **Recorded wire.** New read-only `GET /api/telemetry` (`backend/sentinelswitch/services/replay_feed.py`)
  serves the dataset's 10,524 Zeek connections (DNS query, TLS server name or HTTP request joined by
  uid), 136 RADIUS results and 369 switch syslog lines, columnar, gzip-compressed (388 KB to 101 KB),
  with an ETag. Three backend tests check row counts against the files, compression and caching, and
  that POST, PUT and DELETE are refused.
- **Overview.** A canvas over the field draws each recorded connection as a particle from its port
  through the switch to the responder (the uplink trunk when the responder is not on SW01), coloured by
  service; RADIUS, syslog and alerts flash at their port; the core ring turns with connections per
  second. A two-pane wire console prints the recorded lines at the playhead. The timeline stacks
  connections per 5 minutes by service (log height) with RADIUS and syslog rows up to the switch clock.
  Traffic filter chips by service family.
- **Auto pace** (on by default, toggle in the bar): up to 10× through quiet stretches, 0.15× around each
  recorded alert, about 4 recorded seconds per real second around each containment action. The clock
  always shows recorded time and the bar says which pace applies. The field reaches the busy morning
  about 5 s after load; a full default pass takes about 80 s.
- **Other pages.** Count-up numbers, ordered row entrance, a single scan along panel headers, a
  breathing pending-authorization chip, port LEDs blinking at each port's recorded connection rate
  (Switch), the incident host's recorded traffic looping in the incident view, drift marking each
  observed value that differs, flowing arrows on the architecture diagram, timeline lanes on Alerts.

## Formatting fixes found by sweeps

| Problem | Cause | Fix |
| --- | --- | --- |
| Incidents badge in the sidebar stretched | badge modifier `attention` collided with the `.attention` grid component | renamed to `is-warn` |
| Posture status bar layout | size modifier `lg` collided with the field legend's `.lg` item rule | legend rule scoped to `.sig-legend` |
| Coverage "withheld by policy" chip 302 px wide | chip stretched in a grid cell | chips start-aligned in grid cells |
| Panel collapse toggles invisible (8×8 px) | chevron icon had no size | 28 px toggle, 16 px icon |
| Authentication methods label overlapped | long method name in a 110 px label column | 190 px |
| Posture header split date from time | wrap inside the clock value | kept together |
| Control-status names over-truncated | single line with ellipsis | two lines |
| Evidence context strip left one cell alone | flex wrap | even auto-fit grid |
| Alerts timeline panel half empty | short chart beside a taller panel | timeline lanes fill it |

A collision detector (two stand-alone component classes on one element), a stretched-pill and clipped-
text detector, an undersized-control detector and the page and table overflow sweeps were re-run on
every route after the fixes: no findings.

## Results on the final build

| Check | Result |
| --- | --- |
| Backend tests | 85 passed (82 + 3 new) |
| ruff | passed |
| tsc | passed |
| oxlint | 0 errors; the same 11 pre-existing warnings |
| Validation harness | 9/9 |
| UI audit, demo state | 76 combinations, 0 failing |
| UI audit, baseline state | 72 pass; 4 fail only because INC-2026-0042 does not exist before the demo runs (expected 404) |
| `make playback-check` | 20/20, including auto pace both ways and no request or write in a full pass |
| Default auto-paced loop | no data request and no write; only the 60 s health ping to `/api/meta` |
| Page overflow, 360–2560 px, both states | none |
| Frame timing during the busiest hour, 1× and 4× | p95 8.4 ms (headless Chromium) |

The UI audit now skips text inside the inlined architecture diagram when counting font sizes; the same
file shown as an `<img>` was never counted. Its arrows animate only because it is inlined.

## Not reproduced

The Drift page in the shared screenshot looked about 30 px wider than the window. No page overflows in
Chromium at 13 widths from 1280 to 2560 px in either state, with or without classic scrollbars. Safari
was not tested because the WebKit test browser is not installed.

# Pass 3: timeline drag and calmer replay

- **Alerts timeline drag was broken.** The pass-1 rewrite of the scrubber dropped the guard that treats
  a whole-day window as "select a new range": every drag landed on the full-day window element and was
  read as moving a window that cannot move. Restored the guard. The Overview rail had the same shape
  of problem with the Day preset (00:00–21:15), and a dragged window could slide past the switch clock
  to 24:00; the rail now counts the recorded end as "whole day" and windows stop at the switch clock.
  `scripts/playback_check.py` gained two checks (drag selects a range and filters the table; Home
  restores the whole day): 22/22 pass.
- **Calmer replay.** One pass at 1× now takes 120 s (was 75 s). At most 80 particles a second are drawn
  (an even sample of each moment's connections; every connection still lights the ports it touched),
  with at most 160 in flight, slower, smaller and dimmer than before. The particle canvas now sits
  beneath the ports, so particles never cover a port number or label. Another private address now ends
  at the switch itself instead of the uplink; only public addresses leave through the uplink. Quiet
  stretches still fast-forward; the slow motion around alerts and the containment is unchanged.
- Slow-motion rates under a minute per second now read in seconds instead of "0 min".

Results: 85 backend tests, ruff, tsc, oxlint (same 11 warnings), UI audit 76/76 in demo state,
playback check 22/22.

# Pass 4: containment made visible

The quarantine is the most important outcome in the replay but sat in the last second of the loop.

- **Containment strip** under the field (`components/signal/Containment.tsx`): every recorded
  containment action of the window as a chip coloured by its state at the playhead (to come, holding,
  restored); a chip replays from 20 s before its action. The detail lines give port, endpoint, VLAN
  move, authorization, switch read-back, time held or restore, connections from the host in the minute
  before, and for a quarantine into a VLAN whose sensor-coverage assessment is FAIL, that the VLAN is
  not mirrored to the sensor. Everything comes from the action record, the inventory, the coverage assessment and
  the recorded connections, and every line says "recorded". The strip keeps one height per width in
  every state (172 px two-column, 214 px narrow, 352 px phone), so nothing below it jumps.
- **End-of-record hold:** auto pace holds the last moment for 6 s before looping ("end of record").
- **Field:** a dashed isolation zone around the quarantine colony while it is occupied, and a lock-down
  wave on the canvas when a containment is applied (red quarantine, amber shutdown, green restore).
- **Timeline:** a band for each containment interval with a marker at its start.

Results: playback check 24/24 (adds: end of record holds on the quarantine; a chip replays from just
before its action), UI audit 76/76, 85 backend tests, ruff, tsc, oxlint (same 11 warnings). Strip
measured at 390, 768, 1024, 1200, 1280, 1440, 1600 and 1920 px: constant height per width, no page
overflow.

# Pass 5: the demo analyst

The manual-review detection (Critical Asset Scan, SRV-GIT01 on Gi1/0/12) only reached the replay if a
person approved it on the Incidents page. The demo now plays that analyst, without bypassing anything:

- `services/demo.py: apply_scripted_decisions` calls the existing `response.approve_review` for each open
  review whose containment can execute. That is the same path as the Approve button: analyst
  authorization record, containment controller and adapter, switch read-back, incident `INC-2026-0043`
  with its evidence bundle, then an assessment run. The policy decision and its `critical_assets`
  guard are unchanged and the approval note acknowledges the guard. Reviews that cannot execute stay
  open.
- It runs after the flagship on server start (`SENTINEL_AUTO_DEMO=1`, the hosted demo) and from
  `POST /api/demo/run`. It is on by default; `SENTINEL_DEMO_ANALYST=0`, the body
  `{"scripted_analyst": false}`, or unticking the option in the Overview's replay dialog leave the
  review for a person. `make demo` and `make demo-2` do not use it, so their documented results are
  unchanged.
- The authorization record carries `channel: "scripted-demo"`; the Incidents queue shows a *scripted
  demo* tag and a note explaining it, the incident ledger reads "tlee (scripted demo)", the decision
  tab and the Overview's containment strip say so too. The flagship's authorization stays automatic.
- The replay window now ends at the first whole minute after the last record (21:17 rather than
  21:30), and the particles and wire console stop at the switch clock, so the end-of-record hold shows
  the second quarantine.
- The incident view's traffic loop is anchored on the detection time, not the incident time (an
  approved review opens its incident long after the detection fired).

Results: 88 backend tests (3 new: approval through the workflow, startup with the scripted analyst,
switching it off), playback check 25/25 (adds: the demo analyst's quarantine plays), validation 9/9,
UI audit 76/76 in demo state; baseline state fails only `/incidents/INC-2026-0042` (404 before the
replay, as before).
- `scripts/screenshots.py` starts its temporary server with the demo analyst off, captures the analyst
  approval dialog while the review is open, then resets and replays that temporary server with the
  scripted analyst, so every other image shows the hosted state. It never resets a server given with
  `--base`.

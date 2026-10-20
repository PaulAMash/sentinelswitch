import { useEffect, useMemo, useRef, useState } from 'react'
import type { Alert, TelemetryFeed } from '../../lib/api'
import { useMedia } from '../../lib/hooks'
import { FAMILIES, FAMILY_LABEL, binWire, decodeWire, recordDensity, upper, type Family } from '../../lib/wire'
import { SEVERITIES, SOURCES, fmtClock, fmtSpan, ms, sev3, type AlertFilter, type Sev3, type Window } from '../../lib/telemetry'
import { playback, usePlayback } from '../../lib/playback'
import { vlanName } from '../../lib/format'
import { Segmented } from '../ui'
import { Icon } from '../Icons'
import { Chip, ResponseChip, StatusChip } from '../status'
import { DataTable, Cell2 } from '../table'
import { SignalField, describeNode, type Pulse } from './SignalField'
import { Scrubber } from './Scrubber'
import { PlaybackBar } from './PlaybackBar'
import { AlertInspector, FieldSummary, NodeInspector } from './Inspector'
import { FlowCanvas } from './FlowCanvas'
import { ContainmentStrip } from './Containment'
import { WireTap } from './WireTap'
import { buildField, containmentAt, containmentKey, containmentWindows, layoutField, streamAlerts, type ClusterId, type FieldInputs, type FieldNode, type FillMode, type Preset } from './model'

const BIN = 15 * 60_000
const PULSE_MS = 1500
/** bins of the recorded-traffic lanes and of quiet-stretch pacing */
const LANE_BIN = 5 * 60_000
/** quiet-stretch pacing aims for at least this many recorded lines per real second */
const TARGET_RPS = 100
const PACE_STEPS = [10, 6, 4, 3, 2, 1.5, 1]
/** auto pace slows to this around a recorded alert, from a minute before to 90 s after */
const SLOW_PACE = 0.15
const SLOW_BEFORE = 60_000
const SLOW_AFTER = 90_000
/** around a containment action (12 s before to 5 s after) the clock runs at this many simulated ms per real second */
const DEEP_RATE = 4000
const DEEP_BEFORE = 12_000
const DEEP_AFTER = 5_000
const FAMILY_SHORT: Record<Family, string> = { tls: 'TLS', dns: 'DNS', web: 'HTTP', file: 'file/RPC', admin: 'SSH/RDP', dir: 'directory', infra: 'infra', other: 'other' }

/** Span behind the playhead that counts as "recent" activity: a twelfth of the window, 15–60 minutes. */
function recentSpan(w: Window | null): number {
  if (!w) return 60 * 60_000
  return Math.max(15 * 60_000, Math.min(60 * 60_000, (w.end - w.start) / 12))
}

export interface SignalConsoleProps {
  inputs: FieldInputs
  /** dataset day boundaries (UTC) */
  domain: Window
  day: string
  /** simulated switch clock */
  now: number | null
  /** newest simulated time with recorded data (switch clock or latest record) */
  recordedEnd: number
  traffic?: { ts: string; connections: number }[]
  initialNode?: string | null
  /** recorded Zeek / RADIUS / syslog lines of the dataset day (GET /api/telemetry); the field plays without it */
  wireFeed?: TelemetryFeed | null
}

type View = 'field' | 'list'

/**
 * The Network Signal Field with the shared playback clock. The playhead walks the recorded alerts,
 * incidents, reviews and containment actions in time order and the field shows what those records say
 * at that moment. Playback only reads; it never generates events or calls the API.
 */
export function SignalConsole(p: SignalConsoleProps) {
  const pb = usePlayback()
  const stageRef = useRef<HTMLDivElement>(null)
  const [preset, setPreset] = useState<Preset>('wide')
  const [view, setView] = useState<View>('field')
  const [fill, setFill] = useState<FillMode>('recent')
  const [sevs, setSevs] = useState<Set<Sev3>>(() => new Set(SEVERITIES))
  const [srcs, setSrcs] = useState<Set<string>>(() => new Set(SOURCES))
  const [focus, setFocus] = useState<ClusterId | null>(null)
  const [selNode, setSelNode] = useState<string | null>(p.initialNode ?? null)
  const [selAlert, setSelAlert] = useState<Alert | null>(null)
  const [hover, setHover] = useState<string | null>(null)
  const [pulses, setPulses] = useState<(Pulse & { until: number })[]>([])
  const [arrive, setArrive] = useState(true)
  const [fresh, setFresh] = useState<Set<string>>(new Set())
  const [fams, setFams] = useState<Set<Family>>(() => new Set(FAMILIES))
  const reduce = useMedia('(prefers-reduced-motion: reduce)')
  const wire = useMemo(() => (p.wireFeed ? decodeWire(p.wireFeed) : null), [p.wireFeed])
  // nothing after the switch clock is replayed, so the lanes stop there too
  const lanes = useMemo(() => (wire ? binWire(wire, p.domain.start, p.domain.end, LANE_BIN, p.recordedEnd) : null), [wire, p.domain.start, p.domain.end, p.recordedEnd])

  // auto pace: where few lines were recorded the clock runs up to 10× faster, and around a recorded alert or
  // containment action it slows down so the moment can be followed (the times shown stay true)
  useEffect(() => {
    if (!wire) return
    const dens = recordDensity(wire, p.inputs.alerts, p.domain.start, p.domain.end, LANE_BIN)
    const acts = Float64Array.from(p.inputs.actions.flatMap((a) => [a.applied_at, a.verified_at].filter(Boolean).map((x) => ms(x as string))).sort((a, b) => a - b))
    const marks = Float64Array.from([...p.inputs.alerts.map((a) => ms(a.ts)), ...acts].sort((a, b) => a - b))
    const near = (arr: Float64Array, t: number, before: number, after: number) => {
      const i = upper(arr, t + before)
      return i > 0 && arr[i - 1] >= t - after
    }
    return playback.setPacing((t, rate) => {
      // a containment action is the moment to watch: the burst before it, the move and the read-back
      if (near(acts, t, DEEP_BEFORE, DEEP_AFTER)) return DEEP_RATE / rate
      if (near(marks, t, SLOW_BEFORE, SLOW_AFTER)) return SLOW_PACE
      const k = Math.floor((t - p.domain.start) / LANE_BIN)
      // look one bin ahead so the clock slows before a burst, not inside it
      const d = Math.max(dens[k] ?? 0, dens[k + 1] ?? 0)
      const want = TARGET_RPS / Math.max((d / LANE_BIN) * rate, 1e-9)
      return PACE_STEPS.find((x) => x <= want) ?? 1
    })
  }, [wire, p.inputs.alerts, p.inputs.actions, p.domain.start, p.domain.end])

  const hasData = p.inputs.alerts.some((a) => {
    const x = ms(a.ts)
    return x >= p.domain.start && x < p.domain.end
  })
  // hand the dataset bounds to the shared clock; it starts playing the first time it is configured
  useEffect(() => {
    playback.configure(p.domain, p.recordedEnd, hasData)
    if (!hasData) playback.pause()
  }, [p.domain, p.recordedEnd, hasData])

  useEffect(() => {
    const t = setTimeout(() => setArrive(false), 1600)
    return () => clearTimeout(t)
  }, [])

  // choose the portrait arrangement on narrow stages
  useEffect(() => {
    const el = stageRef.current
    if (!el || typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(([e]) => setPreset(e.contentRect.width < 600 ? 'tall' : 'wide'))
    ro.observe(el)
    return () => ro.disconnect()
  }, [view])

  const win = pb.window ?? p.domain
  // windows end on the 15-minute grid at the recorded end, like the presets: nothing is recorded later
  const limit = Math.min(p.domain.end, p.domain.start + Math.ceil((p.recordedEnd - p.domain.start) / BIN) * BIN)
  const t = pb.ready ? pb.t : win.end
  const recentMs = recentSpan(win)
  const filter: AlertFilter = useMemo(() => ({ severities: sevs, sources: srcs }), [sevs, srcs])

  // records that arrived through a server-event refresh are marked new; the first load is not
  const seen = useRef<Set<string> | null>(null)
  useEffect(() => {
    const ids = new Set(p.inputs.alerts.map((a) => a.id))
    if (seen.current) {
      const added = p.inputs.alerts.filter((a) => !seen.current!.has(a.id))
      if (added.length) {
        setFresh(new Set(added.map((a) => a.id)))
        seen.current = ids
        const tm = setTimeout(() => setFresh(new Set()), 8000)
        return () => clearTimeout(tm)
      }
    }
    seen.current = ids
  }, [p.inputs.alerts])

  // as the playhead advances naturally, every alert it passes pulses its port once
  const prevT = useRef<number | null>(null)
  useEffect(() => {
    const prev = prevT.current
    prevT.current = t
    if (pb.change !== 'tick' || prev == null || t <= prev) return
    const passed = p.inputs.alerts.filter((a) => {
      const x = ms(a.ts)
      return x > prev && x <= t && a.interface && sevs.has(sev3(a.severity)) && srcs.has(a.source)
    })
    if (!passed.length) return
    const until = performance.now() + PULSE_MS
    setPulses((ps) => [...ps.filter((x) => x.until > performance.now()), ...passed.map((a) => ({ key: `play-${a.id}-${pb.loops}`, node: a.interface!, sev: sev3(a.severity), until }))])
  }, [t, pb.change, pb.loops, p.inputs.alerts, sevs, srcs])

  // prune finished pulses
  useEffect(() => {
    if (!pulses.length) return
    const tm = setTimeout(() => {
      const now = performance.now()
      setPulses((ps) => ps.filter((x) => x.until > now))
    }, 400)
    return () => clearTimeout(tm)
  }, [pulses])

  const containment = useMemo(() => containmentAt(p.inputs, t, recentMs, p.recordedEnd), [p.inputs, t, recentMs, p.recordedEnd])
  const ckey = containmentKey(containment)
  // geometry only changes when a port enters or leaves quarantine
  const geo = useMemo(() => layoutField(p.inputs.sw, preset, p.inputs.coverage, containment.quarantined), [p.inputs.sw, preset, p.inputs.coverage, ckey]) // eslint-disable-line react-hooks/exhaustive-deps
  const model = useMemo(() => buildField(p.inputs, geo, preset, { t, start: win.start, recentMs, mode: fill, filter, containment }), [p.inputs, geo, preset, t, win.start, recentMs, fill, filter, containment])
  const byId = useMemo(() => new Map(model.nodes.map((n) => [n.id, n])), [model.nodes])
  const stream = useMemo(() => streamAlerts(p.inputs, byId, win.start, t, filter, focus), [p.inputs, byId, win.start, t, filter, focus])
  const totalInWindow = useMemo(() => p.inputs.alerts.filter((a) => ms(a.ts) >= win.start && ms(a.ts) <= win.end && sevs.has(sev3(a.severity)) && srcs.has(a.source)).length, [p.inputs.alerts, win.start, win.end, sevs, srcs])
  const filteredForTimeline = useMemo(() => p.inputs.alerts.filter((a) => sevs.has(sev3(a.severity)) && srcs.has(a.source)), [p.inputs.alerts, sevs, srcs])
  const alertsAsc = useMemo(() => [...filteredForTimeline].sort((a, b) => ms(a.ts) - ms(b.ts)), [filteredForTimeline])
  const alertT = useMemo(() => Float64Array.from(alertsAsc.map((a) => ms(a.ts))), [alertsAsc])
  const names = useMemo(() => {
    const m = new Map<string, string>()
    for (const d of p.inputs.devices) if (d.ip) m.set(d.ip, d.hostname)
    if (p.inputs.sw.management_ip) m.set(p.inputs.sw.management_ip, p.inputs.sw.hostname)
    return m
  }, [p.inputs.devices, p.inputs.sw])
  // recorded containment actions: the callout on the field and the bands on the timeline
  const cwin = useMemo(() => containmentWindows(p.inputs.actions), [p.inputs.actions])
  const contain = useMemo(
    () =>
      cwin.map((w) => ({
        start: w.applied,
        end: w.restored ?? limit,
        kind: (w.action.action === 'quarantine_vlan' ? 'quarantine' : 'shutdown') as 'quarantine' | 'shutdown',
        label: `${w.action.interface ?? 'port'} ${w.action.action === 'quarantine_vlan' ? `VLAN ${w.action.from_vlan} → ${w.action.to_vlan}` : 'shut down'} at ${fmtClock(w.applied, true)}${w.restored ? `, restored ${fmtClock(w.restored, true)}` : ''}${w.action.incident_id ? ` (${w.action.incident_id})` : ''}`,
      })),
    [cwin, limit],
  )
  const famCounts = useMemo(() => {
    const c = Object.fromEntries(FAMILIES.map((f) => [f, 0])) as Record<Family, number>
    if (!wire) return c
    const end = Math.min(win.end, p.recordedEnd)
    for (let i = upper(wire.t, win.start), j = upper(wire.t, end); i < j; i++) c[FAMILIES[wire.fam[i]]]++
    return c
  }, [wire, win.start, win.end, p.recordedEnd])
  const selFlow = selAlert ? model.flows.find((f) => f.id === selAlert.id) ?? null : null
  const travel = useMemo(() => new Set([...pulses.map((x) => x.key.replace(/^play-/, '').replace(/-\d+$/, '')), ...fresh]), [pulses, fresh])
  const recentIds = useMemo(() => new Set(model.flows.map((f) => f.id).concat(model.nodes.flatMap((n) => n.alerts.map((a) => a.id)))), [model])

  const selectAlert = (a: Alert | null) => {
    setSelAlert(a)
    setSelNode(null)
    if (a?.interface) setPulses((ps) => [...ps, { key: `sel-${a.id}-${performance.now()}`, node: a.interface!, sev: sev3(a.severity), until: performance.now() + PULSE_MS }])
  }
  const selectNode = (id: string | null) => {
    setSelNode(id)
    setSelAlert(null)
  }
  const toggle = <T,>(set: Set<T>, v: T, apply: (s: Set<T>) => void) => {
    const n = new Set(set)
    if (n.has(v)) {
      if (n.size > 1) n.delete(v)
    } else n.add(v)
    apply(n)
  }
  const inWinAll = p.inputs.alerts.filter((a) => {
    const x = ms(a.ts)
    return x >= win.start && x <= win.end
  })
  const sevCount = (s: Sev3) => inWinAll.filter((a) => sev3(a.severity) === s).length
  const srcCount = (s: string) => inWinAll.filter((a) => a.source === s).length
  const hovered = hover ? byId.get(hover) : null
  const selectedNode = selNode ? byId.get(selNode) ?? null : null
  const modeLabel = !hasData ? 'NO RECORDED EVENTS' : pb.playing ? (pb.holding ? 'END OF RECORD' : pb.pace > 1 ? `PLAYBACK ×${pb.pace} QUIET` : pb.pace < 1 ? 'PLAYBACK · SLOW-MOTION' : 'PLAYBACK') : 'PAUSED'

  return (
    <section className="sig instrument" aria-labelledby="sig-title">
      <header className="sig-head">
        <div className="sig-id">
          <div className="sig-eyebrow">
            <span className="idx">01</span> Network signal field
          </div>
          <h2 id="sig-title">SW01 access layer</h2>
          <p className="sig-desc">Each hexagon is a switch interface, grouped by operational VLAN. Playback walks the recorded day; the field shows what the records say at the playhead.</p>
        </div>
        <div className="sig-controls">
          <Segmented
            label="Activity shown as fill"
            options={[
              { id: 'recent', label: `fill: last ${fmtSpan(recentMs)}` },
              { id: 'window', label: 'since window start' },
            ]}
            value={fill}
            onChange={setFill}
          />
          <Segmented
            label="Display"
            options={[
              { id: 'field', label: 'Field' },
              { id: 'list', label: 'List' },
            ]}
            value={view}
            onChange={setView}
          />
        </div>
      </header>

      <div className="sig-filters">
        <div className="sig-filter" role="group" aria-label="Severity filter">
          <span className="sig-filter-k">severity</span>
          {SEVERITIES.map((s) => (
            <button key={s} type="button" className={`fchip sev-${s} ${sevs.has(s) ? 'on' : ''}`} aria-pressed={sevs.has(s)} onClick={() => toggle(sevs, s, setSevs)}>
              <span className={`sev-dot ${s}`} aria-hidden="true" />
              {s}
              <span className="n mono">{sevCount(s)}</span>
            </button>
          ))}
        </div>
        <div className="sig-filter" role="group" aria-label="Detection source filter">
          <span className="sig-filter-k">source</span>
          {SOURCES.map((s) => (
            <button key={s} type="button" className={`fchip src ${srcs.has(s) ? 'on' : ''}`} aria-pressed={srcs.has(s)} onClick={() => toggle(srcs, s, setSrcs)}>
              {s}
              <span className="n mono">{srcCount(s)}</span>
            </button>
          ))}
        </div>
        {wire && (
          <div className="sig-filter" role="group" aria-label="Recorded traffic filter (service families)">
            <span className="sig-filter-k">traffic</span>
            {FAMILIES.map((f) => (
              <button key={f} type="button" className={`fchip svc ${fams.has(f) ? 'on' : ''}`} aria-pressed={fams.has(f)} title={`${FAMILY_LABEL[f]}: recorded Zeek connections`} onClick={() => toggle(fams, f, setFams)}>
                <span className={`svc-dot svc-${f}`} aria-hidden="true" />
                {FAMILY_SHORT[f]}
                <span className="n mono">{famCounts[f]}</span>
              </button>
            ))}
          </div>
        )}
        <span className="sig-filter-note dim">counts: selected window</span>
      </div>
      <div className="sig-body">
        <div className="sig-main">
          {view === 'field' ? (
            <div className="sig-stage" ref={stageRef}>
              <div className="sig-frame tl mono" aria-hidden="true">
                {p.inputs.sw.hostname} · {p.inputs.sw.model} · {p.inputs.sw.interfaces.length} interfaces
              </div>
              <div className={`sig-frame tr mono ${pb.playing ? 'live' : ''}`}>
                {hasData && (
                  <button type="button" className="sig-mini-play" onClick={() => playback.toggle()} aria-label={pb.playing ? 'Pause playback' : 'Play'} title={pb.playing ? 'Pause' : 'Play'}>
                    {pb.playing ? <Icon.pause /> : <Icon.play />}
                  </button>
                )}
                <span>
                  {modeLabel} · {fmtClock(t)} UTC · simulated
                </span>
              </div>
              <div className="sf-wrap">
              <SignalField
                model={model}
                selectedNode={selNode}
                selectedFlow={selFlow}
                selectedAlertPort={selAlert && !selFlow ? selAlert.interface : null}
                focusCluster={focus}
                pulses={pulses}
                travel={travel}
                arrive={arrive}
                playing={pb.playing}
                onSelectNode={selectNode}
                onHoverNode={setHover}
                onFocusCluster={setFocus}
              />
              {wire && !reduce && <FlowCanvas model={model} wire={wire} alerts={alertsAsc} families={fams} actions={p.inputs.actions} />}
              </div>
              <div className="sig-frame bl" aria-live="polite">
                {hovered ? describeNode(hovered) : focus ? `focus · ${model.clusters.find((c) => c.id === focus)?.title ?? ''} — select the label again to clear` : 'hover or tab to a port · arrows move · Enter selects · Esc clears'}
              </div>
            </div>
          ) : (
            <div className="sig-list">
              <DataTable
                cards="narrow"
                compact
                rows={[...model.nodes].sort((a, b) => b.alerts.length - a.alerts.length || a.id.localeCompare(b.id, undefined, { numeric: true }))}
                rowKey={(n) => n.id}
                onRowActivate={(n) => selectNode(n.id)}
                selectedKey={selNode}
                label="Interfaces at the playhead"
                columns={[
                  { key: 'port', header: 'port', className: 'mono', render: (n: FieldNode) => n.id },
                  { key: 'ep', header: 'endpoint', render: (n) => <Cell2 primary={n.device?.hostname ?? (n.unknown ? 'unregistered' : '—')} secondary={n.ip ?? undefined} /> },
                  { key: 'vlan', header: 'vlan', className: 'mono', render: (n) => (n.vlan !== null ? vlanName(n.vlan) : 'trunk') },
                  { key: 'state', header: 'port state', hideBelow: 700, render: (n) => <StatusChip value={n.state} /> },
                  { key: 'alerts', header: fill === 'recent' ? `alerts · ${fmtSpan(recentMs)}` : 'alerts', align: 'right', render: (n) => (n.alerts.length ? <span className="mono">{n.alerts.length}</span> : <span className="faint">0</span>) },
                  { key: 'sev', header: 'max severity', hideBelow: 900, render: (n) => (n.maxSev ? <Chip kind={n.maxSev}>{n.maxSev}</Chip> : <span className="faint">—</span>) },
                  {
                    key: 'resp',
                    header: 'response',
                    render: (n) =>
                      n.response === 'contained' ? (
                        <Chip kind="contained">contained</Chip>
                      ) : n.response === 'review' ? (
                        <Chip kind="pending">awaiting authorization</Chip>
                      ) : n.response === 'held' ? (
                        <Chip kind="held">hold</Chip>
                      ) : n.response === 'restored' ? (
                        <Chip kind="restored">restored</Chip>
                      ) : n.response === 'incident' && n.incidentState ? (
                        <ResponseChip state={n.incidentState} />
                      ) : (
                        <span className="faint">—</span>
                      ),
                  },
                ]}
              />
            </div>
          )}
          <ContainmentStrip windows={cwin} t={t} byId={byId} incidents={p.inputs.incidents} coverage={p.inputs.coverage} wire={wire} />
          {wire && <WireTap wire={wire} alerts={alertsAsc} alertT={alertT} names={names} families={fams} />}
          <div className="sig-transport">
        <PlaybackBar s={pb} disabled={!hasData} note={!hasData ? 'no recorded alerts in the dataset day' : undefined} />
        <Scrubber
          alerts={filteredForTimeline}
          domain={p.domain}
          binMs={BIN}
          window={win}
          onWindow={(w) => (w.start <= p.domain.start && w.end >= limit ? playback.setPreset('day') : playback.setWindow(w))}
          limit={limit}
          traffic={p.traffic}
          lanes={lanes}
          contain={contain}
          now={p.now}
          playback={hasData ? { t, onSeek: playback.seek, onToggle: playback.toggle } : undefined}
          label="Alert timeline for the signal field"
        />
          </div>

          <FieldLegend recent={fmtSpan(recentMs)} wire={!!wire} />
        </div>

        <aside className="sig-side" aria-label="Inspector and event stream">
          <div className="sig-insp" aria-live="polite">
            {selectedNode ? <NodeInspector n={selectedNode} t={t} onSelectAlert={selectAlert} /> : selAlert ? <AlertInspector a={selAlert} flow={selFlow} model={model} /> : <FieldSummary model={model} played={stream.length} total={totalInWindow} t={t} recent={fmtSpan(recentMs)} />}
            {(selectedNode || selAlert) && (
              <button type="button" className="btn sm ghost insp-clear" onClick={() => selectNode(null)} aria-label="Clear selection">
                ×
              </button>
            )}
          </div>
          <div className="sig-stream">
            <div className="sig-stream-head">
              <span className="eyebrow">Event stream</span>
              <span className="mono dim small">
                {stream.length} of {totalInWindow} · to {fmtClock(t)}
              </span>
            </div>
            <ol className="stream" aria-label="Alerts from the window start to the playhead, newest first">
              {stream.length === 0 && <li className="stream-empty">{hasData ? 'No alerts yet at this point of the window.' : 'No recorded alerts match the window and filters.'}</li>}
              {stream.map((a) => {
                const on = selAlert?.id === a.id
                const rel = !on && !!selNode && a.interface === selNode
                const sv = sev3(a.severity)
                return (
                  <li key={a.id} className="ev-li">
                    <button type="button" className={`ev ${on ? 'on' : ''} ${rel ? 'rel' : ''} ${recentIds.has(a.id) ? 'recent' : ''} ${fresh.has(a.id) ? 'fresh' : ''}`} onClick={() => selectAlert(selAlert?.id === a.id ? null : a)} aria-pressed={selAlert?.id === a.id}>
                      <span className={`ev-bar ${sv}`} aria-hidden="true" />
                      <span className="ev-t mono">{fmtClock(ms(a.ts), true)}</span>
                      <span className="ev-s">{a.signature.replace(/^SENTINELSWITCH /, '')}</span>
                      <span className="ev-m">
                        <span className={`sevtag ${sv}`}>{sv}</span>
                        <span className="mono strong-2">{a.interface ?? '—'}</span>
                        {a.device && <span className="strong-2">{a.device}</span>}
                        <span>{a.source}</span>
                        <span className="ev-st">{a.status}</span>
                        {fresh.has(a.id) && <span className="newtag">new</span>}
                      </span>
                    </button>
                  </li>
                )
              })}
            </ol>
          </div>
        </aside>
      </div>
    </section>
  )
}

function FieldLegend({ recent, wire }: { recent: string; wire: boolean }) {
  return (
    <div className="sig-legend" aria-label="Legend">
      <span className="lg-group">
        <span className="lg-k">fill · alerts</span>
        <span className="lg">
          <i className="hxs act low" /> low
        </span>
        <span className="lg">
          <i className="hxs act medium" /> medium
        </span>
        <span className="lg">
          <i className="hxs act high" /> high
        </span>
        <span className="lg dim">faint · earlier than {recent}</span>
      </span>
      <span className="lg-group">
        <span className="lg-k">outline · port</span>
        <span className="lg">
          <i className="hxs ps connected" /> connected
        </span>
        <span className="lg">
          <i className="hxs ps notconnect" /> not connected
        </span>
        <span className="lg">
          <i className="hxs ps disabled" /> shut / unused
        </span>
        <span className="lg">
          <i className="hxs ps trunk" /> trunk
        </span>
        <span className="lg">
          <i className="hxs ps monitor" /> SPAN destination
        </span>
      </span>
      <span className="lg-group">
        <span className="lg-k">ring · response</span>
        <span className="lg">
          <i className="hxs rs contained" /> contained
        </span>
        <span className="lg">
          <i className="hxs rs review" /> awaiting authorization
        </span>
        <span className="lg">
          <i className="hxs rs incident" /> open incident
        </span>
        <span className="lg">
          <i className="hxs rs restored" /> restored
        </span>
      </span>
      {wire && (
        <span className="lg-group">
          <span className="lg-k">motion · recorded lines</span>
          <span className="lg">
            <i className="lg-particle" /> one recorded connection (colour: service) via the switch
          </span>
          <span className="lg">
            <i className="hxs lg-flash" /> RADIUS, syslog or alert at a port
          </span>
          <span className="lg">
            <i className="lg-core" /> core ring: connections per second
          </span>
        </span>
      )}
      <span className="lg-group">
        <span className="lg">
          <i className="lnk" /> recorded flow (alert source → destination)
        </span>
        <span className="lg dim">lattice and spoke motion are decorative</span>
      </span>
    </div>
  )
}

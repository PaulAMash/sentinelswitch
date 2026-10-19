import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { Alert } from '../../lib/api'
import { SEVERITIES, SOURCES, fmtClock, ms, sev3, type AlertFilter, type Sev3, type Window } from '../../lib/telemetry'
import { vlanName } from '../../lib/format'
import { Icon } from '../Icons'
import { Segmented } from '../ui'
import { Chip, ResponseChip, StatusChip } from '../status'
import { DataTable, Cell2 } from '../table'
import { SignalField, describeNode, type Pulse } from './SignalField'
import { Scrubber } from './Scrubber'
import { AlertInspector, FieldSummary, NodeInspector } from './Inspector'
import { buildField, layoutField, streamAlerts, type ClusterId, type FieldInputs, type FieldNode, type Preset } from './model'

const BIN = 15 * 60_000
const PULSE_MS = 1500
const PLAY_MS_FULL_DAY = 16_000

export interface SignalConsoleProps {
  inputs: FieldInputs
  /** dataset day boundaries (UTC) */
  domain: Window
  day: string
  /** simulated switch clock, used for the "last N hours" presets */
  now: number | null
  traffic?: { ts: string; connections: number }[]
  initialNode?: string | null
}

type View = 'field' | 'list'

/**
 * The Network Signal Field with its controls: time window (brushable timeline, presets, replay),
 * severity and source filters, colony focus, inspector and synchronized event stream. All state is
 * derived from the records passed in; replay walks the recorded alert timestamps, it does not
 * generate events.
 */
export function SignalConsole(p: SignalConsoleProps) {
  const stageRef = useRef<HTMLDivElement>(null)
  const [preset, setPreset] = useState<Preset>('wide')
  const [view, setView] = useState<View>('field')
  const [rawWin, setWin] = useState<Window>(p.domain)
  // a window outside a changed domain (e.g. after a reset re-seeds the day) falls back to the full day
  const win = rawWin.start < p.domain.start || rawWin.end > p.domain.end ? p.domain : rawWin
  const [sevs, setSevs] = useState<Set<Sev3>>(() => new Set(SEVERITIES))
  const [srcs, setSrcs] = useState<Set<string>>(() => new Set(SOURCES))
  const [focus, setFocus] = useState<ClusterId | null>(null)
  const [selNode, setSelNode] = useState<string | null>(p.initialNode ?? null)
  const [selAlert, setSelAlert] = useState<Alert | null>(null)
  const [hover, setHover] = useState<string | null>(null)
  const [playhead, setPlayhead] = useState<number | null>(null)
  const [pulses, setPulses] = useState<(Pulse & { until: number })[]>([])
  const [arrive, setArrive] = useState(true)
  const [fresh, setFresh] = useState<Set<string>>(new Set())

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

  // alerts that arrive through a server-event refresh pulse once; the first load does not
  const seen = useRef<Set<string> | null>(null)
  useEffect(() => {
    const ids = new Set(p.inputs.alerts.map((a) => a.id))
    if (seen.current) {
      const added = p.inputs.alerts.filter((a) => !seen.current!.has(a.id))
      if (added.length) {
        const until = performance.now() + PULSE_MS
        setPulses((ps) => [...ps, ...added.filter((a) => a.interface).map((a) => ({ key: `new-${a.id}`, node: a.interface!, sev: sev3(a.severity), until }))])
        setFresh(new Set(added.map((a) => a.id)))
        const t = setTimeout(() => setFresh(new Set()), 6000)
        seen.current = ids
        return () => clearTimeout(t)
      }
    }
    seen.current = ids
  }, [p.inputs.alerts])

  // prune finished pulses
  useEffect(() => {
    if (!pulses.length) return
    const t = setTimeout(() => {
      const now = performance.now()
      setPulses((ps) => ps.filter((x) => x.until > now))
    }, 250)
    return () => clearTimeout(t)
  }, [pulses])

  const filter: AlertFilter = useMemo(() => ({ severities: sevs, sources: srcs }), [sevs, srcs])
  const effWin: Window = playhead != null ? { start: win.start, end: playhead } : win
  const geo = useMemo(() => layoutField(p.inputs.sw, preset, p.inputs.coverage), [p.inputs.sw, preset, p.inputs.coverage])
  const model = useMemo(() => buildField(p.inputs, geo, preset, effWin, filter), [p.inputs, geo, preset, effWin.start, effWin.end, filter]) // eslint-disable-line react-hooks/exhaustive-deps
  const byId = useMemo(() => new Map(model.nodes.map((n) => [n.id, n])), [model.nodes])
  const stream = useMemo(() => streamAlerts(p.inputs, byId, effWin, filter, focus), [p.inputs, byId, effWin.start, effWin.end, filter, focus]) // eslint-disable-line react-hooks/exhaustive-deps
  const filteredForTimeline = useMemo(() => p.inputs.alerts.filter((a) => sevs.has(sev3(a.severity)) && srcs.has(a.source)), [p.inputs.alerts, sevs, srcs])
  const selFlow = selAlert ? model.flows.find((f) => f.id === selAlert.id) ?? null : null
  const travel = useMemo(() => new Set([...pulses.map((x) => x.key.replace(/^(new|play)-/, '')), ...fresh]), [pulses, fresh])

  // replay: walk the playhead through the recorded timestamps of the selected window
  const raf = useRef<number | null>(null)
  const stop = useCallback(() => {
    if (raf.current != null) cancelAnimationFrame(raf.current)
    raf.current = null
    setPlayhead(null)
  }, [])
  const play = () => {
    stop()
    const span = win.end - win.start
    const dur = Math.max(4000, (PLAY_MS_FULL_DAY * span) / (p.domain.end - p.domain.start))
    const t0 = performance.now()
    let last = win.start
    const fired = new Set<string>()
    const tick = (now: number) => {
      const k = Math.min(1, (now - t0) / dur)
      const head = win.start + k * span
      const step = Math.floor((head - win.start) / 60_000) * 60_000 + win.start
      if (step !== last || k === 1) {
        const newly = p.inputs.alerts.filter((a) => {
          const t = ms(a.ts)
          return t > last && t <= head && !fired.has(a.id) && a.interface && sevs.has(sev3(a.severity)) && srcs.has(a.source)
        })
        if (newly.length) {
          const until = performance.now() + PULSE_MS
          newly.forEach((a) => fired.add(a.id))
          setPulses((ps) => [...ps, ...newly.map((a) => ({ key: `play-${a.id}`, node: a.interface!, sev: sev3(a.severity), until }))])
        }
        last = head
        setPlayhead(k === 1 ? null : step)
      }
      if (k < 1) raf.current = requestAnimationFrame(tick)
      else raf.current = null
    }
    setPlayhead(win.start)
    raf.current = requestAnimationFrame(tick)
  }
  useEffect(() => () => stop(), [stop])

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
  const setPresetWindow = (hours: number | null) => {
    stop()
    if (hours == null || p.now == null) return setWin(p.domain)
    const end = Math.min(p.domain.end, Math.ceil(p.now / BIN) * BIN)
    setWin({ start: Math.max(p.domain.start, end - hours * 3600_000), end })
  }
  const inWinAll = p.inputs.alerts.filter((a) => {
    const t = ms(a.ts)
    return t >= effWin.start && t < effWin.end
  })
  const sevCount = (s: Sev3) => inWinAll.filter((a) => sev3(a.severity) === s).length
  const srcCount = (s: string) => inWinAll.filter((a) => a.source === s).length
  const hovered = hover ? byId.get(hover) : null
  const selectedNode = selNode ? byId.get(selNode) ?? null : null
  const isFull = win.start <= p.domain.start && win.end >= p.domain.end
  const hoursPreset = isFull ? 'day' : p.now != null && win.end === Math.min(p.domain.end, Math.ceil(p.now / BIN) * BIN) ? (win.end - win.start === 4 * 3600_000 ? '4h' : win.end - win.start === 3600_000 ? '1h' : 'custom') : 'custom'

  return (
    <section className="sig instrument" aria-labelledby="sig-title">
      <header className="sig-head">
        <div className="sig-id">
          <div className="sig-eyebrow">
            <span className="idx">01</span> Network signal field
          </div>
          <h2 id="sig-title">SW01 access layer</h2>
          <p className="sig-desc">Every hexagon is a switch interface, grouped by its operational VLAN. Fill shows alert activity in the selected window; outlines show port state; rings show response state. Layout is schematic.</p>
        </div>
        <div className="sig-controls">
          <div className="sig-filter" role="group" aria-label="Severity filter">
            {SEVERITIES.map((s) => (
              <button key={s} type="button" className={`fchip sev-${s} ${sevs.has(s) ? 'on' : ''}`} aria-pressed={sevs.has(s)} onClick={() => toggle(sevs, s, setSevs)}>
                <span className={`sev-dot ${s}`} aria-hidden="true" />
                {s}
                <span className="n mono">{sevCount(s)}</span>
              </button>
            ))}
          </div>
          <div className="sig-filter" role="group" aria-label="Detection source filter">
            {SOURCES.map((s) => (
              <button key={s} type="button" className={`fchip src ${srcs.has(s) ? 'on' : ''}`} aria-pressed={srcs.has(s)} onClick={() => toggle(srcs, s, setSrcs)}>
                {s}
                <span className="n mono">{srcCount(s)}</span>
              </button>
            ))}
          </div>
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

      <div className="sig-body">
        <div className="sig-main">
          {view === 'field' ? (
            <div className="sig-stage" ref={stageRef}>
              <div className="sig-frame tl mono" aria-hidden="true">
                {p.inputs.sw.hostname} · {p.inputs.sw.model} · {p.inputs.sw.interfaces.length} interfaces
              </div>
              <div className={`sig-frame tr mono ${playhead != null ? 'live' : ''}`}>{playhead != null ? `REPLAY · ${fmtClock(playhead)} UTC` : `SNAPSHOT · ${p.day} · simulated clock`}</div>
              <SignalField
                model={model}
                selectedNode={selNode}
                selectedFlow={selFlow}
                selectedAlertPort={selAlert && !selFlow ? selAlert.interface : null}
                focusCluster={focus}
                pulses={pulses}
                travel={travel}
                arrive={arrive}
                onSelectNode={selectNode}
                onHoverNode={setHover}
                onFocusCluster={setFocus}
              />
              <div className="sig-frame bl mono" aria-live="polite">
                {hovered ? describeNode(hovered) : focus ? `focus · ${model.clusters.find((c) => c.id === focus)?.title ?? ''} — select the label again to clear` : 'hover or tab to a port · arrows move · Enter selects · Esc clears'}
              </div>
            </div>
          ) : (
            <div className="sig-list">
              <DataTable
                compact
                rows={[...model.nodes].sort((a, b) => b.alerts.length - a.alerts.length || a.id.localeCompare(b.id, undefined, { numeric: true }))}
                rowKey={(n) => n.id}
                onRowActivate={(n) => selectNode(n.id)}
                selectedKey={selNode}
                label="Interfaces"
                columns={[
                  { key: 'port', header: 'port', className: 'mono', render: (n: FieldNode) => n.id },
                  { key: 'ep', header: 'endpoint', render: (n) => <Cell2 primary={n.device?.hostname ?? (n.unknown ? 'unregistered' : '—')} secondary={n.ip ?? undefined} /> },
                  { key: 'vlan', header: 'vlan', className: 'mono', render: (n) => (n.vlan !== null ? vlanName(n.vlan) : 'trunk') },
                  { key: 'state', header: 'port state', priority: 3, render: (n) => <StatusChip value={n.port.state} /> },
                  { key: 'alerts', header: 'alerts', align: 'right', render: (n) => (n.alerts.length ? <span className="mono">{n.alerts.length}</span> : <span className="faint">0</span>) },
                  { key: 'sev', header: 'max severity', priority: 2, render: (n) => (n.maxSev ? <Chip kind={n.maxSev}>{n.maxSev}</Chip> : <span className="faint">—</span>) },
                  { key: 'resp', header: 'response', render: (n) => (n.incidentState && n.response === 'contained' ? <ResponseChip state={n.incidentState} /> : n.response === 'review' ? <Chip kind="pending">awaiting authorization</Chip> : n.response === 'held' ? <Chip kind="held">hold</Chip> : n.response === 'incident' && n.incidentState ? <ResponseChip state={n.incidentState} /> : <span className="faint">—</span>) },
                ]}
              />
            </div>
          )}
          <div className="sig-time">
            <div className="sig-time-ctl">
              <Segmented
                label="Time window"
                options={[
                  { id: 'day', label: 'Day' },
                  { id: '4h', label: '4 h' },
                  { id: '1h', label: '1 h' },
                ]}
                value={hoursPreset === 'custom' ? ('' as 'day') : (hoursPreset as 'day')}
                onChange={(v) => setPresetWindow(v === 'day' ? null : v === '4h' ? 4 : 1)}
              />
              {playhead == null ? (
                <button type="button" className="btn sm" onClick={play} title="Replay the recorded alerts of the selected window in time order">
                  <Icon.play /> Replay window
                </button>
              ) : (
                <button type="button" className="btn sm primary" onClick={stop}>
                  <Icon.close /> Stop replay
                </button>
              )}
            </div>
            <Scrubber
              alerts={filteredForTimeline}
              domain={p.domain}
              binMs={BIN}
              window={win}
              onWindow={(w) => {
                stop()
                setWin(w)
              }}
              traffic={p.traffic}
              playhead={playhead}
              now={p.now}
              label="Alert timeline for the signal field"
            />
          </div>
          <FieldLegend />
        </div>

        <aside className="sig-side" aria-label="Inspector and event stream">
          <div className="sig-insp" aria-live="polite">
            {selectedNode ? <NodeInspector n={selectedNode} onSelectAlert={selectAlert} /> : selAlert ? <AlertInspector a={selAlert} flow={selFlow} model={model} /> : <FieldSummary model={model} visible={stream.length} window={effWin} day={p.day} />}
            {(selectedNode || selAlert) && (
              <button type="button" className="btn sm ghost insp-clear" onClick={() => selectNode(null)} aria-label="Clear selection">
                <Icon.close />
              </button>
            )}
          </div>
          <div className="sig-stream">
            <div className="sig-stream-head">
              <span className="eyebrow">Event stream</span>
              <span className="mono dim small">{stream.length} in window</span>
            </div>
            <ol className="stream" aria-label="Alerts in the selected window, newest first">
              {stream.length === 0 && <li className="stream-empty">No alerts match the window and filters.</li>}
              {stream.map((a) => {
                const on = selAlert?.id === a.id || (selNode && a.interface === selNode)
                return (
                  <li key={a.id}>
                    <button type="button" className={`ev ${on ? 'on' : ''} ${fresh.has(a.id) ? 'fresh' : ''}`} onClick={() => selectAlert(selAlert?.id === a.id ? null : a)} aria-pressed={selAlert?.id === a.id}>
                      <span className={`ev-bar ${sev3(a.severity)}`} aria-hidden="true" />
                      <span className="ev-t mono">{fmtClock(ms(a.ts), true)}</span>
                      <span className="ev-s clip">{a.signature.replace(/^SENTINELSWITCH /, '')}</span>
                      <span className="ev-m">
                        <span className={`sevtag ${sev3(a.severity)}`}>{sev3(a.severity)}</span>
                        <span className="mono">{a.interface ?? '—'}</span>
                        {a.device && <span>{a.device}</span>}
                        <span className="dim">{a.source}</span>
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

function FieldLegend() {
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
      </span>
      <span className="lg-group">
        <span className="lg">
          <i className="lnk" /> observed flow (alert source → destination)
        </span>
        <span className="lg dim">background lattice is decorative</span>
      </span>
    </div>
  )
}

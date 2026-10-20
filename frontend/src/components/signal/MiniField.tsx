import { useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { SEVERITIES, SOURCES, fmtClock, ms, type Window } from '../../lib/telemetry'
import { useMedia } from '../../lib/hooks'
import { FAMILIES, type Wire } from '../../lib/wire'
import { SignalField, describeNode } from './SignalField'
import { FlowCanvas } from './FlowCanvas'
import { LoopClock } from './clock'
import { buildField, containmentAt, layoutField, type FieldInputs, type Preset } from './model'

const ALL = { severities: new Set(SEVERITIES), sources: new Set<string>(SOURCES) }
const NONE = new Set<string>()
const ALL_FAMILIES = new Set(FAMILIES)
/** one pass of the incident replay lasts about this many real seconds */
const REPLAY_SECONDS = 12

export interface MiniReplay {
  /** recorded span to loop over (epoch ms) */
  start: number
  end: number
  /** the incident host: only its recorded connections are drawn */
  ip: string
}

/**
 * The signal field without its console, focused on one port: the port and every port it exchanged
 * alert traffic with stay lit, everything else recedes. Used where a single entity is under
 * investigation (incident workspace).
 */
export function MiniField({ inputs, window: w, focus, caption, wire, replay }: { inputs: FieldInputs; window: Window; focus: string | null; caption?: string; wire?: Wire | null; replay?: MiniReplay | null }) {
  const [sel, setSel] = useState<string | null>(focus)
  const [hover, setHover] = useState<string | null>(null)
  const [preset, setPreset] = useState<Preset>('wide')
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const el = ref.current
    if (!el || typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(([e]) => setPreset(e.contentRect.width < 520 ? 'tall' : 'wide'))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  // the incident view shows the present state of the twin over the whole dataset day
  const containment = useMemo(() => containmentAt(inputs, w.end, 0, -Infinity), [inputs, w.end])
  const geo = useMemo(() => layoutField(inputs.sw, preset, inputs.coverage, containment.quarantined), [inputs.sw, preset, inputs.coverage, containment])
  const model = useMemo(() => buildField(inputs, geo, preset, { t: w.end, start: w.start, recentMs: w.end - w.start, mode: 'window', filter: ALL, containment }), [inputs, geo, preset, w, containment])
  const byId = new Map(model.nodes.map((n) => [n.id, n]))
  const shown = hover ? byId.get(hover) : sel ? byId.get(sel) : null
  // the recorded traffic of the incident host around the incident, looping; nothing when motion is reduced
  const reduce = useMedia('(prefers-reduced-motion: reduce)')
  const clock = useMemo(() => (replay ? new LoopClock(replay.start, replay.end, (replay.end - replay.start) / REPLAY_SECONDS) : null), [replay?.start, replay?.end]) // eslint-disable-line react-hooks/exhaustive-deps
  const hosts = useMemo(() => (replay ? new Set([replay.ip]) : undefined), [replay?.ip]) // eslint-disable-line react-hooks/exhaustive-deps
  const alertsAsc = useMemo(() => [...inputs.alerts].sort((a, b) => ms(a.ts) - ms(b.ts)), [inputs.alerts])
  const clockRef = useRef<HTMLSpanElement>(null)
  useEffect(() => {
    if (!clock || reduce) return
    return clock.subscribeFrame((pos) => {
      if (clockRef.current) clockRef.current.textContent = fmtClock(pos, true)
    })
  }, [clock, reduce])
  const live = !!(wire && clock && replay && !reduce)
  return (
    <div className="mini-field" ref={ref}>
      {live && (
        <div className="mini-replay mono" aria-hidden="true">
          replay <span ref={clockRef} /> UTC · {replay!.ip} recorded connections · loop
        </div>
      )}
      <div className="sf-wrap">
        <SignalField model={model} selectedNode={sel} selectedFlow={null} selectedAlertPort={null} focusCluster={null} pulses={[]} travel={NONE} arrive={false} onSelectNode={(id) => setSel(id ?? focus)} onHoverNode={setHover} onFocusCluster={() => undefined} />
        {live && <FlowCanvas model={model} wire={wire!} alerts={alertsAsc} families={ALL_FAMILIES} clock={clock!} hosts={hosts} />}
      </div>
      <div className="mini-cap">
        <span className="mono small">{shown ? describeNode(shown) : caption}</span>
        <Link to="/" className="small">
          open the signal field
        </Link>
      </div>
    </div>
  )
}

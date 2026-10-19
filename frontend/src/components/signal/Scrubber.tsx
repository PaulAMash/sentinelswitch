import { useMemo, useRef, type KeyboardEvent, type PointerEvent } from 'react'
import type { Alert } from '../../lib/api'
import { binAlerts, fmtClock, fmtEnd, fmtSpan, ms, type Window } from '../../lib/telemetry'

const VB_W = 1000
const VB_H = 56

export interface ScrubberProps {
  alerts: Alert[]
  domain: Window
  binMs: number
  window: Window
  onWindow: (w: Window) => void
  /** optional SPAN connections per bucket, drawn as a faint backdrop on its own scale */
  traffic?: { ts: string; connections: number }[]
  playhead?: number | null
  now?: number | null
  label?: string
}

/**
 * Alert histogram across the dataset day with a brushable window. Drag on the track to select, drag
 * the window to move it, drag an edge to resize; arrow keys shift by one bin, Shift+arrows move the
 * end, Home or Escape restores the full day. Bins are 15 minutes of the simulated switch clock.
 */
export function Scrubber(p: ScrubberProps) {
  const ref = useRef<HTMLDivElement>(null)
  const drag = useRef<{ mode: 'new' | 'move' | 'start' | 'end'; x0: number; w0: Window } | null>(null)
  const span = p.domain.end - p.domain.start
  const bins = useMemo(() => binAlerts(p.alerts, p.domain.start, p.domain.end, p.binMs), [p.alerts, p.domain.start, p.domain.end, p.binMs])
  const peak = Math.max(0, ...bins.map((b) => b.total))
  const max = Math.max(1, peak)
  const bw = VB_W / bins.length
  const trafficPath = useMemo(() => {
    if (!p.traffic?.length) return null
    const pts = p.traffic.map((t) => ({ x: ((ms(t.ts) - p.domain.start) / span) * VB_W, v: t.connections })).filter((t) => t.x >= 0 && t.x <= VB_W)
    if (!pts.length) return null
    const tmax = Math.max(1, ...pts.map((t) => t.v))
    const y = (v: number) => VB_H - (v / tmax) * (VB_H - 6)
    return `M${pts[0].x.toFixed(1)},${VB_H} ` + pts.map((t) => `L${t.x.toFixed(1)},${y(t.v).toFixed(1)}`).join(' ') + ` L${pts[pts.length - 1].x.toFixed(1)},${VB_H} Z`
  }, [p.traffic, p.domain.start, span])

  const frac = (t: number) => Math.max(0, Math.min(1, (t - p.domain.start) / span))
  const snap = (t: number) => p.domain.start + Math.round((t - p.domain.start) / p.binMs) * p.binMs
  const clamp = (w: Window): Window => {
    let { start, end } = w
    if (end - start < p.binMs) end = start + p.binMs
    if (start < p.domain.start) {
      end += p.domain.start - start
      start = p.domain.start
    }
    if (end > p.domain.end) {
      start -= end - p.domain.end
      end = p.domain.end
    }
    return { start: Math.max(p.domain.start, start), end }
  }
  const tAt = (clientX: number) => {
    const r = ref.current!.getBoundingClientRect()
    return p.domain.start + ((clientX - r.left) / r.width) * span
  }
  const onDown = (e: PointerEvent<HTMLDivElement>) => {
    if (e.button !== 0) return
    const t = tAt(e.clientX)
    const target = (e.target as HTMLElement).dataset.part
    const isFull = p.window.start <= p.domain.start && p.window.end >= p.domain.end
    const mode = !isFull && (target === 'start' || target === 'end') ? target : !isFull && target === 'win' && t > p.window.start && t < p.window.end ? 'move' : 'new'
    drag.current = { mode, x0: t, w0: p.window }
    ref.current!.setPointerCapture(e.pointerId)
    if (mode === 'new') p.onWindow(clamp({ start: snap(t), end: snap(t) + p.binMs }))
  }
  const onMove = (e: PointerEvent<HTMLDivElement>) => {
    const d = drag.current
    if (!d) return
    const t = tAt(e.clientX)
    if (d.mode === 'new') {
      const a = snap(Math.min(d.x0, t))
      const b = snap(Math.max(d.x0, t))
      p.onWindow(clamp({ start: a, end: Math.max(b, a + p.binMs) }))
    } else if (d.mode === 'move') {
      const dt = snap(t - d.x0 + p.domain.start) - p.domain.start
      p.onWindow(clamp({ start: d.w0.start + dt, end: d.w0.end + dt }))
    } else if (d.mode === 'start') {
      p.onWindow(clamp({ start: Math.min(snap(t), d.w0.end - p.binMs), end: d.w0.end }))
    } else {
      p.onWindow(clamp({ start: d.w0.start, end: Math.max(snap(t), d.w0.start + p.binMs) }))
    }
  }
  const onUp = () => {
    drag.current = null
  }
  const onKey = (e: KeyboardEvent<HTMLDivElement>) => {
    const step = p.binMs
    if (e.key === 'Home' || e.key === 'Escape') {
      e.preventDefault()
      p.onWindow({ ...p.domain })
    } else if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
      e.preventDefault()
      const dt = e.key === 'ArrowLeft' ? -step : step
      p.onWindow(clamp(e.shiftKey ? { start: p.window.start, end: Math.max(p.window.start + step, p.window.end + dt) } : { start: p.window.start + dt, end: p.window.end + dt }))
    }
  }
  const full = p.window.start <= p.domain.start && p.window.end >= p.domain.end
  const wl = frac(p.window.start) * 100
  const wr = frac(p.window.end) * 100
  const ticks: number[] = []
  for (let h = 0; h <= 24; h += 3) ticks.push(h)
  return (
    <div className="scrub">
      <div
        ref={ref}
        className={`scrub-track ${full ? 'full' : ''}`}
        tabIndex={0}
        role="group"
        aria-label={`${p.label ?? 'Alert timeline'}: window ${fmtClock(p.window.start)} to ${fmtEnd(p.window.start, p.window.end)} UTC. Drag to select a range; arrow keys move it, Shift+arrows resize, Home resets to the full day.`}
        onPointerDown={onDown}
        onPointerMove={onMove}
        onPointerUp={onUp}
        onPointerCancel={onUp}
        onKeyDown={onKey}
      >
        <svg viewBox={`0 0 ${VB_W} ${VB_H}`} preserveAspectRatio="none" aria-hidden="true">
          {trafficPath && <path className="scrub-traffic" d={trafficPath} />}
          {bins.map((b, i) => {
            if (!b.total) return null
            const x = i * bw + 0.8
            const w = Math.max(1, bw - 1.6)
            const h = (v: number) => (v / max) * (VB_H - 4)
            const yl = VB_H - h(b.low)
            const ym = yl - h(b.medium)
            const yh = ym - h(b.high)
            return (
              <g key={i} className="scrub-bin">
                {b.low > 0 && <rect className="low" x={x} y={yl} width={w} height={h(b.low)} />}
                {b.medium > 0 && <rect className="medium" x={x} y={ym} width={w} height={h(b.medium)} />}
                {b.high > 0 && <rect className="high" x={x} y={yh} width={w} height={h(b.high)} />}
              </g>
            )
          })}
        </svg>
        {!full && (
          <>
            <div className="scrub-shade" style={{ left: 0, width: `${wl}%` }} />
            <div className="scrub-shade" style={{ left: `${wr}%`, right: 0 }} />
          </>
        )}
        <div className="scrub-win" data-part="win" style={{ left: `${wl}%`, width: `${wr - wl}%` }}>
          <span className="scrub-h" data-part="start" />
          <span className="scrub-h end" data-part="end" />
        </div>
        {p.now != null && frac(p.now) > 0 && frac(p.now) < 1 && <div className="scrub-now" style={{ left: `${frac(p.now) * 100}%` }} title={`switch clock ${fmtClock(p.now, true)} UTC`} />}
        {p.playhead != null && <div className="scrub-play" style={{ left: `${frac(p.playhead) * 100}%` }} />}
      </div>
      <div className="scrub-axis" aria-hidden="true">
        {ticks.map((h) => (
          <span key={h} style={{ left: `${(h / 24) * 100}%` }}>
            {String(h).padStart(2, '0')}
          </span>
        ))}
      </div>
      <div className="scrub-meta">
        <span className="mono">
          {fmtClock(p.window.start)}–{fmtEnd(p.window.start, p.window.end)} UTC · {fmtSpan(p.window.end - p.window.start)}
        </span>
        <span className="dim">{peak ? `bars: alerts per ${fmtSpan(p.binMs)} · peak ${peak}` : 'no alerts match the filters on this day'}</span>
        {trafficPath && <span className="dim">shaded: SPAN connections, own scale</span>}
      </div>
    </div>
  )
}

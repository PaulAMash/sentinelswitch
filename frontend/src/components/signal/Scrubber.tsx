import { useEffect, useMemo, useRef, type KeyboardEvent, type PointerEvent } from 'react'
import type { Alert } from '../../lib/api'
import { playback } from '../../lib/playback'
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
  now?: number | null
  label?: string
  /**
   * Playback mode: the histogram seeks the shared playhead (pausing playback) and the window is
   * chosen on the rail underneath. Without it the histogram itself brushes the window (Alerts page).
   */
  playback?: { t: number; onSeek: (t: number) => void; onToggle: () => void }
}

/**
 * Alert histogram across the dataset day (15-minute bins of the simulated switch clock). Bars after
 * the playhead are dimmed so the played part of the window reads at a glance.
 */
export function Scrubber(p: ScrubberProps) {
  const trackRef = useRef<HTMLDivElement>(null)
  const railRef = useRef<HTMLDivElement>(null)
  const headRef = useRef<HTMLDivElement>(null)
  const playedRef = useRef<HTMLDivElement>(null)
  const drag = useRef<{ zone: 'track' | 'rail'; mode: 'new' | 'move' | 'start' | 'end' | 'seek'; x0: number; w0: Window } | null>(null)
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
  const tAt = (el: HTMLElement, clientX: number) => {
    const r = el.getBoundingClientRect()
    return p.domain.start + Math.max(0, Math.min(1, (clientX - r.left) / r.width)) * span
  }
  const inWin = (t: number) => Math.max(p.window.start, Math.min(p.window.end, t))

  // the playhead follows the exact clock position every frame without re-rendering React
  useEffect(() => {
    if (!p.playback) return
    const place = (pos: number) => {
      const f = `${frac(pos) * 100}%`
      if (headRef.current) headRef.current.style.left = f
      if (playedRef.current) playedRef.current.style.width = `calc(${f} - ${frac(p.window.start) * 100}%)`
    }
    place(playback.position())
    return playback.subscribeFrame(place)
  })

  const brushDown = (zone: 'track' | 'rail', e: PointerEvent<HTMLDivElement>) => {
    const el = zone === 'track' ? trackRef.current! : railRef.current!
    const t = tAt(el, e.clientX)
    const part = (e.target as HTMLElement).dataset.part
    const mode = part === 'start' || part === 'end' ? part : part === 'win' && t > p.window.start && t < p.window.end ? 'move' : 'new'
    drag.current = { zone, mode, x0: t, w0: p.window }
    el.setPointerCapture(e.pointerId)
    if (mode === 'new') p.onWindow(clamp({ start: snap(t), end: snap(t) + p.binMs }))
  }
  const brushMove = (zone: 'track' | 'rail', e: PointerEvent<HTMLDivElement>) => {
    const d = drag.current
    if (!d || d.zone !== zone || d.mode === 'seek') return
    const el = zone === 'track' ? trackRef.current! : railRef.current!
    const t = tAt(el, e.clientX)
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
  const trackDown = (e: PointerEvent<HTMLDivElement>) => {
    if (e.button !== 0) return
    if (!p.playback) return brushDown('track', e)
    drag.current = { zone: 'track', mode: 'seek', x0: 0, w0: p.window }
    trackRef.current!.setPointerCapture(e.pointerId)
    p.playback.onSeek(inWin(tAt(trackRef.current!, e.clientX)))
  }
  const trackMove = (e: PointerEvent<HTMLDivElement>) => {
    if (drag.current?.mode === 'seek' && p.playback) p.playback.onSeek(inWin(tAt(trackRef.current!, e.clientX)))
    else brushMove('track', e)
  }
  const up = () => {
    drag.current = null
  }
  const windowKeys = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === 'Home' || e.key === 'Escape') {
      e.preventDefault()
      p.onWindow({ ...p.domain })
    } else if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
      e.preventDefault()
      const dt = e.key === 'ArrowLeft' ? -p.binMs : p.binMs
      p.onWindow(clamp(e.shiftKey ? { start: p.window.start, end: Math.max(p.window.start + p.binMs, p.window.end + dt) } : { start: p.window.start + dt, end: p.window.end + dt }))
    }
  }
  const trackKeys = (e: KeyboardEvent<HTMLDivElement>) => {
    if (!p.playback) return windowKeys(e)
    const step = e.shiftKey ? 3600_000 : p.binMs
    const cur = playback.position()
    if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
      e.preventDefault()
      p.playback.onSeek(inWin(cur + (e.key === 'ArrowLeft' ? -step : step)))
    } else if (e.key === 'Home') {
      e.preventDefault()
      p.playback.onSeek(p.window.start)
    } else if (e.key === 'End') {
      e.preventDefault()
      p.playback.onSeek(p.window.end)
    } else if (e.key === ' ' || e.key === 'k') {
      e.preventDefault()
      p.playback.onToggle()
    }
  }

  const full = p.window.start <= p.domain.start && p.window.end >= p.domain.end
  const wl = frac(p.window.start) * 100
  const wr = frac(p.window.end) * 100
  const head = p.playback ? p.playback.t : null
  const ticks: number[] = []
  for (let h = 0; h <= 24; h += 3) ticks.push(h)
  const windowEl = (
    <>
      {!full && (
        <>
          <div className="scrub-shade" style={{ left: 0, width: `${wl}%` }} />
          <div className="scrub-shade" style={{ left: `${wr}%`, right: 0 }} />
        </>
      )}
    </>
  )
  return (
    <div className={`scrub ${p.playback ? 'is-playback' : ''}`}>
      <div
        ref={trackRef}
        className={`scrub-track ${full && !p.playback ? 'full' : ''}`}
        tabIndex={0}
        role={p.playback ? 'slider' : 'group'}
        aria-label={p.playback ? 'Playback position. Arrow keys step 15 minutes, Shift+arrows one hour, Home and End jump to the window edges, Space plays or pauses.' : `${p.label ?? 'Alert timeline'}: window ${fmtClock(p.window.start)} to ${fmtEnd(p.window.start, p.window.end)} UTC. Drag to select a range; arrow keys move it, Shift+arrows resize, Home resets to the full day.`}
        aria-valuemin={p.playback ? p.window.start : undefined}
        aria-valuemax={p.playback ? p.window.end : undefined}
        aria-valuenow={head ?? undefined}
        aria-valuetext={head != null ? `${fmtClock(head)} UTC simulated` : undefined}
        onPointerDown={trackDown}
        onPointerMove={trackMove}
        onPointerUp={up}
        onPointerCancel={up}
        onKeyDown={trackKeys}
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
            const ahead = head != null && b.t0 > head
            return (
              <g key={i} className={`scrub-bin ${ahead ? 'ahead' : ''}`}>
                {b.low > 0 && <rect className="low" x={x} y={yl} width={w} height={h(b.low)} />}
                {b.medium > 0 && <rect className="medium" x={x} y={ym} width={w} height={h(b.medium)} />}
                {b.high > 0 && <rect className="high" x={x} y={yh} width={w} height={h(b.high)} />}
              </g>
            )
          })}
        </svg>
        {windowEl}
        {p.playback ? (
          <>
            <div className="scrub-played" ref={playedRef} style={{ left: `${wl}%` }} />
            <div className="scrub-head" ref={headRef}>
              <span className="knob" />
            </div>
          </>
        ) : (
          <div className="scrub-win" data-part="win" style={{ left: `${wl}%`, width: `${wr - wl}%` }}>
            <span className="scrub-h" data-part="start" />
            <span className="scrub-h end" data-part="end" />
          </div>
        )}
        {p.now != null && frac(p.now) > 0 && frac(p.now) < 1 && <div className="scrub-now" style={{ left: `${frac(p.now) * 100}%` }} title={`switch clock ${fmtClock(p.now, true)} UTC`} />}
      </div>
      {p.playback && (
        <div
          ref={railRef}
          className="scrub-rail"
          tabIndex={0}
          role="group"
          aria-label={`Selected window ${fmtClock(p.window.start)} to ${fmtEnd(p.window.start, p.window.end)} UTC. Drag the ends to resize, drag the bar to move, drag elsewhere to select a new window; arrow keys move it, Shift+arrows resize, Home selects the whole day.`}
          onPointerDown={(e) => e.button === 0 && brushDown('rail', e)}
          onPointerMove={(e) => brushMove('rail', e)}
          onPointerUp={up}
          onPointerCancel={up}
          onKeyDown={windowKeys}
        >
          <div className="scrub-rail-win" data-part="win" style={{ left: `${wl}%`, width: `${wr - wl}%` }}>
            <span className="scrub-h" data-part="start" />
            <span className="scrub-h end" data-part="end" />
          </div>
        </div>
      )}
      <div className="scrub-axis" aria-hidden="true">
        {ticks.map((h) => (
          <span key={h} style={{ left: `${(h / 24) * 100}%` }}>
            {String(h).padStart(2, '0')}
          </span>
        ))}
      </div>
      <div className="scrub-meta">
        <span className="mono">
          window {fmtClock(p.window.start)}–{fmtEnd(p.window.start, p.window.end)} UTC · {fmtSpan(p.window.end - p.window.start)}
        </span>
        <span className="dim">{peak ? `bars: alerts per ${fmtSpan(p.binMs)} · peak ${peak}` : 'no alerts match the filters on this day'}</span>
        {trafficPath && <span className="dim">shaded: SPAN connections, own scale</span>}
      </div>
    </div>
  )
}

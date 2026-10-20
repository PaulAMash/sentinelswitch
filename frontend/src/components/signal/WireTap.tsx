import { useEffect, useRef } from 'react'
import type { Alert } from '../../lib/api'
import { playback } from '../../lib/playback'
import { connLines, eventLines, upper, wireClock, type Family, type Wire, type WireLine } from '../../lib/wire'

const ROWS = 8
const MIN_FRAME_MS = 70

export interface WireTapProps {
  wire: Wire
  /** alerts that pass the field's filters, ascending by time, with their times */
  alerts: Alert[]
  alertT: Float64Array
  names: Map<string, string>
  families: Set<Family>
  /** the switch clock: lines recorded after it are not replayed */
  until?: number
}

/**
 * The recorded lines at the playhead, as the sensors and the switch wrote them: Zeek connections in one
 * pane; RADIUS results, switch syslog and alerts in the other. Rows are written straight to the DOM on
 * the playback frame (about 14 times a second), so a busy minute scrolls without React re-renders.
 */
export function WireTap(p: WireTapProps) {
  const connRef = useRef<HTMLOListElement>(null)
  const evRef = useRef<HTMLOListElement>(null)
  const rateRef = useRef<HTMLSpanElement>(null)
  const evRateRef = useRef<HTMLSpanElement>(null)
  const props = useRef(p)
  useEffect(() => {
    props.current = p
  })
  const forceRef = useRef<() => void>(() => {})

  useEffect(() => {
    let last = 0
    let lastPos = Number.NaN
    const seen = { conn: new Set<string>(), ev: new Set<string>() }
    const fill = (ol: HTMLOListElement | null, lines: WireLine[], prev: Set<string>) => {
      if (!ol) return new Set<string>()
      const keys = new Set<string>()
      const pad = ROWS - lines.length
      for (let i = 0; i < ROWS; i++) {
        const li = ol.children[i] as HTMLLIElement | undefined
        if (!li) continue
        const l = i >= pad ? lines[i - pad] : null
        const [tEl, tagEl, txtEl] = li.children as unknown as HTMLElement[]
        if (!l) {
          li.className = 'wl is-blank'
          tEl.textContent = ''
          tagEl.textContent = ''
          txtEl.textContent = ''
          continue
        }
        keys.add(l.key)
        li.className = `wl k-${l.kind} ${l.tone}${prev.size && !prev.has(l.key) ? ' new' : ''}`
        tEl.textContent = wireClock(l.t)
        tagEl.textContent = l.tag
        txtEl.textContent = l.text
        li.title = `${wireClock(l.t)} ${l.tag} ${l.text}`
      }
      return keys
    }
    let trailing: ReturnType<typeof setTimeout> | null = null
    const update = (pos: number, force = false) => {
      const now = performance.now()
      if (!force && pos === lastPos) return
      if (!force && now - last < MIN_FRAME_MS) {
        // throttled: make sure the last position still lands (a seek while paused sends no further frames)
        if (trailing) clearTimeout(trailing)
        trailing = setTimeout(() => update(playback.position(), true), MIN_FRAME_MS - (now - last))
        return
      }
      if (trailing) {
        clearTimeout(trailing)
        trailing = null
      }
      last = now
      lastPos = pos
      const { wire, alerts, alertT, names, families, until } = props.current
      pos = Math.min(pos, until ?? Infinity)
      seen.conn = fill(connRef.current, connLines(wire, pos, ROWS, names, families), force ? new Set() : seen.conn)
      seen.ev = fill(evRef.current, eventLines(wire, alerts, alertT, pos, ROWS), force ? new Set() : seen.ev)
      const perMin = upper(wire.t, pos) - upper(wire.t, pos - 60_000)
      if (rateRef.current) rateRef.current.textContent = `${perMin} / min`
      const evHour = upper(wire.authT, pos) - upper(wire.authT, pos - 3600_000) + (upper(wire.syslogT, pos) - upper(wire.syslogT, pos - 3600_000))
      if (evRateRef.current) evRateRef.current.textContent = `${evHour} / h`
    }
    forceRef.current = () => update(playback.position(), true)
    update(playback.position(), true)
    const unsub = playback.subscribeFrame((pos) => update(pos))
    return () => {
      unsub()
      if (trailing) clearTimeout(trailing)
    }
  }, [])

  // a filter change re-reads the panes at once
  useEffect(() => {
    forceRef.current()
  }, [p.families, p.alerts])

  const rows = Array.from({ length: ROWS }, (_, i) => (
    <li key={i} className="wl is-blank">
      <span className="wl-t" />
      <span className="wl-tag" />
      <span className="wl-x" />
    </li>
  ))
  return (
    <div className="wire" aria-label="Recorded lines at the playhead">
      <div className="wire-pane">
        <div className="wire-head">
          <span className="wire-k" title="Zeek conn.log, with the DNS query, TLS server name or HTTP request of each connection">zeek · conn</span>
          <span className="wire-rate mono" ref={rateRef} />
        </div>
        <ol className="wire-lines" ref={connRef} aria-hidden="true">
          {rows}
        </ol>
      </div>
      <div className="wire-pane">
        <div className="wire-head">
          <span className="wire-k" title="RADIUS results, switch syslog and alerts">radius · syslog · alerts</span>
          <span className="wire-rate mono" ref={evRateRef} />
        </div>
        <ol className="wire-lines" ref={evRef} aria-hidden="true">
          {rows}
        </ol>
      </div>
    </div>
  )
}

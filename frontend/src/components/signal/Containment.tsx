import { useEffect, useRef, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import type { AssessmentStatus, Incident } from '../../lib/api'
import { vlanName } from '../../lib/format'
import { playback } from '../../lib/playback'
import { upper, wireClock, type Wire } from '../../lib/wire'
import type { ContainmentWindow, FieldNode } from './model'

/** A restore stays in the detail line this long (simulated ms) after it happened. */
const RESTORED_SHOWN_MS = 20 * 60_000
/** Jumping to a containment starts this long before it, so the burst that led to it is seen. */
const LEAD_IN_MS = 20_000

function span(msSpan: number): string {
  const s = Math.max(0, Math.round(msSpan / 1000))
  if (s < 60) return `${s} s`
  const m = Math.round(s / 60)
  if (m < 60) return `${m} min`
  return `${Math.floor(m / 60)} h ${m % 60} min`
}
const hm = (t: number) => wireClock(t).slice(0, 5)
const hms = (t: number) => wireClock(t).slice(0, 8)
const kindOf = (w: ContainmentWindow) => (w.action.action === 'quarantine_vlan' ? 'quarantine' : 'shutdown')

/**
 * The day's recorded containment actions under the field. The track lists every action in time order,
 * coloured by its state at the playhead (still to come, holding, restored); selecting one jumps the
 * replay to just before it. The detail line describes the action holding at the playhead (or one just
 * restored): port, endpoint, VLAN move, authorization, switch read-back, how long it has held and,
 * for a quarantine, whether the quarantine VLAN is visible to the sensor. Every word comes from the
 * action record, the inventory, the sensor-coverage assessment or the recorded connections; it is a
 * replay of what happened, never an action being taken now.
 */
export function ContainmentStrip({ windows, t, byId, incidents, coverage, wire }: { windows: ContainmentWindow[]; t: number; byId: Map<string, FieldNode>; incidents: Incident[]; coverage?: Map<number, AssessmentStatus>; wire: Wire | null }) {
  const rowRef = useRef<HTMLOListElement>(null)
  const stateAt = (w: ContainmentWindow) => (w.applied > t ? 'up' : w.restored != null && w.restored <= t ? 'done' : 'on')
  const active = windows.filter((w) => stateAt(w) === 'on')
  const recentRestore = windows.filter((w) => w.restored != null && w.restored <= t && t - w.restored <= RESTORED_SHOWN_MS).sort((a, b) => b.restored! - a.restored!)
  const pick = [...active].sort((a, b) => b.applied - a.applied)[0] ?? recentRestore[0] ?? null
  const next = windows.find((w) => w.applied > t) ?? null
  const focusId = pick?.action.workflow_id ?? next?.action.workflow_id ?? null
  // when the actions scroll in one row, keep the one that matters at the playhead in view (the row only, never the page)
  useEffect(() => {
    const row = rowRef.current
    const chip = row?.querySelector<HTMLElement>(`[data-wf="${focusId}"]`)
    if (!row || !chip || row.scrollWidth <= row.clientWidth) return
    const left = chip.offsetLeft - row.offsetLeft
    if (left < row.scrollLeft || left + chip.offsetWidth > row.scrollLeft + row.clientWidth) row.scrollTo({ left: Math.max(0, left - 8), behavior: 'smooth' })
  }, [focusId])
  if (!windows.length) return null

  const jump = (w: ContainmentWindow) => {
    const s = playback.getSnapshot()
    if (s.window && (w.applied < s.window.start || w.applied > s.window.end)) playback.setPreset('day')
    playback.seek(w.applied - LEAD_IN_MS)
    playback.play()
  }

  let detail: ReactNode
  let tone = 'idle'
  let detailKey = 'idle'
  if (pick) {
    const a = pick.action
    const quarantine = a.action === 'quarantine_vlan'
    const restored = pick.restored != null && pick.restored <= t
    const verified = pick.verified != null && pick.verified <= t
    const failed = a.verification?.ok === false || a.status === 'containment_failed'
    const state = restored ? 'restored' : failed && verified ? 'failed' : verified ? 'held' : 'executing'
    tone = `${quarantine ? 'quarantine' : 'shutdown'} ${state}`
    detailKey = `${a.workflow_id}-${state}`
    const node = a.interface ? byId.get(a.interface) : undefined
    const device = node?.device?.hostname ?? node?.unknown?.label ?? null
    // the port may have no current DHCP binding (a quarantined host), so fall back to the inventory address
    const ip = node?.ip ?? node?.device?.ip ?? null
    const incident = a.incident_id ? incidents.find((i) => i.id === a.incident_id) : undefined
    let burst: number | null = null
    if (wire && ip) {
      const hi = wire.hosts.indexOf(ip)
      if (hi >= 0) {
        burst = 0
        for (let i = upper(wire.t, pick.applied - 60_000), j = upper(wire.t, pick.applied); i < j; i++) if (wire.o[i] === hi || wire.r[i] === hi) burst++
      }
    }
    const blind = quarantine && !restored && a.to_vlan != null && coverage?.get(a.to_vlan) === 'FAIL'
    const auth = a.authorization
    const headline = state === 'restored' ? 'Restored' : state === 'failed' ? 'Containment failed verification' : state === 'executing' ? 'Applied · awaiting read-back' : quarantine ? 'Contained · quarantine VLAN' : 'Contained · port shut down'
    detail = (
      <>
        <div className="cs-line cs-main">
          <span className="cs-dot" aria-hidden="true" />
          <span className="cs-head">{headline}</span>
          <span className="mono strong">{a.interface ?? 'port not recorded'}</span>
          {device && <span className="strong">{device}</span>}
          {ip && <span className="mono dim">{ip}</span>}
        </div>
        <div className="cs-line cs-sub">
          <span className="cs-move mono">{quarantine ? `VLAN ${vlanName(a.from_vlan)} → ${vlanName(a.to_vlan)}` : 'administrative shutdown'}</span>
          {incident && (
            <Link to={`/incidents/${incident.id}`} className="cs-link" title={incident.title}>
              {incident.id} · {incident.title}
            </Link>
          )}
        </div>
        <div className="cs-line cs-facts">
          <span>
            <i>applied</i> {hms(pick.applied)} UTC (recorded)
          </span>
          <span>
            <i>{restored ? 'restored' : 'held for'}</i> {restored ? `${hms(pick.restored!)}${a.restored_by ? ` by ${a.restored_by}` : ''} after ${span(pick.restored! - pick.applied)}` : span(t - pick.applied)}
          </span>
        </div>
        <div className="cs-line cs-facts">
          <span>
            <i>authorized</i> {auth ? `${auth.mode}${auth.authorized_by ? ` · ${auth.authorized_by}` : ''}` : 'not recorded'}
          </span>
          <span title={a.verification?.expected ? `read-back: ${a.verification.expected}` : undefined}>
            <i>verified</i> {verified ? `${wireClock(pick.verified!)} · ${failed ? 'read-back mismatch' : `read-back “${a.verification?.expected ?? 'matched'}”`}` : 'not yet at this moment'}
          </span>
        </div>
        <div className="cs-line cs-notes">
          {burst != null && burst > 0 && (
            <span>
              {burst} recorded connection{burst === 1 ? '' : 's'} from {device ?? ip} in the minute before
            </span>
          )}
          {active.length > 1 && <span>{active.length - 1} more port{active.length > 2 ? 's' : ''} contained at this moment</span>}
        </div>
        {blind && (
          <div className="cs-line cs-notes">
            <span className="cs-warn" title={`VLAN ${a.to_vlan} is not in the SPAN session (sensor coverage FAIL), so the host’s traffic after the move is not recorded`}>
              VLAN {a.to_vlan} not mirrored to the sensor: traffic after the move is unrecorded
            </span>
          </div>
        )}
      </>
    )
  } else {
    detail = (
      <>
        <div className="cs-line cs-main">
          <span className="cs-dot" aria-hidden="true" />
          <span className="cs-head">No port contained</span>
          <span className="dim">at {hm(t)} UTC</span>
        </div>
        <div className="cs-line cs-facts">
          {next ? (
            <span>
              <i>next</i> {hms(next.applied)} · {next.action.interface} · {kindOf(next) === 'quarantine' ? `quarantine VLAN ${next.action.to_vlan}` : 'port shut down'}
              {next.action.incident_id ? ` · ${next.action.incident_id}` : ''}
            </span>
          ) : (
            <span>
              <i>last</i> every recorded containment is behind the playhead
            </span>
          )}
        </div>
        <div className="cs-line cs-notes">
          <span>
            {windows.length} containment action{windows.length === 1 ? '' : 's'} recorded · select one to replay it
          </span>
        </div>
      </>
    )
  }

  return (
    <div className="cs-wrap">
    <section className={`cstrip ${tone}`} aria-label="Recorded containment actions">
      <div className="cs-track">
        <span className="cs-k">containment · recorded</span>
        <ol className="cs-chips scroll-x" ref={rowRef}>
          {windows.map((w) => {
            const st = stateAt(w)
            return (
              <li key={w.action.workflow_id}>
                <button
                  type="button"
                  data-wf={w.action.workflow_id}
                  className={`cs-chip ${kindOf(w)} ${st} ${pick?.action.workflow_id === w.action.workflow_id ? 'focus' : ''}`}
                  onClick={() => jump(w)}
                  title={`Replay from ${hms(w.applied - LEAD_IN_MS)}: ${w.action.interface} ${kindOf(w) === 'quarantine' ? `quarantined (VLAN ${w.action.from_vlan} → ${w.action.to_vlan})` : 'shut down'}${w.restored ? `, restored ${hms(w.restored)}` : ', still held'}`}
                  aria-label={`Replay containment at ${hms(w.applied)}: ${w.action.interface}, ${kindOf(w) === 'quarantine' ? 'quarantine' : 'port shut down'}, ${st === 'up' ? 'later in the window' : st === 'on' ? 'holding at the playhead' : 'restored'}`}
                >
                  <span className="mono">{hm(w.applied)}</span>
                  <span className="mono">{w.action.interface}</span>
                  <span className="cs-kind">{kindOf(w) === 'quarantine' ? 'quarantine' : 'shut down'}</span>
                  {st === 'done' && <span className="cs-ok">restored</span>}
                </button>
              </li>
            )
          })}
        </ol>
      </div>
      <div className="cs-detail" key={detailKey} aria-live="polite">
        {detail}
      </div>
    </section>
    </div>
  )
}

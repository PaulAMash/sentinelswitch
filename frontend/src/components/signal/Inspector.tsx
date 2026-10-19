import { Link } from 'react-router-dom'
import type { Alert } from '../../lib/api'
import { fmtClock, fmtEnd, ms, sev3, type Window } from '../../lib/telemetry'
import { vlanName } from '../../lib/format'
import { Chip, Id, ResponseChip, SeverityChip, StatusChip } from '../status'
import type { FieldModel, FieldNode, Flow } from './model'

function Hop({ k, v, src, tone = '' }: { k: string; v: string | null; src: string; tone?: string }) {
  return (
    <li className={`hop ${v ? '' : 'missing'} ${tone}`}>
      <span className="k">{k}</span>
      <span className="v">{v ?? 'not observed'}</span>
      <span className="s">{src}</span>
    </li>
  )
}

function SevStrip({ c }: { c: Record<'high' | 'medium' | 'low', number> }) {
  const total = c.high + c.medium + c.low
  if (!total) return <div className="dim small">No alerts on this port in the selected window and filters.</div>
  return (
    <div className="sev-strip" role="img" aria-label={`${c.high} high, ${c.medium} medium, ${c.low} low`}>
      <div className="bar">
        {(['high', 'medium', 'low'] as const).map((s) => (c[s] ? <span key={s} className={s} style={{ flexGrow: c[s] }} /> : null))}
      </div>
      <div className="lbl mono">
        {c.high} high · {c.medium} medium · {c.low} low
      </div>
    </div>
  )
}

export function NodeInspector({ n, onSelectAlert }: { n: FieldNode; onSelectAlert: (a: Alert) => void }) {
  const p = n.port
  const total = n.counts.high + n.counts.medium + n.counts.low
  return (
    <div className="insp">
      <div className="insp-head">
        <Id>{n.id}</Id>
        <StatusChip value={p.state} />
        {n.vlan !== null && <Chip kind="neutral" mono>{vlanName(n.vlan)}</Chip>}
      </div>
      <div className="insp-title">
        {n.device ? <Link to={`/devices/${n.device.hostname}`}>{n.device.hostname}</Link> : n.unknown ? <span>unregistered · {n.unknown.label}</span> : <span className="dim">{p.description || 'no endpoint in inventory'}</span>}
        {n.device && <span className="dim small"> {n.device.role}{n.device.user ? ` · ${n.device.user}` : ''}</span>}
      </div>
      <div className="eyebrow">Attribution · switch tables</div>
      <ol className="hops">
        {n.ip ? <Hop k="IP" v={n.ip} src="DHCP snooping binding" /> : <Hop k="IP" v={n.device?.ip ?? null} src={n.device?.ip ? 'asset inventory · no current DHCP binding on this port' : 'no DHCP binding on this port'} />}
        <Hop k="MAC" v={n.macs.length ? n.macs.join(', ') : null} src="MAC address table" />
        <Hop k="Port" v={`SW01 ${n.id}`} src={p.port_class} tone="port" />
        <Hop k="VLAN" v={n.vlan !== null ? vlanName(n.vlan) : `trunk ${p.allowed_vlans.join(',')}`} src={p.quarantined && p.original_vlan ? `quarantined · was ${vlanName(p.original_vlan)}` : 'operational VLAN'} tone={p.quarantined ? 'contained' : ''} />
        <Hop k="Endpoint" v={n.device?.hostname ?? (n.unknown ? `unregistered (${n.unknown.vendor})` : null)} src={n.device ? 'asset inventory' : n.unknown ? 'seen on port, not in inventory' : 'inventory'} />
      </ol>
      <div className="eyebrow">Activity · selected window ({total})</div>
      <SevStrip c={n.counts} />
      {n.alerts.slice(0, 4).map((a) => (
        <button key={a.id} type="button" className="insp-alert" onClick={() => onSelectAlert(a)}>
          <span className="mono">{fmtClock(ms(a.ts), true)}</span>
          <span className={`sev-dot ${sev3(a.severity)}`} aria-hidden="true" />
          <span className="clip">{a.signature.replace(/^SENTINELSWITCH /, '')}</span>
        </button>
      ))}
      {(n.incident || n.review || n.response) && <div className="eyebrow">Response · current state</div>}
      {n.response === 'contained' && <div className="insp-note contained">Port is in the quarantine VLAN on the switch twin.</div>}
      {n.response === 'held' && <div className="insp-note warn">Port is under an administrative hold.</div>}
      {n.incident && (
        <div className="row">
          <Link className="id" to={`/incidents/${n.incident.id}`}>
            {n.incident.id}
          </Link>
          {n.incidentState && <ResponseChip state={n.incidentState} />}
          <span className="dim small clip">{n.incident.rule_name}</span>
        </div>
      )}
      {n.review && (
        <div className="row">
          <Chip kind="pending">awaiting authorization</Chip>
          <Link to="/incidents">review queue</Link>
        </div>
      )}
      <div className="insp-actions">
        {n.device && (
          <Link className="btn sm" to={`/devices/${n.device.hostname}`}>
            Endpoint
          </Link>
        )}
        <Link className="btn sm" to={`/switch?port=${encodeURIComponent(n.id)}`}>
          Port on switch
        </Link>
        {n.incident && (
          <Link className="btn sm" to={`/incidents/${n.incident.id}`}>
            Incident
          </Link>
        )}
      </div>
    </div>
  )
}

export function AlertInspector({ a, flow, model }: { a: Alert; flow: Flow | null; model: FieldModel }) {
  const src = a.interface ? model.nodes.find((n) => n.id === a.interface) : null
  const dst = flow?.to ? model.nodes.find((n) => n.id === flow.to) : null
  return (
    <div className="insp">
      <div className="insp-head">
        <SeverityChip value={a.severity} />
        <Chip kind="source">{a.source}</Chip>
        <StatusChip value={a.status} />
      </div>
      <div className="insp-title">{a.signature}</div>
      <div className="mono small dim">
        {a.ts.slice(0, 10)} {fmtClock(ms(a.ts), true)} UTC · {a.id}
      </div>
      <div className="eyebrow">Observed</div>
      <ol className="hops">
        <Hop k="Source" v={a.src_ip ? `${a.src_ip}${a.src_port ? `:${a.src_port}` : ''}` : a.mac} src={src ? `${src.id}${src.device ? ` · ${src.device.hostname}` : ''}` : a.interface ?? 'port not recorded'} tone="port" />
        {a.dest_ip && <Hop k="Dest" v={`${a.dest_ip}${a.dest_port ? `:${a.dest_port}` : ''}`} src={dst ? `${dst.id}${dst.device ? ` · ${dst.device.hostname}` : ''}` : 'not attributed to a SW01 port'} />}
        {a.proto && <Hop k="Proto" v={a.proto} src={a.category} />}
      </ol>
      {(a.detection_id || a.incident_id) && <div className="eyebrow">Pipeline</div>}
      {a.detection_id && (
        <div className="row small">
          <span className="dim">detection</span> <Id dim>{a.detection_id}</Id>
        </div>
      )}
      {a.incident_id && (
        <div className="row small">
          <span className="dim">incident</span>
          <Link className="id" to={`/incidents/${a.incident_id}`}>
            {a.incident_id}
          </Link>
        </div>
      )}
      <div className="insp-actions">
        {a.incident_id && (
          <Link className="btn sm" to={`/incidents/${a.incident_id}`}>
            Incident
          </Link>
        )}
        {a.device && (
          <Link className="btn sm" to={`/devices/${a.device}`}>
            Endpoint
          </Link>
        )}
        <Link className="btn sm" to="/alerts">
          All alerts
        </Link>
      </div>
    </div>
  )
}

export function FieldSummary({ model, visible, window: w, day }: { model: FieldModel; visible: number; window: Window; day: string }) {
  const active = model.nodes.filter((n) => n.heat > 0).length
  const contained = model.nodes.filter((n) => n.response === 'contained' || n.response === 'held')
  const review = model.nodes.filter((n) => n.response === 'review')
  const open = model.nodes.filter((n) => n.incident && n.incident.status !== 'resolved' && n.incident.status !== 'closed')
  return (
    <div className="insp">
      <div className="eyebrow">Selected window</div>
      <div className="insp-stats">
        <div>
          <b className="mono">{visible}</b>
          <span>alerts</span>
        </div>
        <div>
          <b className="mono">{active}</b>
          <span>ports with activity</span>
        </div>
        <div>
          <b className="mono">{model.flows.length}</b>
          <span>observed flows</span>
        </div>
      </div>
      <div className="dim small">
        {day} · {fmtClock(w.start)}–{fmtEnd(w.start, w.end)} UTC
      </div>
      <div className="eyebrow">Current state</div>
      <ul className="insp-list">
        <li>
          <span className={`n ${contained.length ? 'danger' : ''}`}>{contained.length}</span> contained or held {contained.length ? <span className="mono dim">{contained.map((n) => n.id).join(', ')}</span> : null}
        </li>
        <li>
          <span className={`n ${review.length ? 'warn' : ''}`}>{review.length}</span> awaiting authorization {review.length ? <span className="mono dim">{review.map((n) => n.id).join(', ')}</span> : null}
        </li>
        <li>
          <span className={`n ${open.length ? 'danger' : ''}`}>{open.length}</span> open incidents{' '}
          {open.map((n) => (
            <Link key={n.id} className="id" to={`/incidents/${n.incident!.id}`}>
              {n.incident!.id}
            </Link>
          ))}
        </li>
      </ul>
      <div className="dim small">Select a port or an event to trace it through the switch tables.</div>
    </div>
  )
}

import { useState } from 'react'
import { kv, type KVRow } from '../lib/kv'
import { Link, useParams } from 'react-router-dom'
import { endpoints, type Authorization } from '../lib/api'
import { useApi } from '../lib/hooks'
import { Card, Chip, KV, Loading, Sev, Tabs, Term, Ts } from '../components/ui'
import { Chain, Steps } from '../components/Chain'
import { chainFromAttribution } from '../lib/chain'
import { Timeline } from '../components/Timeline'
import { Confidence, Features } from '../components/Features'
import { fmtBytes, fmtSeconds, vlanName } from '../lib/format'

type Tab = 'timeline' | 'detections' | 'decision' | 'evidence' | 'verify'

export function IncidentDetail() {
  const { id = '' } = useParams()
  const { data, error, reload } = useApi(() => endpoints.incident(id), [id])
  const [tab, setTab] = useState<Tab>('timeline')
  const [busy, setBusy] = useState(false)
  const [restoreError, setRestoreError] = useState<string | null>(null)
  if (!data) return <Loading error={error} />
  const inc = data.incident
  const det = data.detection
  const att = data.attribution
  const action = data.actions.find((a) => ['verified', 'restored', 'failed'].includes(a.status)) ?? data.actions[0]
  const auth: Authorization | undefined = inc.authorization ?? action?.authorization
  const metrics = (det && att && action) ? { ttd: null as number | null } : null
  void metrics
  const restore = async () => {
    setBusy(true)
    setRestoreError(null)
    try {
      await endpoints.restore(inc.id, { actor: 'tlee', note: 'Endpoint re-imaged and cleared by IT; returning to production VLAN.' })
      reload()
    } catch (e) {
      setRestoreError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <>
      <div className="page-head">
        <div>
          <div className="row" style={{ marginBottom: 6 }}>
            <span className="mono strong" style={{ fontSize: 15 }}>{inc.id}</span>
            <Sev s={inc.severity} />
            <Chip kind={inc.status} />
            <Chip kind={inc.disposition} />
            {inc.mitre.map((m) => (
              <span key={m} className="chip neutral mono">{m}</span>
            ))}
          </div>
          <h1>{inc.title}</h1>
          <p>{inc.summary}</p>
        </div>
        <div className="toolbar">
          {inc.status === 'contained' && (
            <button className="btn" onClick={restore} disabled={busy}>
              Release containment (restore VLAN {inc.original_vlan})
            </button>
          )}
          <Link className="btn" to={`/evidence/${inc.id}`}>Evidence bundle</Link>
          {restoreError && <div className="error">Restore failed: {restoreError}</div>}
        </div>
      </div>

      <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))' }}>
        <Card><KV rows={[kv('endpoint', inc.device ? <Link to={`/devices/${inc.device}`}>{inc.device}</Link> : inc.impersonated_device ? `unknown (impersonating ${inc.impersonated_device})` : 'unknown device'), kv('user', inc.user ? `${inc.user} (${inc.department})` : '—'), kv('vendor', inc.vendor ?? '—')]} /></Card>
        <Card><KV rows={[kv('ip', inc.ip ?? '—'), kv('mac', inc.mac ?? '—'), kv('attribution', `${((inc.attribution_confidence ?? 1) * 100).toFixed(0)}% · ${inc.flags.length ? inc.flags.join(', ') : 'clean'}`)]} /></Card>
        <Card><KV rows={[kv('switch', inc.switch), kv('interface', inc.interface ?? '—'), kv('port class', inc.port_class ?? '—')]} /></Card>
        <Card><KV rows={[kv('original vlan', vlanName(inc.original_vlan)), kv('current vlan', vlanName(inc.current_vlan)), kv('mechanism', inc.action === 'quarantine_vlan' ? 'quarantine VLAN' : inc.action === 'port_shutdown' ? 'administrative shutdown' : inc.mechanism ?? '—')]} /></Card>
        <Card><KV rows={[kv('opened', <Ts ts={inc.opened_at} date />), kv('contained', <Ts ts={inc.contained_at} date />), kv('closed', inc.closed_at ? <><Ts ts={inc.closed_at} date /> <span className="dim">by {inc.closed_by}</span></> : '—')]} /></Card>
        <Card><KV rows={authRows(auth)} /></Card>
      </div>

      <Card title="Correlation chain" sub="IP → DHCP binding → MAC → MAC table → port → VLAN → containment">
        <Chain nodes={chainFromAttribution(att, action?.to_vlan, inc.action)} />
        {att && (
          <div style={{ marginTop: 14 }}>
            <Steps steps={att.steps} />
          </div>
        )}
      </Card>

      <div className="card">
        <Tabs<Tab>
          tabs={[
            { id: 'timeline', label: 'Timeline' },
            { id: 'detections', label: `Source detections (${data.alerts.length})` },
            { id: 'decision', label: 'Containment decision' },
            { id: 'verify', label: 'Switch verification' },
            { id: 'evidence', label: `Evidence (${data.evidence.files.length})` },
          ]}
          value={tab}
          onChange={setTab}
        />
        <div className="card-body">
          {tab === 'timeline' && (
            <div className="grid side-main">
              <div>
                <h3 style={{ marginBottom: 8 }}>Measured on the simulated clock</h3>
                {det && action && (
                  <KV rows={[
                    kv('first anomalous event', <Ts ts={data.timeline[0]?.ts} />),
                    kv('incident detection', <Ts ts={det.ts} />),
                    kv('attribution complete', <Ts ts={att?.completed_at} />),
                    kv('containment applied', <Ts ts={action.applied_at} />),
                    kv('verified', <Ts ts={action.verified_at} />),
                    kv('evidence finalized', <Ts ts={inc.evidence_finalized_at} />),
                    kv('time to detect', fmtSeconds(diff(data.timeline[0]?.ts, det.ts))),
                    kv('time to attribute', fmtSeconds(diff(det.ts, att?.completed_at))),
                    kv('time to contain', fmtSeconds(diff(det.ts, action.verified_at)))]} />
                )}
                {inc.resolution_note && <div className="notice" style={{ marginTop: 12 }}>{inc.resolution_note}</div>}
              </div>
              <Timeline entries={data.timeline} />
            </div>
          )}
          {tab === 'detections' && (
            <div className="grid side-main">
              <div>
                {det && (
                  <>
                    <h3 style={{ marginBottom: 8 }}>{det.rule_name} · {det.rule}</h3>
                    <Confidence value={det.confidence} base={det.base_confidence} />
                    <div style={{ marginTop: 10 }}><Features features={det.features} /></div>
                    <div className="dim small" style={{ marginTop: 8 }}>trigger {det.trigger_ts.slice(11, 23)} · scored {det.ts.slice(11, 23)} · {det.event_refs.length} contributing events</div>
                  </>
                )}
              </div>
              <div className="table-wrap">
                <table className="data">
                  <thead><tr><th>time</th><th>severity</th><th>source</th><th>signature</th><th>src → dst</th></tr></thead>
                  <tbody>
                    {data.alerts.map((a) => (
                      <tr key={a.id}>
                        <td><Ts ts={a.ts} /></td>
                        <td><Sev s={a.severity} /></td>
                        <td><Chip kind="source">{a.source}</Chip></td>
                        <td className="wrap" style={{ minWidth: 260 }}>{a.signature}</td>
                        <td className="mono">{a.src_ip ?? a.mac ?? a.interface} {a.dest_ip ? `→ ${a.dest_ip}:${a.dest_port ?? ''}` : ''}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
          {tab === 'decision' && action && (
            <div className="grid two">
              <div className="stack">
                <h3>Policy evaluation</h3>
                <DecisionView incidentId={inc.id} />
                <h3 style={{ marginTop: 6 }}>Authorization</h3>
                {auth ? (
                  <>
                    <div className="row">
                      <Chip kind={auth.status} />
                      <span className="mono">{auth.mode}</span>
                      <span className="dim">{auth.action}</span>
                    </div>
                    <KV rows={[
                      kv('authorized by', auth.authorized_by),
                      kv('authorized at', <Ts ts={auth.authorized_at} date />),
                      kv('basis', auth.basis),
                      kv('reason', <span className="wrap">{auth.reason}</span>),
                      kv('guards', auth.guards.length ? <span className="mono">{auth.guards.join(', ')}</span> : 'none'),
                      kv('note', auth.note ?? '—')]} />
                    <div className="small dim">The authorization record is written separately from the policy decision and from execution: the policy tier says what the engine would do, the authorization says who allowed it and on what basis.</div>
                  </>
                ) : (
                  <div className="dim">No authorization record is attached to this incident.</div>
                )}
              </div>
              <div className="stack">
                <h3>Containment action</h3>
                <KV rows={[
                  kv('workflow', action.workflow_id),
                  kv('action', action.action),
                  kv('mechanism', action.mechanism),
                  kv('interface', `${action.switch} ${action.interface}`),
                  kv('vlan', action.to_vlan ? `${action.from_vlan} → ${action.to_vlan}` : '—'),
                  kv('requested', <Ts ts={action.requested_at} />),
                  kv('applied', <Ts ts={action.applied_at} />),
                  kv('verified', <><Ts ts={action.verified_at} /> {action.verification?.ok ? <Chip kind="ok">ok</Chip> : <Chip kind="fail">failed</Chip>}</>),
                  kv('actor', action.actor),
                  kv('status', <Chip kind={action.status} />),
                  ...(action.restored_at ? [kv('restored', <><Ts ts={action.restored_at} date /> by {action.restored_by} — {action.restore_note}</>)] : [])]} />
                <Term text={action.transcript} hl={['switchport access vlan', 'shutdown']} />
              </div>
            </div>
          )}
          {tab === 'verify' && (
            <div className="grid two">
              <div className="stack">
                <h3>show interfaces {inc.interface} switchport</h3>
                <Term text={data.verification.switchport ?? ''} hl={['Access Mode VLAN']} />
                <h3>show interfaces {inc.interface} status</h3>
                <Term text={data.verification.status ?? ''} />
              </div>
              <div className="stack">
                <h3>show mac address-table interface {inc.interface}</h3>
                <Term text={data.verification.mac_table ?? ''} />
                <h3>show running-config interface {inc.interface}</h3>
                <Term text={data.verification.running_config ?? ''} hl={['switchport access vlan']} />
              </div>
            </div>
          )}
          {tab === 'evidence' && (
            <div>
              <p className="dim" style={{ marginBottom: 10 }}>Bundle written to <code>{data.evidence.path}/</code> on the simulated clock; every artifact is plain JSON or Markdown.</p>
              <div className="table-wrap">
                <table className="data">
                  <thead><tr><th>artifact</th><th>size</th><th>contents</th></tr></thead>
                  <tbody>
                    {data.evidence.files.map((f) => (
                      <tr key={f.name}>
                        <td className="mono"><Link to={`/evidence/${inc.id}?file=${f.name}`}>{f.name}</Link></td>
                        <td className="num">{fmtBytes(f.bytes)}</td>
                        <td className="dim">{describe(f.name)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  )
}

function DecisionView({ incidentId }: { incidentId: string }) {
  const { data } = useApi(() => endpoints.evidenceFile(incidentId, 'containment.json') as Promise<{ decision: { disposition: string; action: string; reason: string; factors: { factor: string; value: unknown }[]; guards_triggered: string[]; tier_before_guards: string | null } }>, [incidentId])
  if (!data) return <div className="loading">…</div>
  const d = data.decision
  return (
    <>
      <div className="row">
        <Chip kind={d.disposition} />
        <span className="mono">{d.action}</span>
      </div>
      <div className="dim">{d.reason}</div>
      <KV rows={d.factors.map((f) => kv(f.factor, String(f.value)))} />
      <div className="small dim">guards triggered: {d.guards_triggered.length ? d.guards_triggered.join(', ') : 'none — protected ports, trunks, SPAN destination and critical assets are exempt from automatic action'}</div>
    </>
  )
}

function authRows(a: Authorization | undefined): KVRow[] {
  if (!a) return [kv('authorization', <span className="dim">not recorded</span>)]
  return [
    kv('authorization', <><Chip kind={a.status} /> <span className="dim">{a.mode}</span></>),
    kv('authorized by', a.authorized_by),
    kv('authorized at', <Ts ts={a.authorized_at} date />),
    // a zero-width space after each underscore lets long policy-tier names wrap inside the narrow card
    kv('basis', <span className="wrap">{a.basis.replaceAll('_', '_\u200b')}</span>),
    kv('guards', a.guards.length ? <span className="mono">{a.guards.join(', ')}</span> : 'none'),
    kv('note', a.note ?? '—'),
  ]
}

function describe(name: string): string {
  return {
    'incident.json': 'incident record, detection, metrics, attribution chain',
    'timeline.json': 'ordered phases from first telemetry to evidence',
    'alerts.json': 'source detections with raw Suricata/Zeek/RADIUS/syslog records',
    'network-context.json': 'attribution, VLANs, SPAN session, port intent',
    'dhcp-binding.json': 'DHCP snooping binding used for IP → MAC',
    'mac-table.json': 'MAC address table entries and observation history',
    'switch-port.json': 'interface state before/after with show output',
    'containment.json': 'policy decision and executed action with transcript',
    'related-connections.json': 'Zeek conn records for the actor around the incident',
    'related-dns.json': 'Zeek dns records for the actor around the incident',
    'README.md': 'generated human-readable report',
  }[name] ?? ''
}

function diff(a?: string | null, b?: string | null): number | null {
  if (!a || !b) return null
  return (new Date(b).getTime() - new Date(a).getTime()) / 1000
}

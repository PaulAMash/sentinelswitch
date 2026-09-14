import { useMemo, useState } from 'react'
import { kv } from '../lib/kv'
import { Link } from 'react-router-dom'
import { endpoints, type Alert } from '../lib/api'
import { useApi } from '../lib/hooks'
import { Card, Chip, Drawer, KV, Loading, Sev, Term, Ts } from '../components/ui'
import { Features as FeatureList, Confidence } from '../components/Features'
import { sevRank } from '../lib/format'

export function Alerts() {
  const { data, error } = useApi(() => endpoints.alerts('?limit=1000'))
  const [sev, setSev] = useState('all')
  const [src, setSrc] = useState('all')
  const [status, setStatus] = useState('all')
  const [q, setQ] = useState('')
  const [sel, setSel] = useState<Alert | null>(null)
  const rows = useMemo(() => {
    if (!data) return []
    return data
      .filter((a) => sev === 'all' || a.severity === sev)
      .filter((a) => src === 'all' || a.source === src)
      .filter((a) => status === 'all' || a.status === status)
      .filter((a) => !q || `${a.signature} ${a.src_ip} ${a.dest_ip} ${a.device} ${a.mac} ${a.interface}`.toLowerCase().includes(q.toLowerCase()))
      .sort((a, b) => (a.ts < b.ts ? 1 : -1))
  }, [data, sev, src, status, q])
  if (!data) return <Loading error={error} />
  const counts = { high: data.filter((a) => a.severity === 'high').length, medium: data.filter((a) => a.severity === 'medium').length, low: data.filter((a) => sevRank(a.severity) <= 1).length }
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Alerts</h1>
          <p>Raw detections from every telemetry source, linked to the correlation detection and incident that consumed them.</p>
        </div>
        <div className="toolbar">
          <span className="chip high">{counts.high} high</span>
          <span className="chip medium">{counts.medium} medium</span>
          <span className="chip low">{counts.low} low</span>
        </div>
      </div>
      <Card
        bodyClass="tight"
        title={`${rows.length} of ${data.length} alerts`}
        right={
          <div className="toolbar">
            <input type="search" placeholder="search signature, host, MAC…" value={q} onChange={(e) => setQ(e.target.value)} />
            <select value={sev} onChange={(e) => setSev(e.target.value)}>
              <option value="all">all severities</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
            </select>
            <select value={src} onChange={(e) => setSrc(e.target.value)}>
              <option value="all">all sources</option>
              <option value="suricata">suricata</option>
              <option value="zeek">zeek</option>
              <option value="radius">radius</option>
              <option value="syslog">syslog</option>
            </select>
            <select value={status} onChange={(e) => setStatus(e.target.value)}>
              <option value="all">all statuses</option>
              {['contained', 'resolved', 'review', 'monitor', 'closed', 'informational'].map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>
        }
      >
        <div className="table-wrap" style={{ maxHeight: 'calc(100vh - 230px)' }}>
          <table className="data">
            <thead>
              <tr>
                <th>time</th><th>severity</th><th>signature</th><th>source</th><th>src</th><th>dst</th><th>device / port</th><th>status</th><th>incident</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((a) => (
                <tr key={a.id} className={`clickable ${sel?.id === a.id ? 'selected' : ''}`} onClick={() => setSel(a)}>
                  <td><Ts ts={a.ts} /></td>
                  <td><Sev s={a.severity} /></td>
                  <td className="wrap" style={{ minWidth: 300 }}>{a.signature}</td>
                  <td><Chip kind="source">{a.source}</Chip></td>
                  <td className="mono">{a.src_ip ? `${a.src_ip}${a.src_port ? ':' + a.src_port : ''}` : a.mac ?? '—'}</td>
                  <td className="mono">{a.dest_ip ? `${a.dest_ip}${a.dest_port ? ':' + a.dest_port : ''}` : '—'}</td>
                  <td>
                    {a.device ? <Link to={`/devices/${a.device}`}>{a.device}</Link> : <span className="dim">unknown</span>}
                    {a.interface && <span className="mono dim"> · {a.interface}</span>}
                  </td>
                  <td><Chip kind={a.status} /></td>
                  <td>{a.incident_id ? <Link to={`/incidents/${a.incident_id}`}>{a.incident_id}</Link> : <span className="faint">—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      {sel && <AlertDrawer alert={sel} onClose={() => setSel(null)} />}
    </>
  )
}

function AlertDrawer({ alert, onClose }: { alert: Alert; onClose: () => void }) {
  const { data } = useApi(() => endpoints.alert(alert.id), [alert.id])
  const det = data?.detection
  const raw = data?.alert.raw
  return (
    <Drawer title={<span><Sev s={alert.severity} /> {alert.id}</span>} onClose={onClose}>
      <div style={{ fontSize: 14, fontWeight: 600 }}>{alert.signature}</div>
      <KV rows={[
        kv('time', <Ts ts={alert.ts} date />),
        kv('source', <Chip kind="source">{alert.source}</Chip>),
        kv('category', alert.category),
        kv('source address', alert.src_ip ?? alert.mac ?? '—'),
        kv('destination', alert.dest_ip ? `${alert.dest_ip}:${alert.dest_port ?? ''}` : '—'),
        kv('device', alert.device ? <Link to={`/devices/${alert.device}`}>{alert.device}</Link> : 'unknown'),
        kv('interface', alert.interface ?? '—'),
        kv('status', <Chip kind={alert.status} />),
        kv('incident', alert.incident_id ? <Link to={`/incidents/${alert.incident_id}`}>{alert.incident_id}</Link> : '—')]} />
      {det && (
        <Card title="Correlation detection" sub={det.rule}>
          <Confidence value={det.confidence} base={det.base_confidence} />
          <div style={{ marginTop: 10 }}>
            <FeatureList features={det.features} />
          </div>
          <div className="dim small" style={{ marginTop: 8 }}>
            disposition: <Chip kind={det.disposition ?? 'monitor'} /> · {det.event_refs.length} contributing events
          </div>
        </Card>
      )}
      {raw && <Term text={JSON.stringify(raw, null, 2)} />}
    </Drawer>
  )
}

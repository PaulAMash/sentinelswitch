import { Link } from 'react-router-dom'
import { endpoints } from '../lib/api'
import { useApi } from '../lib/hooks'
import { Card, Chip, Loading, Sev, Ts } from '../components/ui'
import { vlanName } from '../lib/format'

export function Incidents() {
  const { data, error } = useApi(endpoints.incidents)
  const { data: reviews } = useApi(endpoints.reviews)
  if (!data) return <Loading error={error} />
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Incidents</h1>
          <p>Cases opened when the policy engine approved automatic containment. Manual-review detections are listed separately below.</p>
        </div>
      </div>
      <Card bodyClass="tight" title={`${data.length} incidents`}>
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr><th>id</th><th>opened</th><th>severity</th><th>title</th><th>endpoint</th><th>port</th><th>vlan</th><th>confidence</th><th>status</th></tr>
            </thead>
            <tbody>
              {data.map((i) => (
                <tr key={i.id}>
                  <td className="mono strong"><Link to={`/incidents/${i.id}`}>{i.id}</Link></td>
                  <td><Ts ts={i.opened_at} /></td>
                  <td><Sev s={i.severity} /></td>
                  <td className="wrap" style={{ minWidth: 260 }}>{i.title}</td>
                  <td>
                    {i.device ? <Link to={`/devices/${i.device}`}>{i.device}</Link> : <span className="dim">unknown</span>}
                    {i.user && <span className="dim"> · {i.user}</span>}
                  </td>
                  <td className="mono">{i.switch} {i.interface}</td>
                  <td className="mono">{i.action === 'quarantine_vlan' ? `${i.original_vlan} → ${i.status === 'contained' ? 50 : i.current_vlan}` : vlanName(i.original_vlan)}</td>
                  <td className="mono">{i.confidence.toFixed(2)}</td>
                  <td><Chip kind={i.status} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      <Card bodyClass="tight" title="Manual review queue" sub="detections between the review and automatic thresholds">
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr><th>opened</th><th>severity</th><th>detection</th><th>rule</th><th>confidence</th><th>disposition</th><th>closed</th><th>note</th></tr>
            </thead>
            <tbody>
              {(reviews ?? []).map((r) => (
                <tr key={r.detection_id}>
                  <td><Ts ts={r.opened_at} /></td>
                  <td><Sev s={r.severity} /></td>
                  <td className="wrap" style={{ minWidth: 220 }}>{r.title}</td>
                  <td className="mono">{r.rule}</td>
                  <td className="mono">{r.confidence.toFixed(2)}</td>
                  <td><Chip kind={r.decision?.disposition ?? r.status} /></td>
                  <td>{r.closed_at ? <><Ts ts={r.closed_at} /> <span className="dim">by {r.closed_by}</span></> : <Chip kind="review">open</Chip>}</td>
                  <td className="wrap" style={{ minWidth: 320 }}>{r.note ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  )
}

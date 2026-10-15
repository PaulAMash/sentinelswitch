import { useState } from 'react'
import { Link } from 'react-router-dom'
import { endpoints } from '../lib/api'
import { useApi } from '../lib/hooks'
import { Card, Chip, Loading, Sev, Ts } from '../components/ui'
import { vlanName } from '../lib/format'

export function Incidents() {
  const { data, error, reload } = useApi(endpoints.incidents)
  const { data: reviews, error: reviewsError, reload: reloadReviews } = useApi(endpoints.reviews)
  const [busy, setBusy] = useState<string | null>(null)
  const [errs, setErrs] = useState<Record<string, string>>({})
  if (!data) return <Loading error={error} />
  const respond = async (id: string, kind: 'approve' | 'reject') => {
    setBusy(id)
    setErrs((prev) => {
      const next = { ...prev }
      delete next[id]
      return next
    })
    try {
      if (kind === 'approve') await endpoints.approveReview(id, { actor: 'tlee', note: 'approved after analyst review' })
      else await endpoints.rejectReview(id, { actor: 'tlee', note: 'containment declined after analyst review' })
      reloadReviews()
      reload()
    } catch (e) {
      setErrs((prev) => ({ ...prev, [id]: (e as Error).message }))
    } finally {
      setBusy(null)
    }
  }
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Incidents</h1>
          <p>Cases opened when the policy engine authorized automatic containment or an analyst approved a manual-review detection. Manual-review detections are listed separately below; an analyst authorization is recorded for each decision, distinct from the policy tier.</p>
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
                  <td><Ts ts={i.opened_at} date /></td>
                  <td><Sev s={i.severity} /></td>
                  <td className="wrap" style={{ minWidth: 260 }}>{i.title}</td>
                  <td>
                    {i.device ? <Link to={`/devices/${i.device}`}>{i.device}</Link> : <span className="dim">unknown</span>}
                    {i.user && <span className="dim"> · {i.user}</span>}
                  </td>
                  <td className="mono">{i.switch} {i.interface}</td>
                  <td className="mono">{i.action === 'quarantine_vlan' ? `${i.original_vlan} → ${i.current_vlan}` : vlanName(i.original_vlan)}</td>
                  <td className="mono">{i.confidence.toFixed(2)}</td>
                  <td><Chip kind={i.status} /></td>
                </tr>
              ))}
              {data.length === 0 && (
                <tr><td colSpan={9} className="dim">No incidents yet</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>
      <Card bodyClass="tight" title="Manual review queue" sub="detections between the review and automatic thresholds">
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr><th>opened</th><th>severity</th><th>detection</th><th>rule</th><th>confidence</th><th>disposition</th><th>authorization</th><th>analyst action</th><th>closed</th><th>note</th></tr>
            </thead>
            <tbody>
              {(reviews ?? []).map((r) => {
                const guards = r.decision?.guards_triggered ?? []
                const auth = r.authorization
                const working = busy === r.detection_id
                return (
                  <tr key={r.detection_id}>
                    <td><Ts ts={r.opened_at} date /></td>
                    <td><Sev s={r.severity} /></td>
                    <td className="wrap" style={{ minWidth: 220 }}>{r.title}</td>
                    <td className="mono">{r.rule}</td>
                    <td className="mono">{r.confidence.toFixed(2)}</td>
                    <td><Chip kind={r.decision?.disposition ?? r.status} /></td>
                    <td>
                      <div className="row" style={{ gap: 6, flexWrap: 'nowrap' }}>
                        {auth ? <Chip kind={auth.status} /> : <span className="dim">—</span>}
                        {auth && <span className="dim small">{auth.mode}{auth.authorized_by ? ` · ${auth.authorized_by}` : ''}</span>}
                      </div>
                      <div className="mono small dim" style={{ marginTop: 3 }}>guards: {guards.length ? guards.join(', ') : 'none'}</div>
                    </td>
                    <td>
                      {r.status === 'review' ? (
                        <div className="toolbar" style={{ flexWrap: 'nowrap' }}>
                          <button className="btn sm primary" disabled={working} onClick={() => respond(r.detection_id, 'approve')}>Approve containment</button>
                          <button className="btn sm" disabled={working} onClick={() => respond(r.detection_id, 'reject')}>Reject</button>
                        </div>
                      ) : r.incident_id ? (
                        <Link className="mono strong" to={`/incidents/${r.incident_id}`}>{r.incident_id}</Link>
                      ) : (
                        <span className="dim">—</span>
                      )}
                      {errs[r.detection_id] && <div className="small wrap" style={{ color: '#ff8a80', marginTop: 4, maxWidth: 320 }}>{errs[r.detection_id]}</div>}
                    </td>
                    <td>{r.closed_at ? <><Ts ts={r.closed_at} date /> <span className="dim">by {r.closed_by}</span></> : <Chip kind="review">open</Chip>}</td>
                    <td className="wrap" style={{ minWidth: 320 }}>{r.note ?? '—'}</td>
                  </tr>
                )
              })}
              {reviews && reviews.length === 0 && (
                <tr><td colSpan={10} className="dim">No detections in the manual review queue</td></tr>
              )}
              {!reviews && (
                <tr><td colSpan={10}><Loading error={reviewsError} /></td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  )
}

import { useState } from 'react'
import { Link } from 'react-router-dom'
import { endpoints, type ContainmentAction, type Incident, type Review } from '../lib/api'
import { useApi } from '../lib/hooks'
import { ErrorState, Loading, Panel, Ts } from '../components/ui'
import { PageHeader } from '../components/layout'
import { Chip, Id, ResponseChip, SeverityChip, StatusChip, responseStateOf } from '../components/status'
import { DataTable, Cell2 } from '../components/table'
import { ConfirmDialog } from '../components/dialog'
import { useToast } from '../components/toast'
import { vlanName } from '../lib/format'

const ANALYST = 'tlee'
const APPROVE_NOTE = 'approved after analyst review'
const REJECT_NOTE = 'containment declined after analyst review'

type Pending = { kind: 'approve' | 'reject'; review: Review }

export function Incidents() {
  const { data, error, reload } = useApi(endpoints.incidents)
  const { data: reviews, error: reviewsError, reload: reloadReviews } = useApi(endpoints.reviews)
  const { data: overview } = useApi(endpoints.overview)
  const toast = useToast()
  const [pending, setPending] = useState<Pending | null>(null)
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState<string | null>(null)
  const [dlgError, setDlgError] = useState<string | null>(null)
  const [errs, setErrs] = useState<Record<string, string>>({})
  if (error && !data) return <ErrorState error={error} retry={reload} />
  if (!data) return <Loading rows={5} />

  const open = (kind: Pending['kind'], review: Review) => {
    setPending({ kind, review })
    setNote(kind === 'approve' ? APPROVE_NOTE : REJECT_NOTE)
    setDlgError(null)
  }
  const confirm = async () => {
    if (!pending) return
    const id = pending.review.detection_id
    setBusy(id)
    setDlgError(null)
    try {
      if (pending.kind === 'approve') {
        const r = await endpoints.approveReview(id, { actor: ANALYST, note })
        toast.push({ title: `Containment authorized for ${id}`, detail: `${r.incident.id} · action ${r.action.status}`, tone: 'ok' })
      } else {
        await endpoints.rejectReview(id, { actor: ANALYST, note })
        toast.push({ title: `Containment declined for ${id}`, detail: 'the switch was not touched', tone: 'info' })
      }
      setErrs((prev) => {
        const next = { ...prev }
        delete next[id]
        return next
      })
      setPending(null)
      reloadReviews()
      reload()
    } catch (e) {
      const msg = (e as Error).message
      setDlgError(msg)
      setErrs((prev) => ({ ...prev, [id]: msg }))
    } finally {
      setBusy(null)
    }
  }

  const queue = reviews ?? []
  const waiting = queue.filter((r) => r.status === 'review').length
  // latest action per incident, preferring the one that reached verification/restore
  const actionFor = new Map<string, ContainmentAction>()
  for (const a of overview?.containment_activity ?? []) {
    if (!a.incident_id) continue
    const cur = actionFor.get(a.incident_id)
    if (!cur || ['verified', 'restored', 'containment_failed'].includes(a.status)) actionFor.set(a.incident_id, a)
  }
  const pr = pending?.review
  const pd = pr?.decision
  const pa = pr?.attribution
  return (
    <>
      <PageHeader
        title="Incidents"
        sub="Cases opened when policy authorized automatic containment or an analyst approved a manual-review detection"
        info={<>Manual-review detections are listed in the queue above the incident table; an analyst authorization is recorded for each decision, distinct from the policy tier. The response state of every row is derived from the backend's action status, authorization record and read-back verification — never inferred.</>}
      />

      <Panel title={waiting ? 'Awaiting authorization' : 'Manual review queue'} sub="detections between the review and automatic thresholds" right={waiting ? <Chip kind="pending">{waiting} waiting</Chip> : undefined} bodyClass="none">
        <DataTable
          cards
          rows={reviews}
          loading={!reviews}
          error={!reviews ? reviewsError : null}
          rowKey={(r) => r.detection_id}
          empty="No detections are waiting for a decision"
          columns={[
            { key: 'opened', header: 'opened', render: (r) => <Ts ts={r.opened_at} date ms={false} /> },
            { key: 'sev', header: 'severity', render: (r) => <SeverityChip value={r.severity} /> },
            { key: 'det', header: 'detection', wrap: true, render: (r) => <Cell2 primary={r.title} secondary={<Id dim>{r.detection_id}</Id>} /> },
            { key: 'rule', header: 'rule', className: 'mono', priority: 3, render: (r) => r.rule },
            { key: 'conf', header: 'confidence', className: 'mono', priority: 3, render: (r) => r.confidence.toFixed(2) },
            { key: 'disp', header: 'policy', render: (r) => <StatusChip value={r.decision?.disposition ?? r.status} /> },
            { key: 'guards', header: 'guards', className: 'mono small', priority: 2, render: (r) => (r.decision?.guards_triggered.length ? r.decision.guards_triggered.join(', ') : <span className="dim">none</span>) },
            {
              key: 'auth',
              header: 'authorization',
              render: (r) => (
                <Cell2
                  primary={<ResponseChip state={responseStateOf(null, null, r, busy === r.detection_id)} />}
                  secondary={r.authorization ? `${r.authorization.mode}${r.authorization.authorized_by ? ` · ${r.authorization.authorized_by}` : ''}` : r.closed_at ? `closed by ${r.closed_by}` : undefined}
                />
              ),
            },
            {
              key: 'actions',
              header: 'analyst action',
              render: (r) =>
                r.status === 'review' ? (
                  <div className="queue-actions">
                    <button className="btn sm consequential" type="button" disabled={busy === r.detection_id} onClick={(e) => { e.stopPropagation(); open('approve', r) }}>
                      Approve containment
                    </button>
                    <button className="btn sm" type="button" disabled={busy === r.detection_id} onClick={(e) => { e.stopPropagation(); open('reject', r) }}>
                      Reject
                    </button>
                    {errs[r.detection_id] && <div className="small danger wrap">{errs[r.detection_id]}</div>}
                  </div>
                ) : r.incident_id ? (
                  <Link className="id" to={`/incidents/${r.incident_id}`}>
                    {r.incident_id}
                  </Link>
                ) : (
                  <span className="dim">—</span>
                ),
            },
            { key: 'note', header: 'note', wrap: true, priority: 2, render: (r) => <span className="small dim">{r.note ?? '—'}</span> },
          ]}
        />
      </Panel>

      <Panel title="Incidents" sub={`${data.length} total`} bodyClass="none">
        <DataTable
          rows={data}
          rowKey={(i) => i.id}
          empty="No incidents yet"
          columns={[
            { key: 'id', header: 'id', render: (i) => <Link className="id" to={`/incidents/${i.id}`}>{i.id}</Link> },
            { key: 'opened', header: 'opened', render: (i) => <Ts ts={i.opened_at} date ms={false} /> },
            { key: 'sev', header: 'severity', render: (i) => <SeverityChip value={i.severity} /> },
            { key: 'title', header: 'title', wrap: true, render: (i) => i.title },
            {
              key: 'endpoint',
              header: 'endpoint',
              priority: 2,
              render: (i) => (
                <>
                  {i.device ? <Link to={`/devices/${i.device}`}>{i.device}</Link> : <span className="dim">unknown</span>}
                  {i.user && <span className="dim"> · {i.user}</span>}
                </>
              ),
            },
            { key: 'port', header: 'port', className: 'mono', priority: 2, render: (i) => `${i.switch} ${i.interface ?? ''}` },
            { key: 'vlan', header: 'vlan', className: 'mono', priority: 3, render: (i) => (i.action === 'quarantine_vlan' ? `${i.original_vlan} → ${i.current_vlan}` : vlanName(i.original_vlan)) },
            { key: 'conf', header: 'confidence', className: 'mono', priority: 3, render: (i) => i.confidence.toFixed(2) },
            { key: 'state', header: 'response', render: (i) => <IncidentState incident={i} action={actionFor.get(i.id) ?? null} /> },
          ]}
        />
      </Panel>

      <ConfirmDialog
        open={!!pending}
        tone="consequential"
        title={pending?.kind === 'approve' ? 'Authorize containment' : 'Decline containment'}
        summary={
          pending?.kind === 'approve' ? (
            <>
              Quarantine <span className="mono">{pa?.device ?? pr?.title}</span> on <span className="mono">{pa?.interface ?? '—'}</span>: VLAN {pa?.vlan ?? '—'} → {pd?.quarantine_vlan ?? 50}.{' '}
              {pd?.guards_triggered.length ? <>Policy withheld automation because: <span className="mono">{pd.guards_triggered.join(', ')}</span>.</> : 'Policy routed this detection to manual review.'} The backend executes only if the authorization is accepted and the port is not protected.
            </>
          ) : (
            <>
              Record that containment was declined for <span className="mono">{pr?.detection_id}</span>. The switch is not touched.
            </>
          )
        }
        note={{ label: 'Note (recorded with the decision)', value: note, onChange: setNote }}
        actor={ANALYST}
        confirmLabel={pending?.kind === 'approve' ? 'Authorize and contain' : 'Record rejection'}
        busy={busy !== null}
        error={dlgError}
        onCancel={() => setPending(null)}
        onConfirm={confirm}
      />
    </>
  )
}

/**
 * Response chip for the incident list. The list endpoint carries no action record, so the action
 * comes from the overview's containment activity (one request for the whole table); when an incident
 * has no action there, the chip falls back to the incident's own lifecycle status word.
 */
function IncidentState({ incident, action }: { incident: Incident; action: ContainmentAction | null }) {
  if (!action) return <StatusChip value={incident.status} />
  return <ResponseChip state={responseStateOf(incident, action)} />
}

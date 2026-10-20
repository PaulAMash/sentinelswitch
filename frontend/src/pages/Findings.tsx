import { useMemo, useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { kv } from '../lib/kv'
import { endpoints, type Finding, type FindingEvent } from '../lib/api'
import { useApi } from '../lib/hooks'
import { Empty, ErrorState, KV, Loading, Panel, Segmented, Ts } from '../components/ui'
import { PageHeader } from '../components/layout'
import { AssessChip, Chip, Id, SeverityChip, StatusChip } from '../components/status'
import { DataTable, Cell2 } from '../components/table'
import { Terminal } from '../components/terminal'
import { ConfirmDialog } from '../components/dialog'
import { useToast } from '../components/toast'
import { fmtTime, sevRank, title, vlanName } from '../lib/format'
import { EvidenceList, Freshness, ValueBlock, fmtInline } from './Controls'
import { LifecycleStrip } from '../charts/viz'

type RemediateResult = Awaited<ReturnType<typeof endpoints.remediate>>

const ANALYST = 'tlee'
const REMEDIATE_NOTE = 'remediated from the dashboard'
/** Finding states in which an analyst may request remediation (mirrors RemediationService). */
const REMEDIABLE = new Set<string>(['open', 'reopened', 'remediation_failed'])
const REM_CHIP: Record<string, string> = { not_started: 'neutral', requested: 'pending', executed: 'ok', refused: 'refused' }
const EVENT_PHASE: Record<string, string> = {
  opened: 'detection',
  reopened: 'detection',
  remediation_requested: 'policy',
  remediation_executed: 'containment',
  remediation_refused: 'alert',
  verification_failed: 'incident',
  verified: 'verification',
}
const HL = ['switchport access vlan', 'shutdown', 'clear authentication', 'monitor session', 'port-security', 'authentication port-control', 'ip dhcp snooping trust', 'ip arp inspection trust']

export function Findings() {
  const { id } = useParams()
  const nav = useNavigate()
  if (id) return <FindingDetail key={id} id={id} onBack={() => nav('/findings')} />
  return <FindingList onOpen={(fid) => nav(`/findings/${fid}`)} />
}

// ---- list ---------------------------------------------------------------------------------------
function FindingList({ onOpen }: { onOpen: (id: string) => void }) {
  const [params, setParams] = useSearchParams()
  const openOnly = params.get('view') !== 'all' // /findings?view=all opens the full history
  const [sev, setSev] = useState('all')
  const [status, setStatus] = useState('all')
  const { data, fresh, error } = useApi(() => endpoints.findings(openOnly ? '?open_only=true' : ''), [openOnly])
  const { data: posture } = useApi(endpoints.posture)
  // Rows are only shown when they answer the current open-only/all question; while the new request is
  // in flight (or if it failed) the table shows a loading or error row instead of the previous result.
  const current = fresh ? data : null
  const rows = useMemo(
    () =>
      (current ?? [])
        .filter((f) => sev === 'all' || f.severity === sev)
        .filter((f) => status === 'all' || f.status === status)
        .sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || a.opened_at.localeCompare(b.opened_at) || a.id.localeCompare(b.id)),
    [current, sev, status],
  )
  if (error && !data) return <ErrorState error={error} />
  if (!data) return <Loading rows={5} />
  const statuses = Array.from(new Set((current ?? data).map((f) => f.status)))
  const bySev = { high: 0, medium: 0, low: 0 }
  for (const f of rows) bySev[f.severity] += 1
  return (
    <>
      <PageHeader
        title="Findings"
        sub={current ? `${rows.length} shown · ${bySev.high} high · ${bySev.medium} medium · ${bySev.low} low` : 'loading…'}
        info={<>Every FAIL or STALE assessment opens a finding with a stable identifier that is never deleted. Remediation is requested by an analyst, executed on the switch twin with an IOS transcript, re-assessed and verified; each step is recorded as an event.</>}
      >
        <Segmented
          label="Finding scope"
          options={[
            { id: 'open', label: 'open only' },
            { id: 'all', label: 'all' },
          ]}
          value={openOnly ? 'open' : 'all'}
          onChange={(v) => setParams(v === 'all' ? { view: 'all' } : {})}
        />
        <select value={sev} onChange={(e) => setSev(e.target.value)} aria-label="Severity">
          <option value="all">all severities</option>
          <option value="high">high</option>
          <option value="medium">medium</option>
          <option value="low">low</option>
        </select>
        <select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status">
          <option value="all">all statuses</option>
          {statuses.map((s) => (
            <option key={s} value={s}>
              {title(s).toLowerCase()}
            </option>
          ))}
        </select>
      </PageHeader>

      <Panel title="Lifecycle" sub="every finding ever recorded, by current state · findings are never deleted">
        {posture ? <LifecycleStrip byStatus={posture.findings.by_status} /> : <Loading rows={2} />}
      </Panel>

      <Panel title={openOnly ? 'Open findings' : 'All findings'} sub="open a row for evidence and remediation" bodyClass="none">
        <DataTable
          cards="narrow"
          rows={current ? rows : null}
          loading={!current}
          error={!current ? error : null}
          rowKey={(f) => f.id}
          onRowActivate={(f) => onOpen(f.id)}
          empty={current && current.length === 0 ? (openOnly ? 'No open findings — every assessed control passes or is awaiting evidence' : 'No findings have been recorded yet') : 'No findings match the current filters'}
          columns={[
            { key: 'sev', header: 'severity', render: (f) => <SeverityChip value={f.severity} /> },
            { key: 'id', header: 'finding', className: 'break-ids', render: (f) => <Id>{f.id}</Id> },
            { key: 'control', header: 'control', wrap: true, render: (f) => <Cell2 primary={f.control_name} secondary={<Id dim>{f.control_id}</Id>} /> },
            { key: 'scope', header: 'asset / scope', className: 'mono', hideBelow: 1200, render: (f) => <>{f.asset ?? f.scope.id}{f.scope.interface && f.scope.interface !== f.asset && <span className="dim"> · {f.scope.interface}</span>}</> },
            { key: 'result', header: 'result', render: (f) => <AssessChip value={f.result} /> },
            { key: 'status', header: 'status', render: (f) => <StatusChip value={f.status} /> },
            { key: 'opened', header: 'opened', hideBelow: 900, render: (f) => <Ts ts={f.opened_at} date ms={false} /> },
            { key: 'occ', header: 'occurrences', align: 'right', hideBelow: 900, render: (f) => f.occurrences },
            { key: 'why', header: 'explanation', wrap: true, hideBelow: 1200, render: (f) => <span className="clamp-2 small dim" title={f.explanation}>{f.explanation}</span> },
          ]}
        />
      </Panel>
    </>
  )
}

// ---- detail -------------------------------------------------------------------------------------
function FindingDetail({ id, onBack }: { id: string; onBack: () => void }) {
  const { data, error, reload } = useApi(() => endpoints.finding(id), [id])
  const toast = useToast()
  const [dialog, setDialog] = useState(false)
  const [note, setNote] = useState(REMEDIATE_NOTE)
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<RemediateResult | null>(null)
  const [dlgError, setDlgError] = useState<string | null>(null)
  if (error && !data) return <ErrorState error={error} retry={reload} />
  if (!data) return <Loading rows={6} />
  const f: Finding = data.finding
  const a = data.assessment
  const rem = f.remediation
  const ver = f.verification
  const canRemediate = REMEDIABLE.has(f.status) && !!rem.action
  const why = reason(f)
  const csf = data.control?.csf ?? a?.framework.nist_csf_2_0 ?? []
  const history = [...data.history].reverse()
  const remediate = async () => {
    setBusy(true)
    setDlgError(null)
    try {
      const r = await endpoints.remediate(f.id, { actor: ANALYST, note })
      setResult(r)
      toast.push({ title: r.executed ? 'Remediation executed on the twin' : 'Remediation refused by the adapter', detail: r.run ? `re-assessed by ${r.run.run_id} · finding ${r.finding.status}` : r.refused ?? undefined, tone: r.executed ? 'ok' : 'warn' })
      setDialog(false)
      reload()
    } catch (e) {
      setDlgError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <>
      <PageHeader
        eyebrow={
          <span className="row">
            <Id>{f.id}</Id>
            <SeverityChip value={f.severity} />
            <StatusChip value={f.status} />
            <AssessChip value={f.result} />
            {ver.outcome && (
              <span className="row nowrap small dim">
                verified <AssessChip value={ver.outcome} />
              </span>
            )}
            <Chip kind="neutral">{f.category}</Chip>
          </span>
        }
        title={f.control_name}
        sub={f.explanation}
      >
        <button className="btn" type="button" onClick={onBack}>
          ← All findings
        </button>
        <Link className="btn" to={`/controls/${f.control_id}`}>
          Control {f.control_id}
        </Link>
      </PageHeader>

      <div className="grid grid-main-rail">
        <div className="stack">
          <Panel title="Remediation" right={<Chip kind={REM_CHIP[rem.status] ?? 'neutral'}>{title(rem.status)}</Chip>}>
            <div className="stack">
              <p>{rem.guidance}</p>
              <div className="eyebrow">Proposed commands</div>
              {rem.commands.length ? <Terminal text={rem.commands.join('\n')} hl={HL} /> : <div className="dim small">No executable commands were produced for this finding; manual follow-up is required.</div>}
              <KV
                rows={[
                  kv('executable action', rem.action ? <span className="mono wrap">{fmtInline(rem.action)}</span> : <span className="dim">none — manual follow-up</span>),
                  kv('requested', rem.requested_at ? <><Ts ts={rem.requested_at} date /> <span className="dim">by {rem.requested_by ?? '—'}</span></> : '—'),
                  kv('executed', rem.executed_at ? <><Ts ts={rem.executed_at} date /> <span className="dim">by {rem.executed_by ?? '—'}</span></> : '—'),
                  kv('verified', ver.at ? <><Ts ts={ver.at} date /> <span className="dim">run {ver.run_id}</span></> : '—'),
                  ...(rem.note ? [kv('note', rem.note)] : []),
                ]}
              />
              {rem.transcript && (
                <>
                  <div className="eyebrow">{rem.status === 'refused' ? 'Adapter response' : 'Switch transcript'}</div>
                  <Terminal text={rem.transcript} hl={HL} />
                </>
              )}
              <div className="row">
                <button className="btn consequential" type="button" onClick={() => setDialog(true)} disabled={!canRemediate || busy}>
                  {busy ? 'Remediating…' : 'Remediate'}
                </button>
                <span className="dim small">{canRemediate ? 'requests, executes on the twin, then re-assesses to verify (it may fail)' : why}</span>
              </div>
              {result && <RemediationResult r={result} />}
            </div>
          </Panel>

          <Panel title="Verification" right={ver.outcome ? <AssessChip value={ver.outcome} /> : <Chip kind="outline">not verified</Chip>}>
            <KV
              rows={[
                kv('outcome', ver.outcome ? <AssessChip value={ver.outcome} /> : <span className="dim">no verification run has re-assessed this scope yet</span>),
                kv('at', <Ts ts={ver.at} date />),
                kv('run', ver.run_id ? <Id dim>{ver.run_id}</Id> : '—'),
                ...(ver.after_remediation !== undefined ? [kv('after remediation', ver.after_remediation ? 'yes — verified after an executed remediation' : 'no — condition cleared without remediation')] : []),
              ]}
            />
          </Panel>

          <Panel title="Events" sub="finding history, newest last" right={<span className="count mono dim small">{data.events.length}</span>}>
            <EventsTimeline events={data.events} />
          </Panel>

          <Panel title="Assessment history" sub="every run that assessed this scope" right={<span className="mono dim small">{history.length} run{history.length === 1 ? '' : 's'}</span>} bodyClass="none">
            <DataTable
              cards="narrow"
              compact
              rows={history}
              rowKey={(h) => `${h.run_id}-${h.assessed_at}`}
              empty="No assessment history recorded"
              columns={[
                { key: 'run', header: 'run', className: 'mono small', render: (h) => h.run_id },
                { key: 'status', header: 'status', render: (h) => <AssessChip value={h.status} /> },
                { key: 'at', header: 'assessed', render: (h) => <Ts ts={h.assessed_at} date ms={false} /> },
                { key: 'obs', header: 'observed', wrap: true, className: 'mono small', hideBelow: 700, render: (h) => fmtInline(h.observed) },
              ]}
            />
          </Panel>
        </div>

        <div className="stack">
          <Panel title="Finding" bodyClass="flush">
            <KV
              rows={[
                kv('control', <><Link to={`/controls/${f.control_id}`}>{f.control_name}</Link> <Id dim>{f.control_id}</Id></>),
                kv('scope', `${f.scope.type} · ${f.scope.id}`),
                kv('asset', f.asset ?? '—'),
                kv(f.scope.interface ? 'interface' : 'switch', f.scope.interface ? `${f.scope.switch} ${f.scope.interface}` : f.scope.switch),
                kv('vlan', vlanName(f.scope.vlan)),
                ...(f.scope.description ? [kv('description', f.scope.description)] : []),
                kv('opened', <Ts ts={f.opened_at} date />),
                kv('updated', <Ts ts={f.updated_at} date />),
                kv('first run', <Id dim>{f.first_run_id}</Id>),
                kv('last run', <Id dim>{f.last_run_id}</Id>),
                kv('occurrences', `${f.occurrences} run${f.occurrences === 1 ? '' : 's'} with this result`),
                kv('assessment', <Id dim>{f.assessment_id}</Id>),
                ...(f.resolved_at ? [kv('resolved', <Ts ts={f.resolved_at} date />)] : []),
              ]}
            />
          </Panel>
          <Panel title="Expected vs observed" sub="from the run that last produced this result" bodyClass="flush">
            <div className="stack tight">
              <div className="eyebrow">Expected</div>
              <ValueBlock v={f.expected} />
              <div className="eyebrow">Observed</div>
              <ValueBlock v={f.observed} />
            </div>
          </Panel>
          <Panel title="Evidence" sub={a ? `assessment ${a.id} · collected ${fmtTime(a.evidence_collected_at, { date: true, ms: false })}` : 'latest assessment'} right={a ? <AssessChip value={a.status} /> : undefined} bodyClass="flush">
            {a ? (
              <div className="stack">
                {a.explanation !== f.explanation && <div className="notice">{a.explanation}</div>}
                <EvidenceList items={a.evidence} />
                <div className="eyebrow">Freshness</div>
                <Freshness f={a.freshness} />
                <div className="dim small">
                  source of truth: <span className="mono wrap">{a.source_of_truth}</span>
                  {a.limitations && <div>Limitation: {a.limitations}</div>}
                </div>
              </div>
            ) : (
              <Empty>No assessment record is linked to this finding</Empty>
            )}
          </Panel>
          <Panel title="Related incidents" bodyClass="flush">
            {f.related_incidents.length ? (
              <div className="row">
                {f.related_incidents.map((i) => (
                  <Link key={i} className="id" to={`/incidents/${i}`}>
                    {i}
                  </Link>
                ))}
              </div>
            ) : (
              <span className="dim small">No related incidents</span>
            )}
          </Panel>
          <Panel title="Framework mapping" sub="NIST CSF 2.0 · documentation aid, not a framework assessment" bodyClass="flush">
            {csf.length ? (
              <div className="stack tight">
                {csf.map((r) => (
                  <div key={r.id} className="wrap">
                    <Chip kind="neutral" mono>
                      {r.id}
                    </Chip>{' '}
                    <span className="dim">{r.text}</span>
                  </div>
                ))}
              </div>
            ) : (
              <span className="dim small">No framework references for this control</span>
            )}
          </Panel>
        </div>
      </div>

      <ConfirmDialog
        open={dialog}
        tone="consequential"
        title="Remediate finding"
        summary={
          <div className="stack tight">
            <span>These IOS commands will be applied to {f.scope.switch} through the adapter, then the scope is re-assessed. The adapter refuses protected interfaces; the result may still fail verification.</span>
            {rem.commands.length > 0 && <Terminal text={rem.commands.join('\n')} copy={false} maxHeight={160} />}
          </div>
        }
        note={{ label: 'Note (recorded with the request)', value: note, onChange: setNote }}
        actor={ANALYST}
        confirmLabel="Request and execute"
        busy={busy}
        error={dlgError}
        onCancel={() => setDialog(false)}
        onConfirm={remediate}
      />
    </>
  )
}

function RemediationResult({ r }: { r: RemediateResult }) {
  const counts = r.run ? Object.entries(r.run.counts).map(([k, v]) => `${v} ${k}`).join(' · ') : null
  return (
    <div className={r.executed ? 'notice ok' : 'error'}>
      <div className="stack tight">
        <div className="row">
          <b>{r.executed ? 'Remediation executed on the twin' : 'Remediation refused by the switch adapter'}</b>
          <span className="dim small">resulting status</span>
          <StatusChip value={r.finding.status} />
          {r.finding.verification.outcome && <AssessChip value={r.finding.verification.outcome} />}
        </div>
        {r.refused && <div>{r.refused}</div>}
        {r.run ? (
          <div className="small">
            re-assessed by run <Id dim>{r.run.run_id}</Id> at {fmtTime(r.run.assessed_at, { date: true, ms: false })} · {counts} · {r.run.findings_open} finding{r.run.findings_open === 1 ? '' : 's'} open
          </div>
        ) : (
          r.executed && <div className="small dim">No re-assessment run was returned; the next assessment run will verify the change.</div>
        )}
        {r.commands && r.commands.length > 0 && <div className="small dim">{r.commands.length} command{r.commands.length === 1 ? '' : 's'} applied — transcript recorded in the remediation panel and the event history.</div>}
      </div>
    </div>
  )
}

function EventsTimeline({ events }: { events: FindingEvent[] }) {
  if (events.length === 0) return <Empty>No events recorded for this finding</Empty>
  return (
    <div className="timeline">
      {events.map((e, i) => {
        const phase = EVENT_PHASE[e.event] ?? 'evidence'
        return (
          <div key={i} className={`tl-item ${phase}`}>
            <span className="tl-ts" title={e.ts}>
              {e.ts.slice(11, 23)}
            </span>
            <span className="tl-dot" />
            <div className="tl-body">
              <span className={`tl-phase ${phase}`}>{title(e.event)}</span>
              <span className="tl-msg">
                {e.detail ?? ''}
                {e.actor && <span className="dim"> · {e.actor}</span>}
              </span>
              <div className="faint small mono">{e.ts.slice(0, 10)}</div>
              {e.transcript && (
                <details>
                  <summary className="dim small">transcript ({e.transcript.split('\n').length} lines)</summary>
                  <Terminal text={e.transcript} hl={HL} />
                </details>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}

function reason(f: Finding): string {
  if (f.status === 'verified' || f.status === 'closed') return `already ${f.status}${f.resolved_at ? ` at ${fmtTime(f.resolved_at, { date: true, ms: false })}` : ''}; nothing to remediate`
  if (f.status === 'remediation_requested') return 'a remediation is already in progress for this finding'
  if (f.status === 'remediated') return 'remediation executed; awaiting verification by the next assessment run'
  if (!f.remediation.action) return 'no executable remediation for this control; manual follow-up is required'
  return 'remediation is not available in the current state'
}

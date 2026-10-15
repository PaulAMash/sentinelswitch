import { useMemo, useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { kv } from '../lib/kv'
import { endpoints, type Finding, type FindingEvent } from '../lib/api'
import { useApi } from '../lib/hooks'
import { Card, Chip, Empty, KV, Loading, Sev, Term, Ts } from '../components/ui'
import { fmtTime, sevRank, title, vlanName } from '../lib/format'
import { EvidenceList, Freshness, ValueBlock } from './Controls'

type RemediateResult = Awaited<ReturnType<typeof endpoints.remediate>>

/** Finding states in which an analyst may request remediation (mirrors RemediationService). */
const REMEDIABLE = new Set<string>(['open', 'reopened', 'remediation_failed'])
const REM_CHIP: Record<string, string> = { not_started: 'neutral', requested: 'pending', executed: 'ok', refused: 'fail' }
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
  const [params] = useSearchParams()
  const [openOnly, setOpenOnly] = useState(params.get('view') !== 'all')  // /findings?view=all opens the full history
  const [sev, setSev] = useState('all')
  const [status, setStatus] = useState('all')
  const { data, fresh, error } = useApi(() => endpoints.findings(openOnly ? '?open_only=true' : ''), [openOnly])
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
  if (!data) return <Loading error={error} />
  const statuses = Array.from(new Set((current ?? data).map((f) => f.status)))
  const bySev = { high: 0, medium: 0, low: 0 }
  for (const f of rows) bySev[f.severity] += 1
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Findings &amp; remediation</h1>
          <p>Every FAIL or STALE assessment opens a finding with a stable identifier that is never deleted. Remediation is requested by an analyst, executed on the switch twin with an IOS transcript, re-assessed and verified; each step is recorded as an event.</p>
        </div>
        <div className="toolbar">
          <span className="chip neutral">{current ? rows.length : '…'} shown</span>
          <span className="chip high">{current ? bySev.high : '…'} high</span>
          <span className="chip medium">{current ? bySev.medium : '…'} medium</span>
          <span className="chip low">{current ? bySev.low : '…'} low</span>
        </div>
      </div>

      <Card
        title={openOnly ? 'Open findings' : 'All findings'}
        sub="click a row for evidence and remediation"
        bodyClass="tight"
        right={
          <div className="toolbar">
            <div className="seg">
              <button className={openOnly ? 'active' : ''} onClick={() => setOpenOnly(true)}>open only</button>
              <button className={openOnly ? '' : 'active'} onClick={() => setOpenOnly(false)}>all</button>
            </div>
            <select value={sev} onChange={(e) => setSev(e.target.value)}>
              <option value="all">all severities</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
            </select>
            <select value={status} onChange={(e) => setStatus(e.target.value)}>
              <option value="all">all statuses</option>
              {statuses.map((s) => (
                <option key={s} value={s}>{title(s).toLowerCase()}</option>
              ))}
            </select>
          </div>
        }
      >
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr><th>severity</th><th>finding</th><th>control</th><th>asset / scope</th><th>result</th><th>status</th><th>opened</th><th>occurrences</th><th>explanation</th></tr>
            </thead>
            <tbody>
              {!current && (
                <tr>
                  <td colSpan={9}><Loading error={error} /></td>
                </tr>
              )}
              {current && rows.map((f) => (
                <tr key={f.id} className="clickable" onClick={() => onOpen(f.id)}>
                  <td><span className={`sev-dot ${f.severity}`} /><Sev s={f.severity} /></td>
                  <td className="mono">{f.id}</td>
                  <td className="wrap" style={{ minWidth: 200 }}>
                    <div>{f.control_name}</div>
                    <div className="mono dim small">{f.control_id}</div>
                  </td>
                  <td className="mono">
                    {f.asset ?? f.scope.id}
                    {f.scope.interface && f.scope.interface !== f.asset && <span className="dim"> · {f.scope.interface}</span>}
                  </td>
                  <td><Chip kind={f.result}>{f.result}</Chip></td>
                  <td><Chip kind={f.status} /></td>
                  <td><Ts ts={f.opened_at} date /></td>
                  <td className="num">{f.occurrences}</td>
                  <td className="wrap small dim" style={{ minWidth: 300, maxWidth: 520 }}>{short(f.explanation)}</td>
                </tr>
              ))}
              {current && rows.length === 0 && (
                <tr>
                  <td colSpan={9}>
                    <Empty>{current.length === 0 ? (openOnly ? 'No open findings — every assessed control passes or is awaiting evidence' : 'No findings have been recorded yet') : 'No findings match the current filters'}</Empty>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  )
}

// ---- detail -------------------------------------------------------------------------------------
function FindingDetail({ id, onBack }: { id: string; onBack: () => void }) {
  const { data, error, reload } = useApi(() => endpoints.finding(id), [id])
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<RemediateResult | null>(null)
  const [err, setErr] = useState<string | null>(null)
  if (!data) return <Loading error={error} />
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
    setErr(null)
    try {
      const r = await endpoints.remediate(f.id, { actor: 'tlee', note: 'remediated from the dashboard' })
      setResult(r)
      reload()
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <>
      <div className="page-head">
        <div>
          <div className="row" style={{ marginBottom: 6 }}>
            <span className="mono strong" style={{ fontSize: 15 }}>{f.id}</span>
            <span><span className={`sev-dot ${f.severity}`} /><Sev s={f.severity} /></span>
            <Chip kind={f.status} />
            <Chip kind={f.result}>{f.result}</Chip>
            <Chip kind="neutral">{f.category}</Chip>
          </div>
          <h1>{f.control_name}</h1>
          <p>{f.explanation}</p>
        </div>
        <div className="toolbar">
          <button className="btn" onClick={onBack}>← All findings</button>
          <Link className="btn" to={`/controls/${f.control_id}`}>Control {f.control_id}</Link>
        </div>
      </div>

      <div className="grid two">
        <div className="stack" style={{ minWidth: 0 }}>
          <Card title="Finding">
            <KV rows={[
              kv('control', <><Link to={`/controls/${f.control_id}`}>{f.control_name}</Link> <span className="mono dim small">{f.control_id}</span></>),
              kv('scope', `${f.scope.type} · ${f.scope.id}`),
              kv('asset', f.asset ?? '—'),
              kv(f.scope.interface ? 'interface' : 'switch', f.scope.interface ? `${f.scope.switch} ${f.scope.interface}` : f.scope.switch),
              kv('vlan', vlanName(f.scope.vlan)),
              ...(f.scope.description ? [kv('description', f.scope.description)] : []),
              kv('opened', <Ts ts={f.opened_at} date />),
              kv('updated', <Ts ts={f.updated_at} date />),
              kv('first run', <span className="mono">{f.first_run_id}</span>),
              kv('last run', <span className="mono">{f.last_run_id}</span>),
              kv('occurrences', `${f.occurrences} run${f.occurrences === 1 ? '' : 's'} with this result`),
              kv('assessment', <span className="mono">{f.assessment_id}</span>),
              ...(f.resolved_at ? [kv('resolved', <Ts ts={f.resolved_at} date />)] : [])]} />
          </Card>

          <Card title="Expected vs observed" sub="from the run that last produced this result">
            <div className="stack">
              <div>
                <h3 style={{ marginBottom: 6 }}>Expected</h3>
                <ValueBlock v={f.expected} />
              </div>
              <div>
                <h3 style={{ marginBottom: 6 }}>Observed</h3>
                <ValueBlock v={f.observed} />
              </div>
            </div>
          </Card>

          <Card
            title="Evidence"
            sub={a ? `latest assessment ${a.id} · ${a.status} · collected ${fmtTime(a.evidence_collected_at, { date: true, ms: false })}` : 'latest assessment'}
            right={a ? <Chip kind={a.status}>{a.status}</Chip> : undefined}
          >
            {a ? (
              <div className="stack">
                {a.explanation !== f.explanation && <div className="notice">{a.explanation}</div>}
                <EvidenceList items={a.evidence} />
                <div>
                  <h3 style={{ marginBottom: 6 }}>Freshness</h3>
                  <Freshness f={a.freshness} />
                </div>
                <div className="dim small">
                  source of truth: <span className="mono" style={{ wordBreak: 'break-word' }}>{a.source_of_truth}</span>
                  {a.limitations && <div style={{ marginTop: 4 }}>Limitation: {a.limitations}</div>}
                </div>
              </div>
            ) : (
              <Empty>No assessment record is linked to this finding</Empty>
            )}
          </Card>

          <Card title="Related incidents">
            {f.related_incidents.length ? (
              <div className="row">
                {f.related_incidents.map((i) => (
                  <Link key={i} className="mono" to={`/incidents/${i}`}>{i}</Link>
                ))}
              </div>
            ) : (
              <Empty>No related incidents</Empty>
            )}
          </Card>

          <Card title="Framework mapping" sub="NIST CSF 2.0 · documentation aid for simulated checks, not a framework assessment">
            {csf.length ? (
              <div className="stack" style={{ gap: 6 }}>
                {csf.map((r) => (
                  <div key={r.id} className="wrap"><span className="chip neutral mono">{r.id}</span> <span className="dim">{r.text}</span></div>
                ))}
              </div>
            ) : (
              <Empty>No framework references for this control</Empty>
            )}
          </Card>
        </div>

        <div className="stack" style={{ minWidth: 0 }}>
          <Card title="Remediation" right={<Chip kind={REM_CHIP[rem.status] ?? 'neutral'}>{title(rem.status)}</Chip>}>
            <div className="stack">
              <p>{rem.guidance}</p>
              <div>
                <h3 style={{ marginBottom: 6 }}>Proposed commands</h3>
                {rem.commands.length ? <Term text={rem.commands.join('\n')} hl={HL} /> : <div className="dim small">No executable commands were produced for this finding; manual follow-up is required.</div>}
              </div>
              <KV rows={[
                kv('executable action', rem.action ? <span className="mono wrap" style={{ wordBreak: 'break-word' }}>{fmtInline(rem.action)}</span> : <span className="dim">none — manual follow-up</span>),
                kv('requested', rem.requested_at ? <><Ts ts={rem.requested_at} date /> <span className="dim">by {rem.requested_by ?? '—'}</span></> : '—'),
                kv('executed', rem.executed_at ? <><Ts ts={rem.executed_at} date /> <span className="dim">by {rem.executed_by ?? '—'}</span></> : '—'),
                kv('verified', ver.at ? <><Ts ts={ver.at} date /> <span className="dim">run {ver.run_id}</span></> : '—'),
                ...(rem.note ? [kv('note', rem.note)] : [])]} />
              {rem.transcript && (
                <div>
                  <h3 style={{ marginBottom: 6 }}>{rem.status === 'refused' ? 'Adapter response' : 'Switch transcript'}</h3>
                  <Term text={rem.transcript} hl={HL} />
                </div>
              )}
              <div className="row">
                <button className="btn primary" onClick={remediate} disabled={!canRemediate || busy}>{busy ? 'Remediating…' : 'Remediate'}</button>
                {canRemediate ? (
                  <span className="dim small">requests, executes on the twin as tlee, then re-assesses to verify (it may fail)</span>
                ) : (
                  <span className="dim small">{why}</span>
                )}
              </div>
              {err && <div className="error">Remediation request failed: {err}</div>}
              {result && <RemediationResult r={result} />}
            </div>
          </Card>

          <Card title="Verification" right={ver.outcome ? <Chip kind={ver.outcome}>{ver.outcome}</Chip> : <Chip kind="neutral">not verified</Chip>}>
            <KV rows={[
              kv('outcome', ver.outcome ? <Chip kind={ver.outcome}>{ver.outcome}</Chip> : <span className="dim">no verification run has re-assessed this scope yet</span>),
              kv('at', <Ts ts={ver.at} date />),
              kv('run', ver.run_id ? <span className="mono">{ver.run_id}</span> : '—'),
              ...(ver.after_remediation !== undefined ? [kv('after remediation', ver.after_remediation ? 'yes — verified after an executed remediation' : 'no — condition cleared without remediation')] : [])]} />
          </Card>

          <Card title={`Events (${data.events.length})`} sub="finding history, newest last">
            <EventsTimeline events={data.events} />
          </Card>

          <Card title={`Assessment history (${history.length} run${history.length === 1 ? '' : 's'})`} sub="every run that assessed this scope" bodyClass="tight">
            <div className="table-wrap" style={{ maxHeight: 300 }}>
              <table className="data">
                <thead><tr><th>run</th><th>status</th><th>assessed</th><th>observed</th></tr></thead>
                <tbody>
                  {history.map((h) => (
                    <tr key={`${h.run_id}-${h.assessed_at}`}>
                      <td className="mono small">{h.run_id}</td>
                      <td><Chip kind={h.status}>{h.status}</Chip></td>
                      <td><Ts ts={h.assessed_at} date /></td>
                      <td className="mono wrap small" style={{ minWidth: 160, wordBreak: 'break-word' }}>{fmtInline(h.observed)}</td>
                    </tr>
                  ))}
                  {history.length === 0 && <tr><td colSpan={4}><Empty>No assessment history recorded</Empty></td></tr>}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      </div>
    </>
  )
}

function RemediationResult({ r }: { r: RemediateResult }) {
  const counts = r.run ? Object.entries(r.run.counts).map(([k, v]) => `${v} ${k}`).join(' · ') : null
  return (
    <div className={r.executed ? 'notice' : 'error'}>
      <div className="row">
        <b>{r.executed ? 'Remediation executed on the twin' : 'Remediation refused by the switch adapter'}</b>
        <span className="dim small">resulting status</span>
        <Chip kind={r.finding.status} />
        {r.finding.verification.outcome && <Chip kind={r.finding.verification.outcome}>{r.finding.verification.outcome}</Chip>}
      </div>
      {r.refused && <div style={{ marginTop: 6 }}>{r.refused}</div>}
      {r.run ? (
        <div className="small" style={{ marginTop: 6 }}>
          re-assessed by run <span className="mono">{r.run.run_id}</span> at {fmtTime(r.run.assessed_at, { date: true, ms: false })} · {counts} · {r.run.findings_open} finding{r.run.findings_open === 1 ? '' : 's'} open
        </div>
      ) : (
        r.executed && <div className="small dim" style={{ marginTop: 6 }}>No re-assessment run was returned; the next assessment run will verify the change.</div>
      )}
      {r.commands && r.commands.length > 0 && <div className="small dim" style={{ marginTop: 4 }}>{r.commands.length} command{r.commands.length === 1 ? '' : 's'} applied — transcript recorded in the remediation card and the event history.</div>}
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
            <span className="tl-ts" title={e.ts}>{e.ts.slice(11, 23)}</span>
            <span className="tl-dot" />
            <div className="tl-body">
              <span className={`tl-phase ${phase}`}>{title(e.event)}</span>
              <span className="tl-msg">
                {e.detail ?? ''}
                {e.actor && <span className="dim"> · {e.actor}</span>}
              </span>
              <div className="faint small mono">{e.ts.slice(0, 10)}</div>
              {e.transcript && (
                <details style={{ marginTop: 6 }}>
                  <summary className="dim small" style={{ cursor: 'pointer' }}>transcript ({e.transcript.split('\n').length} lines)</summary>
                  <div style={{ marginTop: 6 }}><Term text={e.transcript} hl={HL} /></div>
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

function short(s: string, n = 140): string {
  return s.length > n ? s.slice(0, n - 1) + '…' : s
}

function fmtInline(v: unknown): string {
  if (v === null || v === undefined) return '(absent)'
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}

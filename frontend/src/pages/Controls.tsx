import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { kv } from '../lib/kv'
import { endpoints, type Assessment, type AssessmentStatus, type ControlCatalogEntry, type EvidenceItem } from '../lib/api'
import { useApi } from '../lib/hooks'
import { Card, Chip, Drawer, Empty, KV, Kpi, Loading, Sev, Term, Ts } from '../components/ui'
import { fmtTime, vlanName } from '../lib/format'

const STATUSES: AssessmentStatus[] = ['PASS', 'FAIL', 'UNKNOWN', 'STALE']
/** Display priority for assessment rows: failures first, passes last. */
const PRIORITY: AssessmentStatus[] = ['FAIL', 'STALE', 'UNKNOWN', 'PASS']

export function Controls() {
  const { id } = useParams()
  const nav = useNavigate()
  if (id) return <ControlDetail key={id} id={id} onBack={() => nav('/controls')} />
  return <Catalog onOpen={(cid) => nav(`/controls/${cid}`)} />
}

// ---- catalog ------------------------------------------------------------------------------------
function Catalog({ onOpen }: { onOpen: (id: string) => void }) {
  const { data, error, reload } = useApi(endpoints.controls)
  const [busy, setBusy] = useState(false)
  const [runError, setRunError] = useState<string | null>(null)
  if (!data) return <Loading error={error} />
  const byId = new Map(data.status.map((s) => [s.control_id, s]))
  const totals = data.status.reduce(
    (acc, s) => ({ assessments: acc.assessments + s.assessments, pass: acc.pass + s.pass, fail: acc.fail + s.fail, unknown: acc.unknown + s.unknown, stale: acc.stale + s.stale, open: acc.open + s.open_findings }),
    { assessments: 0, pass: 0, fail: 0, unknown: 0, stale: 0, open: 0 },
  )
  const assessedControls = data.status.filter((s) => s.assessments > 0).length
  const failingControls = data.status.filter((s) => s.status === 'FAIL').length
  const run = async () => {
    setBusy(true)
    setRunError(null)
    try {
      await endpoints.runAssessment('tlee')
      reload()
    } catch (e) {
      setRunError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }
  const last = data.last_run
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Controls</h1>
          <p>Control catalog for the access layer. Each control names the exact source of truth it reads in the switch twin or the application store and the states it can reach. Results are recorded per scope; UNKNOWN and STALE never count as a pass.</p>
        </div>
        <div className="toolbar">
          {last ? (
            <span className="dim small">
              last run <span className="mono">{last.run_id}</span> · <Ts ts={last.assessed_at} date /> · {last.trigger} · {last.actor}
            </span>
          ) : (
            <span className="chip neutral">no assessment run yet</span>
          )}
          <button className="btn primary" onClick={run} disabled={busy}>Run assessment</button>
        </div>
      </div>
      {runError && <div className="error">Assessment run failed: {runError}</div>}

      <div className="grid kpis">
        <Kpi label="Controls" value={data.catalog.length} hint={last ? `${assessedControls} with results · last run ${last.run_id}` : `${assessedControls} with results`} />
        <Kpi label="Assessments" value={totals.assessments} hint="one per control and scope" />
        <Kpi label="Pass" value={totals.pass} unit={`/ ${totals.assessments}`} tone="good" hint="share of all results; UNKNOWN and STALE count against it" />
        <Kpi label="Fail" value={totals.fail} tone={totals.fail ? 'danger' : 'good'} hint={`${failingControls} control${failingControls === 1 ? '' : 's'} failing`} />
        <Kpi label="Unknown / stale" value={totals.unknown + totals.stale} tone={totals.unknown + totals.stale ? 'warn' : undefined} hint={`${totals.unknown} unknown · ${totals.stale} stale · not counted as pass`} />
        <Kpi label="Open findings" value={totals.open} tone={totals.open ? 'warn' : 'good'} hint="FAIL or STALE awaiting verification" />
      </div>

      <Card title="Control catalog" sub="click a row for its assessments and evidence" bodyClass="tight">
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr>
                <th>control</th><th>category</th><th>scope</th><th>severity</th><th>freshness</th><th>nist csf 2.0</th><th>assessed</th><th>pass</th><th>fail</th><th>unknown</th><th>stale</th><th>open</th><th>status</th>
              </tr>
            </thead>
            <tbody>
              {data.catalog.map((c) => {
                const s = byId.get(c.id)
                return (
                  <tr key={c.id} className="clickable" onClick={() => onOpen(c.id)}>
                    <td className="wrap" style={{ minWidth: 240 }}>
                      <div className="strong">{c.name}</div>
                      <div className="mono dim small">{c.id}</div>
                    </td>
                    <td><Chip kind="neutral">{c.category}</Chip></td>
                    <td className="dim">{c.scope_type}</td>
                    <td><Sev s={c.severity} /></td>
                    <td className="mono">{fmtWindow(c.freshness_window)}</td>
                    <td><CsfChips refs={c.csf} /></td>
                    <td className="num">{s ? <span className="row" style={{ gap: 8, justifyContent: 'flex-end', flexWrap: 'nowrap' }}><StatusBar counts={s} /><span className="mono">{s.assessments}</span></span> : <span className="faint">—</span>}</td>
                    <td className="num"><Count n={s?.pass} tone="#7ee2a8" /></td>
                    <td className="num"><Count n={s?.fail} tone="#ff8a80" /></td>
                    <td className="num"><Count n={s?.unknown} tone="var(--text-2)" /></td>
                    <td className="num"><Count n={s?.stale} tone="#f0c36b" /></td>
                    <td className="num"><Count n={s?.open_findings} tone="#f0c36b" /></td>
                    <td><Chip kind={s?.status ?? 'NOT_ASSESSED'} /></td>
                  </tr>
                )
              })}
              {data.catalog.length === 0 && (
                <tr><td colSpan={13}><Empty>The control catalog is empty</Empty></td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  )
}

// ---- control detail -----------------------------------------------------------------------------
function ControlDetail({ id, onBack }: { id: string; onBack: () => void }) {
  const { data, error } = useApi(() => endpoints.control(id), [id])
  const [sel, setSel] = useState<string | null>(null)
  if (!data) return <Loading error={error} />
  const c = data.control
  const counts = countStatuses(data.assessments)
  const rows = [...data.assessments].sort((a, b) => PRIORITY.indexOf(a.status) - PRIORITY.indexOf(b.status) || a.scope.id.localeCompare(b.scope.id, undefined, { numeric: true }))
  return (
    <>
      <div className="page-head">
        <div>
          <div className="row" style={{ marginBottom: 6 }}>
            <span className="mono strong" style={{ fontSize: 15 }}>{c.id}</span>
            <Sev s={c.severity} />
            <Chip kind="neutral">{c.category}</Chip>
            <Chip kind="neutral">{c.scope_type} scope</Chip>
            <CsfChips refs={c.csf} />
          </div>
          <h1>{c.name}</h1>
          <p>{c.description}</p>
        </div>
        <div className="toolbar">
          <button className="btn" onClick={onBack}>← All controls</button>
          <Link className="btn" to="/findings">Findings</Link>
        </div>
      </div>

      <div className="grid two">
        <Card title="Definition">
          <KV rows={[
            kv('source of truth', <span className="mono wrap" style={{ wordBreak: 'break-word' }}>{c.source_of_truth}</span>),
            kv('states reachable', <span className="row" style={{ gap: 6 }}>{c.states.map((s) => <Chip key={s} kind={s}>{s}</Chip>)}</span>),
            kv('freshness window', c.freshness_window ? `${fmtWindow(c.freshness_window)} · event-derived evidence older than this is reported STALE` : 'state-based · evidence is read live from the twin, no window applies'),
            kv('severity on FAIL', <Sev s={c.severity} />),
            kv('scope type', c.scope_type),
            kv('nist csf 2.0', <CsfList refs={c.csf} />)]} />
        </Card>
        <Card title="Remediation and limitations">
          <div className="stack">
            <div>
              <h3 style={{ marginBottom: 6 }}>Remediation guidance</h3>
              <p>{c.remediation || <span className="dim">No remediation guidance documented.</span>}</p>
            </div>
            <div>
              <h3 style={{ marginBottom: 6 }}>Limitations</h3>
              <p>{c.limitations || <span className="dim">None documented for this control.</span>}</p>
            </div>
            <div>
              <h3 style={{ marginBottom: 6 }}>Current result</h3>
              <div className="row">
                <StatusBar counts={counts} width={180} />
                {STATUSES.map((s) => (
                  <Chip key={s} kind={s}>{counts[s]} {s}</Chip>
                ))}
                <span className="dim small">{data.findings.length} finding{data.findings.length === 1 ? '' : 's'} recorded</span>
              </div>
            </div>
          </div>
        </Card>
      </div>

      <Card title="Assessments" sub={`${data.assessments.length} scope${data.assessments.length === 1 ? '' : 's'} · click a row for evidence and history`} bodyClass="tight">
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr><th>scope</th><th>status</th><th>expected</th><th>observed</th><th>assessed</th><th>evidence</th><th>finding</th></tr>
            </thead>
            <tbody>
              {rows.map((a) => (
                <tr key={a.id} className={`clickable ${sel === a.id ? 'selected' : ''}`} onClick={() => setSel(a.id)}>
                  <td>
                    <div className="strong">{a.scope.asset ?? a.scope.id}</div>
                    <div className="mono dim small">{a.scope.interface ?? a.scope.id}{a.scope.vlan !== null && a.scope.type !== 'vlan' ? ` · VLAN ${a.scope.vlan}` : ''}</div>
                  </td>
                  <td><Chip kind={a.status}>{a.status}</Chip></td>
                  <td className="mono wrap small" style={{ wordBreak: 'break-word' }}>{fmtInline(a.expected)}</td>
                  <td className="mono wrap small" style={{ wordBreak: 'break-word' }}>{fmtInline(a.observed)}</td>
                  <td><Ts ts={a.assessed_at} date /></td>
                  <td className="num">{a.evidence.length}</td>
                  <td>{a.finding_id ? <Link className="mono" to={`/findings/${a.finding_id}`} onClick={(e) => e.stopPropagation()}>{a.finding_id}</Link> : <span className="faint">—</span>}</td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr><td colSpan={7}><Empty>No assessments recorded for this control yet — run an assessment from the catalog</Empty></td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {data.findings.length > 0 && (
        <Card title="Findings for this control" sub="open and closed" bodyClass="tight">
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>finding</th><th>asset</th><th>severity</th><th>result</th><th>status</th><th>opened</th><th>occurrences</th><th>remediation</th></tr></thead>
              <tbody>
                {data.findings.map((f) => (
                  <tr key={f.id}>
                    <td><Link className="mono" to={`/findings/${f.id}`}>{f.id}</Link></td>
                    <td className="mono">{f.asset ?? f.scope.id}</td>
                    <td><Sev s={f.severity} /></td>
                    <td><Chip kind={f.result}>{f.result}</Chip></td>
                    <td><Chip kind={f.status} /></td>
                    <td><Ts ts={f.opened_at} date /></td>
                    <td className="num">{f.occurrences}</td>
                    <td className="dim">{f.remediation.status.replace(/_/g, ' ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {sel && <AssessmentDrawer id={sel} onClose={() => setSel(null)} />}
    </>
  )
}

// ---- assessment drawer --------------------------------------------------------------------------
function AssessmentDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const { data, error } = useApi(() => endpoints.assessment(id), [id])
  if (!data) return <Drawer title={id} onClose={onClose}><Loading error={error} /></Drawer>
  const a = data.assessment
  const history = [...data.history].reverse()
  return (
    <Drawer title={<span>{a.scope.asset ?? a.scope.id} <Chip kind={a.status}>{a.status}</Chip> <Sev s={a.severity} /></span>} onClose={onClose}>
      <div className="mono dim small">{a.id}</div>
      <KV rows={[
        kv('control', <Link to={`/controls/${a.control_id}`}>{a.control_name}</Link>),
        kv('scope', `${a.scope.type} · ${a.scope.id}`),
        kv('asset', a.scope.asset ?? '—'),
        kv('interface', a.scope.interface ? `${a.scope.switch} ${a.scope.interface}` : a.scope.switch),
        kv('vlan', vlanName(a.scope.vlan)),
        ...(a.scope.description ? [kv('description', a.scope.description)] : []),
        kv('assessed', <Ts ts={a.assessed_at} date />),
        kv('run', <span className="mono">{a.run_id}</span>),
        kv('detector', <span className="mono">{a.detector}</span>),
        kv('finding', a.finding_id ? <Link className="mono" to={`/findings/${a.finding_id}`}>{a.finding_id}</Link> : '—')]} />
      <div className="notice">{a.explanation}</div>
      <Card title="Expected vs observed">
        <div className="stack">
          <div>
            <h3 style={{ marginBottom: 6 }}>Expected</h3>
            <ValueBlock v={a.expected} />
          </div>
          <div>
            <h3 style={{ marginBottom: 6 }}>Observed</h3>
            <ValueBlock v={a.observed} />
          </div>
        </div>
      </Card>
      <Card title={`Evidence (${a.evidence.length})`} sub={`collected ${fmtTime(a.evidence_collected_at, { date: true, ms: false })}`}>
        <EvidenceList items={a.evidence} />
      </Card>
      <Card title="Freshness">
        <Freshness f={a.freshness} />
      </Card>
      <Card title="Source of truth">
        <div className="mono small wrap" style={{ wordBreak: 'break-word' }}>{a.source_of_truth}</div>
        {a.limitations && <div className="dim small" style={{ marginTop: 8 }}>Limitation: {a.limitations}</div>}
      </Card>
      <Card title="Related incidents">
        {a.related_incidents.length ? (
          <div className="row">
            {a.related_incidents.map((i) => (
              <Link key={i} className="mono" to={`/incidents/${i}`}>{i}</Link>
            ))}
          </div>
        ) : (
          <Empty>No related incidents</Empty>
        )}
      </Card>
      {(a.remediation.commands.length > 0 || a.status === 'FAIL' || a.status === 'STALE') && (
        <Card title="Remediation">
          <div className="stack">
            <p>{a.remediation.guidance}</p>
            {a.remediation.commands.length > 0 ? <Term text={a.remediation.commands.join('\n')} /> : <div className="dim small">No executable commands proposed; manual follow-up.</div>}
            <div className="dim small">{a.remediation.action ? <>executable action <span className="mono">{a.remediation.action.type as string}</span></> : 'no executable action'}</div>
          </div>
        </Card>
      )}
      <Card title={`History (${history.length} run${history.length === 1 ? '' : 's'})`} bodyClass="tight">
        <div className="table-wrap" style={{ maxHeight: 280 }}>
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
              {history.length === 0 && <tr><td colSpan={4}><Empty>No previous runs recorded</Empty></td></tr>}
            </tbody>
          </table>
        </div>
      </Card>
    </Drawer>
  )
}

// ---- shared pieces (also used by Findings.tsx) --------------------------------------------------
export function EvidenceList({ items }: { items: EvidenceItem[] }) {
  if (items.length === 0) return <Empty>No evidence was collected; the result cannot be verified from this record</Empty>
  return (
    <div className="evidence-list">
      {items.map((e, i) => (
        <div key={i} className="evidence-item">
          <div>
            <div className="src">{e.source}</div>
            <div className="at">{fmtTime(e.collected_at, { date: true, ms: false })}</div>
          </div>
          <div style={{ minWidth: 0 }}>
            <div className="ref" style={{ wordBreak: 'break-word' }}>{e.ref}</div>
            <div className="det">{e.detail}</div>
          </div>
        </div>
      ))}
    </div>
  )
}

export function Freshness({ f }: { f: Assessment['freshness'] }) {
  if (!f.window_seconds) {
    return <div className="dim small">State-based control: evidence is read live from the twin at assessment time, so no freshness window applies.</div>
  }
  if (!f.applied) {
    return (
      <KV rows={[
        kv('window', fmtWindow(f.window_seconds)),
        kv('applied', <span className="dim">no — the result is UNKNOWN or has no event-derived evidence</span>)]} />
    )
  }
  return (
    <KV rows={[
      kv('window', fmtWindow(f.window_seconds)),
      kv('oldest evidence', <Ts ts={f.oldest_evidence_at} date />),
      kv('age at assessment', fmtAge(f.age_seconds)),
      kv('fresh', f.fresh ? <Chip kind="ok">fresh</Chip> : <Chip kind="STALE">stale · older than the window</Chip>)]} />
  )
}

/** Expected / observed value: objects and arrays as pretty JSON in a terminal block, scalars as wrapped text. */
export function ValueBlock({ v }: { v: unknown }) {
  if (v !== null && typeof v === 'object') return <Term text={JSON.stringify(v, null, 2)} />
  return <div className="mono wrap" style={{ wordBreak: 'break-word', color: 'var(--text-2)' }}>{v === null || v === undefined ? '(absent)' : String(v)}</div>
}

function CsfChips({ refs }: { refs: ControlCatalogEntry['csf'] }) {
  return (
    <span className="row" style={{ gap: 4, flexWrap: 'nowrap' }}>
      {refs.map((r) => (
        <span key={r.id} className="chip neutral mono" title={r.text}>{r.id}</span>
      ))}
    </span>
  )
}

function CsfList({ refs }: { refs: ControlCatalogEntry['csf'] }) {
  if (refs.length === 0) return <span className="dim">—</span>
  return (
    <div className="stack" style={{ gap: 4 }}>
      {refs.map((r) => (
        <div key={r.id} className="wrap"><span className="mono">{r.id}</span> <span className="dim">{r.text}</span></div>
      ))}
    </div>
  )
}

function StatusBar({ counts, width = 90 }: { counts: { pass: number; fail: number; unknown: number; stale: number } | Record<AssessmentStatus, number>; width?: number }) {
  const c = 'PASS' in counts ? counts : { PASS: counts.pass, FAIL: counts.fail, UNKNOWN: counts.unknown, STALE: counts.stale }
  const total = c.PASS + c.FAIL + c.UNKNOWN + c.STALE
  return (
    <div className="status-bar" style={{ width, flex: 'none' }} title={`${c.PASS} pass · ${c.FAIL} fail · ${c.UNKNOWN} unknown · ${c.STALE} stale`}>
      {total > 0 && STATUSES.filter((s) => c[s] > 0).map((s) => <span key={s} className={s} style={{ width: `${(c[s] / total) * 100}%` }} />)}
    </div>
  )
}

function Count({ n, tone }: { n: number | undefined; tone: string }) {
  if (!n) return <span className="faint mono">{n ?? '—'}</span>
  return <span className="mono strong" style={{ color: tone }}>{n}</span>
}

function countStatuses(list: { status: AssessmentStatus }[]): Record<AssessmentStatus, number> {
  const out: Record<AssessmentStatus, number> = { PASS: 0, FAIL: 0, UNKNOWN: 0, STALE: 0 }
  for (const a of list) out[a.status] += 1
  return out
}

function fmtWindow(seconds: number | null): string {
  if (!seconds) return 'state-based'
  const m = Math.round(seconds / 60)
  return m >= 120 && m % 60 === 0 ? `${m / 60} h` : `${m} min`
}

function fmtAge(seconds: number | undefined): string {
  if (seconds === undefined) return '—'
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  return h ? `${h}h ${m}m` : `${m} min`
}

function fmtInline(v: unknown): string {
  if (v === null || v === undefined) return '(absent)'
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}

import { useState, type CSSProperties } from 'react'
import { Link } from 'react-router-dom'
import { endpoints, type AssessmentRun, type AssessmentStatus, type Finding } from '../lib/api'
import { useApi } from '../lib/hooks'
import { Card, Chip, Empty, Kpi, Loading, Sev, Ts } from '../components/ui'
import { Legend } from '../charts'
import { fmtTime, pct } from '../lib/format'
import { Icon } from '../components/Icons'

const STATUSES: AssessmentStatus[] = ['PASS', 'FAIL', 'UNKNOWN', 'STALE']
/** Swatches match `.status-bar` in components.css so the legend, the bar and the counts agree. */
const SWATCH: Record<AssessmentStatus, string> = { PASS: '#2f9e4f', FAIL: '#e05a5a', UNKNOWN: '#56657a', STALE: '#c99420' }
const INK: Record<AssessmentStatus, string> = { PASS: '#7ee2a8', FAIL: '#ff8a80', UNKNOWN: '#b3c0cf', STALE: '#f0c36b' }

interface Tally {
  pass: number
  fail: number
  unknown: number
  stale: number
}

const ellipsis: CSSProperties = { overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }
const clamp2: CSSProperties = { display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden', whiteSpace: 'normal' }
const clamp3: CSSProperties = { ...clamp2, WebkitLineClamp: 3 }

function tallyOf(counts: AssessmentRun['counts']): Tally {
  return { pass: counts.PASS ?? 0, fail: counts.FAIL ?? 0, unknown: counts.UNKNOWN ?? 0, stale: counts.STALE ?? 0 }
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? '' : 's'}`
}

/** Four per-status counts in a fixed order (pass · fail · unknown · stale); zeros are dimmed. Self-styled so it reads the same inside stat rows and table cells. */
function Counts({ t }: { t: Tally }) {
  return (
    <span className="counts" style={{ display: 'inline-flex', gap: 5, fontFamily: 'var(--mono)', fontSize: 11.5, fontVariantNumeric: 'tabular-nums' }}>
      {STATUSES.map((s) => {
        const n = t[s.toLowerCase() as keyof Tally]
        return (
          <span key={s} title={`${n} ${s}`} style={{ color: n ? INK[s] : 'var(--faint)', padding: '1px 5px', borderRadius: 3, background: 'var(--panel-3)' }}>
            {n}
          </span>
        )
      })}
    </span>
  )
}

function StatusBar({ t, total }: { t: Tally; total: number }) {
  return (
    <div className="status-bar" aria-label="assessment outcomes">
      {total > 0 &&
        STATUSES.map((s) => {
          const n = t[s.toLowerCase() as keyof Tally]
          if (!n) return null
          return <span key={s} className={s} style={{ width: `${(100 * n) / total}%` }} title={`${s} ${n} / ${total}`} />
        })}
    </div>
  )
}

function scopeOf(f: Finding): { main: string; sub: string } {
  const s = f.scope
  const main = f.asset ?? s.asset ?? s.id
  const parts: string[] = [s.type]
  if (s.interface && s.interface !== main) parts.push(s.interface)
  else if (s.description && s.description !== main) parts.push(s.description)
  return { main, sub: parts.join(' · ') }
}

/** Closed findings with the result they had and the verification outcome of the reassessment that closed them. */
function ClosedTable({ rows, showScope = false, showStatus = true }: { rows: Finding[]; showScope?: boolean; showStatus?: boolean }) {
  const cols = 3 + (showScope ? 1 : 0) + (showStatus ? 1 : 0)
  return (
    <div className="table-wrap">
      <table className="data">
        <thead>
          <tr>
            <th>finding</th>
            {showScope && <th>scope</th>}
            <th>was → verified</th>
            <th>closed</th>
            {showStatus && <th>status</th>}
          </tr>
        </thead>
        <tbody>
          {rows.map((fc) => {
            const scope = scopeOf(fc)
            return (
              <tr key={fc.id}>
                <td style={{ maxWidth: 300 }}>
                  <div style={ellipsis}>
                    <span className={`sev-dot ${fc.severity}`} title={`${fc.severity} severity`} />
                    <Link className="mono strong" to={`/findings/${fc.id}`}>{fc.id}</Link>
                  </div>
                  <div className="dim small" style={{ ...ellipsis, paddingLeft: 14 }} title={fc.control_name}>{fc.control_name}</div>
                </td>
                {showScope && (
                  <td>
                    <div className="mono">{scope.main}</div>
                    <div className="dim small">{scope.sub}</div>
                  </td>
                )}
                <td>
                  <div className="row" style={{ gap: 6, flexWrap: 'nowrap' }}>
                    <Chip kind={fc.result} />
                    <span className="faint">→</span>
                    {fc.verification.outcome ? <Chip kind={fc.verification.outcome} /> : <span className="dim">not reassessed</span>}
                  </div>
                  {fc.verification.outcome && <div className="dim small">{fc.verification.after_remediation ? 'after remediation' : 'on reassessment'}</div>}
                </td>
                <td><Ts ts={fc.resolved_at ?? fc.verification.at} date /></td>
                {showStatus && <td><Chip kind={fc.status} /></td>}
              </tr>
            )
          })}
          {rows.length === 0 && (
            <tr><td colSpan={cols} className="dim">No findings closed yet</td></tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

export function Posture() {
  const { data: p, error, reload } = useApi(endpoints.posture)
  const { data: meta } = useApi(endpoints.meta)
  const [busy, setBusy] = useState(false)
  const [runError, setRunError] = useState<string | null>(null)
  if (!p) return <Loading error={error} />
  const t = p.totals
  const f = p.findings
  const run = p.last_run
  const unverified = t.unknown + t.stale
  const verified = f.by_status.verified ?? 0
  const closed = f.by_status.closed ?? 0
  const org = meta?.organization
  const openShown = f.open_items.slice(0, 8)
  const share = (n: number) => (t.assessments ? (100 * n) / t.assessments : null)

  const runAssessment = async () => {
    setBusy(true)
    setRunError(null)
    try {
      await endpoints.runAssessment()
      reload()
    } catch (e) {
      setRunError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Security posture</h1>
          <p style={{ maxWidth: 'none' }}>
            {org ? `${org.name} · ${org.site}` : 'Simulated event network'} — assessment clock <span className="mono">{fmtTime(p.clock, { date: true, ms: false })}</span> UTC
          </p>
        </div>
        <div className="toolbar" style={{ flexWrap: 'nowrap' }}>
          {run ? (
            <span className="chip neutral mono" style={{ ...ellipsis, maxWidth: 320, display: 'inline-block' }} title={`last run ${run.run_id} · trigger ${run.trigger} · ${run.actor} · ${run.assessments} assessments · ${fmtTime(run.assessed_at, { date: true, ms: false })} UTC`}>
              {run.run_id}
            </span>
          ) : (
            <Chip kind="neutral">no assessment run yet</Chip>
          )}
          <button className="btn primary" onClick={runAssessment} disabled={busy}>
            <Icon.play /> {busy ? 'Assessing…' : 'Run assessment'}
          </button>
        </div>
      </div>
      {runError && <div className="error">Assessment run failed: {runError}</div>}

      <div className="posture-hero">
        <div className="grid" style={{ gridTemplateColumns: 'repeat(3, minmax(0, 1fr))' }}>
          <Kpi label="Assessments" value={t.assessments} unit={`across ${plural(t.controls, 'control')}`} hint={`one result per control and scope · ${plural(p.runs, 'run')} recorded${run ? ` · last trigger ${run.trigger}` : ''}${t.retired ? ` · ${plural(t.retired, 'retired result')} excluded` : ''}`} />
          <Kpi label="Coverage" value={pct(t.coverage_pct)} unit={`${t.determinate} / ${t.assessments}`} tone="accent" hint={p.definitions.coverage_pct} />
          <Kpi label="Determinate pass rate" value={pct(t.pass_rate_of_determinate_pct)} unit={`${t.pass} / ${t.determinate}`} tone={t.determinate === 0 ? undefined : t.fail ? 'warn' : (t.coverage_pct ?? 0) >= 95 ? 'good' : undefined} hint={p.definitions.pass_rate_of_determinate_pct} />
          <Kpi label="Open findings" value={f.open} unit={`${f.by_severity.high} high · ${f.by_severity.medium} medium · ${f.by_severity.low} low`} tone={f.by_severity.high ? 'danger' : f.open ? 'warn' : 'good'} hint={p.definitions.open_findings} />
          <Kpi label="Unverified" value={unverified} unit={`${t.unknown} unknown · ${t.stale} stale`} tone={unverified ? 'warn' : 'good'} hint={`${p.definitions.pass_rate_of_all_pct} (${pct(t.pass_rate_of_all_pct)})`} />
          <Kpi label="Incidents" value={p.incidents.open} unit={`open · ${p.incidents.resolved} resolved`} tone={p.incidents.open ? 'danger' : undefined} hint={`${plural(p.incidents.total, 'incident')} on ${p.generated_for} · response controls are assessed per incident`} />
        </div>

        <Card title="Assessment outcomes" sub={`${plural(t.assessments, 'result')} · ${plural(t.controls, 'control')}`} bodyClass="flush">
          {t.assessments === 0 ? (
            <Empty>No assessments recorded — run an assessment to populate this page</Empty>
          ) : (
            <>
              <div className="grid" style={{ gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: 10, marginTop: 6 }}>
                {STATUSES.map((s) => {
                  const n = t[s.toLowerCase() as keyof Tally]
                  return (
                    <div key={s}>
                      <div style={{ fontSize: 10.5, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--muted)' }}>{s}</div>
                      <div style={{ fontSize: 22, fontWeight: 600, letterSpacing: '-0.02em', fontVariantNumeric: 'tabular-nums', color: n ? INK[s] : 'var(--faint)', display: 'flex', alignItems: 'baseline', gap: 6 }}>
                        {n}
                        <small className="dim" style={{ fontSize: 11, fontWeight: 500 }}>{pct(share(n))}</small>
                      </div>
                    </div>
                  )
                })}
              </div>
              <div style={{ marginTop: 10 }}>
                <StatusBar t={t} total={t.assessments} />
              </div>
              <div style={{ marginTop: 8 }}>
                <Legend items={STATUSES.map((s) => [s, SWATCH[s]] as [string, string])} />
              </div>
              <h3 style={{ margin: '12px 0 2px' }}>Outcomes by category</h3>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', columnGap: 20 }}>
                {p.by_category.map((c) => (
                  <div key={c.category} className="stat-row" style={{ padding: '3px 0' }}>
                    <span style={ellipsis} title={c.category}>{c.category}</span>
                    <Counts t={c} />
                  </div>
                ))}
              </div>
            </>
          )}
        </Card>
      </div>

      <div className="grid" style={{ gridTemplateColumns: 'minmax(0, 1fr) minmax(380px, 500px)' }}>
        <Card title="Unresolved findings" sub={`${f.open} open · ${f.closed} closed`} right={<Link to="/findings">all findings</Link>} bodyClass="tight">
          {openShown.length === 0 ? (
            <>
              <Empty>
                No open findings — {plural(verified, 'finding')} verified{closed ? `, ${closed} closed (scope retired)` : ''}
                {f.recently_closed.length > 0 && <span className="faint"> · most recently closed, newest first:</span>}
              </Empty>
              {f.recently_closed.length > 0 && <ClosedTable rows={f.recently_closed} showScope showStatus={false} />}
            </>
          ) : (
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr><th>finding</th><th>scope</th><th title="assessment result · finding status">result</th><th>opened</th><th>explanation</th></tr>
                </thead>
                <tbody>
                  {openShown.map((fi) => {
                    const scope = scopeOf(fi)
                    return (
                      <tr key={fi.id}>
                        <td style={{ maxWidth: 272 }}>
                          <div style={ellipsis}>
                            <span className={`sev-dot ${fi.severity}`} title={`${fi.severity} severity`} />
                            <Link className="mono strong" to={`/findings/${fi.id}`}>{fi.id}</Link>
                          </div>
                          <div className="dim small" style={{ ...ellipsis, paddingLeft: 14 }} title={fi.control_name}>{fi.control_name}</div>
                        </td>
                        <td>
                          <div className="mono">{scope.main}</div>
                          <div className="dim small">{scope.sub}</div>
                        </td>
                        <td>
                          <div className="stack" style={{ gap: 3, alignItems: 'flex-start' }}>
                            <Chip kind={fi.result} />
                            <Chip kind={fi.status} />
                          </div>
                        </td>
                        <td>
                          <span className="ts" title={fi.occurrences > 1 ? `seen in ${plural(fi.occurrences, 'run')} since ${fi.first_run_id}` : fi.first_run_id}>{fmtTime(fi.opened_at, { date: true, ms: false })}</span>
                        </td>
                        <td className="wrap" style={{ minWidth: 190, fontSize: 12, lineHeight: 1.35 }}>
                          <div style={clamp3} title={fi.explanation}>{fi.explanation}</div>
                        </td>
                      </tr>
                    )
                  })}
                  {f.open_items.length > openShown.length && (
                    <tr>
                      <td colSpan={5} className="dim">
                        <Link to="/findings">{f.open_items.length - openShown.length} more open findings</Link>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        <Card title="Control status" sub="pass · fail · unknown · stale" right={<Link to="/controls">all controls</Link>} bodyClass="flush">
          {p.by_control.length === 0 ? (
            <Empty>No controls in the catalog</Empty>
          ) : (
            p.by_control.map((c) => (
              <div key={c.control_id} className="stat-row" style={{ padding: '2px 0', lineHeight: 1.2 }}>
                <div style={{ minWidth: 0 }}>
                  <div style={{ ...ellipsis, fontSize: 12 }} title={`${c.control_id} — ${c.name}`}>
                    <Link to={`/controls/${c.control_id}`} style={{ color: 'inherit', fontWeight: 600 }}>{c.name}</Link>
                  </div>
                  <div style={{ ...ellipsis, fontSize: 10.5, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--muted)' }}>
                    {c.category}
                    {c.open_findings ? <span style={{ color: '#ff8a80' }}> · {plural(c.open_findings, 'open finding')}</span> : ''}
                  </div>
                </div>
                <div className="row" style={{ gap: 8, flexWrap: 'nowrap' }}>
                  <Counts t={c} />
                  <Chip kind={c.status} />
                </div>
              </div>
            ))
          )}
        </Card>
      </div>

      <div className="grid two">
        <Card title="Assets with open findings" sub={`${plural(p.assets_with_open_findings.length, 'asset')}`} bodyClass="tight">
          {p.assets_with_open_findings.length === 0 ? (
            <Empty>No assets carry an open finding</Empty>
          ) : (
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr><th>asset</th><th>interface</th><th>findings</th><th>worst</th><th>controls</th></tr>
                </thead>
                <tbody>
                  {p.assets_with_open_findings.map((a) => (
                    <tr key={a.asset}>
                      <td className="mono strong">{a.asset}</td>
                      <td className="mono">{a.interface ?? <span className="dim">—</span>}</td>
                      <td className="num">{a.findings}</td>
                      <td><Sev s={a.worst} /></td>
                      <td className="wrap mono small" style={{ minWidth: 200 }}>
                        {a.controls.map((cid) => (
                          <Link key={cid} to={`/controls/${cid}`} style={{ marginRight: 8 }}>{cid}</Link>
                        ))}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        <Card title="Unverified assessments" sub="UNKNOWN and STALE results — never counted as a pass" bodyClass="tight">
          {p.unverified.length === 0 ? (
            <Empty>Every assessment has a determinate result</Empty>
          ) : (
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr><th>scope</th><th>result</th><th>explanation</th></tr>
                </thead>
                <tbody>
                  {p.unverified.map((u) => (
                    <tr key={u.id}>
                      <td>
                        <div className="mono strong">{u.scope.id}</div>
                        <div className="dim small">
                          <Link to={`/controls/${u.control_id}`}>{u.control_id}</Link>
                          {u.scope.asset && u.scope.asset !== u.scope.id ? ` · ${u.scope.asset}` : ''}
                        </div>
                      </td>
                      <td><Chip kind={u.status} /></td>
                      <td className="wrap" style={{ minWidth: 260 }}>
                        <div style={clamp2} title={u.explanation}>{u.explanation}</div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>

      <Card title="Recent activity" sub="assessment runs and closed findings, newest first" bodyClass="tight">
        <div className="grid" style={{ gridTemplateColumns: 'minmax(0, 1.15fr) minmax(0, 1fr)', gap: 0 }}>
          <div style={{ minWidth: 0 }}>
            <div className="card-head">
              <h2>
                Assessment runs<span className="sub">{plural(p.runs, 'run')} recorded</span>
              </h2>
            </div>
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr><th>run</th><th>assessed</th><th>results</th><th title="pass · fail · unknown · stale">outcomes</th><th>open</th></tr>
                </thead>
                <tbody>
                  {p.recent_runs.map((r) => (
                    <tr key={r.run_id}>
                      <td style={{ maxWidth: 330 }}>
                        <div className="mono strong" style={ellipsis} title={r.run_id}>{r.run_id}</div>
                        <div className="dim small" style={ellipsis}>{r.trigger} · {r.actor}</div>
                      </td>
                      <td><Ts ts={r.assessed_at} date /></td>
                      <td className="num" title={`${r.assessments} assessments across ${r.controls} controls`}>{r.assessments}</td>
                      <td><Counts t={tallyOf(r.counts)} /></td>
                      <td className="num">{r.findings_open}</td>
                    </tr>
                  ))}
                  {p.recent_runs.length === 0 && (
                    <tr><td colSpan={5} className="dim">No assessment runs recorded</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
          <div style={{ minWidth: 0, borderLeft: '1px solid var(--border)' }}>
            <div className="card-head">
              <h2>
                Recently closed findings<span className="sub">verification outcome from the reassessment that closed them</span>
              </h2>
            </div>
            <ClosedTable rows={f.recently_closed} />
          </div>
        </div>
      </Card>

      <Card title="NIST CSF 2.0 mapping" sub="limited mapping of simulated checks — a documentation aid, not a framework assessment" bodyClass="tight">
        {p.csf.length === 0 ? (
          <Empty>No assessed controls map to a subcategory yet</Empty>
        ) : (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr><th>subcategory</th><th>fn</th><th>outcome</th><th>controls</th><th title="pass · fail · unknown · stale">outcomes</th></tr>
              </thead>
              <tbody>
                {p.csf.map((c) => (
                  <tr key={c.id}>
                    <td className="mono strong">{c.id}</td>
                    <td><Chip kind="neutral">{c.function}</Chip></td>
                    <td className="wrap small" style={{ minWidth: 220 }}>{c.text}</td>
                    <td className="mono small wrap" style={{ minWidth: 160 }}>
                      {c.controls.map((cid) => (
                        <Link key={cid} to={`/controls/${cid}`} style={{ marginRight: 8 }}>{cid}</Link>
                      ))}
                    </td>
                    <td><Counts t={c} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <p className="dim small">{p.scope_note}</p>
    </>
  )
}

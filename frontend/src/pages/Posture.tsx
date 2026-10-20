import { useState } from 'react'
import { Link } from 'react-router-dom'
import { endpoints, type AssessmentRun, type AssessmentStatus, type Finding } from '../lib/api'
import { useApi } from '../lib/hooks'
import { Empty, ErrorState, Loading, Panel, Ts } from '../components/ui'
import { PageHeader, Section } from '../components/layout'
import { Counts, Metric, Ratio, StatusBar, StatusLegend } from '../components/metric'
import { AssessChip, Chip, Id, SeverityChip, StatusChip } from '../components/status'
import { DataTable, Cell2 } from '../components/table'
import { useToast } from '../components/toast'
import { CategoryStack, CsfWheel, RunLedger } from '../charts/viz'
import { fmtTime, pct } from '../lib/format'
import { Icon } from '../components/Icons'

const STATUSES: AssessmentStatus[] = ['PASS', 'FAIL', 'UNKNOWN', 'STALE']

function tallyOf(counts: AssessmentRun['counts']) {
  return { PASS: counts.PASS ?? 0, FAIL: counts.FAIL ?? 0, UNKNOWN: counts.UNKNOWN ?? 0, STALE: counts.STALE ?? 0 }
}
function upper(c: { pass: number; fail: number; unknown: number; stale: number }) {
  return { PASS: c.pass, FAIL: c.fail, UNKNOWN: c.unknown, STALE: c.stale }
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? '' : 's'}`
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
  return (
    <DataTable
      compact
      rows={rows}
      rowKey={(f) => f.id}
      empty="No findings closed yet"
      columns={[
        {
          key: 'finding',
          header: 'finding',
          render: (fc) => (
            <Cell2
              primary={
                <>
                  <span className={`sev-dot ${fc.severity}`} title={`${fc.severity} severity`} />
                  <Link className="id" to={`/findings/${fc.id}`}>
                    {fc.id}
                  </Link>
                </>
              }
              secondary={fc.control_name}
            />
          ),
        },
        ...(showScope ? [{ key: 'scope', header: 'scope', render: (fc: Finding) => <Cell2 primary={<span className="mono">{scopeOf(fc).main}</span>} secondary={scopeOf(fc).sub} /> }] : []),
        {
          key: 'was',
          header: 'was → verified',
          render: (fc) => (
            <Cell2
              primary={
                <span className="row nowrap">
                  <AssessChip value={fc.result} />
                  <span className="faint">→</span>
                  {fc.verification.outcome ? <AssessChip value={fc.verification.outcome} /> : <span className="dim">not reassessed</span>}
                </span>
              }
              secondary={fc.verification.outcome ? (fc.verification.after_remediation ? 'after remediation' : 'on reassessment') : undefined}
            />
          ),
        },
        { key: 'closed', header: 'closed', render: (fc) => <Ts ts={fc.resolved_at ?? fc.verification.at} date ms={false} /> },
        ...(showStatus ? [{ key: 'status', header: 'status', hideBelow: 400 as const, render: (fc: Finding) => <StatusChip value={fc.status} /> }] : []),
      ]}
    />
  )
}

export function Posture() {
  const { data: p, error, reload } = useApi(endpoints.posture)
  const { data: meta } = useApi(endpoints.meta)
  const toast = useToast()
  const [busy, setBusy] = useState(false)
  const [runError, setRunError] = useState<string | null>(null)
  const [csfOpen, setCsfOpen] = useState(false)
  if (error && !p) return <ErrorState error={error} retry={reload} />
  if (!p) return <Loading rows={6} />
  const t = p.totals
  const f = p.findings
  const run = p.last_run
  const verified = f.by_status.verified ?? 0
  const closed = f.by_status.closed ?? 0
  const org = meta?.organization
  const openShown = f.open_items.slice(0, 8)
  const share = (n: number) => (t.assessments ? (100 * n) / t.assessments : null)
  const counts = { PASS: t.pass, FAIL: t.fail, UNKNOWN: t.unknown, STALE: t.stale }

  const runAssessment = async () => {
    setBusy(true)
    setRunError(null)
    try {
      const r = await endpoints.runAssessment()
      toast.push({ title: `Assessment run ${r.run_id}`, detail: `${r.assessments} results · ${r.counts.PASS ?? 0} pass · ${r.counts.FAIL ?? 0} fail · ${r.counts.UNKNOWN ?? 0} unknown · ${r.counts.STALE ?? 0} stale`, tone: 'ok' })
      reload()
    } catch (e) {
      setRunError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <PageHeader
        title="Security posture"
        sub={
          <>
            {org ? `${org.name} · ${org.site}` : 'Simulated event network'} — assessment clock <span className="mono">{fmtTime(p.clock, { date: true, ms: false })}</span> UTC
          </>
        }
        info={<>Evidence-driven control assessment summary. Every ratio keeps its denominator visible; UNKNOWN and STALE results are never counted as a pass; RETIRED results are excluded from totals. {p.scope_note}</>}
      >
        {run ? (
          <Chip kind="neutral" mono title={`last run ${run.run_id} · trigger ${run.trigger} · ${run.actor} · ${run.assessments} assessments · ${fmtTime(run.assessed_at, { date: true, ms: false })} UTC`}>
            {run.run_id}
          </Chip>
        ) : (
          <Chip kind="neutral">no assessment run yet</Chip>
        )}
        <button className="btn primary" type="button" onClick={runAssessment} disabled={busy}>
          <Icon.play /> {busy ? 'Assessing…' : 'Run assessment'}
        </button>
      </PageHeader>
      {runError && <div className="error">Assessment run failed: {runError}</div>}

      {t.assessments === 0 ? (
        <Panel>
          <Empty>No assessments recorded — run an assessment to populate this page</Empty>
        </Panel>
      ) : (
        <div className="posture-hero">
          <div className="stack">
            <div className="ratio-band">
              <Metric hero label="Determinate pass rate" value={pct(t.pass_rate_of_determinate_pct)} tone={t.determinate === 0 ? undefined : t.fail ? 'warn' : 'good'} hint={p.definitions.pass_rate_of_determinate_pct} chip={<Ratio num={t.pass} den={t.determinate} />} />
              <Metric hero label="Coverage" value={pct(t.coverage_pct)} tone="accent" hint={p.definitions.coverage_pct} chip={<Ratio num={t.determinate} den={t.assessments} />} />
            </div>
          <Panel title="NIST CSF 2.0 subcategories" sub="worst result per subcategory · documentation aid, not a framework assessment">
            <CsfWheel csf={p.csf} />
          </Panel>
          </div>
          <Panel title="Assessment outcomes" sub={`${plural(t.assessments, 'result')} · ${plural(t.controls, 'control')} · ${plural(p.runs, 'run')}${t.retired ? ` · ${plural(t.retired, 'retired result')} excluded` : ''}`} bodyClass="flush">
            <div className="stack">
              <div className="outcome-row">
                {STATUSES.map((s) => {
                  const n = counts[s]
                  return (
                    <div key={s}>
                      <div className="eyebrow">{s}</div>
                      <div className={`n ${n ? s : 'zero'}`}>
                        {n}
                        <small>{pct(share(n))}</small>
                      </div>
                    </div>
                  )
                })}
              </div>
              <StatusBar counts={counts} large label="assessment outcomes" />
              <StatusLegend />
              <div className="eyebrow">Outcomes by category</div>
              <CategoryStack rows={p.by_category} />
            </div>
          </Panel>
        </div>
      )}

      <div className="grid grid-main-rail">
        <div className="stack">
          <Panel title="Open findings" sub={`${f.open} open · ${f.closed} closed`} right={<Link to="/findings">all findings</Link>} bodyClass="none">
            {openShown.length === 0 ? (
              <>
                <Empty>
                  No open findings — {plural(verified, 'finding')} verified{closed ? `, ${closed} closed (scope retired)` : ''}
                  {f.recently_closed.length > 0 && <span className="faint"> · most recently closed, newest first:</span>}
                </Empty>
                {f.recently_closed.length > 0 && <ClosedTable rows={f.recently_closed} showScope showStatus={false} />}
              </>
            ) : (
              <DataTable
                cards="narrow"
                rows={openShown}
                rowKey={(fi) => fi.id}
                columns={[
                  { key: 'sev', header: 'severity', render: (fi) => <SeverityChip value={fi.severity} /> },
                  { key: 'id', header: 'finding', render: (fi) => <Cell2 primary={<Link className="id" to={`/findings/${fi.id}`}>{fi.id}</Link>} secondary={fi.control_name} /> },
                  { key: 'scope', header: 'scope', hideBelow: 1000, render: (fi) => <Cell2 primary={<span className="mono">{scopeOf(fi).main}</span>} secondary={scopeOf(fi).sub} /> },
                  {
                    key: 'result',
                    header: 'result → status',
                    render: (fi) => (
                      <span className="row nowrap">
                        <AssessChip value={fi.result} />
                        <StatusChip value={fi.status} />
                      </span>
                    ),
                  },
                  { key: 'opened', header: 'opened', hideBelow: 700, render: (fi) => <span title={fi.occurrences > 1 ? `seen in ${plural(fi.occurrences, 'run')} since ${fi.first_run_id}` : fi.first_run_id}><Ts ts={fi.opened_at} date ms={false} /></span> },
                  { key: 'why', header: 'explanation', wrap: true, hideBelow: 1000, render: (fi) => <span className="clamp-2 small dim" title={fi.explanation}>{fi.explanation}</span> },
                ]}
                footer={
                  f.open_items.length > openShown.length ? (
                    <tr>
                      <td colSpan={6} className="dim">
                        <Link to="/findings">{f.open_items.length - openShown.length} more open findings</Link>
                      </td>
                    </tr>
                  ) : undefined
                }
              />
            )}
          </Panel>
          <div className="stack">
            <Panel title="Assets with open findings" sub={plural(p.assets_with_open_findings.length, 'asset')} bodyClass="none">
              {p.assets_with_open_findings.length === 0 ? (
                <Empty>No assets carry an open finding</Empty>
              ) : (
                <DataTable
                  cards="narrow"
                  compact
                  rows={p.assets_with_open_findings}
                  rowKey={(a) => a.asset}
                  columns={[
                    { key: 'asset', header: 'asset', className: 'mono strong', render: (a) => a.asset },
                    { key: 'iface', header: 'interface', className: 'mono', render: (a) => a.interface ?? <span className="dim">—</span> },
                    { key: 'n', header: 'findings', align: 'right', render: (a) => a.findings },
                    { key: 'worst', header: 'worst', render: (a) => <SeverityChip value={a.worst} /> },
                    { key: 'controls', header: 'controls', wrap: true, hideBelow: 600, render: (a) => <span className="row">{a.controls.map((cid) => <Link key={cid} className="mono small" to={`/controls/${cid}`}>{cid}</Link>)}</span> },
                  ]}
                />
              )}
            </Panel>
            <Panel title="Unverified assessments" sub="UNKNOWN and STALE results — never counted as a pass" bodyClass="none">
              {p.unverified.length === 0 ? (
                <Empty>Every assessment has a determinate result</Empty>
              ) : (
                <DataTable
                  cards="narrow"
                  compact
                  rows={p.unverified}
                  rowKey={(u) => u.id}
                  columns={[
                    {
                      key: 'scope',
                      header: 'scope',
                      render: (u) => (
                        <Cell2
                          primary={<span className="mono strong">{u.scope.id}</span>}
                          secondary={
                            <>
                              <Link to={`/controls/${u.control_id}`}>{u.control_id}</Link>
                              {u.scope.asset && u.scope.asset !== u.scope.id ? ` · ${u.scope.asset}` : ''}
                            </>
                          }
                        />
                      ),
                    },
                    { key: 'status', header: 'result', render: (u) => <AssessChip value={u.status} /> },
                    { key: 'why', header: 'explanation', wrap: true, render: (u) => <span className="clamp-2 small" title={u.explanation}>{u.explanation}</span> },
                  ]}
                />
              )}
            </Panel>
          </div>
        </div>
        <Panel title="Control status" sub="pass · fail · unknown · stale" right={<Link to="/controls">all controls</Link>} bodyClass="flush" className="rail">
          {p.by_control.length === 0 ? (
            <Empty>No controls in the catalog</Empty>
          ) : (
            <div className="ctl-status">
              {p.by_control.map((c) => (
                <div key={c.control_id} className="stat-row">
                  <div className="stack tight">
                    <Link to={`/controls/${c.control_id}`} className="name" title={`${c.control_id} — ${c.name}`}>
                      {c.name}
                    </Link>
                    <div className="cat">
                      {c.category}
                      {c.open_findings ? <span className="open"> · {plural(c.open_findings, 'open finding')}</span> : ''}
                    </div>
                  </div>
                  <div className="row nowrap">
                    <Counts counts={upper(c)} />
                    <AssessChip value={c.status} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>

      <div className="vz-grid c12">
        <Panel title="Run ledger" sub="every assessment run, oldest first" right={run ? <span className="mono dim small">last {fmtTime(run.assessed_at, { ms: false })} UTC</span> : undefined}>
          <RunLedger runs={p.recent_runs} />
        </Panel>
        <Panel title="Assessment runs" sub={`${plural(p.runs, 'run')} recorded`} bodyClass="none">
          <DataTable
            cards="narrow"
            compact
            rows={p.recent_runs}
            rowKey={(r) => r.run_id}
            empty="No assessment runs recorded"
            columns={[
              { key: 'run', header: 'run', wrap: true, className: 'break-ids', render: (r) => <Cell2 primary={<Id>{r.run_id}</Id>} secondary={`${r.trigger} · ${r.actor}`} /> },
              { key: 'at', header: 'assessed', render: (r) => <Ts ts={r.assessed_at} date ms={false} /> },
              { key: 'n', header: 'results', align: 'right', hideBelow: 600, render: (r) => <span title={`${r.assessments} assessments across ${r.controls} controls`}>{r.assessments}</span> },
              { key: 'outcomes', header: 'outcomes', render: (r) => <Counts counts={tallyOf(r.counts)} /> },
              { key: 'open', header: 'open', align: 'right', render: (r) => r.findings_open },
            ]}
          />
        </Panel>
      </div>

      <Panel title="Recently closed findings" sub="verification outcome from the reassessment that closed them" bodyClass="none">
        <ClosedTable rows={f.recently_closed} />
      </Panel>

      <Panel
        title="NIST CSF 2.0 mapping"
        sub="limited mapping of simulated checks — a documentation aid, not a framework assessment"
        collapsible
        collapsed={!csfOpen}
        onToggle={() => setCsfOpen((o) => !o)}
        bodyClass="none"
      >
        {p.csf.length === 0 ? (
          <Empty>No assessed controls map to a subcategory yet</Empty>
        ) : (
          <DataTable
            compact
            rows={p.csf}
            rowKey={(c) => c.id}
            columns={[
              { key: 'id', header: 'subcategory', className: 'mono strong', render: (c) => c.id },
              { key: 'fn', header: 'fn', render: (c) => <Chip kind="neutral">{c.function}</Chip> },
              { key: 'text', header: 'outcome', wrap: true, render: (c) => <span className="small">{c.text}</span> },
              { key: 'controls', header: 'controls', wrap: true, hideBelow: 700, render: (c) => <span className="row">{c.controls.map((cid) => <Link key={cid} className="mono small" to={`/controls/${cid}`}>{cid}</Link>)}</span> },
              { key: 'outcomes', header: 'outcomes', render: (c) => <Counts counts={upper(c)} /> },
            ]}
          />
        )}
      </Panel>

      <Section title="Scope">
        <p className="dim small">{p.scope_note}</p>
      </Section>
    </>
  )
}

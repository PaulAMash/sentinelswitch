import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { kv } from '../lib/kv'
import { endpoints, type Assessment, type AssessmentStatus, type ControlCatalogEntry, type EvidenceItem } from '../lib/api'
import { useApi } from '../lib/hooks'
import { Drawer, Empty, ErrorState, KV, Loading, Panel, Ts } from '../components/ui'
import { PageHeader, Section } from '../components/layout'
import { Counts, Metric, Ratio, StatusBar } from '../components/metric'
import { AssessChip, Chip, Id, SeverityChip, StatusChip } from '../components/status'
import { DataTable, Cell2 } from '../components/table'
import { Terminal } from '../components/terminal'
import { useToast } from '../components/toast'
import { fmtTime, pct, vlanName } from '../lib/format'
import { Icon } from '../components/Icons'

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
  const { data: posture } = useApi(endpoints.posture)
  const toast = useToast()
  const [busy, setBusy] = useState(false)
  const [runError, setRunError] = useState<string | null>(null)
  if (error && !data) return <ErrorState error={error} retry={reload} />
  if (!data) return <Loading rows={5} />
  const byId = new Map(data.status.map((s) => [s.control_id, s]))
  const t = posture?.totals
  const run = async () => {
    setBusy(true)
    setRunError(null)
    try {
      const r = await endpoints.runAssessment('tlee')
      toast.push({ title: `Assessment run ${r.run_id}`, detail: `${r.assessments} results · ${r.counts.PASS ?? 0} pass · ${r.counts.FAIL ?? 0} fail · ${r.counts.UNKNOWN ?? 0} unknown · ${r.counts.STALE ?? 0} stale`, tone: 'ok' })
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
      <PageHeader
        title="Controls"
        sub={last ? <>last run <Id dim>{last.run_id}</Id> · <Ts ts={last.assessed_at} date ms={false} /> · {last.trigger} · {last.actor}</> : 'no assessment run yet'}
        info={<>Control catalog for the access layer. Each control names the exact source of truth it reads in the switch twin or the application store and the states it can reach. Results are recorded per scope; UNKNOWN and STALE never count as a pass.</>}
      >
        <button className="btn primary" type="button" onClick={run} disabled={busy}>
          <Icon.play /> {busy ? 'Assessing…' : 'Run assessment'}
        </button>
      </PageHeader>
      {runError && <div className="error">Assessment run failed: {runError}</div>}

      {t && t.assessments > 0 && (
        <div className="grid-metrics">
          <Metric label="Determinate pass rate" value={pct(t.pass_rate_of_determinate_pct)} chip={<Ratio num={t.pass} den={t.determinate} />} hint={posture?.definitions.pass_rate_of_determinate_pct} tone={t.fail ? 'warn' : 'good'} />
          <Metric label="Coverage" value={pct(t.coverage_pct)} chip={<Ratio num={t.determinate} den={t.assessments} />} hint={posture?.definitions.coverage_pct} tone="accent" />
          <Metric
            label="Outcomes"
            value={<Counts counts={{ PASS: t.pass, FAIL: t.fail, UNKNOWN: t.unknown, STALE: t.stale }} />}
            hint={
              <span className="stack tight">
                <StatusBar counts={{ PASS: t.pass, FAIL: t.fail, UNKNOWN: t.unknown, STALE: t.stale }} label="assessment outcomes" />
                <span>
                  {t.controls} controls · {t.assessments} scopes{t.retired ? ` · ${t.retired} retired excluded` : ''}
                </span>
              </span>
            }
          />
          <Metric label="Open findings" value={posture?.findings.open ?? '—'} tone={posture?.findings.open ? 'warn' : 'good'} hint="FAIL or STALE awaiting verification" />
        </div>
      )}

      <Panel title="Control catalog" sub="open a row for its assessments and evidence" bodyClass="none">
        <DataTable
          rows={data.catalog}
          rowKey={(c) => c.id}
          onRowActivate={(c) => onOpen(c.id)}
          empty="The control catalog is empty"
          label="Control catalog"
          columns={[
            { key: 'control', header: 'control', wrap: true, render: (c) => <Cell2 primary={<span className="strong">{c.name}</span>} secondary={<Id dim>{c.id}</Id>} /> },
            { key: 'cat', header: 'category', priority: 2, render: (c) => <Chip kind="neutral">{c.category}</Chip> },
            { key: 'scope', header: 'scope', priority: 3, render: (c) => <span className="dim">{c.scope_type}</span> },
            { key: 'sev', header: 'severity', render: (c) => <SeverityChip value={c.severity} /> },
            { key: 'fresh', header: 'freshness', className: 'mono', priority: 3, render: (c) => fmtWindow(c.freshness_window) },
            {
              key: 'outcomes',
              header: 'outcomes',
              render: (c) => {
                const s = byId.get(c.id)
                if (!s || s.assessments === 0) return <span className="faint">—</span>
                return (
                  <span className="stack tight">
                    <StatusBar counts={{ PASS: s.pass, FAIL: s.fail, UNKNOWN: s.unknown, STALE: s.stale }} label={`${c.name} outcomes`} />
                    <Counts counts={{ PASS: s.pass, FAIL: s.fail, UNKNOWN: s.unknown, STALE: s.stale }} />
                  </span>
                )
              },
            },
            { key: 'open', header: 'open', align: 'right', priority: 2, render: (c) => <Count n={byId.get(c.id)?.open_findings} tone="warn" /> },
            { key: 'status', header: 'status', render: (c) => <AssessChip value={byId.get(c.id)?.status ?? 'NOT_ASSESSED'} /> },
          ]}
        />
      </Panel>
    </>
  )
}

// ---- control detail -----------------------------------------------------------------------------
function ControlDetail({ id, onBack }: { id: string; onBack: () => void }) {
  const { data, error, reload } = useApi(() => endpoints.control(id), [id])
  const [sel, setSel] = useState<string | null>(null)
  if (error && !data) return <ErrorState error={error} retry={reload} />
  if (!data) return <Loading rows={5} />
  const c = data.control
  const counts = countStatuses(data.assessments)
  const rows = [...data.assessments].sort((a, b) => PRIORITY.indexOf(a.status) - PRIORITY.indexOf(b.status) || a.scope.id.localeCompare(b.scope.id, undefined, { numeric: true }))
  return (
    <>
      <PageHeader
        eyebrow={
          <span className="row">
            <Id>{c.id}</Id>
            <SeverityChip value={c.severity} />
            <Chip kind="neutral">{c.category}</Chip>
            <Chip kind="neutral">{c.scope_type} scope</Chip>
            <CsfChips refs={c.csf} />
          </span>
        }
        title={c.name}
        sub={c.description}
      >
        <button className="btn" type="button" onClick={onBack}>
          ← All controls
        </button>
        <Link className="btn" to="/findings">
          Findings
        </Link>
      </PageHeader>

      <div className="grid grid-main-rail">
        <div className="stack">
          <Panel title="Assessments" sub={`${data.assessments.length} scope${data.assessments.length === 1 ? '' : 's'} · open a row for evidence and history`} bodyClass="none">
            <DataTable
              rows={rows}
              rowKey={(a) => a.id}
              onRowActivate={(a) => setSel(a.id)}
              selectedKey={sel}
              empty="No assessments recorded for this control yet — run an assessment from the catalog"
              columns={[
                { key: 'scope', header: 'scope', render: (a) => <Cell2 primary={<span className="strong">{a.scope.asset ?? a.scope.id}</span>} secondary={<span className="mono">{a.scope.interface ?? a.scope.id}{a.scope.vlan !== null && a.scope.type !== 'vlan' ? ` · VLAN ${a.scope.vlan}` : ''}</span>} /> },
                { key: 'status', header: 'status', render: (a) => <AssessChip value={a.status} /> },
                { key: 'expected', header: 'expected', wrap: true, priority: 2, className: 'mono small', render: (a) => fmtInline(a.expected) },
                { key: 'observed', header: 'observed', wrap: true, priority: 2, className: 'mono small', render: (a) => fmtInline(a.observed) },
                { key: 'at', header: 'assessed', priority: 3, render: (a) => <Ts ts={a.assessed_at} date ms={false} /> },
                { key: 'ev', header: 'evidence', align: 'right', priority: 3, render: (a) => a.evidence.length },
                { key: 'finding', header: 'finding', render: (a) => (a.finding_id ? <Link className="id" to={`/findings/${a.finding_id}`} onClick={(e) => e.stopPropagation()}>{a.finding_id}</Link> : <span className="faint">—</span>) },
              ]}
            />
          </Panel>
          {data.findings.length > 0 && (
            <Panel title="Findings for this control" sub="open and closed" bodyClass="none">
              <DataTable
                compact
                rows={data.findings}
                rowKey={(f) => f.id}
                columns={[
                  { key: 'id', header: 'finding', render: (f) => <Link className="id" to={`/findings/${f.id}`}>{f.id}</Link> },
                  { key: 'asset', header: 'asset', className: 'mono', render: (f) => f.asset ?? f.scope.id },
                  { key: 'sev', header: 'severity', render: (f) => <SeverityChip value={f.severity} /> },
                  { key: 'result', header: 'result', render: (f) => <AssessChip value={f.result} /> },
                  { key: 'status', header: 'status', render: (f) => <StatusChip value={f.status} /> },
                  { key: 'opened', header: 'opened', priority: 2, render: (f) => <Ts ts={f.opened_at} date ms={false} /> },
                  { key: 'occ', header: 'occurrences', align: 'right', priority: 3, render: (f) => f.occurrences },
                  { key: 'rem', header: 'remediation', priority: 3, render: (f) => <span className="dim">{f.remediation.status.replace(/_/g, ' ')}</span> },
                ]}
              />
            </Panel>
          )}
        </div>
        <div className="stack">
          <Panel title="Definition" bodyClass="flush">
            <KV
              rows={[
                kv('source of truth', <span className="mono wrap">{c.source_of_truth}</span>),
                kv('states reachable', <span className="row">{c.states.map((s) => <AssessChip key={s} value={s} />)}</span>),
                kv('freshness window', c.freshness_window ? `${fmtWindow(c.freshness_window)} · event-derived evidence older than this is reported STALE` : 'state-based · evidence is read live from the twin, no window applies'),
                kv('severity on FAIL', <SeverityChip value={c.severity} />),
                kv('scope type', c.scope_type),
              ]}
            />
          </Panel>
          <Panel title="Current result" bodyClass="flush">
            <div className="stack tight">
              <StatusBar counts={counts} large label="current result" />
              <div className="row">
                {STATUSES.map((s) => (
                  <Chip key={s} kind={s} className="mono">
                    {counts[s]} {s}
                  </Chip>
                ))}
              </div>
              <span className="dim small">{data.findings.length} finding{data.findings.length === 1 ? '' : 's'} recorded</span>
            </div>
          </Panel>
          <Panel title="Remediation guidance" bodyClass="flush">
            <p>{c.remediation || <span className="dim">No remediation guidance documented.</span>}</p>
          </Panel>
          <Panel title="Limitations" bodyClass="flush">
            <p>{c.limitations || <span className="dim">None documented for this control.</span>}</p>
          </Panel>
          <Panel title="NIST CSF 2.0" sub="documentation aid" bodyClass="flush">
            <CsfList refs={c.csf} />
          </Panel>
        </div>
      </div>

      {sel && <AssessmentDrawer id={sel} onClose={() => setSel(null)} />}
    </>
  )
}

// ---- assessment drawer --------------------------------------------------------------------------
function AssessmentDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const { data, error } = useApi(() => endpoints.assessment(id), [id])
  if (!data)
    return (
      <Drawer title={id} onClose={onClose}>
        <Loading error={error} />
      </Drawer>
    )
  const a = data.assessment
  const history = [...data.history].reverse()
  return (
    <Drawer
      title={
        <>
          {a.scope.asset ?? a.scope.id} <AssessChip value={a.status} /> <SeverityChip value={a.severity} />
        </>
      }
      sub={a.id}
      onClose={onClose}
    >
      <KV
        rows={[
          kv('control', <Link to={`/controls/${a.control_id}`}>{a.control_name}</Link>),
          kv('scope', `${a.scope.type} · ${a.scope.id}`),
          kv('asset', a.scope.asset ?? '—'),
          kv('interface', a.scope.interface ? `${a.scope.switch} ${a.scope.interface}` : a.scope.switch),
          kv('vlan', vlanName(a.scope.vlan)),
          ...(a.scope.description ? [kv('description', a.scope.description)] : []),
          kv('assessed', <Ts ts={a.assessed_at} date />),
          kv('run', <Id dim>{a.run_id}</Id>),
          kv('detector', <span className="mono">{a.detector}</span>),
          kv('finding', a.finding_id ? <Link className="id" to={`/findings/${a.finding_id}`}>{a.finding_id}</Link> : '—'),
        ]}
      />
      <div className="notice">{a.explanation}</div>
      <Section title="Expected vs observed">
        <span />
      </Section>
      <div className="stack tight">
        <div className="eyebrow">Expected</div>
        <ValueBlock v={a.expected} />
        <div className="eyebrow">Observed</div>
        <ValueBlock v={a.observed} />
      </div>
      <Section title="Evidence" count={a.evidence.length} right={<span className="dim small">collected {fmtTime(a.evidence_collected_at, { date: true, ms: false })}</span>}>
        <span />
      </Section>
      <EvidenceList items={a.evidence} />
      <Section title="Freshness">
        <span />
      </Section>
      <Freshness f={a.freshness} />
      <Section title="Source of truth">
        <span />
      </Section>
      <div className="mono small wrap">{a.source_of_truth}</div>
      {a.limitations && <div className="dim small">Limitation: {a.limitations}</div>}
      <Section title="Related incidents">
        <span />
      </Section>
      {a.related_incidents.length ? (
        <div className="row">
          {a.related_incidents.map((i) => (
            <Link key={i} className="id" to={`/incidents/${i}`}>
              {i}
            </Link>
          ))}
        </div>
      ) : (
        <div className="dim small">No related incidents</div>
      )}
      {(a.remediation.commands.length > 0 || a.status === 'FAIL' || a.status === 'STALE') && (
        <>
          <Section title="Remediation">
            <span />
          </Section>
          <p>{a.remediation.guidance}</p>
          {a.remediation.commands.length > 0 ? <Terminal text={a.remediation.commands.join('\n')} /> : <div className="dim small">No executable commands proposed; manual follow-up.</div>}
          <div className="dim small">{a.remediation.action ? <>executable action <span className="mono">{a.remediation.action.type as string}</span></> : 'no executable action'}</div>
        </>
      )}
      <Section title="History" count={history.length}>
        <span />
      </Section>
      <DataTable
        compact
        rows={history}
        rowKey={(h) => `${h.run_id}-${h.assessed_at}`}
        empty="No previous runs recorded"
        columns={[
          { key: 'run', header: 'run', className: 'mono small', render: (h) => h.run_id },
          { key: 'status', header: 'status', render: (h) => <AssessChip value={h.status} /> },
          { key: 'at', header: 'assessed', render: (h) => <Ts ts={h.assessed_at} date ms={false} /> },
          { key: 'obs', header: 'observed', wrap: true, className: 'mono small', render: (h) => fmtInline(h.observed) },
        ]}
      />
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
          <div className="stack tight">
            <div className="ref">{e.ref}</div>
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
    return <KV rows={[kv('window', fmtWindow(f.window_seconds)), kv('applied', <span className="dim">no — the result is UNKNOWN or has no event-derived evidence</span>)]} />
  }
  return (
    <KV
      rows={[
        kv('window', fmtWindow(f.window_seconds)),
        kv('oldest evidence', <Ts ts={f.oldest_evidence_at} date />),
        kv('age at assessment', fmtAge(f.age_seconds)),
        kv('fresh', f.fresh ? <Chip kind="ok">fresh</Chip> : <Chip kind="STALE" className="caps mono">STALE · {fmtAge(f.age_seconds)} old, window {fmtWindow(f.window_seconds)}</Chip>),
      ]}
    />
  )
}

/** Expected / observed value: objects and arrays as pretty JSON in a terminal block, scalars as wrapped text. */
export function ValueBlock({ v }: { v: unknown }) {
  if (v !== null && typeof v === 'object') return <Terminal text={JSON.stringify(v, null, 2)} copy={false} />
  return <div className="mono wrap dim">{v === null || v === undefined ? '(absent)' : String(v)}</div>
}

function CsfChips({ refs }: { refs: ControlCatalogEntry['csf'] }) {
  return (
    <>
      {refs.map((r) => (
        <Chip key={r.id} kind="neutral" mono title={r.text}>
          {r.id}
        </Chip>
      ))}
    </>
  )
}

function CsfList({ refs }: { refs: ControlCatalogEntry['csf'] }) {
  if (refs.length === 0) return <span className="dim">—</span>
  return (
    <div className="stack tight">
      {refs.map((r) => (
        <div key={r.id} className="wrap">
          <span className="mono">{r.id}</span> <span className="dim">{r.text}</span>
        </div>
      ))}
    </div>
  )
}

function Count({ n, tone }: { n: number | undefined; tone: 'warn' | 'danger' | 'ok' }) {
  if (!n) return <span className="faint mono">{n ?? '—'}</span>
  return <span className={`mono strong ${tone === 'warn' ? 'warn-ink' : tone}`}>{n}</span>
}

function countStatuses(list: { status: AssessmentStatus }[]): Record<AssessmentStatus, number> {
  const out: Record<AssessmentStatus, number> = { PASS: 0, FAIL: 0, UNKNOWN: 0, STALE: 0 }
  for (const a of list) out[a.status] += 1
  return out
}

export function fmtWindow(seconds: number | null): string {
  if (!seconds) return 'state-based'
  const m = Math.round(seconds / 60)
  return m >= 120 && m % 60 === 0 ? `${m / 60} h` : `${m} min`
}

export function fmtAge(seconds: number | undefined): string {
  if (seconds === undefined) return '—'
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  return h ? `${h} h ${m} m` : `${m} min`
}

export function fmtInline(v: unknown): string {
  if (v === null || v === undefined) return '(absent)'
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}

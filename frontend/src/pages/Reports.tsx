import { useState } from 'react'
import { Link } from 'react-router-dom'
import { kv } from '../lib/kv'
import { endpoints, type ReportInfo, BASE } from '../lib/api'
import { useApi } from '../lib/hooks'
import { Empty, ErrorState, KV, Loading, Panel, Ts } from '../components/ui'
import { PageHeader } from '../components/layout'
import { Metric, MetricBand } from '../components/metric'
import { Chip, SeverityChip, StatusChip } from '../components/status'
import { DataTable, Cell2 } from '../components/table'
import { useToast } from '../components/toast'
import { fmtBytes, fmtTime } from '../lib/format'
import { Icon } from '../components/Icons'

/** Top-level keys of the schema 2.0 JSON export (backend/sentinelswitch/assurance/export.py: build_export). */
const SCHEMA: [string, string][] = [
  ['schema_version', 'Version of the export document schema.'],
  ['generator', 'Producing component: SentinelSwitch name, package version and the exporting module.'],
  ['generated_at', 'Simulated-clock timestamp at which the persisted records were read.'],
  ['clock_basis', 'Which clock every timestamp is measured on (switch-twin clock, dataset day).'],
  ['simulation_notice', 'Statement that all assets, telemetry, incidents and assessments are synthetic.'],
  ['scope', 'Organization, switch, VLANs and the number of assets and controls in scope.'],
  ['methodology', 'Definitions of PASS / FAIL / UNKNOWN / STALE, the freshness rule and every posture metric.'],
  ['posture', 'Totals with explicit denominators, per-control, per-category and CSF rollups, finding counts.'],
  ['controls', 'The control catalog: description, severity, scope type, source of truth, CSF references, freshness window.'],
  ['assessments', 'Current assessment per control and scope with expected vs observed, evidence rows and freshness.'],
  ['findings', 'Every finding with its remediation record, verification and full event history.'],
  ['assets_with_open_findings', 'Assets grouped by their open findings with worst severity and affected controls.'],
  ['unverified', 'UNKNOWN and STALE assessments; these are never counted as passes.'],
  ['assessment_runs', 'Run ledger: trigger, actor, controls and assessments evaluated, state counts.'],
  ['incidents', 'Incidents with timeline, containment actions and the artifacts present in each evidence bundle.'],
  ['manual_reviews', 'Detections routed to analyst review with the policy decision and the authorization outcome.'],
  ['containment_actions', 'Every containment workflow with its authorization record, transcript and read-back verification.'],
  ['validation', 'Scenario harness metrics and per-scenario detect / attribute / contain results.'],
  ['framework_mapping', 'NIST CSF 2.0 subcategory rollup, provided for orientation only.'],
  ['limitations', 'Explicit caveats of the simulated environment.'],
  ['reproducibility', 'Commands, dataset manifest and determinism flag needed to regenerate the export.'],
]

/** Narrow view of the untyped export document for the fields this page reads. */
interface ExportDoc {
  schema_version?: string
  generator?: { name?: string; version?: string; component?: string }
  generated_at?: string
  clock_basis?: string
  simulation_notice?: string
  scope?: { switch?: { hostname?: string; model?: string }; assets_in_scope?: number; controls_in_scope?: number; vlans?: unknown[] }
  posture?: { totals?: { assessments?: number; pass?: number; fail?: number; unknown?: number; stale?: number; retired?: number }; findings_open?: number; findings_closed?: number }
  limitations?: string[]
  reproducibility?: { commands?: string[]; dataset_manifest?: string; deterministic?: boolean }
}

function shape(v: unknown): string {
  if (v === null || v === undefined) return 'null'
  if (Array.isArray(v)) return `array · ${v.length} ${v.length === 1 ? 'item' : 'items'}`
  if (typeof v === 'object') return `object · ${Object.keys(v as object).length} keys`
  return typeof v
}

function count(doc: Record<string, unknown>, key: string): number {
  const v = doc[key]
  return Array.isArray(v) ? v.length : 0
}

export function Reports() {
  const { data, error, reload } = useApi(endpoints.reportJson)
  const { data: bundles, error: bundlesError } = useApi(endpoints.evidence)
  const toast = useToast()
  const [info, setInfo] = useState<ReportInfo | null>(null)
  const [genError, setGenError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [previewKey, setPreviewKey] = useState(0)
  const [preview, setPreview] = useState(false)
  const [schemaOpen, setSchemaOpen] = useState(false)
  const [limitsOpen, setLimitsOpen] = useState(false)
  if (error && !data) return <ErrorState error={error} retry={reload} />
  if (!data) return <Loading rows={5} />
  const doc = data as ExportDoc & Record<string, unknown>
  const totals = doc.posture?.totals
  const generate = async () => {
    setBusy(true)
    setGenError(null)
    try {
      const r = await endpoints.reportGenerate()
      setInfo(r)
      setPreviewKey((k) => k + 1)
      toast.push({ title: 'Reports generated', detail: `${r.assessments} assessments · ${r.findings} findings${r.pdf ? ' · PDF rendered' : ' · PDF unavailable'}`, tone: 'ok' })
    } catch (e) {
      setGenError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }
  const html = `${BASE}/api/reports/posture.html`
  return (
    <>
      <PageHeader
        title="Reports"
        sub="Machine-readable and human-readable exports of the assessment state, assembled from persisted records at the moment they are requested"
        info={<>Every export is built from SQLite and the evidence bundles when requested; nothing is computed only for the report. The JSON document (schema {doc.schema_version ?? '—'}) is the primary artifact; the HTML report is rendered from the same document and the PDF from the HTML, when headless Chromium is available on the API host.</>}
      >
        <button className="btn primary" type="button" onClick={generate} disabled={busy}>
          <Icon.report /> {busy ? 'Generating…' : 'Generate reports'}
        </button>
        <a className="btn" href={html} target="_blank" rel="noreferrer">
          Open HTML <Icon.external />
        </a>
        <a className="btn" href={`${BASE}/api/reports/posture.json`} target="_blank" rel="noreferrer">
          JSON <Icon.external />
        </a>
        {info?.pdf ? (
          <a className="btn" href={`${BASE}/api/reports/posture.pdf`} target="_blank" rel="noreferrer">
            PDF <Icon.external />
          </a>
        ) : (
          <button className="btn" type="button" disabled title={info ? 'PDF unavailable: headless Chromium (Playwright) is not installed on the API host' : 'Generate reports first; the PDF is rendered from the HTML with headless Chromium when it is available on the API host'}>
            PDF
          </button>
        )}
      </PageHeader>

      <MetricBand>
        <Metric label="Assessments" value={totals?.assessments ?? count(doc, 'assessments')} hint={totals ? `${totals.pass ?? 0} pass · ${totals.fail ?? 0} fail · ${totals.unknown ?? 0} unknown · ${totals.stale ?? 0} stale${totals.retired ? ` · ${totals.retired} retired (exported, not counted)` : ''}` : 'current assessments in the export'} />
        <Metric label="Findings" value={count(doc, 'findings')} tone={(doc.posture?.findings_open ?? 0) > 0 ? 'danger' : 'good'} hint={`${doc.posture?.findings_open ?? 0} open · ${doc.posture?.findings_closed ?? 0} closed`} />
        <Metric label="Incidents" value={count(doc, 'incidents')} hint="with timeline, actions and bundle contents" />
        <Metric label="Containment actions" value={count(doc, 'containment_actions')} hint="authorization + read-back verification" />
        <Metric label="Manual reviews" value={count(doc, 'manual_reviews')} hint="analyst authorization decisions" />
        <Metric label="Assessment runs" value={count(doc, 'assessment_runs')} hint="run ledger entries" />
      </MetricBand>

      <div className="grid grid-main-rail">
        <Panel title="Artifacts" sub="exported reports · written under the artifacts directory by Generate reports">
          <div className="stack">
            {genError && <div className="error">Report generation failed: {genError}</div>}
            {info && <div className="notice ok">Generated: {info.assessments} assessment rows · {info.findings} findings{info.pdf ? ' · PDF rendered' : ' · PDF unavailable (headless Chromium not installed on the API host)'}</div>}
            <div className="artifact-rows">
              <div className="artifact-row">
                <span className="fmt">JSON</span>
                <Chip kind="ok">live</Chip>
                <span className="stack tight">
                  <a className="mono small" href={`${BASE}/api/reports/posture.json`} target="_blank" rel="noreferrer">
                    /api/reports/posture.json
                  </a>
                  <span className="dim small">Full export document, built on every request.</span>
                  {info && <span className="path">{info.json}</span>}
                </span>
              </div>
              <div className="artifact-row">
                <span className="fmt">HTML</span>
                <Chip kind="ok">live</Chip>
                <span className="stack tight">
                  <a className="mono small" href={html} target="_blank" rel="noreferrer">
                    /api/reports/posture.html
                  </a>
                  <span className="dim small">Sectioned posture report rendered from the JSON document.</span>
                  {info && <span className="path">{info.html}</span>}
                </span>
              </div>
              <div className="artifact-row">
                <span className="fmt">PDF</span>
                {info ? info.pdf ? <Chip kind="ok">generated</Chip> : <Chip kind="neutral">unavailable</Chip> : <Chip kind="pending">not generated</Chip>}
                <span className="stack tight">
                  {info?.pdf ? (
                    <a className="mono small" href={`${BASE}/api/reports/posture.pdf`} target="_blank" rel="noreferrer">
                      /api/reports/posture.pdf
                    </a>
                  ) : (
                    <span className="mono small dim">/api/reports/posture.pdf</span>
                  )}
                  <span className="dim small">{info ? (info.pdf ? 'Rendered from the HTML report with headless Chromium.' : 'Headless Chromium (Playwright) is not installed on the API host, so only JSON and HTML were written.') : 'Written only by Generate reports, and only when headless Chromium (Playwright) is available on the API host.'}</span>
                  {info?.pdf && <span className="path">{info.pdf}</span>}
                </span>
              </div>
            </div>
            {doc.simulation_notice && <div className="notice">{doc.simulation_notice}</div>}
          </div>
        </Panel>
        <Panel title="Document facts" bodyClass="flush">
          <KV
            rows={[
              kv('generated at', doc.generated_at ? <Ts ts={doc.generated_at} date /> : '—'),
              kv('clock basis', doc.clock_basis ?? '—'),
              kv('generator', doc.generator ? `${doc.generator.name ?? ''} ${doc.generator.version ?? ''} · ${doc.generator.component ?? ''}` : '—'),
              kv('scope', doc.scope ? `${doc.scope.switch?.hostname ?? ''} (${doc.scope.switch?.model ?? ''}) · ${doc.scope.assets_in_scope ?? 0} assets · ${doc.scope.controls_in_scope ?? 0} controls · ${doc.scope.vlans?.length ?? 0} VLANs` : '—'),
              kv('schema', doc.schema_version ?? '—'),
              kv('reproduce', doc.reproducibility?.commands?.length ? <span className="mono wrap">{doc.reproducibility.commands.join(' ; ')}</span> : '—'),
            ]}
          />
        </Panel>
      </div>

      <Panel
        title="Preview"
        sub="/api/reports/posture.html"
        collapsible
        collapsed={!preview}
        onToggle={() => setPreview((p) => !p)}
        right={
          <>
            <button className="btn sm" type="button" onClick={() => setPreviewKey((k) => k + 1)}>
              Reload preview
            </button>
            <a className="btn sm" href={html} target="_blank" rel="noreferrer">
              Open in new tab
            </a>
          </>
        }
        bodyClass="none"
      >
        {preview && <iframe key={`${doc.generated_at ?? ''}-${previewKey}`} title="Security posture report" src={html} className="report-frame" />}
      </Panel>

      <div className="grid grid-2">
        <Panel title="Evidence bundles" sub="original evidence · data/incidents/<id>/" right={<Link to="/evidence">browse</Link>} bodyClass="none">
          <DataTable
            cards="narrow"
            compact
            rows={bundles}
            loading={!bundles}
            error={!bundles ? bundlesError : null}
            rowKey={(e) => e.incident.id}
            empty="No evidence bundles yet. Bundles are written when an incident is contained."
            columns={[
              { key: 'id', header: 'incident', wrap: true, render: (e) => <Cell2 primary={<Link className="id" to={`/evidence/${e.incident.id}`}>{e.incident.id}</Link>} secondary={e.incident.title} /> },
              { key: 'state', header: 'state', render: (e) => <span className="row"><SeverityChip value={e.incident.severity} /><StatusChip value={e.incident.status} /></span> },
              { key: 'files', header: 'artifacts', align: 'right', render: (e) => <span className={e.complete ? 'mono' : 'mono warn-ink'}>{e.files.length} · {fmtBytes(e.files.reduce((n, f) => n + f.bytes, 0))}</span> },
            ]}
          />
        </Panel>
        <div className="stack">
          <Panel title="Export schema" sub={`top-level keys · schema ${doc.schema_version ?? '—'}`} collapsible collapsed={!schemaOpen} onToggle={() => setSchemaOpen((o) => !o)} bodyClass="none">
            <DataTable
              compact
              rows={SCHEMA}
              rowKey={([k]) => k}
              columns={[
                { key: 'k', header: 'key', className: 'mono strong', render: ([k]) => k },
                { key: 'in', header: 'in this export', className: 'mono', render: ([k]) => (k in doc ? <span className="dim">{shape(doc[k])}</span> : <Chip kind="neutral">missing</Chip>) },
                { key: 'm', header: 'meaning', wrap: true, hideBelow: 600, render: ([, m]) => <span className="small">{m}</span> },
              ]}
            />
          </Panel>
          <Panel title="Limitations" sub="carried verbatim in every export" collapsible collapsed={!limitsOpen} onToggle={() => setLimitsOpen((o) => !o)}>
            {doc.limitations && doc.limitations.length > 0 ? (
              <ul className="dim list">
                {doc.limitations.map((l) => (
                  <li key={l}>{l}</li>
                ))}
              </ul>
            ) : (
              <Empty>No limitations listed in this export</Empty>
            )}
          </Panel>
        </div>
      </div>
      <span className="sr-only">{fmtTime(doc.generated_at)}</span>
    </>
  )
}

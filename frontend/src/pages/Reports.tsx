import { useState } from 'react'
import { Link } from 'react-router-dom'
import { kv } from '../lib/kv'
import { endpoints, type ReportInfo, BASE } from '../lib/api'
import { useApi } from '../lib/hooks'
import { Card, Chip, Empty, KV, Kpi, Loading, Sev, Ts } from '../components/ui'
import { fmtBytes, fmtTime } from '../lib/format'

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
  const { data, error } = useApi(endpoints.reportJson)
  const { data: bundles, error: bundlesError } = useApi(endpoints.evidence)
  const [info, setInfo] = useState<ReportInfo | null>(null)
  const [genError, setGenError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [previewKey, setPreviewKey] = useState(0)
  if (!data) return <Loading error={error} />
  const doc = data as ExportDoc & Record<string, unknown>
  const totals = doc.posture?.totals
  const generate = async () => {
    setBusy(true)
    setGenError(null)
    try {
      const r = await endpoints.reportGenerate()
      setInfo(r)
      setPreviewKey((k) => k + 1)
    } catch (e) {
      setGenError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }
  const pathCell = (p: string) => <code className="wrap" style={{ wordBreak: 'break-all' }}>{p}</code>
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Evidence &amp; reports</h1>
          <p>
            Machine-readable and human-readable exports of the assessment state. Every export is assembled from persisted records (SQLite and the evidence bundles) at the moment it is requested; nothing is computed only for the report.
          </p>
        </div>
        <div className="toolbar">
          <button className="btn primary" onClick={generate} disabled={busy}>{busy ? 'Generating…' : 'Generate reports'}</button>
          <a className="btn" href={`${BASE}/api/reports/posture.html`} target="_blank" rel="noreferrer">Open HTML report</a>
          <a className="btn" href={`${BASE}/api/reports/posture.json`} target="_blank" rel="noreferrer">JSON</a>
          {info?.pdf ? (
            <a className="btn" href={`${BASE}/api/reports/posture.pdf`} target="_blank" rel="noreferrer">PDF</a>
          ) : (
            <button className="btn" disabled title="Generate reports first; the PDF is rendered from the HTML with headless Chromium when it is available on the API host">PDF</button>
          )}
        </div>
      </div>

      <div className="grid kpis">
        <Kpi label="Assessments" value={totals?.assessments ?? count(doc, 'assessments')} hint={totals ? `${totals.pass ?? 0} pass · ${totals.fail ?? 0} fail · ${totals.unknown ?? 0} unknown · ${totals.stale ?? 0} stale${totals.retired ? ` · ${totals.retired} retired (exported, not counted)` : ''}` : 'current assessments in the export'} />
        <Kpi label="Findings" value={count(doc, 'findings')} tone={(doc.posture?.findings_open ?? 0) > 0 ? 'danger' : 'good'} hint={`${doc.posture?.findings_open ?? 0} open · ${doc.posture?.findings_closed ?? 0} closed`} />
        <Kpi label="Incidents" value={count(doc, 'incidents')} hint="with timeline, actions and bundle contents" />
        <Kpi label="Containment actions" value={count(doc, 'containment_actions')} hint="authorization + read-back verification" />
        <Kpi label="Manual reviews" value={count(doc, 'manual_reviews')} hint="analyst authorization decisions" />
        <Kpi label="Assessment runs" value={count(doc, 'assessment_runs')} hint="run ledger entries" />
      </div>

      <div className="grid main-side">
        <Card title="Exports" sub="read from persisted records at export time">
          <div className="stack">
            <p className="dim">
              The JSON document (schema {doc.schema_version ?? '—'}) is the primary artifact: it carries every assessment with its evidence rows, every finding with its event history, incidents with their timelines and containment actions, manual reviews with their authorization records, the validation results and the explicit limitations. The HTML report is rendered from the same document; the PDF is rendered from the HTML.
            </p>
            {doc.simulation_notice && <div className="notice">{doc.simulation_notice}</div>}
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>format</th><th>endpoint</th><th>availability</th><th>contents</th></tr></thead>
                <tbody>
                  <tr>
                    <td className="strong">JSON</td>
                    <td className="mono"><a href={`${BASE}/api/reports/posture.json`} target="_blank" rel="noreferrer">/api/reports/posture.json</a></td>
                    <td><Chip kind="ok">live</Chip></td>
                    <td className="wrap">Full export document, built on every request.</td>
                  </tr>
                  <tr>
                    <td className="strong">HTML</td>
                    <td className="mono"><a href={`${BASE}/api/reports/posture.html`} target="_blank" rel="noreferrer">/api/reports/posture.html</a></td>
                    <td><Chip kind="ok">live</Chip></td>
                    <td className="wrap">Sectioned posture report rendered from the JSON document; opens in a new tab.</td>
                  </tr>
                  <tr>
                    <td className="strong">PDF</td>
                    <td className="mono">{info?.pdf ? <a href={`${BASE}/api/reports/posture.pdf`} target="_blank" rel="noreferrer">/api/reports/posture.pdf</a> : '/api/reports/posture.pdf'}</td>
                    <td>{info ? (info.pdf ? <Chip kind="ok">generated</Chip> : <Chip kind="neutral">unavailable</Chip>) : <Chip kind="pending">not generated</Chip>}</td>
                    <td className="wrap">{info ? (info.pdf ? 'Rendered from the HTML report with headless Chromium.' : 'PDF unavailable: headless Chromium (Playwright) is not installed on the API host, so only JSON and HTML were written.') : 'Written only by Generate reports, and only when headless Chromium (Playwright) is available on the API host.'}</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <KV rows={[
              kv('generated at', doc.generated_at ? <span className="ts">{fmtTime(doc.generated_at, { date: true })}</span> : '—'),
              kv('clock basis', doc.clock_basis ?? '—'),
              kv('generator', doc.generator ? `${doc.generator.name ?? ''} ${doc.generator.version ?? ''} · ${doc.generator.component ?? ''}` : '—'),
              kv('scope', doc.scope ? `${doc.scope.switch?.hostname ?? ''} (${doc.scope.switch?.model ?? ''}) · ${doc.scope.assets_in_scope ?? 0} assets · ${doc.scope.controls_in_scope ?? 0} controls · ${doc.scope.vlans?.length ?? 0} VLANs` : '—'),
              kv('reproduce', doc.reproducibility?.commands?.length ? <span className="mono">{doc.reproducibility.commands.join(' ; ')}</span> : '—')]} />
          </div>
        </Card>
        <Card title="Generated artifacts" sub="written under the artifacts directory">
          {genError && <div className="error" style={{ marginBottom: 10 }}>Report generation failed: {genError}</div>}
          {info ? (
            <KV rows={[
              kv('json', pathCell(info.json)),
              kv('html', pathCell(info.html)),
              kv('pdf', info.pdf ? pathCell(info.pdf) : <span className="dim">PDF unavailable (headless Chromium not installed on the API host)</span>),
              kv('assessment rows exported', info.assessments),
              kv('findings', info.findings)]} />
          ) : (
            <Empty>Not generated in this session. Generate reports writes the JSON and HTML files to disk and renders the PDF when headless Chromium is available; the JSON and HTML endpoints are live regardless.</Empty>
          )}
        </Card>
      </div>

      <Card
        title="Preview"
        sub="/api/reports/posture.html"
        right={
          <div className="toolbar">
            <button className="btn sm" onClick={() => setPreviewKey((k) => k + 1)}>Reload preview</button>
            <a className="btn sm" href={`${BASE}/api/reports/posture.html`} target="_blank" rel="noreferrer">Open in new tab</a>
          </div>
        }
      >
        <iframe
          key={`${doc.generated_at ?? ''}-${previewKey}`}
          title="Security posture report"
          src={`${BASE}/api/reports/posture.html`}
          style={{ width: '100%', height: 720, border: '1px solid var(--border)', borderRadius: 'var(--radius)', background: '#fff', display: 'block' }}
        />
      </Card>

      <div className="grid two">
        <Card title="Export schema" sub={`top-level keys · schema ${doc.schema_version ?? '—'}`} bodyClass="tight">
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>key</th><th>in this export</th><th>meaning</th></tr></thead>
              <tbody>
                {SCHEMA.map(([key, meaning]) => (
                  <tr key={key}>
                    <td className="mono strong">{key}</td>
                    <td className="mono dim">{key in doc ? shape(doc[key]) : <Chip kind="neutral">missing</Chip>}</td>
                    <td className="wrap small" style={{ minWidth: 240 }}>{meaning}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
        <div className="stack">
          <Card title="Evidence bundles" sub="data/incidents/<id>/" right={<Link to="/evidence">browse</Link>} bodyClass="tight">
            {!bundles ? (
              <Loading error={bundlesError} />
            ) : bundles.length === 0 ? (
              <Empty>No evidence bundles yet. Bundles are written when an incident is contained.</Empty>
            ) : (
              <div className="table-wrap">
                <table className="data">
                  <thead><tr><th>incident</th><th>opened</th><th>severity</th><th>status</th><th>artifacts</th><th>size</th></tr></thead>
                  <tbody>
                    {bundles.map((e) => (
                      <tr key={e.incident.id}>
                        <td className="mono strong"><Link to={`/evidence/${e.incident.id}`}>{e.incident.id}</Link></td>
                        <td><Ts ts={e.incident.opened_at} date /></td>
                        <td><Sev s={e.incident.severity} /></td>
                        <td><Chip kind={e.incident.status} /></td>
                        <td>{e.complete ? <Chip kind="ok">{e.files.length} files</Chip> : <Chip kind="medium">{e.files.length} files</Chip>}</td>
                        <td className="num mono">{fmtBytes(e.files.reduce((n, f) => n + f.bytes, 0))}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
          {doc.limitations && doc.limitations.length > 0 && (
            <Card title="Limitations" sub="carried verbatim in every export">
              <ul style={{ margin: 0, paddingLeft: 18 }} className="dim">
                {doc.limitations.map((l) => (
                  <li key={l}>{l}</li>
                ))}
              </ul>
            </Card>
          )}
        </div>
      </div>
    </>
  )
}

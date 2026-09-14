import { endpoints } from '../lib/api'
import { useApi } from '../lib/hooks'
import { Card, Chip, Kpi, Loading, Sev, Term } from '../components/ui'

export function Drift() {
  const { data, error } = useApi(endpoints.drift)
  if (!data) return <Loading error={error} />
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Configuration drift</h1>
          <p>Desired state comes from <code>{data.desired_source}</code>; observed state is the twin's running configuration. Containment changes made by SentinelSwitch are reported as approved deviations, not drift.</p>
        </div>
      </div>
      <div className="grid kpis">
        <Kpi label="Interfaces checked" value={data.checked_interfaces} hint={`${data.checks} settings compared`} />
        <Kpi label="Compliant" value={data.compliant_interfaces} tone="good" />
        <Kpi label="Open findings" value={data.open} tone={data.open ? 'warn' : 'good'} hint={`${data.by_severity.high} high · ${data.by_severity.medium} medium · ${data.by_severity.low} low · ${data.by_severity.info} info`} />
        <Kpi label="Approved deviations" value={data.approved} hint="SentinelSwitch containment" />
      </div>
      <Card title="Findings" bodyClass="tight">
        <div className="table-wrap">
          <table className="data">
            <thead><tr><th>id</th><th>interface</th><th>setting</th><th>expected</th><th>observed</th><th>severity</th><th>status</th><th>recommended action</th></tr></thead>
            <tbody>
              {data.findings.map((f) => (
                <tr key={f.id}>
                  <td className="mono">{f.id}</td>
                  <td className="mono">{f.interface ?? 'global'}</td>
                  <td className="mono">{f.setting}</td>
                  <td className="mono wrap">{fmt(f.expected)}</td>
                  <td className="mono wrap">{fmt(f.observed)}</td>
                  <td><Sev s={f.severity} /></td>
                  <td><Chip kind={f.status === 'approved' ? 'ok' : 'review'}>{f.status}</Chip>{f.note && <div className="dim small" style={{ whiteSpace: 'normal', maxWidth: 260 }}>{f.note}</div>}</td>
                  <td><Term text={f.recommendation} /></td>
                </tr>
              ))}
              {data.findings.length === 0 && <tr><td colSpan={8} className="dim">No drift detected</td></tr>}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  )
}

function fmt(v: unknown): string {
  if (v === null || v === undefined) return '(absent)'
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}

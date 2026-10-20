import { endpoints } from '../lib/api'
import { useApi } from '../lib/hooks'
import { ErrorState, Loading, Panel } from '../components/ui'
import { PageHeader } from '../components/layout'
import { Metric, MetricBand } from '../components/metric'
import { Chip, SeverityChip } from '../components/status'
import { DataTable, Cell2 } from '../components/table'
import { Terminal } from '../components/terminal'

export function Drift() {
  const { data, error, reload } = useApi(endpoints.drift)
  if (error && !data) return <ErrorState error={error} retry={reload} />
  if (!data) return <Loading rows={4} />
  return (
    <>
      <PageHeader title="Configuration drift" sub={`desired state from ${data.desired_source} · observed state from the twin's running configuration`} info={<>Containment changes made by SentinelSwitch are reported as approved deviations, not drift.</>} />
      <MetricBand>
        <Metric label="Interfaces checked" value={data.checked_interfaces} hint={`${data.checks} settings compared`} />
        <Metric label="Compliant" value={data.compliant_interfaces} tone="good" />
        <Metric label="Open findings" value={data.open} tone={data.open ? 'warn' : 'good'} hint={`${data.by_severity.high} high · ${data.by_severity.medium} medium · ${data.by_severity.low} low · ${data.by_severity.info} info`} />
        <Metric label="Approved deviations" value={data.approved} hint="SentinelSwitch containment" />
      </MetricBand>
      <Panel title="Findings" bodyClass="none">
        <DataTable
          cards
          rows={data.findings}
          rowKey={(f) => f.id}
          empty="No drift detected"
          columns={[
            { key: 'id', header: 'id', className: 'mono', render: (f) => f.id },
            { key: 'if', header: 'interface', className: 'mono', render: (f) => f.interface ?? 'global' },
            { key: 'setting', header: 'setting', className: 'mono', render: (f) => f.setting },
            {
              key: 'cmp',
              header: 'expected → observed',
              wrap: true,
              render: (f) => (
                <span className="drift-cmp">
                  <span className="exp mono">{fmt(f.expected)}</span>
                  <span className="obs mono">{fmt(f.observed)}</span>
                </span>
              ),
            },
            { key: 'sev', header: 'severity', render: (f) => <SeverityChip value={f.severity} /> },
            { key: 'status', header: 'status', wrap: true, render: (f) => <Cell2 primary={<Chip kind={f.status === 'approved' ? 'outline-ok' : 'review'}>{f.status}</Chip>} secondary={f.note ? <span className="wrap">{f.note}</span> : undefined} /> },
            { key: 'rec', header: 'recommended action', wrap: true, render: (f) => <Terminal text={f.recommendation} maxHeight={120} className="wrap-lines" /> },
          ]}
        />
      </Panel>
    </>
  )
}

function fmt(v: unknown): string {
  if (v === null || v === undefined) return '(absent)'
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}

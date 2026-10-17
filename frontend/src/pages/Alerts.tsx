import { useMemo, useState } from 'react'
import { kv } from '../lib/kv'
import { Link } from 'react-router-dom'
import { endpoints, type Alert } from '../lib/api'
import { useApi } from '../lib/hooks'
import { Drawer, ErrorState, KV, Loading, Panel, Ts } from '../components/ui'
import { PageHeader, Section } from '../components/layout'
import { Chip, SeverityChip, StatusChip } from '../components/status'
import { DataTable } from '../components/table'
import { Terminal } from '../components/terminal'
import { Features as FeatureList, Confidence } from '../components/Features'
import { sevRank } from '../lib/format'

export function Alerts() {
  const { data, error, reload } = useApi(() => endpoints.alerts('?limit=1000'))
  const [sev, setSev] = useState('all')
  const [src, setSrc] = useState('all')
  const [status, setStatus] = useState('all')
  const [q, setQ] = useState('')
  const [sel, setSel] = useState<Alert | null>(null)
  const rows = useMemo(() => {
    if (!data) return []
    return data
      .filter((a) => sev === 'all' || a.severity === sev)
      .filter((a) => src === 'all' || a.source === src)
      .filter((a) => status === 'all' || a.status === status)
      .filter((a) => !q || `${a.signature} ${a.src_ip} ${a.dest_ip} ${a.device} ${a.mac} ${a.interface}`.toLowerCase().includes(q.toLowerCase()))
      .sort((a, b) => (a.ts < b.ts ? 1 : -1))
  }, [data, sev, src, status, q])
  if (error && !data) return <ErrorState error={error} retry={reload} />
  if (!data) return <Loading rows={6} />
  const counts = { high: data.filter((a) => a.severity === 'high').length, medium: data.filter((a) => a.severity === 'medium').length, low: data.filter((a) => sevRank(a.severity) <= 1).length }
  return (
    <>
      <PageHeader title="Alerts" sub={`${data.length} alerts · ${counts.high} high · ${counts.medium} medium · ${counts.low} low`} info={<>Raw detections from every telemetry source, linked to the correlation detection and incident that consumed them.</>}>
        <input type="search" placeholder="search signature, host, MAC…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search alerts" />
        <select value={sev} onChange={(e) => setSev(e.target.value)} aria-label="Severity">
          <option value="all">all severities</option>
          <option value="high">high</option>
          <option value="medium">medium</option>
          <option value="low">low</option>
        </select>
        <select value={src} onChange={(e) => setSrc(e.target.value)} aria-label="Source">
          <option value="all">all sources</option>
          <option value="suricata">suricata</option>
          <option value="zeek">zeek</option>
          <option value="radius">radius</option>
          <option value="syslog">syslog</option>
        </select>
        <select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status">
          <option value="all">all statuses</option>
          {['contained', 'resolved', 'review', 'monitor', 'closed', 'informational'].map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </PageHeader>
      <Panel title={`${rows.length} of ${data.length} alerts`} sub="open a row for the correlation detection and the raw record" bodyClass="none">
        <div className="scroll-page">
          <DataTable
            rows={rows}
            rowKey={(a) => a.id}
            onRowActivate={setSel}
            selectedKey={sel?.id ?? null}
            empty="No alerts match the current filters"
            label="Alerts"
            columns={[
              { key: 'time', header: 'time', render: (a) => <Ts ts={a.ts} /> },
              { key: 'sev', header: 'severity', render: (a) => <SeverityChip value={a.severity} /> },
              { key: 'sig', header: 'signature', wrap: true, render: (a) => a.signature },
              { key: 'src', header: 'source', render: (a) => <Chip kind="source">{a.source}</Chip> },
              { key: 'from', header: 'src', className: 'mono', priority: 2, render: (a) => (a.src_ip ? `${a.src_ip}${a.src_port ? ':' + a.src_port : ''}` : a.mac ?? '—') },
              { key: 'to', header: 'dst', className: 'mono', priority: 2, render: (a) => (a.dest_ip ? `${a.dest_ip}${a.dest_port ? ':' + a.dest_port : ''}` : '—') },
              {
                key: 'dev',
                header: 'device / port',
                priority: 2,
                render: (a) => (
                  <>
                    {a.device ? <Link to={`/devices/${a.device}`} onClick={(e) => e.stopPropagation()}>{a.device}</Link> : <span className="dim">unknown</span>}
                    {a.interface && <span className="mono dim"> · {a.interface}</span>}
                  </>
                ),
              },
              { key: 'status', header: 'status', render: (a) => <StatusChip value={a.status} /> },
              { key: 'inc', header: 'incident', priority: 3, render: (a) => (a.incident_id ? <Link className="id" to={`/incidents/${a.incident_id}`} onClick={(e) => e.stopPropagation()}>{a.incident_id}</Link> : <span className="faint">—</span>) },
            ]}
          />
        </div>
      </Panel>
      {sel && <AlertDrawer alert={sel} onClose={() => setSel(null)} />}
    </>
  )
}

function AlertDrawer({ alert, onClose }: { alert: Alert; onClose: () => void }) {
  const { data, error } = useApi(() => endpoints.alert(alert.id), [alert.id])
  const det = data?.detection
  const raw = data?.alert.raw
  return (
    <Drawer
      title={
        <>
          <SeverityChip value={alert.severity} /> <span className="mono">{alert.id}</span>
        </>
      }
      onClose={onClose}
    >
      <div className="strong">{alert.signature}</div>
      <KV
        rows={[
          kv('time', <Ts ts={alert.ts} date />),
          kv('source', <Chip kind="source">{alert.source}</Chip>),
          kv('category', alert.category),
          kv('source address', <span className="mono">{alert.src_ip ?? alert.mac ?? '—'}</span>),
          kv('destination', <span className="mono">{alert.dest_ip ? `${alert.dest_ip}:${alert.dest_port ?? ''}` : '—'}</span>),
          kv('device', alert.device ? <Link to={`/devices/${alert.device}`}>{alert.device}</Link> : 'unknown'),
          kv('interface', <span className="mono">{alert.interface ?? '—'}</span>),
          kv('status', <StatusChip value={alert.status} />),
          kv('incident', alert.incident_id ? <Link className="id" to={`/incidents/${alert.incident_id}`}>{alert.incident_id}</Link> : '—'),
        ]}
      />
      {error && <div className="error">Could not load the detection: {error}</div>}
      {!data && !error && <Loading rows={3} />}
      {det && (
        <>
          <Section title="Correlation detection" right={<span className="mono dim small">{det.rule}</span>}>
            <span />
          </Section>
          <Confidence value={det.confidence} base={det.base_confidence} />
          <FeatureList features={det.features} />
          <div className="dim small row">
            disposition <StatusChip value={det.disposition ?? 'monitor'} /> · {det.event_refs.length} contributing events
          </div>
        </>
      )}
      {raw && (
        <>
          <Section title="Raw record">
            <span />
          </Section>
          <Terminal text={JSON.stringify(raw, null, 2)} maxHeight={480} />
        </>
      )}
    </Drawer>
  )
}

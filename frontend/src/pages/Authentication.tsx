import { endpoints } from '../lib/api'
import { useApi } from '../lib/hooks'
import { ErrorState, Loading, Panel, Ts } from '../components/ui'
import { PageHeader } from '../components/layout'
import { Metric, MetricBand, Ratio } from '../components/metric'
import { Chip } from '../components/status'
import { DataTable } from '../components/table'
import { AuthBars, HBars, Legend } from '../charts'
import { pct } from '../lib/format'

export function Authentication() {
  const { data, error, reload } = useApi(endpoints.auth)
  if (error && !data) return <ErrorState error={error} retry={reload} />
  if (!data) return <Loading rows={5} />
  const t = data.totals
  return (
    <>
      <PageHeader title="Authentication" sub="802.1X / MAB results from FreeRADIUS (SRV-RADIUS01) for SW01" info={<>Corporate endpoints use EAP-TLS or PEAP; unknown endpoints fail MAB and fall back to the guest VLAN only on conference drops. All events are on the dataset day.</>} />
      <MetricBand>
        <Metric label="Success rate" value={pct(t.success_rate)} tone="good" hint={<Ratio num={`${t.accepts} accepts`} den={`${t.accepts + t.rejects} decisions`} />} />
        <Metric label="Access-Accept" value={t.accepts} />
        <Metric label="Access-Reject" value={t.rejects} tone={t.rejects ? 'warn' : undefined} />
        <Metric label="Guest VLAN fallbacks" value={t.guest} hint="no supplicant response" />
        <Metric label="Events" value={t.events} hint="dataset day" />
      </MetricBand>
      <div className="grid grid-main-rail">
        <div className="stack">
          <Panel title="Results per hour" right={<Legend items={[['Access-Accept', 'c2'], ['Guest VLAN', 'c1'], ['Access-Reject', 'c3']]} />}>
            <AuthBars data={data.series} />
          </Panel>
          <Panel title="Recent authentication records" bodyClass="none">
            <div className="scroll-480">
              <DataTable
                compact
                rows={data.recent}
                rowKey={(e) => e.event_id}
                columns={[
                  { key: 'time', header: 'time', render: (e) => <Ts ts={e.timestamp} /> },
                  { key: 'result', header: 'result', render: (e) => <Chip kind={e.result === 'Access-Accept' ? 'ok' : e.result === 'Access-Reject' ? 'danger' : 'info'}>{e.result}</Chip> },
                  { key: 'id', header: 'identity', className: 'mono', render: (e) => e.identity },
                  { key: 'method', header: 'method', priority: 3, render: (e) => e.method },
                  { key: 'cs', header: 'calling station', className: 'mono', priority: 2, render: (e) => e.calling_station_id },
                  { key: 'port', header: 'port', className: 'mono', render: (e) => e.nas_port_id.replace('GigabitEthernet', 'Gi') },
                  { key: 'vlan', header: 'vlan', className: 'mono', priority: 3, render: (e) => <>{e.assigned_vlan ?? '—'}{e.vlan_source === 'guest-vlan' && <span className="dim"> guest</span>}</> },
                  { key: 'reason', header: 'reason', wrap: true, priority: 2, render: (e) => <span className="dim">{e.reason ?? '—'}</span> },
                ]}
              />
            </div>
          </Panel>
        </div>
        <div className="stack">
          <Panel title="Methods">
            <HBars data={data.methods.map((m) => ({ name: m.method, count: m.count }))} labelWidth={110} />
          </Panel>
          <Panel title="VLAN assignments" sub="successful sessions">
            <HBars data={data.vlans.map((v) => ({ name: `VLAN ${v.vlan}`, count: v.count }))} tone="c5" labelWidth={110} />
          </Panel>
          <Panel title="Most rejected identities">
            <HBars data={data.top_rejected.map((u) => ({ name: u.username, count: u.count }))} tone="c3" labelWidth={130} />
          </Panel>
        </div>
      </div>
    </>
  )
}

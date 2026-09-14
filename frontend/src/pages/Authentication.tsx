import { endpoints } from '../lib/api'
import { useApi } from '../lib/hooks'
import { Card, Chip, Kpi, Loading, Ts } from '../components/ui'
import { AuthBars, HBars, Legend } from '../charts'
import { pct } from '../lib/format'

export function Authentication() {
  const { data, error } = useApi(endpoints.auth)
  if (!data) return <Loading error={error} />
  const t = data.totals
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Authentication</h1>
          <p>802.1X / MAB results from FreeRADIUS (SRV-RADIUS01) for SW01. Corporate endpoints use EAP-TLS or PEAP; unknown endpoints fail MAB and fall back to the guest VLAN only on conference drops.</p>
        </div>
      </div>
      <div className="grid kpis">
        <Kpi label="Success rate" value={pct(t.success_rate)} tone="good" hint="accepts / (accepts + rejects)" />
        <Kpi label="Access-Accept" value={t.accepts} />
        <Kpi label="Access-Reject" value={t.rejects} tone={t.rejects ? 'warn' : undefined} />
        <Kpi label="Guest VLAN fallbacks" value={t.guest} hint="no supplicant response" />
        <Kpi label="Events" value={t.events} hint="dataset day" />
      </div>
      <div className="grid main-side">
        <Card title="Results per hour" right={<Legend items={[['Access-Accept', '#2f9e4f'], ['Guest VLAN', '#3987e5'], ['Access-Reject', '#e05a5a']]} />}>
          <AuthBars data={data.series} />
        </Card>
        <Card title="Methods">
          <HBars data={data.methods.map((m) => ({ name: m.method, count: m.count }))} />
        </Card>
      </div>
      <div className="grid main-side">
        <Card title="Recent authentication records" bodyClass="tight">
          <div className="table-wrap" style={{ maxHeight: 480 }}>
            <table className="data">
              <thead><tr><th>time</th><th>result</th><th>identity</th><th>method</th><th>calling station</th><th>port</th><th>vlan</th><th>reason</th></tr></thead>
              <tbody>
                {data.recent.map((e) => (
                  <tr key={e.event_id}>
                    <td><Ts ts={e.timestamp} /></td>
                    <td><Chip kind={e.result === 'Access-Accept' ? 'ok' : e.result === 'Access-Reject' ? 'high' : 'low'}>{e.result}</Chip></td>
                    <td className="mono">{e.identity}</td>
                    <td>{e.method}</td>
                    <td className="mono">{e.calling_station_id}</td>
                    <td className="mono">{e.nas_port_id.replace('GigabitEthernet', 'Gi')}</td>
                    <td className="mono">{e.assigned_vlan ?? '—'}{e.vlan_source === 'guest-vlan' && <span className="dim"> guest</span>}</td>
                    <td className="wrap dim" style={{ minWidth: 220 }}>{e.reason ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
        <div className="stack">
          <Card title="VLAN assignments" sub="successful sessions">
            <HBars data={data.vlans.map((v) => ({ name: `VLAN ${v.vlan}`, count: v.count }))} color="#31a0b0" />
          </Card>
          <Card title="Most rejected identities">
            <HBars data={data.top_rejected.map((u) => ({ name: u.username, count: u.count }))} color="#e05a5a" />
          </Card>
        </div>
      </div>
    </>
  )
}

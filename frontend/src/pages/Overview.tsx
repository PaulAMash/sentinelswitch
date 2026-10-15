import { useState } from 'react'
import { Link } from 'react-router-dom'
import { endpoints } from '../lib/api'
import { useApi } from '../lib/hooks'
import { Card, Chip, Kpi, Loading, Sev, Ts } from '../components/ui'
import { AlertTimeline, HBars, Legend, TrafficArea } from '../charts'
import { fmtNum, fmtSeconds, pct, vlanName } from '../lib/format'
import { Icon } from '../components/Icons'

export function Overview() {
  const { data, error, reload } = useApi(endpoints.overview)
  const [busy, setBusy] = useState(false)
  const [metric, setMetric] = useState<'bytes' | 'connections'>('bytes')
  if (!data) return <Loading error={error} />
  const k = data.kpis
  const stage = data.demo.stage
  const run = async () => {
    setBusy(true)
    try {
      await endpoints.demoRun()
      reload()
    } finally {
      setBusy(false)
    }
  }
  const reset = async () => {
    setBusy(true)
    try {
      await endpoints.demoReset()
      reload()
    } finally {
      setBusy(false)
    }
  }
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Security overview</h1>
          <p>
            Access-layer posture for {data.dataset.day}. Every number on this page is derived from the seeded synthetic dataset and the live state of the SW01 digital twin.
          </p>
        </div>
        <div className="toolbar">
          {stage === 'baseline' ? (
            <button className="btn primary" onClick={run} disabled={busy}>
              <Icon.play /> Replay flagship incident
            </button>
          ) : (
            <button className="btn" onClick={reset} disabled={busy}>
              <Icon.reset /> Reset to baseline
            </button>
          )}
        </div>
      </div>

      <div className="grid kpis nine">
        <Kpi label="Devices online" value={k.devices_online} unit={`/ ${k.devices_total}`} hint="MAC-table presence" />
        <Kpi label="Security alerts" value={k.alerts} hint="Suricata · Zeek · AAA · syslog" />
        <Kpi label="High severity" value={k.high_alerts} tone={k.high_alerts ? 'danger' : undefined} hint={`${k.incidents} incidents · ${k.open_incidents} open`} />
        <Kpi label="Quarantined hosts" value={k.quarantined_hosts} tone={k.quarantined_hosts ? 'danger' : 'good'} hint="VLAN 50 or administrative hold" />
        <Kpi label="802.1X success" value={pct(k.auth_success_rate)} tone="good" hint={`${k.auth_accepts} accepts · ${k.auth_rejects} rejects`} />
        <Kpi label="Traffic observed" value={k.traffic_human} hint={`${fmtNum(k.connections)} connections on SPAN`} />
        <Kpi label="Active VLANs" value={k.active_vlans} hint={k.active_vlan_ids.join(', ')} />
        <Kpi label="Mean time to detect" value={fmtSeconds(k.mttd)} tone="accent" hint={`${k.validation_total ?? "—"} validation scenarios`} />
        <Kpi label="Mean time to contain" value={fmtSeconds(k.mttc)} tone="accent" hint="detection → verified" />
      </div>

      <div className="grid main-side">
        <Card title="Security alert timeline" sub="alerts per hour by severity" right={<Legend items={[['high', '#e05a5a'], ['medium', '#c99420'], ['low / info', '#3987e5']]} />}>
          <AlertTimeline data={data.alert_timeline} />
        </Card>
        <Card title="Alerts by category" sub="all sources">
          <HBars data={data.alerts_by_category.map((c) => ({ name: c.category, count: c.count }))} />
        </Card>
      </div>

      <div className="grid main-side">
        <Card
          title="Network activity"
          sub="SPAN feed, 15-minute buckets"
          right={
            <div className="seg">
              <button className={metric === 'bytes' ? 'active' : ''} onClick={() => setMetric('bytes')}>bytes</button>
              <button className={metric === 'connections' ? 'active' : ''} onClick={() => setMetric('connections')}>connections</button>
            </div>
          }
        >
          <TrafficArea data={data.traffic} metric={metric} />
        </Card>
        <Card title="Devices by VLAN" sub="inventory + quarantine">
          <HBars data={data.devices_by_vlan.map((v) => ({ name: vlanName(v.vlan), count: v.devices }))} color="#31a0b0" />
        </Card>
      </div>

      <div className="grid three">
        <Card title="Recent alerts" right={<Link to="/alerts">all alerts</Link>} bodyClass="tight">
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr><th>time</th><th>sev</th><th>signature</th><th>source</th></tr>
              </thead>
              <tbody>
                {data.recent_alerts.map((a) => (
                  <tr key={a.id}>
                    <td><Ts ts={a.ts} /></td>
                    <td><Sev s={a.severity} /></td>
                    <td className="wrap" style={{ minWidth: 180 }}>{a.signature}</td>
                    <td className="mono">{a.src_ip ?? a.mac ?? a.interface ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
        <Card title="Recent authentication" right={<Link to="/authentication">details</Link>} bodyClass="tight">
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr><th>time</th><th>result</th><th>identity</th><th>port</th></tr>
              </thead>
              <tbody>
                {data.recent_auth.map((e) => (
                  <tr key={e.event_id}>
                    <td><Ts ts={e.timestamp} /></td>
                    <td><Chip kind={e.result === 'Access-Accept' ? 'ok' : e.result === 'Access-Reject' ? 'high' : 'low'}>{e.result}</Chip></td>
                    <td className="mono">{e.username}</td>
                    <td className="mono">{e.nas_port_id.replace('GigabitEthernet', 'Gi')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
        <Card title="Containment activity" right={<Link to="/incidents">incidents</Link>} bodyClass="tight">
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr><th>time</th><th>port</th><th>action</th><th>status</th></tr>
              </thead>
              <tbody>
                {data.containment_activity.map((a) => (
                  <tr key={a.workflow_id}>
                    <td><Ts ts={a.applied_at ?? a.requested_at} /></td>
                    <td className="mono">
                      <Link to={`/incidents/${a.incident_id}`}>{a.interface}</Link>
                    </td>
                    <td>{a.action === 'quarantine_vlan' ? `VLAN ${a.from_vlan} → ${a.to_vlan}` : 'shutdown'}</td>
                    <td><Chip kind={a.status} /></td>
                  </tr>
                ))}
                {data.containment_activity.length === 0 && (
                  <tr><td colSpan={4} className="dim">No containment actions yet</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      </div>
    </>
  )
}

import { useMemo, useState } from 'react'
import { kv } from '../lib/kv'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { endpoints, type Device } from '../lib/api'
import { useApi } from '../lib/hooks'
import { Card, Chip, Drawer, KV, Loading, Sev, Ts } from '../components/ui'
import { fmtTime, title, vlanName } from '../lib/format'

export function Devices() {
  const { data, error } = useApi(endpoints.devices)
  const { hostname } = useParams()
  const nav = useNavigate()
  const [vlan, setVlan] = useState('all')
  const [q, setQ] = useState('')
  const rows = useMemo(() => {
    if (!data) return []
    return data.devices
      .filter((d) => vlan === 'all' || String(d.current_vlan) === vlan)
      .filter((d) => !q || `${d.hostname} ${d.ip} ${d.mac} ${d.user} ${d.role} ${d.interface}`.toLowerCase().includes(q.toLowerCase()))
      .sort((a, b) => (a.vlan - b.vlan) || a.interface.localeCompare(b.interface, undefined, { numeric: true }))
  }, [data, vlan, q])
  if (!data) return <Loading error={error} />
  const online = data.devices.filter((d) => d.online).length
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Devices</h1>
          <p>Asset inventory joined with the live MAC address table, DHCP snooping bindings and 802.1X session state of the twin.</p>
        </div>
        <div className="toolbar">
          <span className="chip ok">{online} online</span>
          <span className="chip neutral">{data.devices.length} inventoried</span>
          <span className="chip medium">{data.unknown.length} unknown seen today</span>
        </div>
      </div>
      <Card
        bodyClass="tight"
        title="Inventory"
        right={
          <div className="toolbar">
            <input type="search" placeholder="search…" value={q} onChange={(e) => setQ(e.target.value)} />
            <select value={vlan} onChange={(e) => setVlan(e.target.value)}>
              <option value="all">all VLANs</option>
              {[10, 20, 30, 40, 50, 99].map((v) => (
                <option key={v} value={String(v)}>{vlanName(v)}</option>
              ))}
            </select>
          </div>
        }
      >
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr><th>hostname</th><th>role</th><th>ip</th><th>mac</th><th>vlan</th><th>port</th><th>user</th><th>auth</th><th>criticality</th><th>state</th></tr>
            </thead>
            <tbody>
              {rows.map((d) => (
                <tr key={d.hostname} className={`clickable ${hostname === d.hostname ? 'selected' : ''}`} onClick={() => nav(`/devices/${d.hostname}`)}>
                  <td className="strong">{d.hostname}</td>
                  <td>{d.role}</td>
                  <td className="mono">{d.ip ?? '—'}</td>
                  <td className="mono">{d.mac}</td>
                  <td className="mono">{d.quarantined ? <span className="chip quarantined">50 QUARANTINE</span> : vlanName(d.current_vlan)}</td>
                  <td className="mono">{d.interface}{d.via_trunk && <span className="dim"> (trunk)</span>}</td>
                  <td>{d.user ?? <span className="faint">—</span>}</td>
                  <td>{d.auth}</td>
                  <td><Chip kind={d.criticality === 'critical' ? 'high' : d.criticality === 'high' ? 'medium' : 'neutral'}>{d.criticality}</Chip></td>
                  <td>{d.online ? <Chip kind="ok">online</Chip> : <Chip kind="neutral">offline</Chip>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      <Card bodyClass="tight" title="Unregistered devices observed today" sub="not in inventory; each became a detection">
        <div className="table-wrap">
          <table className="data">
            <thead><tr><th>label</th><th>mac</th><th>oui vendor</th><th>port</th><th>window</th><th>description</th></tr></thead>
            <tbody>
              {data.unknown.map((u) => (
                <tr key={u.mac}>
                  <td className="strong">{u.label}</td>
                  <td className="mono">{u.mac}</td>
                  <td>{u.vendor}</td>
                  <td className="mono">{u.interface}</td>
                  <td className="mono">{fmtTime(u.schedule[0], { ms: false })} – {fmtTime(u.schedule[1], { ms: false })}</td>
                  <td className="wrap">{u.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      {hostname && <DeviceDrawer hostname={hostname} onClose={() => nav('/devices')} />}
    </>
  )
}

function DeviceDrawer({ hostname, onClose }: { hostname: string; onClose: () => void }) {
  const { data, error } = useApi(() => endpoints.device(hostname), [hostname])
  if (!data) return <Drawer title={hostname} onClose={onClose}><Loading error={error} /></Drawer>
  const d: Device = data.device
  const i = data.interface
  return (
    <Drawer title={<span>{d.hostname} <Chip kind={d.online ? 'ok' : 'neutral'}>{d.online ? 'online' : 'offline'}</Chip></span>} onClose={onClose}>
      <KV rows={[
        kv('role', `${title(d.role)} · ${d.vendor}`),
        kv('os', d.os),
        kv('ip', d.ip ?? '—'),
        kv('mac', d.mac),
        kv('user', data.user ? `${data.user.display_name} (${data.user.username}, ${data.user.department})` : '—'),
        kv('switch port', `SW01 ${d.interface}`),
        kv('vlan', d.quarantined ? <span className="chip quarantined">quarantined · VLAN 50 (was {d.vlan})</span> : vlanName(d.current_vlan)),
        kv('criticality', d.criticality),
        kv('802.1X', i?.auth_state ? `${i.auth_state} (${i.auth_method ?? '—'})` : d.auth),
        kv('schedule', d.schedule ? `${fmtTime(d.schedule[0], { ms: false })} – ${fmtTime(d.schedule[1], { ms: false })}` : 'always attached'),
        kv('tags', d.tags.length ? d.tags.join(', ') : '—'),
        kv('notes', d.notes ?? '—')]} />
      {i && (
        <Card title={`Interface ${i.name}`} sub={i.description}>
          <KV rows={[kv('status', `${i.oper_status} / admin ${i.admin_status}`), kv('access vlan', String(i.access_vlan)), kv('port security', String((i.settings.port_security as { maximum?: number } | undefined)?.maximum ?? '—') + ' max, ' + String((i.settings.port_security as { violation?: string } | undefined)?.violation ?? '—')), kv('last change', <Ts ts={i.last_change} date />)]} />
        </Card>
      )}
      {data.incidents.length > 0 && (
        <Card title="Incidents">
          {data.incidents.map((x) => (
            <div key={x.id} className="row" style={{ marginBottom: 6 }}>
              <Link to={`/incidents/${x.id}`} className="mono">{x.id}</Link> <Sev s={x.severity} /> <Chip kind={x.status} /> <span className="dim">{x.rule_name}</span>
            </div>
          ))}
        </Card>
      )}
      <Card title={`Alerts (${data.alerts.length})`} bodyClass="tight">
        <div className="table-wrap" style={{ maxHeight: 260 }}>
          <table className="data">
            <thead><tr><th>time</th><th>sev</th><th>signature</th></tr></thead>
            <tbody>
              {data.alerts.slice(0, 20).map((a) => (
                <tr key={a.id}><td><Ts ts={a.ts} /></td><td><Sev s={a.severity} /></td><td className="wrap">{a.signature}</td></tr>
              ))}
              {data.alerts.length === 0 && <tr><td colSpan={3} className="dim">No alerts for this device</td></tr>}
            </tbody>
          </table>
        </div>
      </Card>
      <Card title={`Authentication (${data.auth.length})`} bodyClass="tight">
        <div className="table-wrap" style={{ maxHeight: 220 }}>
          <table className="data">
            <thead><tr><th>time</th><th>result</th><th>method</th><th>port</th></tr></thead>
            <tbody>
              {data.auth.slice(0, 12).map((e) => (
                <tr key={e.event_id}><td><Ts ts={e.timestamp} /></td><td><Chip kind={e.result === 'Access-Accept' ? 'ok' : e.result === 'Access-Reject' ? 'high' : 'low'}>{e.result}</Chip></td><td>{e.method}</td><td className="mono">{e.nas_port_id.replace('GigabitEthernet', 'Gi')}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </Drawer>
  )
}

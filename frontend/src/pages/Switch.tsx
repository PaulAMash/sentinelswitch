import { useEffect, useState } from 'react'
import { kv } from '../lib/kv'
import { Link } from 'react-router-dom'
import { endpoints } from '../lib/api'
import { useApi } from '../lib/hooks'
import { Card, Chip, KV, Loading, Term, Ts } from '../components/ui'
import { PortLegend, SwitchPanel } from '../components/SwitchPanel'
import { vlanName } from '../lib/format'

export function SwitchPage() {
  const { data, error } = useApi(endpoints.switch)
  const [sel, setSel] = useState<string | null>('Gi1/0/23')
  const [cmd, setCmd] = useState('show interfaces Gi1/0/23 switchport')
  const [out, setOut] = useState<string | null>(null)
  useEffect(() => {
    endpoints.show('show interfaces Gi1/0/23 switchport').then(setOut).catch(() => setOut(null))
  }, [])
  const { data: iface } = useApi(() => (sel ? endpoints.iface(sel) : Promise.resolve(null)), [sel])
  if (!data) return <Loading error={error} />
  const run = async (c: string) => {
    setCmd(c)
    setOut(await endpoints.show(c))
  }
  const s = data.summary
  return (
    <>
      <div className="page-head">
        <div>
          <h1>{data.hostname} · {data.model}</h1>
          <p>Digital twin of the access switch: IOS {data.ios_version}, uptime {data.uptime}, management {data.management_ip}. Click a port for its state, intent and IOS output.</p>
        </div>
        <div className="toolbar">
          <span className="chip ok">{s.connected} connected</span>
          <span className="chip low">{s.trunk} trunks</span>
          <span className="chip neutral">{s.notconnect} notconnect · {s.disabled} shutdown</span>
          {s.quarantined > 0 && <span className="chip quarantined">{s.quarantined} quarantined</span>}
        </div>
      </div>
      <Card title="Front panel" sub="48 × 10/100/1000 PoE+ · 2 × SFP+" right={<PortLegend />}>
        <SwitchPanel ports={data.interfaces} selected={sel} onSelect={setSel} />
      </Card>
      <div className="grid main-side">
        <Card
          title="IOS command console"
          sub="read-only show commands against the twin"
          right={
            <div className="toolbar">
              <select value={cmd} onChange={(e) => run(e.target.value)}>
                {[...data.commands, 'show interfaces Gi1/0/23 switchport', 'show running-config interface Gi1/0/23', 'show mac address-table interface Gi1/0/23', 'show port-security interface Gi1/0/23', 'show authentication sessions interface Gi1/0/23'].map((c) => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
              <button className="btn primary sm" onClick={() => run(cmd)}>run</button>
            </div>
          }
        >
          <Term text={out ?? `${data.hostname}#\n(select a command and press run)`} hl={['Access Mode VLAN', 'QUARANTINE']} />
        </Card>
        <Card title={sel ? `Interface ${sel}` : 'Select a port'} sub={iface?.interface.description}>
          {iface ? (
            <div className="stack">
              <div className="row">
                <Chip kind={iface.interface.state} />
                {iface.interface.protected && <Chip kind="low">protected</Chip>}
                {iface.interface.quarantined && <Chip kind="neutral">workflow {iface.interface.quarantine_workflow}</Chip>}
                {iface.interface.hold && <Chip kind="held">administrative hold</Chip>}
              </div>
              <KV rows={[
                kv('mode', iface.interface.mode),
                kv('access vlan', iface.interface.mode === 'access' ? vlanName(iface.interface.access_vlan) : `trunk: ${iface.interface.allowed_vlans.join(',')}`),
                kv('operational vlan', iface.interface.mode === 'access' ? vlanName(iface.interface.oper_vlan) : '—'),
                kv('status', `${iface.interface.oper_status} / admin ${iface.interface.admin_status}`),
                kv('original vlan', iface.interface.original_vlan ? vlanName(iface.interface.original_vlan) : '—'),
                kv('device', iface.device ? <Link to={`/devices/${iface.device}`}>{iface.device}</Link> : '—'),
                kv('802.1X', iface.interface.auth_state ?? '—'),
                kv('class / profile', `${String(iface.intent.class)} · ${String(iface.intent.profile)}`),
                kv('MACs learned', iface.macs.length ? (iface.macs as { mac: string; vlan: number }[]).map((m) => `${m.mac} (vlan ${m.vlan})`).join(', ') : 'none'),
                kv('bindings', iface.bindings.length ? (iface.bindings as { ip: string; binding_type: string }[]).map((b) => `${b.ip} (${b.binding_type})`).join(', ') : 'none'),
                kv('last change', <Ts ts={iface.interface.last_change} date />),
                kv('workflow', iface.interface.quarantine_workflow ?? '—'),
              ]} />
              <Term text={iface.show.running_config} hl={['switchport access vlan', 'shutdown']} />
            </div>
          ) : (
            <div className="empty">Click a port on the front panel</div>
          )}
        </Card>
      </div>
      <div className="grid three">
        <Card title="VLANs" bodyClass="tight">
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>id</th><th>name</th><th>subnet</th><th>controls</th></tr></thead>
              <tbody>
                {Object.values(data.vlans).map((v) => (
                  <tr key={v.id}>
                    <td className="mono">{v.id}</td>
                    <td className="strong">{v.name}</td>
                    <td className="mono">{v.subnet ?? '—'}</td>
                    <td className="small">{[data.dhcp_snooping_vlans.includes(v.id) && 'snooping', data.dai_vlans.includes(v.id) && 'DAI', data.span.source_vlans.includes(v.id) && 'SPAN'].filter(Boolean).join(' · ') || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
        <Card title="Recent configuration changes" sub="config_changes on the twin" bodyClass="tight">
          <div className="table-wrap" style={{ maxHeight: 300 }}>
            <table className="data">
              <thead><tr><th>time</th><th>actor</th><th>interface</th><th>commands</th></tr></thead>
              <tbody>
                {[...data.config_changes].reverse().map((c, i) => (
                  <tr key={i}>
                    <td><Ts ts={c.ts} /></td>
                    <td className="mono">{c.actor}</td>
                    <td className="mono">{c.interface ?? '—'}</td>
                    <td className="mono wrap" style={{ minWidth: 200 }}>{c.commands.map((x) => x.trim()).join(' / ')}</td>
                  </tr>
                ))}
                {data.config_changes.length === 0 && <tr><td colSpan={4} className="dim">No changes since the last reset</td></tr>}
              </tbody>
            </table>
          </div>
        </Card>
        <Card title="Logging buffer" sub="last 40 lines" bodyClass="tight">
          <Term text={data.log_tail.join('\n')} hl={['%SW_DAI', '%DHCP_SNOOPING', '%PORT_SECURITY', '%SPANTREE', 'sentinel']} />
        </Card>
      </div>
      <div className="grid two">
        <Card title={`MAC address table (${data.mac_table.length})`} bodyClass="tight">
          <div className="table-wrap" style={{ maxHeight: 360 }}>
            <table className="data">
              <thead><tr><th>vlan</th><th>mac</th><th>type</th><th>port</th></tr></thead>
              <tbody>
                {[...data.mac_table].sort((a, b) => a.vlan - b.vlan || a.interface.localeCompare(b.interface, undefined, { numeric: true })).map((e, i) => (
                  <tr key={i}><td className="mono">{e.vlan}</td><td className="mono">{e.mac}</td><td>{e.entry_type}</td><td className="mono">{e.interface}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
        <Card title={`DHCP snooping bindings (${data.dhcp_bindings.length})`} bodyClass="tight">
          <div className="table-wrap" style={{ maxHeight: 360 }}>
            <table className="data">
              <thead><tr><th>ip</th><th>mac</th><th>vlan</th><th>port</th><th>type</th><th>expires</th></tr></thead>
              <tbody>
                {[...data.dhcp_bindings].sort((a, b) => a.vlan - b.vlan || a.ip.localeCompare(b.ip, undefined, { numeric: true })).map((b, i) => (
                  <tr key={i}><td className="mono">{b.ip}</td><td className="mono">{b.mac}</td><td className="mono">{b.vlan}</td><td className="mono">{b.interface}</td><td>{b.binding_type}</td><td className="mono">{b.binding_type === 'static' ? 'infinite' : b.lease_expires.replace('T', ' ').slice(5, 16)}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      </div>
    </>
  )
}

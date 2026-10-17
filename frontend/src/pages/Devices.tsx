import { useMemo, useState } from 'react'
import { kv } from '../lib/kv'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { endpoints, type Device } from '../lib/api'
import { useApi } from '../lib/hooks'
import { Drawer, ErrorState, KV, Loading, Panel, Ts } from '../components/ui'
import { PageHeader, Section } from '../components/layout'
import { Chip, SeverityChip, StatusChip } from '../components/status'
import { DataTable } from '../components/table'
import { fmtTime, title, vlanName } from '../lib/format'

export function Devices() {
  const { data, error, reload } = useApi(endpoints.devices)
  const { hostname } = useParams()
  const nav = useNavigate()
  const [vlan, setVlan] = useState('all')
  const [q, setQ] = useState('')
  const rows = useMemo(() => {
    if (!data) return []
    return data.devices
      .filter((d) => vlan === 'all' || String(d.current_vlan) === vlan)
      .filter((d) => !q || `${d.hostname} ${d.ip} ${d.mac} ${d.user} ${d.role} ${d.interface}`.toLowerCase().includes(q.toLowerCase()))
      .sort((a, b) => a.vlan - b.vlan || a.interface.localeCompare(b.interface, undefined, { numeric: true }))
  }, [data, vlan, q])
  if (error && !data) return <ErrorState error={error} retry={reload} />
  if (!data) return <Loading rows={6} />
  const online = data.devices.filter((d) => d.online).length
  return (
    <>
      <PageHeader title="Assets" sub={`${online} online · ${data.devices.length} inventoried · ${data.unknown.length} unknown seen today`} info={<>Asset inventory joined with the live MAC address table, DHCP snooping bindings and 802.1X session state of the twin.</>}>
        <input type="search" placeholder="search…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search assets" />
        <select value={vlan} onChange={(e) => setVlan(e.target.value)} aria-label="VLAN">
          <option value="all">all VLANs</option>
          {[10, 20, 30, 40, 50, 99].map((v) => (
            <option key={v} value={String(v)}>
              {vlanName(v)}
            </option>
          ))}
        </select>
      </PageHeader>
      <Panel title="Inventory" sub={`${rows.length} shown`} bodyClass="none">
        <DataTable
          rows={rows}
          rowKey={(d) => d.hostname}
          onRowActivate={(d) => nav(`/devices/${d.hostname}`)}
          selectedKey={hostname ?? null}
          label="Inventory"
          columns={[
            { key: 'host', header: 'hostname', className: 'strong', render: (d) => d.hostname },
            { key: 'role', header: 'role', priority: 3, render: (d) => d.role },
            { key: 'ip', header: 'ip', className: 'mono', render: (d) => d.ip ?? '—' },
            { key: 'mac', header: 'mac', className: 'mono', priority: 2, render: (d) => d.mac },
            { key: 'vlan', header: 'vlan', className: 'mono', render: (d) => (d.quarantined ? <StatusChip value="quarantined" /> : vlanName(d.current_vlan)) },
            { key: 'port', header: 'port', className: 'mono', render: (d) => <>{d.interface}{d.via_trunk && <span className="dim"> (trunk)</span>}</> },
            { key: 'user', header: 'user', priority: 2, render: (d) => d.user ?? <span className="faint">—</span> },
            { key: 'auth', header: 'auth', priority: 3, render: (d) => d.auth },
            { key: 'crit', header: 'criticality', priority: 3, render: (d) => <Chip kind={d.criticality === 'critical' ? 'danger' : d.criticality === 'high' ? 'warn' : 'neutral'}>{d.criticality}</Chip> },
            { key: 'state', header: 'state', render: (d) => <StatusChip value={d.online ? 'online' : 'offline'} /> },
          ]}
        />
      </Panel>
      <Panel title="Unregistered devices observed today" sub="not in inventory; each became a detection" bodyClass="none">
        <DataTable
          compact
          rows={data.unknown}
          rowKey={(u) => u.mac}
          columns={[
            { key: 'label', header: 'label', className: 'strong', render: (u) => u.label },
            { key: 'mac', header: 'mac', className: 'mono', render: (u) => u.mac },
            { key: 'vendor', header: 'oui vendor', priority: 3, render: (u) => u.vendor },
            { key: 'port', header: 'port', className: 'mono', render: (u) => u.interface },
            { key: 'win', header: 'window', className: 'mono', priority: 2, render: (u) => `${fmtTime(u.schedule[0], { ms: false })} – ${fmtTime(u.schedule[1], { ms: false })}` },
            { key: 'desc', header: 'description', wrap: true, priority: 2, render: (u) => u.description },
          ]}
        />
      </Panel>
      {hostname && <DeviceDrawer hostname={hostname} onClose={() => nav('/devices')} />}
    </>
  )
}

function DeviceDrawer({ hostname, onClose }: { hostname: string; onClose: () => void }) {
  const { data, error } = useApi(() => endpoints.device(hostname), [hostname])
  if (!data)
    return (
      <Drawer title={hostname} onClose={onClose}>
        <Loading error={error} />
      </Drawer>
    )
  const d: Device = data.device
  const i = data.interface
  return (
    <Drawer
      title={
        <>
          {d.hostname} <StatusChip value={d.online ? 'online' : 'offline'} /> {d.quarantined && <StatusChip value="quarantined" />}
        </>
      }
      onClose={onClose}
    >
      <KV
        rows={[
          kv('role', `${title(d.role)} · ${d.vendor}`),
          kv('os', d.os),
          kv('ip', <span className="mono">{d.ip ?? '—'}</span>),
          kv('mac', <span className="mono">{d.mac}</span>),
          kv('user', data.user ? `${data.user.display_name} (${data.user.username}, ${data.user.department})` : '—'),
          kv('switch port', <span className="mono">SW01 {d.interface}</span>),
          kv('vlan', d.quarantined ? `quarantined · ${vlanName(50)} (was ${vlanName(d.vlan)})` : vlanName(d.current_vlan)),
          kv('criticality', d.criticality),
          kv('802.1X', i?.auth_state ? `${i.auth_state} (${i.auth_method ?? '—'})` : d.auth),
          kv('schedule', d.schedule ? `${fmtTime(d.schedule[0], { ms: false })} – ${fmtTime(d.schedule[1], { ms: false })}` : 'always attached'),
          kv('tags', d.tags.length ? d.tags.join(', ') : '—'),
          kv('notes', d.notes ?? '—'),
        ]}
      />
      {i && (
        <>
          <Section title={`Interface ${i.name}`} right={<span className="dim small">{i.description}</span>}>
            <span />
          </Section>
          <div className="trace vertical" role="list" aria-label="Port to VLAN">
            <div className={`trace-node ${i.oper_status === 'up' ? 'confirmed' : 'none'}`} role="listitem">
              <span className="k">interface</span>
              <span className="v">{i.name}</span>
              <span className="s">
                {i.oper_status} / admin {i.admin_status}
              </span>
            </div>
            <div className="trace-arrow" aria-hidden="true" />
            <div className={`trace-node ${i.quarantined ? 'to' : 'from'}`} role="listitem">
              <span className="k">vlan</span>
              <span className="v">{vlanName(i.oper_vlan ?? i.access_vlan)}</span>
              <span className="s">{i.quarantined ? `quarantined · was ${vlanName(i.original_vlan)}` : i.port_class}</span>
            </div>
          </div>
          <KV rows={[kv('port security', String((i.settings.port_security as { maximum?: number } | undefined)?.maximum ?? '—') + ' max, ' + String((i.settings.port_security as { violation?: string } | undefined)?.violation ?? '—')), kv('last change', <Ts ts={i.last_change} date />)]} />
        </>
      )}
      {data.incidents.length > 0 && (
        <>
          <Section title="Incidents" count={data.incidents.length}>
            <span />
          </Section>
          <div className="stack tight">
            {data.incidents.map((x) => (
              <div key={x.id} className="row">
                <Link to={`/incidents/${x.id}`} className="id">
                  {x.id}
                </Link>{' '}
                <SeverityChip value={x.severity} /> <StatusChip value={x.status} /> <span className="dim">{x.rule_name}</span>
              </div>
            ))}
          </div>
        </>
      )}
      <Section title="Alerts" count={data.alerts.length}>
        <span />
      </Section>
      <DataTable
        compact
        rows={data.alerts.slice(0, 20)}
        rowKey={(a) => a.id}
        empty="No alerts for this device"
        columns={[
          { key: 'time', header: 'time', render: (a) => <Ts ts={a.ts} /> },
          { key: 'sev', header: 'sev', render: (a) => <SeverityChip value={a.severity} /> },
          { key: 'sig', header: 'signature', wrap: true, render: (a) => a.signature },
        ]}
      />
      <Section title="Authentication" count={data.auth.length}>
        <span />
      </Section>
      <DataTable
        compact
        rows={data.auth.slice(0, 12)}
        rowKey={(e) => e.event_id}
        empty="No authentication records"
        columns={[
          { key: 'time', header: 'time', render: (e) => <Ts ts={e.timestamp} /> },
          { key: 'result', header: 'result', render: (e) => <Chip kind={e.result === 'Access-Accept' ? 'ok' : e.result === 'Access-Reject' ? 'danger' : 'info'}>{e.result}</Chip> },
          { key: 'method', header: 'method', render: (e) => e.method },
          { key: 'port', header: 'port', className: 'mono', render: (e) => e.nas_port_id.replace('GigabitEthernet', 'Gi') },
        ]}
      />
    </Drawer>
  )
}

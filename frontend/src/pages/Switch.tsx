import { useEffect, useState } from 'react'
import { kv } from '../lib/kv'
import { Link, useSearchParams } from 'react-router-dom'
import { endpoints } from '../lib/api'
import { useApi } from '../lib/hooks'
import { ErrorState, KV, Loading, Panel, Ts } from '../components/ui'
import { PageHeader } from '../components/layout'
import { Chip, StatusChip } from '../components/status'
import { DataTable, Cell2 } from '../components/table'
import { Console, Terminal } from '../components/terminal'
import { PortLegend, SwitchPanel } from '../components/SwitchPanel'
import { vlanName } from '../lib/format'

const INITIAL_CMD = 'show interfaces Gi1/0/23 switchport'

export function SwitchPage() {
  const { data, error, reload } = useApi(endpoints.switch)
  const [params] = useSearchParams()
  const [sel, setSel] = useState<string | null>(params.get('port') ?? 'Gi1/0/23')
  const [initial, setInitial] = useState<{ cmd: string; out: string } | null | undefined>(undefined)
  useEffect(() => {
    endpoints
      .show(INITIAL_CMD)
      .then((out) => setInitial({ cmd: INITIAL_CMD, out }))
      .catch(() => setInitial(null))
  }, [])
  const { data: iface, error: ifaceError } = useApi(() => (sel ? endpoints.iface(sel) : Promise.resolve(null)), [sel])
  if (error && !data) return <ErrorState error={error} retry={reload} />
  if (!data) return <Loading rows={5} />
  const s = data.summary
  // completion list: the server's known commands plus per-interface templates for the selected port
  const commands = sel ? [...data.commands, `show interfaces ${sel} switchport`, `show interfaces ${sel} status`, `show running-config interface ${sel}`, `show mac address-table interface ${sel}`, `show port-security interface ${sel}`, `show authentication sessions interface ${sel}`] : data.commands
  return (
    <>
      <PageHeader
        title={`${data.hostname} · ${data.model}`}
        sub={`IOS ${data.ios_version} · uptime ${data.uptime} · management ${data.management_ip}`}
        info={<>Digital twin of the access switch. Select a port on the front panel (click, or Tab and arrow keys) for its state, intent and IOS output. The console sends the typed string unchanged to the twin; only <code>show</code> commands are accepted, enforced by the API.</>}
      >
        <Chip kind="accent">{s.connected} connected</Chip>
        <Chip kind="info">{s.trunk} trunks</Chip>
        <Chip kind="neutral">
          {s.notconnect} notconnect · {s.disabled} shutdown
        </Chip>
        {s.quarantined > 0 && <Chip kind="quarantined">{s.quarantined} quarantined</Chip>}
      </PageHeader>

      <div className="switch-hero">
        <SwitchPanel ports={data.interfaces} selected={sel} onSelect={setSel} hostname={data.hostname} model={data.model} highlight={sel} />
        <PortLegend />
      </div>

      <div className="switch-grid">
        <Panel title="IOS console" sub="read-only show commands against the twin" bodyClass="none">
          {initial === undefined ? <Loading rows={3} /> : <Console hostname={data.hostname} commands={Array.from(new Set(commands))} run={endpoints.show} initial={initial} hl={['Access Mode VLAN', 'QUARANTINE']} />}
        </Panel>
        <Panel title={sel ? `Interface ${sel}` : 'Select a port'} sub={iface?.interface.description} className="rail">
          {!sel ? (
            <div className="empty">Select a port on the front panel</div>
          ) : ifaceError ? (
            <ErrorState error={ifaceError} />
          ) : !iface ? (
            <Loading rows={4} />
          ) : (
            <div className="stack">
              <div className="row">
                <StatusChip value={iface.interface.state} />
                {iface.interface.protected && <Chip kind="protected">protected</Chip>}
                {iface.interface.quarantined && <Chip kind="neutral">workflow {iface.interface.quarantine_workflow}</Chip>}
                {iface.interface.hold && <Chip kind="held">administrative hold</Chip>}
              </div>
              <KV
                rows={[
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
                ]}
              />
              <div className="eyebrow">show running-config interface {sel}</div>
              <Terminal text={iface.show.running_config} hl={['switchport access vlan', 'shutdown']} />
            </div>
          )}
        </Panel>
      </div>

      <div className="vz-grid c12">
        <Panel title="VLANs" bodyClass="none">
          <DataTable
            compact
            rows={Object.values(data.vlans)}
            rowKey={(v) => String(v.id)}
            columns={[
              { key: 'id', header: 'id', className: 'mono', render: (v) => v.id },
              { key: 'name', header: 'name · subnet', render: (v) => <Cell2 primary={<span className="strong">{v.name}</span>} secondary={<span className="mono">{v.subnet ?? '—'}</span>} /> },
              { key: 'ctl', header: 'controls', render: (v) => <span className="small">{[data.dhcp_snooping_vlans.includes(v.id) && 'snooping', data.dai_vlans.includes(v.id) && 'DAI', data.span.source_vlans.includes(v.id) && 'SPAN'].filter(Boolean).join(' · ') || '—'}</span> },
            ]}
          />
        </Panel>
        <Panel title="Recent configuration changes" sub="config_changes on the twin" bodyClass="none">
          <DataTable
            cards="narrow"
            compact
            rows={[...data.config_changes].reverse()}
            rowKey={(c, i) => `${c.ts}-${i}`}
            empty="No changes since the last reset"
            columns={[
              { key: 'ts', header: 'time', render: (c) => <Ts ts={c.ts} /> },
              { key: 'actor', header: 'actor', className: 'mono', render: (c) => c.actor },
              { key: 'if', header: 'interface', className: 'mono', render: (c) => c.interface ?? '—' },
              { key: 'cmds', header: 'commands', wrap: true, className: 'mono small', render: (c) => c.commands.map((x) => x.trim()).join(' / ') },
            ]}
          />
        </Panel>
      </div>
      <Panel title="Logging buffer" sub="last 40 lines" bodyClass="none">
          <Terminal text={data.log_tail.join('\n')} hl={['%SW_DAI', '%DHCP_SNOOPING', '%PORT_SECURITY', '%SPANTREE', 'sentinel']} maxHeight={320} />
      </Panel>

      <div className="grid grid-2">
        <Panel title="MAC address table" sub={`${data.mac_table.length} entries`} bodyClass="none">
          <div className="scroll-360">
            <DataTable
              cards="narrow"
              compact
              rows={[...data.mac_table].sort((a, b) => a.vlan - b.vlan || a.interface.localeCompare(b.interface, undefined, { numeric: true }))}
              rowKey={(e, i) => `${e.mac}-${i}`}
              columns={[
                { key: 'vlan', header: 'vlan', className: 'mono', render: (e) => e.vlan },
                { key: 'mac', header: 'mac', className: 'mono', render: (e) => e.mac },
                { key: 'type', header: 'type', render: (e) => e.entry_type },
                { key: 'port', header: 'port', className: 'mono', render: (e) => e.interface },
              ]}
            />
          </div>
        </Panel>
        <Panel title="DHCP snooping bindings" sub={`${data.dhcp_bindings.length} bindings`} bodyClass="none">
          <div className="scroll-360">
            <DataTable
              cards="narrow"
              compact
              rows={[...data.dhcp_bindings].sort((a, b) => a.vlan - b.vlan || a.ip.localeCompare(b.ip, undefined, { numeric: true }))}
              rowKey={(b, i) => `${b.ip}-${i}`}
              columns={[
                { key: 'ip', header: 'ip', className: 'mono', render: (b) => b.ip },
                { key: 'mac', header: 'mac', className: 'mono', render: (b) => b.mac },
                { key: 'vlan', header: 'vlan', className: 'mono', render: (b) => b.vlan },
                { key: 'port', header: 'port', className: 'mono', render: (b) => b.interface },
                { key: 'type', header: 'type', hideBelow: 500, render: (b) => b.binding_type },
                { key: 'exp', header: 'expires', className: 'mono', hideBelow: 600, render: (b) => (b.binding_type === 'static' ? 'infinite' : b.lease_expires.replace('T', ' ').slice(5, 16)) },
              ]}
            />
          </div>
        </Panel>
      </div>
    </>
  )
}

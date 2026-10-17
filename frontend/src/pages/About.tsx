import { endpoints } from '../lib/api'
import { kv } from '../lib/kv'
import { useApi } from '../lib/hooks'
import { ErrorState, KV, Loading, Panel } from '../components/ui'
import { PageHeader } from '../components/layout'
import { Chip } from '../components/status'
import { DataTable } from '../components/table'

export function About() {
  const { data, error, reload } = useApi(endpoints.about)
  if (error && !data) return <ErrorState error={error} retry={reload} />
  if (!data) return <Loading rows={4} />
  const layers = ['access', 'telemetry', 'detection', 'response', 'platform']
  const components = layers.flatMap((l) => data.components.filter((c) => c.layer === l))
  return (
    <>
      <PageHeader title="Architecture" sub={`${data.name} — ${data.tagline}`} info={<>A reproducible network-defense digital twin: deterministic synthetic telemetry drives a real detection, attribution and containment pipeline against a simulated Catalyst 2960-X access layer.</>} />
      <Panel title="System architecture" sub="diagrams/svg/architecture.svg">
        <div className="diagram">
          <img src="/diagrams/architecture.svg" alt="SentinelSwitch architecture" />
        </div>
      </Panel>
      <div className="grid grid-2">
        <Panel title="Components and trust boundaries" bodyClass="none">
          <DataTable
            compact
            rows={components}
            rowKey={(c) => c.name}
            columns={[
              { key: 'layer', header: 'layer', render: (c) => <Chip kind="neutral">{c.layer}</Chip> },
              { key: 'name', header: 'component', className: 'strong', render: (c) => c.name },
              { key: 'role', header: 'role', wrap: true, render: (c) => c.role },
            ]}
          />
        </Panel>
        <div className="stack">
          <Panel title="Modelled environment" bodyClass="flush">
            <KV
              rows={[
                kv('organization', `${data.organization.name} (${data.organization.domain})`),
                kv('switch', `${String(data.switch.hostname)} · ${String(data.switch.model)} · IOS ${String(data.switch.ios_version)}`),
                kv('security stack', 'SEC-TP01 — Lenovo ThinkPad, Debian 12: Zeek + Suricata on the SPAN NIC, FreeRADIUS on SRV-RADIUS01, SentinelSwitch controller'),
                kv('telemetry', 'SPAN (VLANs 20/30/40) → Zeek + Suricata; syslog + RADIUS to the collector on VLAN 99'),
                kv('stack', data.stack.join(' · ')),
              ]}
            />
          </Panel>
          <Panel title="VLAN plan" bodyClass="none">
            <DataTable
              compact
              rows={data.vlans.filter((v) => v.id !== 999)}
              rowKey={(v) => String(v.id)}
              columns={[
                { key: 'id', header: 'vlan', className: 'mono', render: (v) => v.id },
                { key: 'name', header: 'name', className: 'strong', render: (v) => v.name },
                { key: 'subnet', header: 'subnet', className: 'mono', render: (v) => v.subnet ?? '—' },
                { key: 'purpose', header: 'purpose', wrap: true, render: (v) => v.purpose },
              ]}
            />
          </Panel>
          <div className="notice">All identities, addresses and events in this application are synthetic. The telemetry is generated deterministically by the simulator from the canonical fixtures; no production or physical network was involved.</div>
        </div>
      </div>
      {data.diagrams.length > 1 && (
        <div className="grid grid-2">
          {data.diagrams
            .filter((d) => d !== 'architecture.svg' && !d.includes('portrait'))
            .map((d) => (
              <Panel key={d} title={d.replace('.svg', '').replace(/-/g, ' ')} sub={`diagrams/svg/${d}`}>
                <div className="diagram">
                  <img src={`/diagrams/${d}`} alt={d} />
                </div>
              </Panel>
            ))}
        </div>
      )}
    </>
  )
}

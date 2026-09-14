import { endpoints } from '../lib/api'
import { kv } from '../lib/kv'
import { useApi } from '../lib/hooks'
import { Card, Chip, KV, Loading } from '../components/ui'

export function About() {
  const { data, error } = useApi(endpoints.about)
  if (!data) return <Loading error={error} />
  const layers = ['access', 'telemetry', 'detection', 'response', 'platform']
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Architecture</h1>
          <p>{data.name} — {data.tagline}. A reproducible network-defense digital twin: deterministic synthetic telemetry drives a real detection, attribution and containment pipeline against a simulated Catalyst 2960-X access layer.</p>
        </div>
      </div>
      <Card title="System architecture" sub="diagrams/svg/architecture.svg">
        <div style={{ background: '#0b0f14', borderRadius: 6, padding: 8, border: '1px solid var(--border)' }}>
          <img src="/diagrams/architecture.svg" alt="SentinelSwitch architecture" style={{ width: '100%', display: 'block' }} />
        </div>
      </Card>
      <div className="grid two">
        <Card title="Components and trust boundaries" bodyClass="tight">
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>layer</th><th>component</th><th>role</th></tr></thead>
              <tbody>
                {layers.flatMap((l) => data.components.filter((c) => c.layer === l).map((c) => (
                  <tr key={c.name}><td><Chip kind="neutral">{l}</Chip></td><td className="strong">{c.name}</td><td className="wrap">{c.role}</td></tr>
                )))}
              </tbody>
            </table>
          </div>
        </Card>
        <div className="stack">
          <Card title="Modelled environment">
            <KV rows={[
              kv('organization', `${data.organization.name} (${data.organization.domain})`),
              kv('switch', `${String(data.switch.hostname)} · ${String(data.switch.model)} · IOS ${String(data.switch.ios_version)}`),
              kv('security stack', 'SEC-TP01 — Lenovo ThinkPad, Debian 12: Zeek + Suricata on the SPAN NIC, FreeRADIUS on SRV-RADIUS01, SentinelSwitch controller'),
              kv('telemetry', 'SPAN (VLANs 20/30/40) → Zeek + Suricata; syslog + RADIUS to the collector on VLAN 99'),
              kv('stack', data.stack.join(' · '))]} />
          </Card>
          <Card title="VLAN plan" bodyClass="tight">
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>vlan</th><th>name</th><th>subnet</th><th>purpose</th></tr></thead>
                <tbody>
                  {data.vlans.filter((v) => v.id !== 999).map((v) => (
                    <tr key={v.id}><td className="mono">{v.id}</td><td className="strong">{v.name}</td><td className="mono">{v.subnet}</td><td className="wrap">{v.purpose}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
          <div className="notice">
            All identities, addresses and events in this application are synthetic. The telemetry is generated deterministically by the simulator from the canonical fixtures; no production or physical network was involved.
          </div>
        </div>
      </div>
      {data.diagrams.length > 1 && (
        <div className="grid two">
          {data.diagrams.filter((d) => d !== 'architecture.svg' && !d.includes('portrait')).map((d) => (
            <Card key={d} title={d.replace('.svg', '').replace(/-/g, ' ')} sub={`diagrams/svg/${d}`}>
              <div style={{ background: '#0b0f14', borderRadius: 6, padding: 8, border: '1px solid var(--border)' }}>
                <img src={`/diagrams/${d}`} alt={d} style={{ width: '100%', display: 'block' }} />
              </div>
            </Card>
          ))}
        </div>
      )}
    </>
  )
}

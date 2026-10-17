/**
 * Fixed-size branded cards rendered from live application state. `scripts/screenshots.py` opens
 * /media/<slug> in headless Chromium at 1080×1350 (portrait carousel) or 1600×800 (landscape hero).
 */
import { useEffect, useState } from 'react'
import { kv } from '../lib/kv'
import { useParams } from 'react-router-dom'
import { endpoints, type IncidentDetail, type Overview, type SwitchState, type Validation } from '../lib/api'
import { Wordmark } from '../components/Logo'
import { KV, Panel } from '../components/ui'
import { Metric } from '../components/metric'
import { Chip, SeverityChip } from '../components/status'
import { Chain, Steps } from '../components/Chain'
import { chainFromAttribution } from '../lib/chain'
import { Timeline } from '../components/Timeline'
import { Confidence, Features } from '../components/Features'
import { SwitchPanel } from '../components/SwitchPanel'
import { AlertTimeline, Legend } from '../charts'
import { fmtSeconds, pct, vlanName } from '../lib/format'
import '../styles/media.css'

const FLAGSHIP = 'INC-2026-0042'

interface Bundle {
  overview: Overview
  incident: IncidentDetail | null
  validation: Validation
  sw: SwitchState
  show: Record<string, string>
}

function useBundle() {
  const [b, setB] = useState<Bundle | null>(null)
  const [err, setErr] = useState<string | null>(null)
  useEffect(() => {
    let cancelled = false
    const load = async (attempt: number): Promise<void> => {
      try {
        const overview = await endpoints.overview()
        const validation = await endpoints.validation()
        const sw = await endpoints.switch()
        let incident: IncidentDetail | null = null
        try {
          incident = await endpoints.incident(FLAGSHIP)
        } catch {
          incident = null
        }
        const cmds = ['show interfaces Gi1/0/23 switchport', 'show mac address-table interface Gi1/0/23', 'show vlan id 50', 'show interfaces Gi1/0/23 status', 'show port-security interface Gi1/0/23']
        const show: Record<string, string> = {}
        for (const c of cmds) show[c] = await endpoints.show(c)
        if (!cancelled) setB({ overview, incident, validation, sw, show })
      } catch (e) {
        if (attempt < 3) {
          await new Promise((r) => setTimeout(r, 600))
          return load(attempt + 1)
        }
        if (!cancelled) setErr((e as Error).message)
      }
    }
    load(0)
    return () => {
      cancelled = true
    }
  }, [])
  return { b, err }
}

function Frame({ step, title, sub, children, landscape = false }: { step?: string; title: string; sub?: string; children: React.ReactNode; landscape?: boolean }) {
  return (
    <div className={`media ${landscape ? 'landscape' : ''}`} id="media-root">
      <div className="m-top">
        <Wordmark size={44} />
        <div className="row">
          {step && <span className="m-step">{step}</span>}
          <span className="chip sim">Simulation · synthetic telemetry</span>
        </div>
      </div>
      <div>
        <h1>{title}</h1>
        {sub && <p className="m-sub">{sub}</p>}
      </div>
      <div className="m-body">{children}</div>
      <div className="m-foot">
        <span>
          <b>SentinelSwitch</b> · Evidence-Driven Network Security &amp; Response Lab
        </span>
        <span>Detect · Attribute · Authorize · Contain · Verify</span>
      </div>
    </div>
  )
}

export function Media() {
  const { slug = '' } = useParams()
  const { b, err } = useBundle()
  useEffect(() => {
    document.body.classList.add('media-body')
    return () => document.body.classList.remove('media-body')
  }, [])
  if (err)
    return (
      <div className="media" id="media-root" data-error={err}>
        media bundle failed: {err}
      </div>
    )
  if (!b) return <div className="media" id="media-root" data-loading="1" />
  const k = b.overview.kpis
  const inc = b.incident
  const act = inc?.actions.find((a) => a.status === 'verified' || a.status === 'restored') ?? inc?.actions[0]
  const timeline = inc?.timeline ?? []
  const det = inc?.detection
  const att = inc?.attribution

  switch (slug) {
    case '01-architecture':
      return (
        <Frame step="01 / 07" title="A digital twin of an enterprise access layer" sub="Simulated endpoints on a Cisco Catalyst 2960-X, SPAN-fed Zeek and Suricata telemetry, 802.1X via FreeRADIUS, and an autonomous detection → attribution → containment pipeline.">
          <div className="m-fill">
            <img src="/diagrams/architecture-portrait.svg" alt="architecture" />
          </div>
        </Frame>
      )
    case '02-soc-overview':
      return (
        <Frame step="02 / 07" title="One console for the whole access layer" sub={`${b.overview.dataset.day}: ${k.devices_total} inventoried devices, ${k.alerts} alerts across Suricata, Zeek, RADIUS and IOS syslog, ${k.incidents} incidents, ${k.quarantined_hosts} host quarantined.`}>
          <div className="m-cols-3">
            <Metric label="Devices online" value={k.devices_online} unit={`/ ${k.devices_total}`} />
            <Metric label="Security alerts" value={k.alerts} hint={`${k.high_alerts} high severity`} />
            <Metric label="Quarantined hosts" value={k.quarantined_hosts} tone="danger" hint="VLAN 50" />
            <Metric label="802.1X success" value={pct(k.auth_success_rate)} tone="good" />
            <Metric label="Mean time to detect" value={fmtSeconds(k.mttd)} tone="accent" />
            <Metric label="Mean time to contain" value={fmtSeconds(k.mttc)} tone="accent" />
          </div>
          <Panel title="Security alert timeline" sub="alerts per hour by severity" right={<Legend items={[['high', 'c3'], ['medium', 'c4'], ['low / info', 'c1']]} />}>
            <AlertTimeline data={b.overview.alert_timeline} height={220} />
          </Panel>
          <Panel title="Recent alerts" bodyClass="none">
            <table className="data">
              <thead>
                <tr>
                  <th>time</th>
                  <th>severity</th>
                  <th>signature</th>
                  <th>source</th>
                </tr>
              </thead>
              <tbody>
                {b.overview.recent_alerts.slice(0, 4).map((a) => (
                  <tr key={a.id}>
                    <td className="mono">{a.ts.slice(11, 23)}</td>
                    <td>
                      <SeverityChip value={a.severity} />
                    </td>
                    <td className="wrap">{a.signature.replace('SENTINELSWITCH ', '')}</td>
                    <td className="mono">{a.src_ip ?? a.mac ?? a.interface}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Panel>
        </Frame>
      )
    case '03-incident-detected':
      return (
        <Frame step="03 / 07" title="21:14 — a laptop starts sweeping the network" sub="ENG-LT-047 (10.20.0.47) probes two subnets, bursts reverse DNS, then fans out SMB/RDP connections. Suricata raises a high-confidence signature and Zeek corroborates with an address-scan notice.">
          <Panel title="Source detections" bodyClass="none">
            <table className="data">
              <thead>
                <tr>
                  <th>time (UTC)</th>
                  <th>severity</th>
                  <th>source</th>
                  <th>detection</th>
                </tr>
              </thead>
              <tbody>
                {(inc?.alerts ?? []).map((a) => (
                  <tr key={a.id}>
                    <td className="mono">{a.ts.slice(11, 23)}</td>
                    <td>
                      <SeverityChip value={a.severity} />
                    </td>
                    <td>
                      <Chip kind="source">{a.source}</Chip>
                    </td>
                    <td className="wrap">{a.signature.replace('SENTINELSWITCH ', '')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Panel>
          {det && (
            <Panel title={`Correlation rule matched: ${det.rule_name}`} sub={`scored ${det.ts.slice(11, 23)}`}>
              <div className="stack">
                <Confidence value={det.confidence} base={det.base_confidence} />
                <Features features={det.features} />
              </div>
            </Panel>
          )}
        </Frame>
      )
    case '04-correlation':
      return (
        <Frame step="04 / 07" title="From an IP address to a physical switch port" sub="Attribution walks the switch's own tables: DHCP snooping binding → MAC address table → interface → VLAN → asset inventory. Every hop is recorded with its source.">
          {att && (
            <div className="m-chain-grid">
              <Panel bodyClass="flush">
                <Chain nodes={chainFromAttribution(att, act?.to_vlan, inc?.incident.action)} vertical />
              </Panel>
              <div className="stack">
                <Panel title="Resolution steps" sub={`${det!.ts.slice(11, 23)} → ${att.completed_at?.slice(11, 23)} · ${fmtSeconds((new Date(att.completed_at!).getTime() - new Date(det!.ts).getTime()) / 1000)} after detection`}>
                  <Steps steps={att.steps} />
                </Panel>
                <div className="m-cols-2">
                  <Panel title="Endpoint">
                    <KV rows={[kv('device', att.device), kv('user', `${att.user} · ${att.department}`), kv('os', 'Ubuntu 24.04 LTS'), kv('criticality', att.criticality)]} />
                  </Panel>
                  <Panel title="Port">
                    <KV rows={[kv('switch', `${att.switch} ${att.interface}`), kv('class', att.port_class), kv('protected', att.protected ? 'yes' : 'no'), kv('confidence', `${(att.confidence * 100).toFixed(0)}% · ${att.flags.length ? att.flags.join(', ') : 'no flags'}`)]} />
                  </Panel>
                </div>
              </div>
            </div>
          )}
        </Frame>
      )
    case '05-auto-quarantine':
      return (
        <Frame step="05 / 07" title="Automated containment in 1.3 seconds" sub="Policy: confidence ≥ 0.95 and high severity on an unprotected access port → move the port to the quarantine VLAN through the switch adapter, then verify.">
          {inc && act && (
            <>
              <div className="m-cols-3">
                <Panel>
                  <div className="metric">
                    <div className="label">before · access VLAN</div>
                    <div className="big-num">
                      {inc.incident.original_vlan}
                      <small>{vlanName(inc.incident.original_vlan).split(' ')[1]}</small>
                    </div>
                  </div>
                </Panel>
                <Panel>
                  <div className="metric">
                    <div className="label">after · access VLAN</div>
                    <div className="big-num danger">
                      {act.to_vlan}
                      <small>QUARANTINE</small>
                    </div>
                  </div>
                </Panel>
                <Panel>
                  <div className="metric">
                    <div className="label">detection → verified</div>
                    <div className="big-num accent">
                      {act.verified_at && det ? fmtSeconds((new Date(act.verified_at).getTime() - new Date(det.ts).getTime()) / 1000).replace(' s', '') : '—'}
                      <small>seconds</small>
                    </div>
                  </div>
                </Panel>
              </div>
              <Panel title="SW01 front panel" sub="Gi1/0/23 highlighted">
                <SwitchPanel ports={b.sw.interfaces} selected="Gi1/0/23" hostname={b.sw.hostname} model={b.sw.model} />
              </Panel>
              <Panel title="Decision → action → verification">
                <Timeline entries={timeline} phases={['policy', 'incident', 'containment', 'verification', 'evidence']} />
              </Panel>
              <Panel title="Switch adapter transcript" sub={act.workflow_id}>
                <pre className="term">
                  {act.transcript.split('\n').map((l, i) => (
                    <span key={i} className={/^SW01/.test(l) ? 'prompt' : l.includes('switchport access vlan') ? 'hl' : undefined}>
                      {l}
                      {'\n'}
                    </span>
                  ))}
                </pre>
              </Panel>
            </>
          )}
        </Frame>
      )
    case '06-cisco-verification':
      return (
        <Frame step="06 / 07" title="Verified on the switch, not just in a database" sub="The containment controller reads the interface back after every change. Gi1/0/23 now reports access VLAN 50 and its MAC is learned in the quarantine VLAN.">
          <pre className="term m-term-fill">
            {renderTerm(b.show['show interfaces Gi1/0/23 switchport'], 12)}
            {'\n'}
            {renderTerm(b.show['show mac address-table interface Gi1/0/23'], 40)}
            {'\n'}
            {renderTerm(b.show['show vlan id 50'], 4)}
            {'\n'}
            {renderTerm(b.show['show interfaces Gi1/0/23 status'], 3)}
            {'\n'}
            {renderTerm(b.show['show port-security interface Gi1/0/23'], 13)}
          </pre>
        </Frame>
      )
    case '07-validation-results':
      return (
        <Frame step="07 / 07" title={`${b.validation.results.length} adversary scenarios, replayed end to end`} sub="Each scenario runs through the real pipeline against an isolated twin, including one withheld from automation by the critical-asset guard. Timings are measured on the simulated clock from the first anomalous event.">
          <Panel title="SentinelSwitch security validation" bodyClass="none">
            <table className="data matrix">
              <thead>
                <tr>
                  <th>scenario</th>
                  <th>detect</th>
                  <th>attribute</th>
                  <th>response</th>
                  <th>ttd</th>
                  <th>ttc</th>
                </tr>
              </thead>
              <tbody>
                {b.validation.results.map((r) => (
                  <tr key={r.scenario_id}>
                    <td className="strong">{r.name}</td>
                    <td className={`pf ${r.detect ? 'pass' : 'fail'}`}>{r.detect ? 'PASS' : 'FAIL'}</td>
                    <td className={`pf ${r.attribute ? 'pass' : 'fail'}`}>{r.attribute ? 'PASS' : 'FAIL'}</td>
                    <td className={`pf ${r.response === 'withheld' ? 'withheld' : r.contain ? 'pass' : 'fail'}`} title={r.response === 'withheld' ? 'automation correctly withheld by policy; analyst decision required' : undefined}>
                      {r.response === 'withheld' ? 'WITHHELD' : r.response === 'contained' ? 'CONTAINED' : r.contain ? 'PASS' : 'FAIL'}
                    </td>
                    <td className="mono num">{fmtSeconds(r.ttd)}</td>
                    <td className="mono num">{fmtSeconds(r.ttc)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Panel>
          <div className="m-cols-3">
            <Metric label="Mean time to detect" value={fmtSeconds(b.validation.metrics.mttd)} tone="accent" hint={`range ${fmtSeconds(b.validation.metrics.min_ttd)} – ${fmtSeconds(b.validation.metrics.max_ttd)}`} />
            <Metric label="Mean time to attribute" value={fmtSeconds(b.validation.metrics.mtta)} tone="accent" hint="detection → identity" />
            <Metric label="Mean time to contain" value={fmtSeconds(b.validation.metrics.mttc)} tone="accent" hint="detection → verified (contained scenarios)" />
          </div>
          <div className="notice">Mechanisms exercised: 802.1X/MAB, Dynamic ARP Inspection, DHCP snooping, sticky port security, BPDU Guard, SPAN-fed Suricata and Zeek, quarantine VLAN and administrative shutdown through the switch adapter.</div>
        </Frame>
      )
    case 'hero':
      return (
        <div className="media landscape hero" id="media-root">
          <div className="m-top">
            <Wordmark size={52} sub={false} />
            <span className="chip sim">Simulation · synthetic telemetry</span>
          </div>
          <div>
            <h1 className="hero-title">Evidence-Driven Network Security &amp; Response Lab</h1>
            <p className="m-sub hero-sub">A reproducible digital twin of a Cisco Catalyst 2960-X access layer: Zeek and Suricata-style telemetry, 802.1X, IP → MAC → port attribution and automated quarantine — with evidence.</p>
          </div>
          <div className="panel hero-panel">
            <SwitchPanel ports={b.sw.interfaces} selected="Gi1/0/23" hostname={b.sw.hostname} model={b.sw.model} />
          </div>
          {att ? (
            <Chain nodes={chainFromAttribution(att, act?.to_vlan, inc?.incident.action)} />
          ) : (
            <div className="m-cols-3">
              <Metric label="Mean time to detect" value={fmtSeconds(k.mttd)} tone="accent" />
              <Metric label="Mean time to attribute" value={fmtSeconds(k.mtta)} tone="accent" />
              <Metric label="Mean time to contain" value={fmtSeconds(k.mttc)} tone="accent" />
            </div>
          )}
          <div className="m-foot hero">
            <span>Python · FastAPI · SQLite · React · TypeScript · Cisco IOS · Zeek · Suricata · FreeRADIUS</span>
            <span>Detect · Attribute · Authorize · Contain · Verify</span>
          </div>
        </div>
      )
    default:
      return (
        <div className="media" id="media-root">
          unknown media slug: {slug}
        </div>
      )
  }
}

function renderTerm(text: string | undefined, maxLines: number) {
  if (!text) return ''
  const lines = text.split('\n').slice(0, maxLines)
  return lines.map((l, i) => {
    const prompt = /^SW01[#>]/.test(l)
    const hl = l.includes('Access Mode VLAN') || l.includes('QUARANTINE') || /^\s*50\s/.test(l)
    return (
      <span key={i} className={prompt ? 'prompt' : hl ? 'hl' : undefined}>
        {l}
        {'\n'}
      </span>
    )
  })
}

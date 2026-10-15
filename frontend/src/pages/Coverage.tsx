import { useState } from 'react'
import { kv } from '../lib/kv'
import { endpoints, type ValidationRow } from '../lib/api'
import { useApi } from '../lib/hooks'
import { Card, Chip, Drawer, KV, Kpi, Loading, Sev } from '../components/ui'
import { Timeline } from '../components/Timeline'
import { Features } from '../components/Features'
import { fmtSeconds } from '../lib/format'

export function Coverage() {
  const { data, error, reload } = useApi(endpoints.validation)
  const { data: rules } = useApi(endpoints.rules)
  const [sel, setSel] = useState<ValidationRow | null>(null)
  const [busy, setBusy] = useState(false)
  if (!data) return <Loading error={error} />
  const m = data.metrics
  const rerun = async () => {
    setBusy(true)
    try {
      await endpoints.runValidation()
      reload()
    } finally {
      setBusy(false)
    }
  }
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Detection coverage</h1>
          <p>{m.scenarios} adversary scenarios replayed through the full pipeline against an isolated copy of the twin. CONTAINED means automatic containment was applied and verified on the switch; WITHHELD means policy correctly kept automation away from the target and left the decision to an analyst. Timings are measured on the scenario's simulated clock, from the first anomalous event to verified containment.</p>
        </div>
        <button className="btn primary" onClick={rerun} disabled={busy}>Re-run validation</button>
      </div>
      <div className="grid kpis">
        <Kpi label="Scenarios passed" value={`${m.passed} / ${m.scenarios}`} tone={m.all_passed ? 'good' : 'danger'} hint={m.contained != null ? `${m.contained} contained · ${m.withheld} withheld by policy` : 'detect · attribute · response'} />
        <Kpi label="Mean time to detect" value={fmtSeconds(m.mttd)} tone="accent" hint={`range ${fmtSeconds(m.min_ttd)} – ${fmtSeconds(m.max_ttd)}`} />
        <Kpi label="Mean time to attribute" value={fmtSeconds(m.mtta)} tone="accent" hint="detection → identity resolved" />
        <Kpi label="Mean time to contain" value={fmtSeconds(m.mttc)} tone="accent" hint={`median ${fmtSeconds(m.median_ttc)}`} />
        <Kpi label="Mean end to end" value={fmtSeconds(m.mean_end_to_end)} hint="first event → verified" />
      </div>
      <Card title="SentinelSwitch security validation" sub="click a row for its timeline" bodyClass="tight">
        <div className="table-wrap">
          <table className="data matrix">
            <thead>
              <tr><th>scenario</th><th>class</th><th>detect</th><th>attribute</th><th>response</th><th>severity</th><th>confidence</th><th>ttd</th><th>tta</th><th>ttc</th><th>mechanism</th><th>port</th></tr>
            </thead>
            <tbody>
              {data.results.map((r) => (
                <tr key={r.scenario_id} className="clickable" onClick={() => setSel(r)}>
                  <td className="strong">{r.name}</td>
                  <td className="dim">{r.class.replace('_', ' ')}</td>
                  <td className={`pf ${r.detect ? 'pass' : 'fail'}`}>{r.detect ? 'PASS' : 'FAIL'}</td>
                  <td className={`pf ${r.attribute ? 'pass' : 'fail'}`}>{r.attribute ? 'PASS' : 'FAIL'}</td>
                  <td className={`pf ${r.contain ? 'pass' : 'fail'}`} title={r.response === 'withheld' ? 'automation correctly withheld by policy; analyst decision required' : undefined}>{r.response === 'withheld' ? 'WITHHELD' : r.response === 'contained' ? 'CONTAINED' : r.contain ? 'PASS' : 'FAIL'}</td>
                  <td>{r.severity && <Sev s={r.severity} />}</td>
                  <td className="mono">{r.confidence?.toFixed(2)}</td>
                  <td className="mono num">{fmtSeconds(r.ttd)}</td>
                  <td className="mono num">{fmtSeconds(r.tta)}</td>
                  <td className="mono num">{fmtSeconds(r.ttc)}</td>
                  <td className="wrap small" style={{ minWidth: 220 }}>{r.mechanism}</td>
                  <td className="mono">{r.interface}{r.to_vlan ? ` · ${r.from_vlan}→${r.to_vlan}` : ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      <div className="grid two">
        <Card title="Correlation rules" sub="detections/correlation/*.yaml" bodyClass="tight">
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>rule</th><th>class</th><th>actor</th><th>window</th><th>base</th><th>features</th><th>mitre</th></tr></thead>
              <tbody>
                {(rules?.correlation ?? []).map((r) => (
                  <tr key={r.id}>
                    <td><div className="strong">{r.name}</div><div className="mono dim small">{r.id}</div></td>
                    <td className="dim">{r.class}</td>
                    <td className="mono">{r.actor_key}</td>
                    <td className="mono">{r.aggregate_window}s</td>
                    <td className="mono">{r.base_confidence.toFixed(2)}</td>
                    <td className="mono">{r.features.length}</td>
                    <td className="mono small">{r.mitre.join(' ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
        <Card title="Suricata local rules" sub="detections/suricata/local.rules" bodyClass="tight">
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>sid</th><th>message</th><th>class</th><th>severity</th></tr></thead>
              <tbody>
                {(rules?.suricata ?? []).map((r) => (
                  <tr key={r.sid}>
                    <td className="mono">{r.sid}</td>
                    <td className="wrap" style={{ minWidth: 260 }}>{r.msg.replace('SENTINELSWITCH ', '')}</td>
                    <td className="dim">{r.class}</td>
                    <td><Sev s={r.severity} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      </div>
      {sel && (
        <Drawer title={<span>{sel.name} <Chip kind={sel.passed ? 'pass' : 'fail'}>{sel.passed ? 'PASS' : 'FAIL'}</Chip></span>} onClose={() => setSel(null)}>
          <KV rows={[
            kv('rule', sel.rule),
            kv('expected', `${String(sel.expected.disposition)} · ${String(sel.expected.action)}`),
            kv('result', `${sel.severity} · ${sel.confidence?.toFixed(2)} · ${sel.action}`),
            kv('chain', sel.chain.join(' → ')),
            kv('flags', sel.attribution_flags.length ? sel.attribution_flags.join(', ') : 'none'),
            kv('first event', sel.t0?.slice(11, 23)),
            kv('detection', sel.detection_ts?.slice(11, 23)),
            kv('verified', sel.verified_ts?.slice(11, 23)),
            kv('ttd / tta / ttc', `${fmtSeconds(sel.ttd)} / ${fmtSeconds(sel.tta)} / ${fmtSeconds(sel.ttc)}`)]} />
          <Card title="Evidence features"><Features features={sel.features} /></Card>
          <Card title="Timeline"><Timeline entries={sel.timeline} compact /></Card>
        </Drawer>
      )}
    </>
  )
}

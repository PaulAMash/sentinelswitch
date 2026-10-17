import { useState } from 'react'
import { kv } from '../lib/kv'
import { endpoints, type ValidationRow } from '../lib/api'
import { useApi } from '../lib/hooks'
import { Drawer, ErrorState, KV, Loading, Panel } from '../components/ui'
import { PageHeader, Section } from '../components/layout'
import { Metric, MetricBand, Ratio } from '../components/metric'
import { Chip, SeverityChip } from '../components/status'
import { DataTable, Cell2 } from '../components/table'
import { useToast } from '../components/toast'
import { Timeline } from '../components/Timeline'
import { Features } from '../components/Features'
import { fmtSeconds } from '../lib/format'
import { Icon } from '../components/Icons'

/** Validation response column: CONTAINED, WITHHELD (policy) and FAIL are distinct outcomes; withheld is never a containment. */
function ResponseCell({ r }: { r: ValidationRow }) {
  if (r.response === 'withheld') return <Chip kind="withheld" className="caps mono" title="automation correctly withheld by policy; analyst decision required">WITHHELD</Chip>
  if (r.response === 'contained' || (r.response === undefined && r.contain)) return <Chip kind="ok" className="caps mono">CONTAINED</Chip>
  return <Chip kind="danger" className="caps mono">FAIL</Chip>
}
function PF({ ok }: { ok: boolean }) {
  return <Chip kind={ok ? 'ok' : 'danger'} className="caps mono">{ok ? 'PASS' : 'FAIL'}</Chip>
}

export function Coverage() {
  const { data, error, reload } = useApi(endpoints.validation)
  const { data: rules } = useApi(endpoints.rules)
  const toast = useToast()
  const [sel, setSel] = useState<ValidationRow | null>(null)
  const [busy, setBusy] = useState(false)
  const [runError, setRunError] = useState<string | null>(null)
  if (error && !data) return <ErrorState error={error} retry={reload} />
  if (!data) return <Loading rows={5} />
  const m = data.metrics
  const rerun = async () => {
    setBusy(true)
    setRunError(null)
    try {
      const r = await endpoints.runValidation()
      toast.push({ title: 'Validation re-run', detail: `${r.metrics.passed} / ${r.metrics.scenarios} scenarios passed`, tone: r.metrics.all_passed ? 'ok' : 'warn' })
      reload()
    } catch (e) {
      setRunError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <>
      <PageHeader
        title="Detection coverage"
        sub={`${m.scenarios} adversary scenarios replayed through the full pipeline against an isolated copy of the twin`}
        info={<>CONTAINED means automatic containment was applied and verified on the switch; WITHHELD means policy correctly kept automation away from the target and left the decision to an analyst. Timings are measured on the scenario's simulated clock, from the first anomalous event to verified containment.</>}
      >
        <button className="btn primary" type="button" onClick={rerun} disabled={busy}>
          <Icon.play /> {busy ? 'Running…' : 'Re-run validation'}
        </button>
      </PageHeader>
      {runError && <div className="error">Validation run failed: {runError}</div>}
      <MetricBand>
        <Metric label="Scenarios passed" value={<Ratio num={m.passed} den={m.scenarios} />} tone={m.all_passed ? 'good' : 'danger'} hint={m.contained != null ? `${m.contained} contained · ${m.withheld} withheld by policy` : 'detect · attribute · response'} />
        <Metric label="Mean time to detect" value={fmtSeconds(m.mttd)} tone="accent" hint={`range ${fmtSeconds(m.min_ttd)} – ${fmtSeconds(m.max_ttd)} · simulated clock`} />
        <Metric label="Mean time to attribute" value={fmtSeconds(m.mtta)} tone="accent" hint="detection → identity resolved" />
        <Metric label="Mean time to contain" value={fmtSeconds(m.mttc)} tone="accent" hint={`median ${fmtSeconds(m.median_ttc)}`} />
        <Metric label="Mean end to end" value={fmtSeconds(m.mean_end_to_end)} hint="first event → verified" />
      </MetricBand>
      <Panel title="Security validation" sub="open a row for its timeline" bodyClass="none">
        <DataTable
          rows={data.results}
          rowKey={(r) => r.scenario_id}
          onRowActivate={setSel}
          selectedKey={sel?.scenario_id ?? null}
          label="Validation results"
          columns={[
            { key: 'name', header: 'scenario', render: (r) => <Cell2 primary={<span className="strong">{r.name}</span>} secondary={r.class.replace('_', ' ')} /> },
            { key: 'detect', header: 'detect', render: (r) => <PF ok={r.detect} /> },
            { key: 'attr', header: 'attribute', render: (r) => <PF ok={r.attribute} /> },
            { key: 'resp', header: 'response', render: (r) => <ResponseCell r={r} /> },
            { key: 'sev', header: 'severity', priority: 2, render: (r) => (r.severity ? <SeverityChip value={r.severity} /> : <span className="faint">—</span>) },
            { key: 'conf', header: 'confidence', className: 'mono', priority: 3, render: (r) => r.confidence?.toFixed(2) ?? '—' },
            { key: 'ttd', header: 'ttd', align: 'right', className: 'mono', priority: 2, render: (r) => fmtSeconds(r.ttd) },
            { key: 'tta', header: 'tta', align: 'right', className: 'mono', priority: 3, render: (r) => fmtSeconds(r.tta) },
            { key: 'ttc', header: 'ttc', align: 'right', className: 'mono', priority: 2, render: (r) => fmtSeconds(r.ttc) },
            { key: 'mech', header: 'mechanism', wrap: true, priority: 2, render: (r) => <span className="small">{r.mechanism ?? '—'}</span> },
            { key: 'port', header: 'port', className: 'mono', priority: 3, render: (r) => `${r.interface ?? '—'}${r.to_vlan ? ` · ${r.from_vlan}→${r.to_vlan}` : ''}` },
          ]}
        />
      </Panel>
      <div className="grid grid-2">
        <Panel title="Correlation rules" sub="detections/correlation/*.yaml" bodyClass="none">
          <DataTable
            compact
            rows={rules?.correlation ?? null}
            loading={!rules}
            rowKey={(r) => r.id}
            columns={[
              { key: 'rule', header: 'rule', render: (r) => <Cell2 primary={<span className="strong">{r.name}</span>} secondary={<span className="mono">{r.id}</span>} /> },
              { key: 'class', header: 'class', priority: 3, render: (r) => <span className="dim">{r.class}</span> },
              { key: 'actor', header: 'actor', className: 'mono', priority: 2, render: (r) => r.actor_key },
              { key: 'win', header: 'window', className: 'mono', render: (r) => `${r.aggregate_window}s` },
              { key: 'base', header: 'base', className: 'mono', render: (r) => r.base_confidence.toFixed(2) },
              { key: 'feat', header: 'features', className: 'mono', align: 'right', priority: 3, render: (r) => r.features.length },
              { key: 'mitre', header: 'mitre', className: 'mono small', priority: 2, render: (r) => r.mitre.join(' ') },
            ]}
          />
        </Panel>
        <Panel title="Suricata local rules" sub="detections/suricata/local.rules" bodyClass="none">
          <DataTable
            compact
            rows={rules?.suricata ?? null}
            loading={!rules}
            rowKey={(r) => String(r.sid)}
            columns={[
              { key: 'sid', header: 'sid', className: 'mono', render: (r) => r.sid },
              { key: 'msg', header: 'message', wrap: true, render: (r) => r.msg.replace('SENTINELSWITCH ', '') },
              { key: 'class', header: 'class', priority: 2, render: (r) => <span className="dim">{r.class}</span> },
              { key: 'sev', header: 'severity', render: (r) => <SeverityChip value={r.severity} /> },
            ]}
          />
        </Panel>
      </div>
      {sel && (
        <Drawer
          title={
            <>
              {sel.name} <PF ok={sel.passed} /> <ResponseCell r={sel} />
            </>
          }
          onClose={() => setSel(null)}
        >
          <KV
            rows={[
              kv('rule', <span className="mono">{sel.rule}</span>),
              kv('expected', `${String(sel.expected.disposition)} · ${String(sel.expected.action)}`),
              kv('result', `${sel.severity} · ${sel.confidence?.toFixed(2)} · ${sel.action}`),
              kv('chain', sel.chain.join(' → ')),
              kv('flags', sel.attribution_flags.length ? sel.attribution_flags.join(', ') : 'none'),
              kv('first event', sel.t0?.slice(11, 23)),
              kv('detection', sel.detection_ts?.slice(11, 23)),
              kv('verified', sel.verified_ts?.slice(11, 23)),
              kv('ttd / tta / ttc', `${fmtSeconds(sel.ttd)} / ${fmtSeconds(sel.tta)} / ${fmtSeconds(sel.ttc)}`),
            ]}
          />
          <Section title="Evidence features">
            <span />
          </Section>
          <Features features={sel.features} />
          <Section title="Timeline">
            <span />
          </Section>
          <Timeline entries={sel.timeline} compact />
        </Drawer>
      )}
    </>
  )
}

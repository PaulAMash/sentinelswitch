import { useState } from 'react'
import { Link } from 'react-router-dom'
import { endpoints, type ContainmentAction } from '../lib/api'
import { useApi } from '../lib/hooks'
import { Loading, Panel, Segmented, Ts, ErrorState } from '../components/ui'
import { PageHeader } from '../components/layout'
import { Metric, MetricBand, Ratio, StatusBar } from '../components/metric'
import { AssessChip, Chip, ResponseChip, SeverityChip, responseStateOf } from '../components/status'
import { DataTable } from '../components/table'
import { ConfirmDialog } from '../components/dialog'
import { useToast } from '../components/toast'
import { AlertTimeline, HBars, Legend, TrafficArea } from '../charts'
import { fmtNum, fmtSeconds, fmtTime, pct, vlanName } from '../lib/format'
import { Icon } from '../components/Icons'

const TELEMETRY_CONTROL = 'CTL-TELEMETRY-FRESH'

export function Overview() {
  const { data, error, reload } = useApi(endpoints.overview)
  const { data: posture } = useApi(endpoints.posture)
  const { data: reviews } = useApi(endpoints.reviews)
  const { data: telemetry } = useApi(() => endpoints.assessments(`?control_id=${TELEMETRY_CONTROL}`))
  const { data: incidents } = useApi(endpoints.incidents)
  const toast = useToast()
  const [metric, setMetric] = useState<'bytes' | 'connections'>('bytes')
  const [dialog, setDialog] = useState<'replay' | 'reset' | null>(null)
  const [busy, setBusy] = useState(false)
  const [dlgError, setDlgError] = useState<string | null>(null)
  if (error && !data) return <ErrorState error={error} retry={reload} />
  if (!data) return <Loading rows={6} />
  const k = data.kpis
  const stage = data.demo.stage
  const awaiting = reviews ? reviews.filter((r) => r.status === 'review').length : null
  const unverified = posture ? posture.totals.unknown + posture.totals.stale : null
  const confirm = async () => {
    setBusy(true)
    setDlgError(null)
    try {
      if (dialog === 'replay') {
        const r = await endpoints.demoRun()
        toast.push({ title: `Replayed ${r.incident.id}`, detail: `status ${r.incident.status}`, tone: 'ok' })
      } else {
        await endpoints.demoReset()
        toast.push({ title: 'Reset to baseline', detail: 'dataset re-seeded; incident and findings history discarded', tone: 'warn' })
      }
      setDialog(null)
      reload()
    } catch (e) {
      setDlgError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }
  const byIncident = new Map((incidents ?? []).map((i) => [i.id, i]))
  const nonPass = posture ? posture.by_control.filter((c) => c.status !== 'PASS' && c.status !== 'NOT_ASSESSED').slice(0, 3) : []
  const telemetryRun = telemetry?.[0]
  return (
    <>
      <PageHeader
        title="Overview"
        sub={`Access-layer status for dataset day ${data.dataset.day}`}
        info={
          <>
            Every number on this page is derived from the seeded synthetic dataset and the live state of the SW01 digital twin. Timestamps are on the simulated switch clock (UTC). The attention strip reads the manual review queue, the twin's quarantined ports, open findings and unverified (UNKNOWN or STALE) assessments; nothing here is recomputed client-side.
          </>
        }
      >
        {stage === 'baseline' || stage === 'unseeded' ? (
          <button className="btn consequential" type="button" onClick={() => setDialog('replay')} disabled={busy}>
            <Icon.play /> Replay flagship incident
          </button>
        ) : (
          <button className="btn destructive" type="button" onClick={() => setDialog('reset')} disabled={busy}>
            <Icon.reset /> Reset to baseline
          </button>
        )}
      </PageHeader>

      {/* 1 · attention strip */}
      <div className="attention" aria-label="Needs attention">
        <Link to="/incidents">
          <span className={`n ${awaiting ? 'on warn' : ''}`}>{awaiting ?? '…'}</span>
          <span className="what">
            <b>{awaiting === 1 ? 'detection awaiting authorization' : 'detections awaiting authorization'}</b>
            <span>manual review queue</span>
          </span>
          <Icon.chevron />
        </Link>
        <Link to="/incidents">
          <span className={`n ${k.quarantined_hosts ? 'on danger' : ''}`}>{k.quarantined_hosts}</span>
          <span className="what">
            <b>{k.quarantined_hosts === 1 ? 'host contained' : 'hosts contained'}</b>
            <span>{k.open_incidents} open {k.open_incidents === 1 ? 'incident' : 'incidents'} · VLAN 50 or administrative hold</span>
          </span>
          <Icon.chevron />
        </Link>
        <Link to="/findings">
          <span className={`n ${posture?.findings.open ? 'on warn' : ''}`}>{posture ? posture.findings.open : '…'}</span>
          <span className="what">
            <b>open findings</b>
            <span>{posture ? `${posture.findings.by_severity.high} high · ${posture.findings.by_severity.medium} medium · ${posture.findings.by_severity.low} low` : 'loading posture'}</span>
          </span>
          <Icon.chevron />
        </Link>
        <Link to="/posture">
          <span className={`n ${unverified ? 'on warn' : ''}`}>{unverified ?? '…'}</span>
          <span className="what">
            <b>unverified assessments</b>
            <span>{posture ? `${posture.totals.unknown} unknown · ${posture.totals.stale} stale` : 'loading posture'}</span>
          </span>
          <Icon.chevron />
        </Link>
      </div>

      {/* 2 · activity stream + response rail */}
      <div className="ov-grid">
        <div className="ov-stream">
          <Panel title="Security activity" sub="alerts per hour by severity" right={<Legend items={[['high', 'c3'], ['medium', 'c4'], ['low / info', 'c1']]} />}>
            <AlertTimeline data={data.alert_timeline} />
          </Panel>
          <Panel title="Recent alerts" right={<Link to="/alerts">all alerts</Link>} bodyClass="none">
            <DataTable
              compact
              rows={data.recent_alerts}
              rowKey={(a) => a.id}
              columns={[
                { key: 'time', header: 'time', render: (a) => <Ts ts={a.ts} /> },
                { key: 'sev', header: 'severity', render: (a) => <SeverityChip value={a.severity} /> },
                { key: 'sig', header: 'signature', wrap: true, render: (a) => a.signature },
                { key: 'src', header: 'source', priority: 2, className: 'mono', render: (a) => a.src_ip ?? a.mac ?? a.interface ?? '—' },
                { key: 'inc', header: 'incident', priority: 3, render: (a) => (a.incident_id ? <Link className="id" to={`/incidents/${a.incident_id}`}>{a.incident_id}</Link> : <span className="faint">—</span>) },
              ]}
            />
          </Panel>
        </div>
        <div className="ov-rail">
          <Panel title="Response" sub="containment activity" right={<Link to="/incidents">incidents</Link>} bodyClass="none">
            <DataTable
              compact
              rows={data.containment_activity}
              rowKey={(a) => a.workflow_id}
              empty="No containment actions since the last reset"
              columns={[
                { key: 'time', header: 'time', render: (a) => <Ts ts={a.applied_at ?? a.requested_at} ms={false} /> },
                { key: 'port', header: 'port', className: 'mono', render: (a: ContainmentAction) => (a.incident_id ? <Link to={`/incidents/${a.incident_id}`}>{a.interface}</Link> : a.interface ?? '—') },
                { key: 'state', header: 'state', render: (a) => <ResponseChip state={responseStateOf(a.incident_id ? byIncident.get(a.incident_id) : null, a)} /> },
              ]}
            />
          </Panel>
          <Panel title="Devices by VLAN" sub="inventory + quarantine">
            <HBars data={data.devices_by_vlan.map((v) => ({ name: vlanName(v.vlan), count: v.devices }))} tone="c5" labelWidth={120} />
          </Panel>
        </div>
      </div>

      {/* 3 · network activity + control status */}
      <div className="ov-grid">
        <Panel
          title="Network activity"
          sub="SPAN feed, 15-minute buckets"
          right={
            <Segmented
              label="Traffic metric"
              options={[
                { id: 'bytes', label: 'bytes' },
                { id: 'connections', label: 'connections' },
              ]}
              value={metric}
              onChange={setMetric}
            />
          }
        >
          <TrafficArea data={data.traffic} metric={metric} />
        </Panel>
        <div className="ov-rail">
          <Panel title="Control status" right={<Link to="/posture">posture</Link>}>
            {!posture ? (
              <Loading rows={3} />
            ) : posture.totals.assessments === 0 ? (
              <div className="empty">No assessment run yet</div>
            ) : (
              <div className="ctl-mini">
                <div className="ratios">
                  <div>
                    <span className="eyebrow" title={posture.definitions.coverage_pct}>
                      coverage
                    </span>
                    <span className="n">
                      {pct(posture.totals.coverage_pct)}
                      <small>
                        {posture.totals.determinate} / {posture.totals.assessments}
                      </small>
                    </span>
                  </div>
                  <div>
                    <span className="eyebrow" title={posture.definitions.pass_rate_of_determinate_pct}>
                      determinate pass
                    </span>
                    <span className="n">
                      {pct(posture.totals.pass_rate_of_determinate_pct)}
                      <small>
                        {posture.totals.pass} / {posture.totals.determinate}
                      </small>
                    </span>
                  </div>
                </div>
                <StatusBar counts={{ PASS: posture.totals.pass, FAIL: posture.totals.fail, UNKNOWN: posture.totals.unknown, STALE: posture.totals.stale }} label="assessment outcomes" />
                {nonPass.length ? (
                  nonPass.map((c) => (
                    <div key={c.control_id} className="stat-row">
                      <Link to={`/controls/${c.control_id}`} className="clip">
                        {c.name}
                      </Link>
                      <AssessChip value={c.status} />
                    </div>
                  ))
                ) : (
                  <div className="dim small">Every assessed control passes</div>
                )}
              </div>
            )}
          </Panel>
          <Panel title="Telemetry freshness" sub={telemetryRun ? `as of run ${telemetryRun.run_id} · ${fmtTime(telemetryRun.assessed_at, { ms: false })} UTC` : 'no assessment run yet'}>
            {!telemetry ? (
              <Loading rows={2} />
            ) : telemetry.length === 0 ? (
              <div className="empty">No assessment run yet — freshness is only known after an assessment</div>
            ) : (
              <div>
                {telemetry.map((a) => (
                  <div key={a.id} className="src-row">
                    <span className="src">{a.scope.id}</span>
                    <AssessChip value={a.status} />
                    <span className="why" title={a.explanation}>
                      {a.explanation}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </Panel>
        </div>
      </div>

      {/* 4 · metric band */}
      <MetricBand>
        <Metric label="Devices online" value={<Ratio num={k.devices_online} den={k.devices_total} />} hint="MAC-table presence" />
        <Metric label="Security alerts" value={fmtNum(k.alerts)} hint="Suricata · Zeek · AAA · syslog" />
        <Metric label="High severity" value={k.high_alerts} tone={k.high_alerts ? 'danger' : undefined} hint={`${k.incidents} incidents · ${k.open_incidents} open`} />
        <Metric label="802.1X success" value={pct(k.auth_success_rate)} tone="good" hint={`${k.auth_accepts} accepts · ${k.auth_rejects} rejects`} />
        <Metric label="Traffic observed" value={k.traffic_human} hint={`${fmtNum(k.connections)} connections on SPAN`} />
        <Metric label="Active VLANs" value={k.active_vlans} hint={k.active_vlan_ids.join(', ')} />
        <Metric label="Mean time to detect" value={fmtSeconds(k.mttd)} tone="accent" hint={`${k.validation_total ?? '—'} validation scenarios · simulated clock`} />
        <Metric label="Mean time to contain" value={fmtSeconds(k.mttc)} tone="accent" hint="detection → verified · simulated clock" />
      </MetricBand>

      <Panel title="Recent authentication" right={<Link to="/authentication">details</Link>} bodyClass="none">
        <DataTable
          compact
          rows={data.recent_auth}
          rowKey={(e) => e.event_id}
          columns={[
            { key: 'time', header: 'time', render: (e) => <Ts ts={e.timestamp} /> },
            { key: 'result', header: 'result', render: (e) => <Chip kind={e.result === 'Access-Accept' ? 'ok' : e.result === 'Access-Reject' ? 'danger' : 'info'}>{e.result}</Chip> },
            { key: 'id', header: 'identity', className: 'mono', render: (e) => e.username },
            { key: 'port', header: 'port', className: 'mono', priority: 2, render: (e) => e.nas_port_id.replace('GigabitEthernet', 'Gi') },
            { key: 'method', header: 'method', priority: 3, render: (e) => e.method },
          ]}
        />
      </Panel>

      <ConfirmDialog
        open={dialog === 'replay'}
        tone="consequential"
        title="Replay the flagship incident"
        summary={<>Replays {data.demo.flagship_incident ?? 'the flagship incident'} through the real detection, attribution and containment pipeline. Gi1/0/23 will be quarantined to VLAN 50 if policy authorizes it, and an assessment run follows.</>}
        confirmLabel="Replay incident"
        busy={busy}
        error={dlgError}
        onCancel={() => {
          setDialog(null)
          setDlgError(null)
        }}
        onConfirm={confirm}
      />
      <ConfirmDialog
        open={dialog === 'reset'}
        tone="destructive"
        title="Reset to baseline"
        summary={<>Re-seeds the dataset on the twin. The current incident, containment actions, assessment runs and findings history are discarded.</>}
        confirmLabel="Reset to baseline"
        busy={busy}
        error={dlgError}
        onCancel={() => {
          setDialog(null)
          setDlgError(null)
        }}
        onConfirm={confirm}
      />
    </>
  )
}

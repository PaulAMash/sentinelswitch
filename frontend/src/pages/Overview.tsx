import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { endpoints, type ContainmentAction } from '../lib/api'
import { useApi } from '../lib/hooks'
import { Loading, Panel, Segmented, Ts, ErrorState } from '../components/ui'
import { PageHeader } from '../components/layout'
import { StatusBar } from '../components/metric'
import { AssessChip, Chip, ResponseChip, responseStateOf } from '../components/status'
import { DataTable, Cell2 } from '../components/table'
import { ConfirmDialog } from '../components/dialog'
import { useToast } from '../components/toast'
import { TrafficStack } from '../charts'
import { BarRows, ResponseFlow, SeverityRing, TechniqueTiles } from '../charts/viz'
import { SignalConsole } from '../components/signal/SignalConsole'
import { AnimatedValue } from '../components/motion'
import { byEndpoint, bySource, ms, severityCounts } from '../lib/telemetry'
import { fmtNum, fmtSeconds, fmtTime, pct } from '../lib/format'
import { Icon } from '../components/Icons'

const TELEMETRY_CONTROL = 'CTL-TELEMETRY-FRESH'

function Sect({ idx, title, children, right }: { idx: string; title: string; children?: React.ReactNode; right?: React.ReactNode }) {
  return (
    <div className="sect">
      <span className="idx">{idx}</span>
      <h2>{title}</h2>
      {children && <p>{children}</p>}
      {right && <span className="right">{right}</span>}
    </div>
  )
}

export function Overview() {
  const { data, error, reload } = useApi(endpoints.overview)
  const { data: sw } = useApi(endpoints.switch)
  const { data: devices } = useApi(endpoints.devices)
  const { data: alerts } = useApi(() => endpoints.alerts('?limit=5000'))
  const { data: detections } = useApi(endpoints.detections)
  const { data: posture } = useApi(endpoints.posture)
  const { data: reviews } = useApi(endpoints.reviews)
  const { data: telemetry } = useApi(() => endpoints.assessments(`?control_id=${TELEMETRY_CONTROL}`))
  const { data: sensorCov } = useApi(() => endpoints.assessments('?control_id=CTL-SENSOR-COVERAGE'))
  const { data: incidents } = useApi(endpoints.incidents)
  const { data: wireFeed } = useApi(endpoints.telemetry)
  const toast = useToast()
  const [metric, setMetric] = useState<'bytes' | 'connections'>('connections')
  const [dialog, setDialog] = useState<'replay' | 'reset' | null>(null)
  const [busy, setBusy] = useState(false)
  const [dlgError, setDlgError] = useState<string | null>(null)

  const inputs = useMemo(
    () =>
      sw && devices && alerts && data && incidents && reviews
        ? { sw, devices: devices.devices, unknown: devices.unknown, alerts, incidents, actions: data.containment_activity, reviews, coverage: new Map((sensorCov ?? []).filter((a) => a.scope.vlan !== null).map((a) => [a.scope.vlan as number, a.status])) }
        : null,
    [sw, devices, alerts, data, incidents, reviews, sensorCov],
  )
  const domain = useMemo(() => (data ? { start: ms(data.dataset.start), end: ms(data.dataset.end) } : null), [data?.dataset.start, data?.dataset.end]) // eslint-disable-line react-hooks/exhaustive-deps
  // newest simulated time with recorded data: the switch clock or the latest alert or containment record
  const recordedEnd = useMemo(() => {
    const times = [sw ? ms(sw.now) : 0, ...(alerts ?? []).map((a) => ms(a.ts)), ...(data?.containment_activity ?? []).flatMap((a) => [a.applied_at, a.verified_at, a.restored_at].filter(Boolean).map((x) => ms(x as string)))]
    return Math.max(...times)
  }, [sw, alerts, data?.containment_activity])

  if (error && !data) return <ErrorState error={error} retry={reload} />
  if (!data) return <Loading rows={6} />
  const k = data.kpis
  const stage = data.demo.stage
  const awaiting = reviews ? reviews.filter((r) => r.status === 'review').length : null
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
  const nonPass = posture ? posture.by_control.filter((c) => c.status !== 'PASS' && c.status !== 'NOT_ASSESSED').slice(0, 4) : []
  const telemetryRun = telemetry?.[0]
  const sev = alerts ? severityCounts(alerts) : null
  const disp = detections ? { auto: detections.filter((d) => d.disposition === 'automatic_containment').length, review: detections.filter((d) => d.disposition === 'manual_review').length, monitor: detections.filter((d) => d.disposition === 'monitor').length } : null
  const openIncidents = incidents ? incidents.filter((i) => i.status !== 'resolved' && i.status !== 'closed').length : k.open_incidents
  const t = posture?.totals
  return (
    <>
      <PageHeader
        eyebrow={<span className="mono xs dim">SW01 · {data.dataset.day} · simulated switch clock</span>}
        title="Network operations"
        info={
          <>
            Every number on this page comes from the seeded synthetic dataset and the current state of the SW01 digital twin, on the simulated switch clock (UTC). Values marked DAY count the whole dataset day; NOW is the current state of the twin and the application store; RUN is the latest assessment run. The page refreshes when the server announces a change; it is not a continuous live feed.
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

      {/* status rail: each cell names its scope */}
      <nav className="status-rail reveal" aria-label="Operational summary" style={{ ['--i' as string]: 0 }}>
        <Link to="/alerts" title="Alerts recorded on the dataset day, all sources">
          <span className="k">
            <span className="kt">alerts</span>
          </span>
          <span className="vrow">
            <span className="v"><AnimatedValue value={alerts ? alerts.length : k.alerts} /></span>
            <span className="scope">DAY</span>
          </span>
          <span className="d">{sev ? `${sev.high} high · ${sev.medium} medium · ${sev.low} low` : '…'}</span>
        </Link>
        <Link to="/coverage" title="Correlation detections scored on the dataset day, by policy disposition">
          <span className="k">
            <span className="kt">detections</span>
          </span>
          <span className="vrow">
            <span className="v"><AnimatedValue value={detections ? detections.length : '…'} /></span>
            <span className="scope">DAY</span>
          </span>
          <span className="d">{disp ? `${disp.auto} automatic · ${disp.review} review · ${disp.monitor} monitor` : '…'}</span>
        </Link>
        <Link to="/incidents" title="Manual-review detections with no analyst decision yet">
          <span className="k">
            <span className="kt">awaiting authorization</span>
          </span>
          <span className="vrow">
            <span className={`v ${awaiting ? 'warn' : 'zero'}`}><AnimatedValue value={awaiting ?? '…'} /></span>
            <span className="scope">NOW</span>
          </span>
          <span className="d">manual review queue</span>
        </Link>
        <Link to="/incidents" title="Ports in the quarantine VLAN or under administrative hold on the twin">
          <span className="k">
            <span className="kt">contained hosts</span>
          </span>
          <span className="vrow">
            <span className={`v ${k.quarantined_hosts ? 'danger' : 'zero'}`}><AnimatedValue value={k.quarantined_hosts} /></span>
            <span className="scope">NOW</span>
          </span>
          <span className="d">VLAN 50 or administrative hold</span>
        </Link>
        <Link to="/incidents" title="Incidents that are not resolved or closed">
          <span className="k">
            <span className="kt">open incidents</span>
          </span>
          <span className="vrow">
            <span className={`v ${openIncidents ? 'danger' : 'zero'}`}><AnimatedValue value={openIncidents} /></span>
            <span className="scope">NOW</span>
          </span>
          <span className="d">{k.incidents} opened on the day</span>
        </Link>
        <Link to="/findings" title="Findings in open, reopened, remediation requested, remediated or remediation failed">
          <span className="k">
            <span className="kt">open findings</span>
          </span>
          <span className="vrow">
            <span className={`v ${posture?.findings.open ? 'warn' : 'zero'}`}><AnimatedValue value={posture ? posture.findings.open : '…'} /></span>
            <span className="scope">NOW</span>
          </span>
          <span className="d">{posture ? `${posture.findings.by_severity.high} high · ${posture.findings.by_severity.medium} medium · ${posture.findings.by_severity.low} low` : '…'}</span>
        </Link>
        <Link to="/posture" title={posture?.definitions.pass_rate_of_determinate_pct ?? 'PASS / (PASS + FAIL)'}>
          <span className="k">
            <span className="kt">determinate pass</span>
          </span>
          <span className="vrow">
            <span className="v accent"><AnimatedValue value={t ? pct(t.pass_rate_of_determinate_pct) : '…'} /></span>
            <span className="scope">RUN</span>
          </span>
          <span className="d">{t ? `${t.pass} / ${t.determinate} determinate results` : '…'}</span>
        </Link>
        <Link to="/posture" title="UNKNOWN plus STALE results; never counted as a pass">
          <span className="k">
            <span className="kt">unverified</span>
          </span>
          <span className="vrow">
            <span className={`v ${t && t.unknown + t.stale ? 'warn' : 'zero'}`}><AnimatedValue value={t ? t.unknown + t.stale : '…'} /></span>
            <span className="scope">RUN</span>
          </span>
          <span className="d">{t ? `${t.unknown} unknown · ${t.stale} stale` : '…'}</span>
        </Link>
      </nav>

      {/* 01 · signal field */}
      <div className="reveal" style={{ ['--i' as string]: 1 }}>
        {inputs && domain ? <SignalConsole inputs={inputs} domain={domain} day={data.dataset.day} now={sw ? ms(sw.now) : null} recordedEnd={recordedEnd} traffic={data.traffic} wireFeed={wireFeed} /> : <div className="sig instrument sig-loading"><Loading rows={8} /></div>}
      </div>

      {/* 02 · telemetry */}
      <Sect idx="02" title="Telemetry">
        Alert composition for the dataset day and the SPAN feed the sensors observed.
      </Sect>
      <div className="vz-grid c3">
        <Panel title="Severity" sub="alerts · dataset day">
          {sev ? <SeverityRing counts={sev} /> : <Loading rows={3} />}
        </Panel>
        <Panel title="Detection sources" sub="alerts by sensor and severity">
          {alerts ? <BarRows variant="source" rows={bySource(alerts).map((r) => ({ key: r.source, label: r.source, counts: r.counts }))} /> : <Loading rows={4} />}
        </Panel>
        <Panel title="Alert classes" sub="Sentinel detection classes" right={<Link to="/alerts">alerts</Link>}>
          <BarRows rows={data.alerts_by_category.map((c) => ({ key: c.category, label: c.category, value: c.count }))} limit={8} />
        </Panel>
      </div>
      <div className="vz-grid c21">
        <Panel
          title="SPAN traffic"
          sub="15-minute buckets · mirrored VLANs 20, 30, 40"
          right={
            <Segmented
              label="Traffic metric"
              options={[
                { id: 'connections', label: 'connections' },
                { id: 'bytes', label: 'bytes' },
              ]}
              value={metric}
              onChange={setMetric}
            />
          }
        >
          <TrafficStack data={data.traffic} metric={metric} height={236} />
          <div className="vz-def">Upper: {metric} per bucket. Lower: DNS queries seen by Zeek per bucket. Separate scales, shared time axis.</div>
        </Panel>
        <Panel title="Endpoint activity" sub="alerts attributed per endpoint · dataset day" right={<Link to="/devices">assets</Link>}>
          {alerts ? (
            <BarRows
              variant="rank"
              limit={8}
              rows={byEndpoint(alerts).map((r) => ({ key: r.key, label: r.device ?? `${r.port} · unregistered`, sub: r.device ? r.port : 'not in inventory', href: r.device ? `/devices/${r.device}` : undefined, counts: r.counts }))}
            />
          ) : (
            <Loading rows={6} />
          )}
        </Panel>
      </div>

      {/* 03 · detection and response */}
      <Sect idx="03" title="Detection and response">
        How each detection was handled, from policy disposition to the recorded outcome.
      </Sect>
      <div className="vz-grid c21">
        <Panel title="Response outcomes" sub="detections → policy disposition → recorded outcome">
          {detections && incidents && reviews ? <ResponseFlow detections={detections} incidents={incidents} actions={data.containment_activity} reviews={reviews} /> : <Loading rows={6} />}
          <div className="vz-def">Outcomes come from each detection&apos;s incident, containment action (including read-back verification) or review record; nothing is inferred from approval alone.</div>
        </Panel>
        <Panel title="ATT&CK techniques" sub="tags on the day's detections" right={<Link to="/coverage">rules</Link>}>
          {detections ? <TechniqueTiles detections={detections} /> : <Loading rows={4} />}
        </Panel>
      </div>
      <div className="vz-grid c21">
        <Panel title="Containment ledger" sub="actions since the last reset" right={<Link to="/incidents">incidents</Link>} bodyClass="none">
          <DataTable
            cards="narrow"
            compact
            rows={data.containment_activity}
            rowKey={(a) => a.workflow_id}
            empty="No containment actions since the last reset"
            columns={[
              { key: 'time', header: 'applied', render: (a) => <Ts ts={a.applied_at ?? a.requested_at} ms={false} /> },
              { key: 'inc', header: 'incident · port', render: (a: ContainmentAction) => <Cell2 primary={a.incident_id ? <Link className="id" to={`/incidents/${a.incident_id}`}>{a.incident_id}</Link> : <span className="faint">—</span>} secondary={<span className="mono">{a.interface ?? '—'}</span>} /> },
              { key: 'act', header: 'action', hideBelow: 600, render: (a) => (a.action === 'quarantine_vlan' ? `VLAN ${a.from_vlan} → ${a.to_vlan}` : a.action === 'port_shutdown' ? 'shutdown' : a.action.replace(/_/g, ' ')) },
              { key: 'state', header: 'state', render: (a) => <ResponseChip state={responseStateOf(a.incident_id ? byIncident.get(a.incident_id) : null, a)} /> },
            ]}
          />
        </Panel>
        <Panel title="Pipeline timing" sub="validation harness · simulated clock" right={<Link to="/coverage">coverage</Link>}>
          <ul className="timing-tiles">
            <li>
              <span className="k">mean time to detect</span>
              <span className="v mono"><AnimatedValue value={fmtSeconds(k.mttd)} /></span>
            </li>
            <li>
              <span className="k">mean time to attribute</span>
              <span className="v mono"><AnimatedValue value={fmtSeconds(k.mtta)} /></span>
            </li>
            <li>
              <span className="k">mean time to contain</span>
              <span className="v mono"><AnimatedValue value={fmtSeconds(k.mttc)} /></span>
            </li>
          </ul>
          <div className="vz-def">
            Means over {k.validation_total ?? '—'} replayed scenarios ({k.validation_passed ?? '—'} met their expected outcome). Detect: first anomalous event → detection; contain: detection → verified containment.
          </div>
        </Panel>
      </div>

      {/* 04 · assurance and access */}
      <Sect idx="04" title="Assurance and access">
        Control state from the latest assessment run, sensor freshness, and 802.1X activity.
      </Sect>
      <div className="vz-grid c3">
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
        <Panel title="Recent authentication" sub={`${pct(k.auth_success_rate)} success · ${fmtNum(k.auth_accepts)} accepts · ${fmtNum(k.auth_rejects)} rejects`} right={<Link to="/authentication">details</Link>} bodyClass="none">
          <DataTable
            compact
            rows={data.recent_auth.slice(0, 6)}
            rowKey={(e) => e.event_id}
            columns={[
              { key: 'time', header: 'time', render: (e) => <Ts ts={e.timestamp} ms={false} /> },
              { key: 'result', header: 'result', render: (e) => <Chip kind={e.result === 'Access-Accept' ? 'ok' : e.result === 'Access-Reject' ? 'danger' : 'info'}>{e.result.replace('Access-', '')}</Chip> },
              { key: 'id', header: 'identity', className: 'mono', render: (e) => e.username },
              { key: 'port', header: 'port', className: 'mono', hideBelow: 400, render: (e) => e.nas_port_id.replace('GigabitEthernet', 'Gi') },
            ]}
          />
        </Panel>
      </div>

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

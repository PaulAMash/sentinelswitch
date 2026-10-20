import { useMemo, useState } from 'react'
import { kv, type KVRow } from '../lib/kv'
import { Link, useParams } from 'react-router-dom'
import { endpoints, type Authorization } from '../lib/api'
import { useApi } from '../lib/hooks'
import { ErrorState, KV, Loading, Panel, Tabs, Ts } from '../components/ui'
import { PageHeader, Section } from '../components/layout'
import { Chip, Id, ResponseChip, SeverityChip, StatusChip, responseStateOf } from '../components/status'
import { ResponseLedger } from '../components/ledger'
import { Trace, TraceLegend } from '../components/trace'
import { Steps } from '../components/Chain'
import { Terminal } from '../components/terminal'
import { DataTable } from '../components/table'
import { ConfirmDialog } from '../components/dialog'
import { useToast } from '../components/toast'
import { Timeline } from '../components/Timeline'
import { Confidence, Features } from '../components/Features'
import { fmtBytes, fmtSeconds, vlanName } from '../lib/format'
import { MiniField } from '../components/signal/MiniField'
import { ms } from '../lib/telemetry'
import { decodeWire } from '../lib/wire'

type Tab = 'timeline' | 'detections' | 'decision' | 'evidence' | 'verify'
const ANALYST = 'tlee'
const RESTORE_NOTE = 'Endpoint re-imaged and cleared by IT; returning to production VLAN.'

export function IncidentDetail() {
  const { id = '' } = useParams()
  const { data, error, reload } = useApi(() => endpoints.incident(id), [id])
  const { data: sw } = useApi(endpoints.switch)
  const { data: devices } = useApi(endpoints.devices)
  const { data: alerts } = useApi(() => endpoints.alerts('?limit=5000'))
  const { data: incidents } = useApi(endpoints.incidents)
  const { data: reviews } = useApi(endpoints.reviews)
  const { data: meta } = useApi(endpoints.meta)
  const { data: feed } = useApi(endpoints.telemetry)
  const wire = useMemo(() => (feed ? decodeWire(feed) : null), [feed])
  const fieldInputs = useMemo(
    () => (sw && devices && alerts && incidents && reviews && data ? { sw, devices: devices.devices, unknown: devices.unknown, alerts, incidents, actions: data.actions, reviews } : null),
    [sw, devices, alerts, incidents, reviews, data],
  )
  const dayWindow = useMemo(() => (meta ? { start: ms(meta.dataset.start), end: ms(meta.dataset.end) } : null), [meta])
  const toast = useToast()
  const [tab, setTab] = useState<Tab>('timeline')
  const [dialog, setDialog] = useState(false)
  const [note, setNote] = useState(RESTORE_NOTE)
  const [busy, setBusy] = useState(false)
  const [dlgError, setDlgError] = useState<string | null>(null)
  const [more, setMore] = useState(false)
  if (error && !data) return <ErrorState error={error} retry={reload} />
  if (!data) return <Loading rows={6} />
  const inc = data.incident
  const det = data.detection
  const att = data.attribution
  const action = data.actions.find((a) => ['verified', 'restored', 'containment_failed', 'applied', 'failed'].includes(a.status)) ?? data.actions[0] ?? null
  const auth: Authorization | undefined = inc.authorization ?? action?.authorization
  const state = responseStateOf(inc, action, null, busy)
  const restore = async () => {
    setBusy(true)
    setDlgError(null)
    try {
      const r = await endpoints.restore(inc.id, { actor: ANALYST, note })
      toast.push({ title: `${inc.id} restored`, detail: `${r.action.interface} · action ${r.action.status}`, tone: 'ok' })
      setDialog(false)
      reload()
    } catch (e) {
      setDlgError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }
  const toNote = auth?.mode === 'analyst' ? `authorized by ${auth.authorized_by}` : auth?.mode === 'automatic' ? 'automatic · policy' : undefined
  return (
    <>
      <PageHeader
        eyebrow={
          <span className="row">
            <Id>{inc.id}</Id>
            <SeverityChip value={inc.severity} />
            <ResponseChip state={state} />
            <StatusChip value={inc.disposition} />
            {inc.mitre.map((m) => (
              <Chip key={m} kind="info" mono>
                {m}
              </Chip>
            ))}
          </span>
        }
        title={inc.title}
        sub={
          <span className={more ? '' : 'clamp-2'}>
            {inc.summary}{' '}
            {inc.summary.length > 180 && (
              <button className="btn sm ghost" type="button" onClick={() => setMore((m) => !m)}>
                {more ? 'less' : 'more'}
              </button>
            )}
          </span>
        }
      >
        {inc.status === 'contained' && (
          <button className="btn consequential" type="button" onClick={() => setDialog(true)} disabled={busy}>
            Release containment
          </button>
        )}
        <Link className="btn" to={`/evidence/${inc.id}`}>
          Evidence bundle
        </Link>
      </PageHeader>

      <Panel title="Response ledger" sub="each stage from its own record · simulated clock" bodyClass="flush">
        <ResponseLedger incident={inc} detection={det} attribution={att} action={action} />
      </Panel>

      <div className="vz-grid c21">
        <Panel title="Position in the access layer" sub={`${inc.interface ?? 'port not recorded'} and every port it exchanged alert traffic with · dataset day`}>
          {fieldInputs && dayWindow ? (
            <MiniField
              inputs={fieldInputs}
              window={dayWindow}
              focus={inc.interface}
              caption={`${inc.interface} · ${inc.device ?? 'unknown device'}`}
              wire={wire}
              // the recorded traffic of the incident host from 90 s before the incident opened until 25 s after
              replay={att?.ip ? { start: ms(inc.opened_at) - 90_000, end: ms(inc.opened_at) + 25_000, ip: att.ip } : null}
            />
          ) : (
            <Loading rows={5} />
          )}
        </Panel>
        {att ? (
          <Panel title="Attribution trace" sub="source IP → containment target">
            <TraceLegend />
            <Trace attribution={att} toVlan={action?.to_vlan} action={inc.action} toNote={toNote} vertical />
          </Panel>
        ) : (
          <Panel title="Attribution trace">
            <div className="dim small">No attribution record is attached to this incident.</div>
          </Panel>
        )}
      </div>

      <div className="inc-workspace">
        <div className="panel">
          <Tabs<Tab>
            label="Investigation"
            tabs={[
              { id: 'timeline', label: 'Timeline' },
              { id: 'detections', label: 'Detections', count: data.alerts.length },
              { id: 'decision', label: 'Decision & authorization' },
              { id: 'verify', label: 'Switch verification' },
              { id: 'evidence', label: 'Evidence', count: data.evidence.files.length },
            ]}
            value={tab}
            onChange={setTab}
          />
          <div className="panel-body tab-body" key={tab}>
            {tab === 'timeline' && (
              <>
                {det && (
                  <div className="measure" role="group" aria-label="Measured on the simulated clock">
                    <div>
                      <div className="k">time to detect</div>
                      <div className="v">{fmtSeconds(diff(data.timeline[0]?.ts, det.ts))}</div>
                    </div>
                    <div>
                      <div className="k">time to attribute</div>
                      <div className="v">{fmtSeconds(diff(det.ts, att?.completed_at))}</div>
                    </div>
                    <div>
                      <div className="k">time to contain</div>
                      <div className="v">{action?.verification?.ok === true ? fmtSeconds(diff(det.ts, action.verified_at)) : '—'}</div>
                    </div>
                    <div>
                      <div className="k">evidence finalized</div>
                      <div className="v">
                        <Ts ts={inc.evidence_finalized_at} />
                      </div>
                    </div>
                  </div>
                )}
                {inc.resolution_note && <div className="notice ok">{inc.resolution_note}</div>}
                <Timeline entries={data.timeline} />
              </>
            )}
            {tab === 'detections' && (
              <div className="stack">
                {det && (
                  <div className="stack tight">
                    <Section title={`${det.rule_name} · ${det.rule}`}>
                      <span />
                    </Section>
                    <Confidence value={det.confidence} base={det.base_confidence} />
                    <Features features={det.features} />
                    <div className="dim small">
                      trigger {det.trigger_ts.slice(11, 23)} · scored {det.ts.slice(11, 23)} · {det.event_refs.length} contributing events
                    </div>
                  </div>
                )}
                <DataTable
                  cards="narrow"
                  compact
                  rows={data.alerts}
                  rowKey={(a) => a.id}
                  columns={[
                    { key: 'time', header: 'time', render: (a) => <Ts ts={a.ts} /> },
                    { key: 'sev', header: 'severity', render: (a) => <SeverityChip value={a.severity} /> },
                    { key: 'src', header: 'source', render: (a) => <Chip kind="source">{a.source}</Chip> },
                    { key: 'sig', header: 'signature', wrap: true, render: (a) => a.signature },
                    { key: 'flow', header: 'src → dst', className: 'mono', hideBelow: 900, render: (a) => `${a.src_ip ?? a.mac ?? a.interface ?? ''} ${a.dest_ip ? `→ ${a.dest_ip}:${a.dest_port ?? ''}` : ''}` },
                  ]}
                />
              </div>
            )}
            {tab === 'decision' && (
              <div className="grid grid-2">
                <div className="stack">
                  <Section title="Policy evaluation">
                    <span />
                  </Section>
                  <DecisionView incidentId={inc.id} />
                  <Section title="Authorization">
                    <span />
                  </Section>
                  {auth ? (
                    <>
                      <div className="row">
                        <StatusChip value={auth.status} />
                        <span className="mono">{auth.mode}</span>
                        <span className="dim">{auth.action}</span>
                      </div>
                      <KV
                        rows={[
                          kv('authorized by', auth.authorized_by),
                          kv('authorized at', <Ts ts={auth.authorized_at} date />),
                          kv('basis', auth.basis),
                          kv('reason', <span className="wrap">{auth.reason}</span>),
                          kv('guards', auth.guards.length ? <span className="mono">{auth.guards.join(', ')}</span> : 'none'),
                          kv('note', auth.note ?? '—'),
                        ]}
                      />
                      <div className="small dim">The authorization record is written separately from the policy decision and from execution: the policy tier says what the engine would do, the authorization says who allowed it and on what basis.</div>
                    </>
                  ) : (
                    <div className="dim">No authorization record is attached to this incident.</div>
                  )}
                </div>
                <div className="stack">
                  <Section title="Containment action">
                    <span />
                  </Section>
                  {action ? (
                    <>
                      <KV
                        rows={[
                          kv('workflow', <Id dim>{action.workflow_id}</Id>),
                          kv('action', action.action),
                          kv('mechanism', action.mechanism),
                          kv('interface', `${action.switch} ${action.interface ?? ''}`),
                          kv('vlan', action.to_vlan ? `${action.from_vlan} → ${action.to_vlan}` : '—'),
                          kv('requested', <Ts ts={action.requested_at} />),
                          kv('applied', <Ts ts={action.applied_at} />),
                          kv(
                            'verified',
                            <>
                              <Ts ts={action.verified_at} /> {action.verification?.ok === true ? <Chip kind="ok">read-back ok</Chip> : action.verification?.ok === false ? <Chip kind="danger">read-back failed</Chip> : <Chip kind="outline">not verified</Chip>}
                            </>,
                          ),
                          kv('actor', action.actor),
                          kv('status', <StatusChip value={action.status} />),
                          ...(action.restored_at
                            ? [
                                kv(
                                  'restored',
                                  <>
                                    <Ts ts={action.restored_at} date /> by {action.restored_by} — {action.restore_note}
                                  </>,
                                ),
                              ]
                            : []),
                          ...(action.notes.length ? [kv('notes', <span className="wrap">{action.notes.join(' · ')}</span>)] : []),
                        ]}
                      />
                      {action.transcript && <Terminal text={action.transcript} hl={['switchport access vlan', 'shutdown']} />}
                    </>
                  ) : (
                    <div className="dim">No containment action is recorded for this incident.</div>
                  )}
                </div>
              </div>
            )}
            {tab === 'verify' && (
              <div className="grid grid-2">
                <div className="stack">
                  <div className="eyebrow">show interfaces {inc.interface} switchport</div>
                  <Terminal text={data.verification.switchport ?? ''} hl={['Access Mode VLAN']} />
                  <div className="eyebrow">show interfaces {inc.interface} status</div>
                  <Terminal text={data.verification.status ?? ''} />
                </div>
                <div className="stack">
                  <div className="eyebrow">show mac address-table interface {inc.interface}</div>
                  <Terminal text={data.verification.mac_table ?? ''} />
                  <div className="eyebrow">show running-config interface {inc.interface}</div>
                  <Terminal text={data.verification.running_config ?? ''} hl={['switchport access vlan']} />
                </div>
              </div>
            )}
            {tab === 'evidence' && (
              <div className="stack">
                <p className="dim small">
                  Original evidence written to <code>{data.evidence.path}/</code> on the simulated clock; every artifact is plain JSON or Markdown.
                </p>
                <DataTable
                  compact
                  rows={data.evidence.files}
                  rowKey={(f) => f.name}
                  columns={[
                    { key: 'name', header: 'artifact', className: 'mono', render: (f) => <Link to={`/evidence/${inc.id}?file=${f.name}`}>{f.name}</Link> },
                    { key: 'size', header: 'size', align: 'right', render: (f) => fmtBytes(f.bytes) },
                    { key: 'desc', header: 'contents', wrap: true, hideBelow: 700, render: (f) => <span className="dim">{describe(f.name)}</span> },
                  ]}
                />
              </div>
            )}
          </div>
        </div>

        <aside className="inc-rail" aria-label="Incident context">
          <Panel title="Endpoint" bodyClass="flush">
            <KV
              rows={[
                kv('device', inc.device ? <Link to={`/devices/${inc.device}`}>{inc.device}</Link> : inc.impersonated_device ? `unknown (impersonating ${inc.impersonated_device})` : 'unknown device'),
                kv('user', inc.user ? `${inc.user}${inc.department ? ` (${inc.department})` : ''}` : '—'),
                kv('vendor', inc.vendor ?? '—'),
              ]}
            />
          </Panel>
          <Panel title="Network location" bodyClass="flush">
            <KV
              rows={[
                kv('switch', inc.switch),
                kv('interface', <span className="mono">{inc.interface ?? '—'}</span>),
                kv('port class', inc.port_class ?? '—'),
                kv('vlan', inc.current_vlan !== inc.original_vlan ? `${vlanName(inc.original_vlan)} → ${vlanName(inc.current_vlan)}` : vlanName(inc.original_vlan)),
                kv('mechanism', inc.action === 'quarantine_vlan' ? 'quarantine VLAN' : inc.action === 'port_shutdown' ? 'administrative shutdown' : inc.mechanism ?? '—'),
              ]}
            />
          </Panel>
          <Panel title="Authorization" bodyClass="flush">
            <KV rows={authRows(auth)} />
          </Panel>
          <Panel title="Addresses" bodyClass="flush">
            <KV
              rows={[
                kv('ip', <span className="mono">{inc.ip ?? '—'}</span>),
                kv('mac', <span className="mono">{inc.mac ?? '—'}</span>),
                kv('attribution', `${((inc.attribution_confidence ?? 1) * 100).toFixed(0)}% · ${inc.flags.length ? inc.flags.join(', ') : 'clean'}`),
                kv('opened', <Ts ts={inc.opened_at} date />),
                kv('closed', inc.closed_at ? <><Ts ts={inc.closed_at} date /> <span className="dim">by {inc.closed_by}</span></> : '—'),
              ]}
            />
          </Panel>
          {att && (
            <Panel title="Correlation steps" bodyClass="flush">
              <Steps steps={att.steps} />
            </Panel>
          )}
        </aside>
      </div>

      <ConfirmDialog
        open={dialog}
        tone="consequential"
        title="Release containment"
        summary={
          <>
            <span className="mono">{inc.interface}</span> returns to VLAN {inc.original_vlan} ({vlanName(inc.original_vlan)}); the restore is read back from the switch and a recovery assessment runs. The incident becomes resolved only if the backend verifies the restore.
          </>
        }
        note={{ label: 'Resolution note', value: note, onChange: setNote }}
        actor={ANALYST}
        confirmLabel="Release containment"
        busy={busy}
        error={dlgError}
        onCancel={() => setDialog(false)}
        onConfirm={restore}
      />
    </>
  )
}

function DecisionView({ incidentId }: { incidentId: string }) {
  const { data, error } = useApi(() => endpoints.evidenceFile(incidentId, 'containment.json') as Promise<{ decision: { disposition: string; action: string; reason: string; factors: { factor: string; value: unknown }[]; guards_triggered: string[]; tier_before_guards: string | null } }>, [incidentId])
  if (error) return <div className="dim small">Policy evaluation unavailable: {error}</div>
  if (!data) return <Loading rows={2} />
  const d = data.decision
  return (
    <>
      <div className="row">
        <StatusChip value={d.disposition} />
        <span className="mono">{d.action}</span>
      </div>
      <div className="dim">{d.reason}</div>
      <KV rows={d.factors.map((f) => kv(f.factor, String(f.value)))} />
      <div className="small dim">guards triggered: {d.guards_triggered.length ? d.guards_triggered.join(', ') : 'none — protected ports, trunks, SPAN destination and critical assets are exempt from automatic action'}</div>
    </>
  )
}

function authRows(a: Authorization | undefined): KVRow[] {
  if (!a) return [kv('record', <span className="dim">not recorded</span>)]
  return [
    kv('status', <><StatusChip value={a.status} /> <span className="dim">{a.mode}</span></>),
    kv('by', a.authorized_by),
    kv('at', <Ts ts={a.authorized_at} date />),
    // a zero-width space after each underscore lets long policy-tier names wrap inside the narrow card
    kv('basis', <span className="wrap">{a.basis.replaceAll('_', '_​')}</span>),
    kv('guards', a.guards.length ? <span className="mono wrap">{a.guards.join(', ')}</span> : 'none'),
    kv('note', a.note ?? '—'),
  ]
}

function describe(name: string): string {
  return {
    'incident.json': 'incident record, detection, metrics, attribution chain',
    'timeline.json': 'ordered phases from first telemetry to evidence',
    'alerts.json': 'source detections with raw Suricata/Zeek/RADIUS/syslog records',
    'network-context.json': 'attribution, VLANs, SPAN session, port intent',
    'dhcp-binding.json': 'DHCP snooping binding used for IP → MAC',
    'mac-table.json': 'MAC address table entries and observation history',
    'switch-port.json': 'interface state before/after with show output',
    'containment.json': 'policy decision and executed action with transcript',
    'related-connections.json': 'Zeek conn records for the actor around the incident',
    'related-dns.json': 'Zeek dns records for the actor around the incident',
    'README.md': 'generated human-readable report',
  }[name] ?? ''
}

function diff(a?: string | null, b?: string | null): number | null {
  if (!a || !b) return null
  return (new Date(b).getTime() - new Date(a).getTime()) / 1000
}

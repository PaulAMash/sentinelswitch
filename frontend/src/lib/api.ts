/* Typed API client for the SentinelSwitch backend. */

export type Severity = 'high' | 'medium' | 'low' | 'info' | 'critical'

export interface Meta {
  name: string
  tagline: string
  version: string
  simulation: boolean
  dataset: { day: string; start: string; end: string; baseline_now: string; seed: number }
  organization: { name: string; domain: string; site: string; timezone: string }
  switch: { hostname: string; model: string; ios_version: string; management_ip: string; now: string; summary: Record<string, number> }
  demo: DemoStatus
  counts: Record<string, number> & { findings_open?: number; reviews_open?: number }
  flagship_incident: string
}

export interface DemoStatus {
  stage: 'unseeded' | 'baseline' | 'contained' | 'restored'
  flagship_incident: string | null
  ran_at: string | null
  checks?: Record<string, boolean>
}

export interface Alert {
  id: string
  ts: string
  source: 'suricata' | 'zeek' | 'radius' | 'syslog'
  severity: Severity
  signature: string
  signature_id: number | null
  category: string
  src_ip: string | null
  src_port: number | null
  dest_ip: string | null
  dest_port: number | null
  proto: string | null
  mac: string | null
  interface: string | null
  device: string | null
  summary: string
  status: string
  detection_id: string | null
  incident_id: string | null
  scenario: string | null
  raw?: Record<string, unknown>
}

export interface Feature {
  id: string
  label: string
  weight: number
  matched: boolean
  evidence: string | null
}

export interface Detection {
  id: string
  rule: string
  rule_name: string
  class: string
  mitre: string[]
  actor_key: string
  actor_value: string
  actor: Record<string, unknown>
  ts: string
  trigger_ts: string
  severity: Severity
  confidence: number
  base_confidence: number
  features: Feature[]
  summary: string
  event_refs: { ts: string; source: string; summary: string }[]
  disposition?: string
  incident_id?: string | null
  scenario?: string | null
}

export interface Step {
  name: string
  status: 'resolved' | 'missing' | 'conflict' | 'fallback' | 'skipped' | 'refused'
  source: string
  input: string | null
  output: string | null
  detail: string
  ts: string
}

export interface Attribution {
  ip: string | null
  mac: string | null
  switch: string
  interface: string | null
  vlan: number | null
  access_vlan: number | null
  port_class: string | null
  port_mode: string | null
  protected: boolean
  trunk: boolean
  span_destination: boolean
  device: string | null
  user: string | null
  department: string | null
  criticality: string | null
  vendor: string | null
  resolved: boolean
  confidence: number
  flags: string[]
  steps: Step[]
  binding: Record<string, unknown> | null
  mac_entries: Record<string, unknown>[]
  observations: Record<string, unknown>[]
  started_at: string | null
  completed_at: string | null
  impersonated_device: string | null
  port_owner: string | null
}

export interface Decision {
  disposition: string
  action: string
  reason: string
  factors: { factor: string; value: unknown }[]
  guards_triggered: string[]
  quarantine_vlan: number | null
  tier_before_guards: string | null
}

export interface ContainmentAction {
  workflow_id: string
  incident_id: string | null
  action: string
  mechanism: string
  interface: string | null
  switch: string
  from_vlan: number | null
  to_vlan: number | null
  reason: string
  initiating_detection: string
  actor: string
  requested_at: string
  applied_at: string | null
  verified_at: string | null
  status: string
  commands: string[]
  transcript: string
  verification: { ok?: boolean; expected?: string; transcript?: string; checked_at?: string }
  restored_at: string | null
  restored_by: string | null
  restore_note: string | null
  restore_transcript: string | null
  notes: string[]
  authorization?: Authorization
}

export interface Incident {
  id: string
  title: string
  severity: Severity
  confidence: number
  status: string
  opened_at: string
  closed_at: string | null
  closed_by?: string | null
  resolution_note?: string | null
  rule: string
  rule_name: string
  class: string
  mitre: string[]
  scenario: string
  detection_id: string
  device: string | null
  user: string | null
  department: string | null
  ip: string | null
  mac: string | null
  vendor: string | null
  switch: string
  interface: string | null
  original_vlan: number | null
  current_vlan: number | null
  port_class: string | null
  chain: string[]
  summary: string
  disposition: string
  action: string
  attribution_confidence: number
  flags: string[]
  impersonated_device: string | null
  workflow_id?: string
  mechanism?: string
  contained_at?: string
  evidence_finalized_at?: string
  evidence_path?: string
  authorization?: Authorization
}

export interface TimelineEntry {
  ts: string
  phase: string
  actor: string
  message: string
  details: Record<string, unknown> | null
}

export interface IncidentDetail {
  incident: Incident
  detection: Detection | null
  attribution: Attribution | null
  actions: ContainmentAction[]
  alerts: Alert[]
  timeline: TimelineEntry[]
  evidence: { path: string; files: { name: string; bytes: number }[] }
  port: PortState | null
  verification: { switchport: string | null; status: string | null; mac_table: string | null; running_config: string | null }
  scenario: Scenario | null
}

export interface Review {
  detection_id: string
  status: string
  opened_at: string
  closed_at: string | null
  closed_by: string | null
  note: string | null
  scenario: string
  rule: string
  actor: Record<string, unknown>
  attribution: Attribution | null
  decision: Decision | null
  timeline: TimelineEntry[]
  severity: Severity
  confidence: number
  title: string
  authorization?: Authorization
  incident_id?: string
  class?: string
}

export interface Device {
  hostname: string
  role: string
  vendor: string
  os: string
  mac: string
  ip: string | null
  vlan: number
  interface: string
  criticality: string
  auth: string
  user: string | null
  tags: string[]
  services: string[]
  via_trunk: boolean
  schedule: [string, string] | null
  online_at_baseline: boolean
  online: boolean
  current_vlan: number
  quarantined: boolean
  port_status: string | null
  port_hold: boolean
  binding: Record<string, unknown> | null
  auth_state: string | null
  user_display: string | null
  department: string | null
  notes: string | null
  asset_tag: string | null
  zone: string | null
}

export interface UnknownDevice {
  label: string
  description: string
  mac: string
  interface: string
  schedule: [string, string]
  vendor: string
}

export interface User {
  username: string
  display_name: string
  department: string
  title: string
  auth_method: string
  roles: string[]
}

export interface PortState {
  name: string
  description: string
  mode: string
  access_vlan: number | null
  native_vlan: number | null
  allowed_vlans: number[]
  admin_status: string
  oper_status: string
  speed: string
  duplex: string
  port_class: string
  protected: boolean
  span_destination: boolean
  settings: Record<string, unknown>
  oper_vlan: number | null
  auth_state: string | null
  auth_method: string | null
  auth_user: string | null
  quarantined: boolean
  original_vlan: number | null
  quarantine_reason: string | null
  quarantine_workflow: string | null
  hold: boolean
  errdisable_reason: string | null
  last_change: string | null
  counters: Record<string, number>
  port_security: Record<string, unknown>
  sticky_macs: string[]
  macs: { mac: string; vlan: number; interface: string; entry_type: string; learned_at: string }[]
  device: string | null
  device_user: string | null
  bindings: Record<string, unknown>[]
  state: string
}

export interface SwitchState {
  hostname: string
  model: string
  ios_version: string
  serial: string
  management_ip: string
  now: string
  uptime: string
  summary: Record<string, number>
  vlans: Record<string, { id: number; name: string; subnet: string | null; gateway: string | null; purpose: string }>
  span: { id: number; source_vlans: number[]; direction: string; destination: string }
  dhcp_snooping_vlans: number[]
  dai_vlans: number[]
  interfaces: PortState[]
  mac_table: { mac: string; vlan: number; interface: string; entry_type: string; learned_at: string }[]
  dhcp_bindings: { mac: string; ip: string; vlan: number; interface: string; lease_expires: string; binding_type: string }[]
  config_changes: { ts: string; actor: string; source: string; interface: string | null; commands: string[]; reason: string | null }[]
  audit: Record<string, unknown>[]
  log_tail: string[]
  commands: string[]
}

export interface AuthEvent {
  timestamp: string
  event_id: string
  username: string
  identity: string
  user: string | null
  device: string | null
  calling_station_id: string
  nas_identifier: string
  nas_port: number
  nas_port_id: string
  result: string
  method: string
  assigned_vlan: number | null
  vlan_source: string | null
  reason: string | null
  audit_session_id: string
}

export interface AuthSummary {
  series: { hour: string; accept: number; reject: number; guest: number }[]
  methods: { method: string; count: number }[]
  vlans: { vlan: string; count: number }[]
  top_rejected: { username: string; count: number }[]
  totals: { events: number; accepts: number; rejects: number; guest: number; success_rate: number }
  recent: AuthEvent[]
}

export interface Overview {
  kpis: {
    devices_online: number
    devices_total: number
    alerts: number
    high_alerts: number
    incidents: number
    open_incidents: number
    quarantined_hosts: number
    auth_success_rate: number
    auth_accepts: number
    auth_rejects: number
    traffic_bytes: number
    traffic_human: string
    connections: number
    active_vlans: number
    active_vlan_ids: number[]
    mttd: number | null
    mtta: number | null
    mttc: number | null
    validation_passed: number | null
    validation_total: number | null
  }
  alert_timeline: { hour: string; high: number; medium: number; low: number }[]
  traffic: { ts: string; connections: number; bytes: number; dns: number; alerts: number; hosts: number }[]
  alerts_by_category: { category: string; count: number }[]
  devices_by_vlan: { vlan: number; name: string; devices: number }[]
  recent_alerts: Alert[]
  recent_auth: AuthEvent[]
  containment_activity: ContainmentAction[]
  incidents: Incident[]
  switch: Record<string, number | string>
  demo: DemoStatus
  dataset: Meta['dataset']
}

export interface ValidationRow {
  scenario_id: string
  name: string
  class: string
  rule: string
  mitre: string[]
  detect: boolean
  attribute: boolean
  contain: boolean
  /** contained = automatic containment applied and verified; withheld = automation correctly withheld by policy */
  response?: 'contained' | 'withheld' | 'failed'
  disposition?: string | null
  passed: boolean
  severity: Severity | null
  confidence: number | null
  expected: Record<string, unknown>
  action: string | null
  mechanism: string | null
  interface: string | null
  from_vlan: number | null
  to_vlan: number | null
  t0: string | null
  first_alert: string | null
  detection_ts: string | null
  verified_ts: string | null
  ttd: number | null
  tta: number | null
  ttc: number | null
  end_to_end: number | null
  attribution_flags: string[]
  chain: string[]
  timeline: TimelineEntry[]
  features: Feature[]
}

export interface Scenario {
  id: string
  name: string
  short: string
  class: string
  rule: string
  mitre: string[]
  description: string
  flagship: boolean
  actor: Record<string, unknown>
  timing: Record<string, number>
  instances: Record<string, { start: string; incident_id: string | null; expected: Record<string, unknown>; parameters: Record<string, unknown>; resolution: Record<string, unknown> | null }>
}

export interface Validation {
  results: ValidationRow[]
  metrics: { scenarios: number; passed: number; contained?: number; withheld?: number; mttd: number; mtta: number; mttc: number; mean_end_to_end: number; max_ttd: number; min_ttd: number; median_ttc: number; all_passed: boolean }
  scenarios: Scenario[]
}

export interface DriftFinding {
  id: string
  scope: string
  interface: string | null
  setting: string
  expected: unknown
  observed: unknown
  severity: string
  recommendation: string
  status: string
  note: string | null
}

export interface DriftReport {
  checked_interfaces: number
  checks: number
  findings: DriftFinding[]
  open: number
  approved: number
  by_severity: Record<string, number>
  compliant_interfaces: number
  desired_source: string
  observed_source: string
}

export interface RuleCatalog {
  correlation: { id: string; name: string; class: string; description: string; mitre: string[]; actor_key: string; trigger: Record<string, unknown>; aggregate_window: number; base_confidence: number; severity: unknown; features: Record<string, unknown>[]; path: string }[]
  suricata: { sid: number; rev: number; msg: string; classtype: string; category: string; class: string; severity: string; proto: string; rule: string }[]
  zeek: { note: string; script: string }[]
  policy: Record<string, unknown>
}

export interface EvidenceEntry {
  incident: Incident
  path: string
  files: { name: string; bytes: number }[]
  complete: boolean
}

export interface About {
  name: string
  tagline: string
  version: string
  organization: Meta['organization']
  switch: Record<string, unknown>
  vlans: { id: number; name: string; subnet: string | null; gateway: string | null; purpose: string }[]
  diagrams: string[]
  components: { name: string; role: string; layer: string }[]
  stack: string[]
}

// ---- SentinelSwitch 2.0 assurance ---------------------------------------------------------------
export type AssessmentStatus = 'PASS' | 'FAIL' | 'UNKNOWN' | 'STALE'
export type FindingStatus = 'open' | 'reopened' | 'remediation_requested' | 'remediated' | 'remediation_failed' | 'verified' | 'closed'

export interface CsfRef {
  id: string
  text: string
}

export interface EvidenceItem {
  source: string
  ref: string
  collected_at: string
  detail: string
}

export interface AssessmentScope {
  type: 'interface' | 'incident' | 'source' | 'vlan' | 'global'
  id: string
  asset: string | null
  interface: string | null
  vlan: number | null
  switch: string
  description?: string
}

export interface Assessment {
  id: string
  run_id: string
  control_id: string
  control_name: string
  category: string
  framework: { nist_csf_2_0: CsfRef[] }
  scope: AssessmentScope
  assessed_at: string
  expected: unknown
  observed: unknown
  status: AssessmentStatus
  severity: 'high' | 'medium' | 'low'
  explanation: string
  evidence: EvidenceItem[]
  evidence_collected_at: string
  freshness: { window_seconds: number | null; applied: boolean; oldest_evidence_at?: string; age_seconds?: number; fresh?: boolean }
  related_incidents: string[]
  detector: string
  source_of_truth: string
  remediation: { guidance: string; commands: string[]; action: Record<string, unknown> | null }
  finding_id: string | null
  limitations: string | null
}

export interface Finding {
  id: string
  control_id: string
  control_name: string
  category: string
  scope: AssessmentScope
  asset: string | null
  severity: 'high' | 'medium' | 'low'
  status: FindingStatus
  result: AssessmentStatus
  opened_at: string
  updated_at: string
  first_run_id: string
  last_run_id: string
  occurrences: number
  assessment_id: string
  expected: unknown
  observed: unknown
  explanation: string
  related_incidents: string[]
  remediation: { guidance: string; commands: string[]; action: Record<string, unknown> | null; status: string; requested_at: string | null; requested_by: string | null; executed_at: string | null; executed_by?: string; transcript: string | null; note?: string | null }
  verification: { outcome: AssessmentStatus | null; at: string | null; run_id: string | null; after_remediation?: boolean }
  resolved_at: string | null
}

export interface FindingEvent {
  ts: string
  event: string
  actor: string | null
  detail?: string
  transcript?: string
}

export interface ControlCatalogEntry {
  id: string
  name: string
  description: string
  category: string
  severity: 'high' | 'medium' | 'low'
  scope_type: string
  source_of_truth: string
  csf: CsfRef[]
  freshness_window: number | null
  states: AssessmentStatus[]
  remediation: string
  limitations: string
}

export interface ControlStatus {
  control_id: string
  name: string
  category: string
  severity: string
  scope_type: string
  csf: CsfRef[]
  assessments: number
  pass: number
  fail: number
  unknown: number
  stale: number
  open_findings: number
  status: AssessmentStatus | 'NOT_ASSESSED'
}

export interface AssessmentRun {
  run_id: string
  assessed_at: string
  trigger: string
  actor: string
  controls: number
  assessments: number
  counts: Record<AssessmentStatus, number>
  findings_open: number
  clock: string
}

export interface Posture {
  generated_for: string
  clock: string | null
  last_run: AssessmentRun | null
  runs: number
  totals: { assessments: number; controls: number; pass: number; fail: number; unknown: number; stale: number; determinate: number; retired?: number; coverage_pct: number | null; pass_rate_of_determinate_pct: number | null; pass_rate_of_all_pct: number | null }
  definitions: Record<string, string>
  findings: { open: number; closed: number; by_severity: Record<'high' | 'medium' | 'low', number>; by_status: Record<string, number>; by_result: Record<string, number>; open_items: Finding[]; recently_closed: Finding[] }
  assets_with_open_findings: { asset: string; interface: string | null; findings: number; worst: 'high' | 'medium' | 'low'; controls: string[] }[]
  unverified: { id: string; control_id: string; scope: AssessmentScope; status: AssessmentStatus; explanation: string }[]
  by_control: ControlStatus[]
  by_category: { category: string; pass: number; fail: number; unknown: number; stale: number }[]
  csf: { id: string; text: string; function: string; controls: string[]; pass: number; fail: number; unknown: number; stale: number }[]
  incidents: { total: number; open: number; resolved: number }
  recent_runs: AssessmentRun[]
  scope_note: string
}

export interface Authorization {
  mode: 'automatic' | 'analyst' | 'rejected'
  status: 'authorized' | 'pending' | 'rejected'
  authorized_by: string
  authorized_at: string | null
  basis: string
  reason: string
  guards: string[]
  action: string
  note: string | null
}

export interface ReportInfo {
  json: string
  html: string
  pdf: string | null
  assessments: number
  findings: number
}

export const BASE = import.meta.env.VITE_API_BASE ?? ''

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { ...init, headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) } })
  if (!res.ok) {
    let detail = res.statusText
    try {
      const body = await res.json()
      detail = body.detail ?? detail
    } catch {
      /* ignore */
    }
    throw new Error(`${res.status} ${detail}`)
  }
  const ct = res.headers.get('content-type') ?? ''
  if (ct.includes('application/json')) return (await res.json()) as T
  return (await res.text()) as unknown as T
}

/** Recorded telemetry of the dataset day (GET /api/telemetry): every row is a line of a dataset file. */
export interface TelemetryFeed {
  day: string
  /** UTC midnight of the dataset day; every `t` is milliseconds after it */
  start: string
  files: Record<string, string>
  counts: { conn: number; auth: number; syslog: number; with_detail: number }
  hosts: string[]
  services: string[]
  /** DNS query, TLS server name or HTTP request joined to a connection by Zeek uid */
  details: string[]
  /** columnar Zeek connections: time, originator host, responder host, responder port, service, bytes, detail (-1 when absent) */
  conn: { t: number[]; o: number[]; r: number[]; p: number[]; s: number[]; b: number[]; d: number[] }
  auth: { t: number; result: string; user: string | null; device: string | null; port: string | null; method: string | null; vlan: number | null }[]
  syslog: { t: number; severity: number; mnemonic: string; port: string | null; message: string }[]
}

let telemetryOnce: Promise<TelemetryFeed> | null = null
/** The feed is static per dataset, so it is fetched once per page load and shared by every view. */
function telemetry(): Promise<TelemetryFeed> {
  if (!telemetryOnce) {
    telemetryOnce = api<TelemetryFeed>('/api/telemetry')
    telemetryOnce.catch(() => {
      telemetryOnce = null
    })
  }
  return telemetryOnce
}

export const endpoints = {
  telemetry,
  meta: () => api<Meta>('/api/meta'),
  overview: () => api<Overview>('/api/overview'),
  alerts: (q = '') => api<Alert[]>(`/api/alerts${q}`),
  alert: (id: string) => api<{ alert: Alert; detection: Detection | null }>(`/api/alerts/${id}`),
  detections: () => api<Detection[]>('/api/detections'),
  reviews: () => api<Review[]>('/api/reviews'),
  incidents: () => api<Incident[]>('/api/incidents'),
  incident: (id: string) => api<IncidentDetail>(`/api/incidents/${id}`),
  evidenceFile: (id: string, name: string) => api<unknown>(`/api/incidents/${id}/evidence/${name}`),
  evidence: () => api<EvidenceEntry[]>('/api/evidence'),
  restore: (id: string, body: { actor: string; note: string }) => api<{ incident: Incident; action: ContainmentAction; transcript: string }>(`/api/incidents/${id}/restore`, { method: 'POST', body: JSON.stringify(body) }),
  devices: () => api<{ devices: Device[]; unknown: UnknownDevice[]; users: User[] }>('/api/devices'),
  device: (h: string) => api<{ device: Device; user: User | null; interface: PortState | null; mac_entries: unknown[]; bindings: unknown[]; observations: unknown[]; alerts: Alert[]; auth: AuthEvent[]; incidents: Incident[] }>(`/api/devices/${h}`),
  switch: () => api<SwitchState>('/api/switch'),
  iface: (name: string) => api<{ interface: PortState; intent: Record<string, unknown>; device: string | null; macs: unknown[]; bindings: unknown[]; show: Record<string, string>; changes: unknown[] }>(`/api/switch/interfaces/${name}`),
  show: (cmd: string) => api<string>(`/api/switch/show?cmd=${encodeURIComponent(cmd)}`),
  auth: () => api<AuthSummary>('/api/auth'),
  validation: () => api<Validation>('/api/validation'),
  runValidation: () => api<{ results: ValidationRow[]; metrics: Validation['metrics'] }>('/api/validation/run', { method: 'POST' }),
  drift: () => api<DriftReport>('/api/drift'),
  rules: () => api<RuleCatalog>('/api/rules'),
  about: () => api<About>('/api/about'),
  demoStatus: () => api<DemoStatus>('/api/demo/status'),
  demoRun: () => api<{ incident: Incident; metrics: Record<string, unknown>; checks: Record<string, boolean>; timeline: TimelineEntry[] }>('/api/demo/run', { method: 'POST' }),
  demoReset: () => api<unknown>('/api/demo/reset', { method: 'POST' }),
  // SentinelSwitch 2.0
  posture: () => api<Posture>('/api/posture'),
  controls: () => api<{ catalog: ControlCatalogEntry[]; status: ControlStatus[]; last_run: AssessmentRun | null }>('/api/controls'),
  control: (id: string) => api<{ control: ControlCatalogEntry; assessments: Assessment[]; findings: Finding[] }>(`/api/controls/${id}`),
  assessments: (q = '') => api<Assessment[]>(`/api/assessments${q}`),
  assessment: (id: string) => api<{ assessment: Assessment; history: Assessment[]; finding: Finding | null; control: ControlCatalogEntry | null }>(`/api/assessments/${id}`),
  assessmentRuns: () => api<AssessmentRun[]>('/api/assessments/runs'),
  runAssessment: (actor = 'tlee') => api<AssessmentRun>('/api/assessments/run', { method: 'POST', body: JSON.stringify({ actor, note: '' }) }),
  findings: (q = '') => api<Finding[]>(`/api/findings${q}`),
  finding: (id: string) => api<{ finding: Finding; events: FindingEvent[]; assessment: Assessment | null; history: Assessment[]; control: ControlCatalogEntry | null }>(`/api/findings/${id}`),
  remediate: (id: string, body: { actor: string; note: string }) => api<{ finding: Finding; executed: boolean; transcript?: string; commands?: string[]; run?: AssessmentRun; refused?: string }>(`/api/findings/${id}/remediate`, { method: 'POST', body: JSON.stringify(body) }),
  review: (id: string) => api<Review & { authorization?: Authorization; incident_id?: string }>(`/api/reviews/${id}`),
  approveReview: (id: string, body: { actor: string; note: string }) => api<{ incident: Incident; action: ContainmentAction; review: Review }>(`/api/reviews/${id}/approve`, { method: 'POST', body: JSON.stringify(body) }),
  rejectReview: (id: string, body: { actor: string; note: string }) => api<{ review: Review }>(`/api/reviews/${id}/reject`, { method: 'POST', body: JSON.stringify(body) }),
  reportJson: () => api<Record<string, unknown>>('/api/reports/posture.json'),
  reportGenerate: () => api<ReportInfo>('/api/reports/generate', { method: 'POST' }),
}

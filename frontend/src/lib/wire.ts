import type { Alert, TelemetryFeed } from './api'
import { ms, sev3, type Sev3 } from './telemetry'

/**
 * The recorded wire: Zeek connections, RADIUS results and switch syslog of the dataset day, decoded
 * from GET /api/telemetry into typed arrays the replay can index by time. Nothing here creates a
 * record; every row is a line of a dataset file, and every view built on it reads from these arrays.
 */

export type Family = 'tls' | 'dns' | 'web' | 'file' | 'admin' | 'dir' | 'infra' | 'other'
export const FAMILIES: Family[] = ['tls', 'dns', 'web', 'file', 'admin', 'dir', 'infra', 'other']
export const FAMILY_LABEL: Record<Family, string> = {
  tls: 'TLS',
  dns: 'DNS',
  web: 'HTTP',
  file: 'file / RPC',
  admin: 'SSH / RDP',
  dir: 'Kerberos / LDAP / RADIUS',
  infra: 'NTP / DHCP / ICMP',
  other: 'other TCP / UDP',
}
const SERVICE_FAMILY: Record<string, Family> = {
  ssl: 'tls',
  dns: 'dns',
  http: 'web',
  smb: 'file',
  netbios: 'file',
  dce_rpc: 'file',
  ipp: 'file',
  ssh: 'admin',
  rdp: 'admin',
  krb_tcp: 'dir',
  krb: 'dir',
  ldap: 'dir',
  radius: 'dir',
  ntp: 'infra',
  dhcp: 'infra',
  icmp: 'infra',
}
export function familyOf(service: string | undefined): Family {
  return (service && SERVICE_FAMILY[service]) || 'other'
}

export interface AuthRow {
  t: number
  result: string
  user: string | null
  device: string | null
  port: string | null
  method: string | null
  vlan: number | null
}
export interface SyslogRow {
  t: number
  severity: number
  mnemonic: string
  port: string | null
  message: string
}

export interface Wire {
  /** epoch ms of the dataset day's UTC midnight */
  start: number
  n: number
  /** epoch ms, ascending */
  t: Float64Array
  o: Int32Array
  r: Int32Array
  p: Int32Array
  svc: Int32Array
  fam: Uint8Array
  b: Float64Array
  d: Int32Array
  hosts: string[]
  services: string[]
  details: string[]
  auth: AuthRow[]
  authT: Float64Array
  syslog: SyslogRow[]
  syslogT: Float64Array
  files: Record<string, string>
}

export function decodeWire(f: TelemetryFeed): Wire {
  const start = ms(f.start)
  const n = f.conn.t.length
  const famOfSvc = f.services.map((s) => FAMILIES.indexOf(familyOf(s)))
  const t = new Float64Array(n)
  const fam = new Uint8Array(n)
  for (let i = 0; i < n; i++) {
    t[i] = start + f.conn.t[i]
    fam[i] = famOfSvc[f.conn.s[i]] ?? FAMILIES.length - 1
  }
  const auth = f.auth.map((a) => ({ ...a, t: start + a.t }))
  const syslog = f.syslog.map((s) => ({ ...s, t: start + s.t }))
  return {
    start,
    n,
    t,
    o: Int32Array.from(f.conn.o),
    r: Int32Array.from(f.conn.r),
    p: Int32Array.from(f.conn.p),
    svc: Int32Array.from(f.conn.s),
    fam,
    b: Float64Array.from(f.conn.b),
    d: Int32Array.from(f.conn.d),
    hosts: f.hosts,
    services: f.services,
    details: f.details,
    auth,
    authT: Float64Array.from(auth.map((a) => a.t)),
    syslog,
    syslogT: Float64Array.from(syslog.map((s) => s.t)),
    files: f.files,
  }
}

/** Number of entries of an ascending array that are ≤ x (so `[upper(a, t0), upper(a, t1))` is the range (t0, t1]). */
export function upper(a: Float64Array, x: number): number {
  let lo = 0
  let hi = a.length
  while (lo < hi) {
    const m = (lo + hi) >>> 1
    if (a[m] <= x) lo = m + 1
    else hi = m
  }
  return lo
}

export interface WireBins {
  start: number
  binMs: number
  /** connections per bin, one array per family in FAMILIES order */
  fam: Uint16Array[]
  conn: Uint16Array
  authOk: Uint16Array
  authBad: Uint16Array
  authGuest: Uint16Array
  sysHigh: Uint16Array
  sysWarn: Uint16Array
  sysInfo: Uint16Array
}

export function binWire(w: Wire, start: number, end: number, binMs: number, until = Infinity): WireBins {
  const nb = Math.max(1, Math.ceil((end - start) / binMs))
  const mk = () => new Uint16Array(nb)
  const out: WireBins = { start, binMs, fam: FAMILIES.map(mk), conn: mk(), authOk: mk(), authBad: mk(), authGuest: mk(), sysHigh: mk(), sysWarn: mk(), sysInfo: mk() }
  const at = (x: number) => (x > until ? -1 : Math.floor((x - start) / binMs))
  for (let i = 0; i < w.n; i++) {
    const k = at(w.t[i])
    if (k < 0 || k >= nb) continue
    out.fam[w.fam[i]][k]++
    out.conn[k]++
  }
  for (const a of w.auth) {
    const k = at(a.t)
    if (k < 0 || k >= nb) continue
    if (a.result === 'Access-Accept') out.authOk[k]++
    else if (a.result === 'Access-Reject') out.authBad[k]++
    else out.authGuest[k]++
  }
  for (const s of w.syslog) {
    const k = at(s.t)
    if (k < 0 || k >= nb) continue
    if (s.severity <= 3) out.sysHigh[k]++
    else if (s.severity === 4) out.sysWarn[k]++
    else out.sysInfo[k]++
  }
  return out
}

/** Records of every kind per bin, for pacing the replay through quiet stretches. */
export function recordDensity(w: Wire, alerts: Alert[], start: number, end: number, binMs: number): Float32Array {
  const b = binWire(w, start, end, binMs)
  const out = new Float32Array(b.conn.length)
  for (let k = 0; k < out.length; k++) out[k] = b.conn[k] + b.authOk[k] + b.authBad[k] + b.authGuest[k] + b.sysHigh[k] + b.sysWarn[k] + b.sysInfo[k]
  for (const a of alerts) {
    const k = Math.floor((ms(a.ts) - start) / binMs)
    if (k >= 0 && k < out.length) out[k] += 1
  }
  return out
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(n < 10 * 1024 ? 1 : 0)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

export type LineKind = 'conn' | 'auth' | 'syslog' | 'alert'
export interface WireLine {
  key: string
  t: number
  kind: LineKind
  /** colour class: a service family, an auth result, a syslog level or an alert severity */
  tone: string
  tag: string
  text: string
}

function clock(t: number): string {
  const d = new Date(t)
  const p = (n: number, w = 2) => String(n).padStart(w, '0')
  return `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}.${p(d.getUTCMilliseconds(), 3)}`
}
export { clock as wireClock }

/** The newest `count` Zeek connections at or before `t`, oldest first. `names` maps an address to its inventory hostname. */
export function connLines(w: Wire, t: number, count: number, names: Map<string, string>, families?: Set<Family>): WireLine[] {
  const host = (i: number) => names.get(w.hosts[i]) ?? w.hosts[i]
  const out: WireLine[] = []
  for (let ci = upper(w.t, t) - 1; ci >= 0 && out.length < count; ci--) {
    const f = FAMILIES[w.fam[ci]]
    if (families && !families.has(f)) continue
    const det = w.d[ci] >= 0 ? `  ${w.details[w.d[ci]]}` : ''
    out.push({ key: `c${ci}`, t: w.t[ci], kind: 'conn', tone: `svc-${f}`, tag: w.services[w.svc[ci]] ?? '?', text: `${host(w.o[ci])} → ${host(w.r[ci])}:${w.p[ci]}${det}  ${fmtBytes(w.b[ci])}` })
  }
  return out.reverse()
}

/** The newest `count` RADIUS results, syslog lines and alerts at or before `t`, oldest first. `alerts` is ascending by time. */
export function eventLines(w: Wire, alerts: Alert[], alertT: Float64Array, t: number, count: number): WireLine[] {
  const out: WireLine[] = []
  for (let ai = upper(w.authT, t) - 1, k = 0; ai >= 0 && k < count; ai--, k++) {
    const a = w.auth[ai]
    const tone = a.result === 'Access-Accept' ? 'ok' : a.result === 'Access-Reject' ? 'bad' : 'guest'
    out.push({ key: `a${ai}`, t: a.t, kind: 'auth', tone: `auth-${tone}`, tag: 'radius', text: `${a.result} ${a.user ?? '?'}${a.device ? ` (${a.device})` : ''} ${a.port ?? ''} ${a.method ?? ''}${a.vlan != null ? ` → VLAN ${a.vlan}` : ''}` })
  }
  for (let si = upper(w.syslogT, t) - 1, k = 0; si >= 0 && k < count; si--, k++) {
    const s = w.syslog[si]
    const tone = s.severity <= 3 ? 'high' : s.severity === 4 ? 'warn' : 'info'
    out.push({ key: `s${si}`, t: s.t, kind: 'syslog', tone: `sys-${tone}`, tag: 'syslog', text: `${s.mnemonic}: ${s.message}` })
  }
  for (let ai = upper(alertT, t) - 1, k = 0; ai >= 0 && k < count; ai--, k++) {
    const a = alerts[ai]
    const sv: Sev3 = sev3(a.severity)
    out.push({ key: `x${a.id}`, t: alertT[ai], kind: 'alert', tone: `sev-${sv}`, tag: `${a.source} alert`, text: `${a.signature}${a.interface ? `  ${a.interface}` : ''}${a.device ? ` ${a.device}` : ''}` })
  }
  out.sort((a, b) => a.t - b.t)
  return out.slice(-count)
}

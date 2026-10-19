import type { Alert, Severity } from './api'

/**
 * Client-side derivations over records the API already returned. Every function documents what it
 * counts; nothing here invents, interpolates or extrapolates data. Timestamps are on the simulated
 * switch clock (UTC).
 */

export type Sev3 = 'high' | 'medium' | 'low'
export const SEVERITIES: Sev3[] = ['high', 'medium', 'low']
export const SOURCES = ['suricata', 'zeek', 'radius', 'syslog'] as const
export type Source = (typeof SOURCES)[number]

/** Severity folded onto the three-level scale used by the charts (critical → high, info → low). */
export function sev3(s: Severity | string | null | undefined): Sev3 {
  if (s === 'critical' || s === 'high') return 'high'
  if (s === 'medium') return 'medium'
  return 'low'
}

export function ms(ts: string | null | undefined): number {
  return ts ? Date.parse(ts) : NaN
}

export interface Window {
  start: number
  end: number
}

export interface AlertFilter {
  severities: Set<Sev3>
  sources: Set<string>
}

export function inWindow(a: Alert, w: Window): boolean {
  const t = ms(a.ts)
  return t >= w.start && t < w.end
}

export interface Bin {
  t0: number
  high: number
  medium: number
  low: number
  total: number
}

/** Alerts per fixed-width bin across [start, end); empty bins are kept as zero (not interpolated). */
export function binAlerts(alerts: Alert[], start: number, end: number, binMs: number): Bin[] {
  const n = Math.max(1, Math.ceil((end - start) / binMs))
  const bins: Bin[] = Array.from({ length: n }, (_, i) => ({ t0: start + i * binMs, high: 0, medium: 0, low: 0, total: 0 }))
  for (const a of alerts) {
    const t = ms(a.ts)
    if (!(t >= start && t < end)) continue
    const b = bins[Math.min(n - 1, Math.floor((t - start) / binMs))]
    b[sev3(a.severity)] += 1
    b.total += 1
  }
  return bins
}

export function severityCounts(alerts: Alert[]): Record<Sev3, number> {
  const c: Record<Sev3, number> = { high: 0, medium: 0, low: 0 }
  for (const a of alerts) c[sev3(a.severity)] += 1
  return c
}

/** Alerts per detection source, split by severity, in the order of SOURCES (sources with zero alerts kept). */
export function bySource(alerts: Alert[]): { source: string; counts: Record<Sev3, number>; total: number }[] {
  const rows = new Map<string, Record<Sev3, number>>()
  for (const s of SOURCES) rows.set(s, { high: 0, medium: 0, low: 0 })
  for (const a of alerts) {
    if (!rows.has(a.source)) rows.set(a.source, { high: 0, medium: 0, low: 0 })
    rows.get(a.source)![sev3(a.severity)] += 1
  }
  return [...rows.entries()].map(([source, counts]) => ({ source, counts, total: counts.high + counts.medium + counts.low }))
}

/**
 * Alerts grouped by the endpoint they were attributed to. The key is the inventory hostname when the
 * alert carries one, otherwise the switch port with an "unregistered" marker; alerts with neither are
 * grouped as "unattributed".
 */
export function byEndpoint(alerts: Alert[]): { key: string; device: string | null; port: string | null; counts: Record<Sev3, number>; total: number }[] {
  const rows = new Map<string, { key: string; device: string | null; port: string | null; counts: Record<Sev3, number>; total: number }>()
  for (const a of alerts) {
    const key = a.device ?? (a.interface ? `${a.interface}` : 'unattributed')
    if (!rows.has(key)) rows.set(key, { key, device: a.device, port: a.interface, counts: { high: 0, medium: 0, low: 0 }, total: 0 })
    const r = rows.get(key)!
    r.counts[sev3(a.severity)] += 1
    r.total += 1
  }
  return [...rows.values()].sort((a, b) => b.total - a.total || b.counts.high - a.counts.high || a.key.localeCompare(b.key))
}

export function fmtClock(t: number, withSeconds = false): string {
  if (!Number.isFinite(t)) return '—'
  const iso = new Date(t).toISOString()
  return withSeconds ? iso.slice(11, 19) : iso.slice(11, 16)
}

/** Window end: a midnight that closes a window is written 24:00 so a full day never reads 00:00–00:00. */
export function fmtEnd(start: number, end: number): string {
  const c = fmtClock(end)
  return c === '00:00' && end > start ? '24:00' : c
}

export function fmtSpan(msSpan: number): string {
  const m = Math.round(msSpan / 60000)
  if (m < 60) return `${m} min`
  const h = m / 60
  return Number.isInteger(h) ? `${h} h` : `${h.toFixed(1)} h`
}

export function portNumber(name: string): string {
  const m = /^(Gi|Te|Fa)\d+\/\d+\/(\d+)$/.exec(name)
  if (!m) return name
  return m[1] === 'Te' ? `T${m[2]}` : m[2]
}

export function portOrder(a: string, b: string): number {
  return a.localeCompare(b, undefined, { numeric: true })
}

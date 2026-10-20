export function fmtTime(ts: string | null | undefined, opts: { ms?: boolean; date?: boolean } = {}): string {
  if (!ts) return '—'
  const t = ts.replace('Z', '')
  const [date, time] = t.split('T')
  const hhmmss = opts.ms === false ? (time ?? '').slice(0, 8) : (time ?? '').slice(0, 12)
  return opts.date ? `${date} ${hhmmss}` : hhmmss
}

export function fmtDate(ts: string | null | undefined): string {
  if (!ts) return '—'
  return ts.slice(0, 10)
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let v = n / 1024
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`
}

export function fmtNum(n: number | null | undefined, digits = 0): string {
  if (n === null || n === undefined) return '—'
  return n.toLocaleString('en-US', { maximumFractionDigits: digits, minimumFractionDigits: digits })
}

export function fmtSeconds(s: number | null | undefined): string {
  if (s === null || s === undefined) return '—'
  if (s >= 120) return `${(s / 60).toFixed(1)} min`
  return `${s.toFixed(3)} s`
}

export function pct(n: number | null | undefined, digits = 1): string {
  if (n === null || n === undefined) return '—'
  return `${n.toFixed(digits)}%`
}

export function title(s: string | null | undefined): string {
  if (!s) return ''
  return s.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

export function sevRank(s: string): number {
  return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[s] ?? 0
}

export function vlanName(v: number | null | undefined): string {
  const names: Record<number, string> = { 10: 'MGMT', 20: 'USERS', 30: 'SERVERS', 40: 'GUEST', 50: 'QUARANTINE', 99: 'MONITORING', 999: 'BLACKHOLE' }
  if (v === null || v === undefined) return '—'
  return names[v] ? `${v} ${names[v]}` : String(v)
}

/** True when an analyst authorization was made by the demo replay's scripted analyst, not at the console. */
export function isScripted(a: { channel?: string } | null | undefined): boolean {
  return a?.channel === 'scripted-demo'
}

/** "analyst · tlee" or "automatic · policy-engine", with the scripted-demo channel when it applies. */
export function authLabel(a: { mode: string; authorized_by?: string | null; channel?: string } | null | undefined): string {
  if (!a) return 'not recorded'
  return `${a.mode}${a.authorized_by ? ` · ${a.authorized_by}` : ''}${isScripted(a) ? ' · scripted demo' : ''}`
}

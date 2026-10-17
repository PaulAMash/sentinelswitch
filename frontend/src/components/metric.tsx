import type { ReactNode } from 'react'
import type { AssessmentStatus } from '../lib/api'

export type MetricTone = 'accent' | 'danger' | 'good' | 'warn'

/** Single number with label, optional unit/hint/chip; `hero` enlarges the value. */
export function Metric({ label, value, unit, hint, tone, chip, hero = false, className = '' }: { label: ReactNode; value: ReactNode; unit?: string; hint?: ReactNode; tone?: MetricTone; chip?: ReactNode; hero?: boolean; className?: string }) {
  return (
    <div className={`panel metric ${tone ?? ''} ${hero ? 'hero' : ''} ${className}`}>
      <div className="label">
        <span className="eyebrow">{label}</span>
        {chip}
      </div>
      <div className="value">
        {value}
        {unit && <small>{unit}</small>}
      </div>
      {hint && <div className="hint">{hint}</div>}
    </div>
  )
}

/** "n / d" with denominators always visible so a rate is never shown without its base. */
export function Ratio({ num, den, suffix }: { num: ReactNode; den: ReactNode; suffix?: string }) {
  return (
    <span className="ratio">
      <span>{num}</span>
      <span className="den">/ {den}{suffix ? ` ${suffix}` : ''}</span>
    </span>
  )
}

/** Proportional PASS/FAIL/UNKNOWN/STALE bar. Zero-width segments are omitted, never padded. */
export function StatusBar({ counts, large = false, label }: { counts: Partial<Record<AssessmentStatus, number>>; large?: boolean; label?: string }) {
  const order: AssessmentStatus[] = ['PASS', 'FAIL', 'UNKNOWN', 'STALE']
  const total = order.reduce((s, k) => s + (counts[k] ?? 0), 0)
  const desc = order.map((k) => `${k} ${counts[k] ?? 0}`).join(', ')
  return (
    <div className={`status-bar ${large ? 'lg' : ''}`} role="img" aria-label={label ? `${label}: ${desc}` : desc} title={desc}>
      {total === 0 ? null : order.map((k) => ((counts[k] ?? 0) > 0 ? <span key={k} className={k} style={{ width: `${((counts[k] ?? 0) / total) * 100}%` }} /> : null))}
    </div>
  )
}

/** Four small count cells; lit only when non-zero so empty states read as empty. */
export function Counts({ counts }: { counts: Partial<Record<AssessmentStatus, number>> }) {
  const order: AssessmentStatus[] = ['PASS', 'FAIL', 'UNKNOWN', 'STALE']
  return (
    <span className="counts">
      {order.map((k) => (
        <span key={k} className={`${k} ${(counts[k] ?? 0) > 0 ? 'on' : ''}`} title={k}>
          {counts[k] ?? 0}
        </span>
      ))}
    </span>
  )
}

export function MetricBand({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`grid-metrics ${className}`}>{children}</div>
}

import type { ReactNode } from 'react'
import { fmtTime, title } from '../lib/format'
import type { KVRow } from '../lib/kv'

export function Card({ title: t, sub, right, children, className = '', bodyClass = '' }: { title?: ReactNode; sub?: ReactNode; right?: ReactNode; children: ReactNode; className?: string; bodyClass?: string }) {
  return (
    <section className={`card ${className}`}>
      {(t || right) && (
        <header className="card-head">
          <h2>
            {t}
            {sub && <span className="sub">{sub}</span>}
          </h2>
          {right}
        </header>
      )}
      <div className={`card-body ${bodyClass}`}>{children}</div>
    </section>
  )
}

export function Kpi({ label, value, unit, hint, tone, chip }: { label: string; value: ReactNode; unit?: string; hint?: string; tone?: 'accent' | 'danger' | 'good' | 'warn'; chip?: ReactNode }) {
  return (
    <div className={`card kpi ${tone ?? ''}`}>
      <div className="label">
        <span>{label}</span>
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

export function Chip({ kind, children, className = '' }: { kind: string; children?: ReactNode; className?: string }) {
  return <span className={`chip ${kind} ${className}`}>{children ?? title(kind)}</span>
}

export function Sev({ s }: { s: string }) {
  return <Chip kind={s}>{s}</Chip>
}

export function Ts({ ts, date = false }: { ts: string | null | undefined; date?: boolean }) {
  if (!ts) return <span className="ts">—</span>
  // Simulated-clock timestamps are UTC; the tooltip always carries the full ISO value.
  return (
    <span className="ts" title={`${ts} (UTC, simulated clock)`}>
      {date && <><span className="date">{ts.slice(0, 10)}</span>{' '}</>}
      <span className="time">{fmtTime(ts)}</span>
    </span>
  )
}

export function Empty({ children = 'Nothing to show' }: { children?: ReactNode }) {
  return <div className="empty">{children}</div>
}

export function Loading({ error }: { error?: string | null }) {
  if (error) return <div className="error">Could not load data: {error}. Is the API running? (make dev)</div>
  return <div className="loading">Loading…</div>
}

export function Term({ text, hl = [] }: { text: string; hl?: string[] }) {
  const lines = text.split('\n')
  return (
    <pre className="term">
      {lines.map((l, i) => {
        const isPrompt = /^[A-Za-z0-9-]+[#>]/.test(l)
        const isHl = hl.some((h) => l.includes(h))
        return (
          <span key={i} className={isPrompt ? 'prompt' : isHl ? 'hl' : undefined}>
            {l}
            {'\n'}
          </span>
        )
      })}
    </pre>
  )
}

export function KV({ rows }: { rows: KVRow[] }) {
  return (
    <dl className="kv">
      {rows.map(([k, v]) => (
        <div key={k} style={{ display: 'contents' }}>
          <dt>{k}</dt>
          <dd>{v ?? '—'}</dd>
        </div>
      ))}
    </dl>
  )
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: string }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div className="tabs">
      {tabs.map((t) => (
        <button key={t.id} className={t.id === value ? 'active' : ''} onClick={() => onChange(t.id)}>
          {t.label}
        </button>
      ))}
    </div>
  )
}

export function Drawer({ title: t, onClose, children }: { title: ReactNode; onClose: () => void; children: ReactNode }) {
  return (
    <aside className="drawer fade-in">
      <div className="drawer-head">
        <h2>{t}</h2>
        <button className="btn sm" onClick={onClose} aria-label="Close">
          ✕
        </button>
      </div>
      <div className="drawer-body">{children}</div>
    </aside>
  )
}

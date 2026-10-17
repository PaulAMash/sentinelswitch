import { useEffect, useId, useRef, type KeyboardEvent, type ReactNode } from 'react'
import { fmtTime } from '../lib/format'
import type { KVRow } from '../lib/kv'
import { Icon } from './Icons'
export { Chip } from './status'

/** Panel: titled container with an optional header row and collapse toggle. */
export function Panel({ title: t, sub, right, children, className = '', bodyClass = '', collapsible = false, collapsed = false, onToggle, id }: { title?: ReactNode; sub?: ReactNode; right?: ReactNode; children: ReactNode; className?: string; bodyClass?: string; collapsible?: boolean; collapsed?: boolean; onToggle?: () => void; id?: string }) {
  const hid = useId()
  return (
    <section className={`panel ${className} ${collapsed ? 'collapsed' : ''}`} id={id} aria-labelledby={t ? hid : undefined}>
      {(t || right) && (
        <header className="panel-head">
          <h2 id={hid}>
            {t}
            {sub && <span className="sub">{sub}</span>}
          </h2>
          <div className="right">
            {right}
            {collapsible && (
              <button className="toggle" type="button" onClick={onToggle} aria-expanded={!collapsed} aria-label={collapsed ? 'Expand' : 'Collapse'}>
                {collapsed ? <Icon.chevron /> : <Icon.chevronDown />}
              </button>
            )}
          </div>
        </header>
      )}
      <div className={`panel-body ${bodyClass}`}>{children}</div>
    </section>
  )
}

export function Ts({ ts, date = false, ms = true }: { ts: string | null | undefined; date?: boolean; ms?: boolean }) {
  if (!ts) return <span className="ts">—</span>
  // Simulated-clock timestamps are UTC; the tooltip always carries the full ISO value.
  return (
    <span className="ts mono" title={`${ts} (UTC, simulated clock)`}>
      {date && (
        <>
          <span className="date">{ts.slice(0, 10)}</span>{' '}
        </>
      )}
      <span className="time">{fmtTime(ts, { ms })}</span>
    </span>
  )
}

export function Empty({ children = 'Nothing to show' }: { children?: ReactNode }) {
  return <div className="empty">{children}</div>
}

export function Loading({ error, rows = 3 }: { error?: string | null; rows?: number }) {
  if (error) return <ErrorState error={error} />
  return (
    <div className="skeleton" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <span key={i} style={{ width: `${88 - i * 14}%` }} />
      ))}
    </div>
  )
}

export function ErrorState({ error, retry }: { error: string; retry?: () => void }) {
  return (
    <div className="error" role="alert">
      <span>Could not load data: {error}. Is the API running? (make dev)</span>
      {retry && (
        <button className="btn sm" type="button" onClick={retry}>
          Retry
        </button>
      )}
    </div>
  )
}

export function Notice({ tone = '', children }: { tone?: '' | 'warn' | 'ok'; children: ReactNode }) {
  return <div className={`notice ${tone}`}>{children}</div>
}

export function KV({ rows }: { rows: KVRow[] }) {
  return (
    <dl className="kv">
      {rows.map(([k, v]) => (
        <div key={k} className="contents">
          <dt>{k}</dt>
          <dd>{v ?? '—'}</dd>
        </div>
      ))}
    </dl>
  )
}

/** Tab strip with roving focus (Left/Right/Home/End). */
export function Tabs<T extends string>({ tabs, value, onChange, label }: { tabs: { id: T; label: ReactNode; count?: number }[]; value: T; onChange: (v: T) => void; label?: string }) {
  const refs = useRef<(HTMLButtonElement | null)[]>([])
  const onKey = (e: KeyboardEvent, i: number) => {
    let next = i
    if (e.key === 'ArrowRight') next = (i + 1) % tabs.length
    else if (e.key === 'ArrowLeft') next = (i - 1 + tabs.length) % tabs.length
    else if (e.key === 'Home') next = 0
    else if (e.key === 'End') next = tabs.length - 1
    else return
    e.preventDefault()
    onChange(tabs[next].id)
    refs.current[next]?.focus()
  }
  return (
    <div className="tabs" role="tablist" aria-label={label}>
      {tabs.map((t, i) => (
        <button
          key={t.id}
          ref={(el) => {
            refs.current[i] = el
          }}
          role="tab" type="button" aria-selected={t.id === value} tabIndex={t.id === value ? 0 : -1} className={t.id === value ? 'active' : ''} onClick={() => onChange(t.id)} onKeyDown={(e) => onKey(e, i)}>
          {t.label}
          {t.count !== undefined && <span className="dim"> {t.count}</span>}
        </button>
      ))}
    </div>
  )
}

/** Segmented control for filters (single select). */
export function Segmented<T extends string>({ options, value, onChange, label }: { options: { id: T; label: ReactNode }[]; value: T; onChange: (v: T) => void; label?: string }) {
  return (
    <div className="seg" role="group" aria-label={label}>
      {options.map((o) => (
        <button key={o.id} type="button" className={o.id === value ? 'active' : ''} aria-pressed={o.id === value} onClick={() => onChange(o.id)}>
          {o.label}
        </button>
      ))}
    </div>
  )
}

/**
 * Right-hand drawer: Escape closes, focus moves in on open and back to the opener on close,
 * the backdrop closes on click, and the page behind is inert for assistive tech.
 */
export function Drawer({ title: t, onClose, children, sub }: { title: ReactNode; sub?: ReactNode; onClose: () => void; children: ReactNode }) {
  const ref = useRef<HTMLElement>(null)
  const hid = useId()
  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null
    ref.current?.querySelector<HTMLElement>('button, [href], input, [tabindex]:not([tabindex="-1"])')?.focus()
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        onClose()
      }
    }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      opener?.focus?.()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} aria-hidden="true" />
      <aside className="drawer" ref={ref} role="dialog" aria-modal="true" aria-labelledby={hid}>
        <div className="drawer-head">
          <h2 id={hid}>
            {t}
            {sub && <span className="sub dim small">{sub}</span>}
          </h2>
          <button className="btn sm icon ghost" type="button" onClick={onClose} aria-label="Close">
            <Icon.close />
          </button>
        </div>
        <div className="drawer-body">{children}</div>
      </aside>
    </>
  )
}

export function Button({ children, tone = '', size = '', icon, className = '', ...rest }: { children?: ReactNode; tone?: '' | 'primary' | 'consequential' | 'destructive' | 'ghost'; size?: '' | 'sm'; icon?: ReactNode; className?: string } & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button type="button" className={`btn ${tone} ${size} ${!children ? 'icon' : ''} ${className}`} {...rest}>
      {icon}
      {children}
    </button>
  )
}

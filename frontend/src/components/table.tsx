import type { ReactNode } from 'react'

export type HideBelow = 400 | 500 | 600 | 700 | 800 | 900 | 1000 | 1100 | 1200 | 1300

export interface Column<T> {
  key: string
  header: ReactNode
  render: (row: T, index: number) => ReactNode
  className?: string
  /**
   * Progressive disclosure: hide the column while the table's own container is narrower than this
   * many px (a container query, so a table in a half-width panel sheds detail before a full-width one).
   * Rows with a drawer or detail page keep every field there.
   */
  hideBelow?: HideBelow
  align?: 'left' | 'right'
  wrap?: boolean
  /** plain-text label for stacked (card) mode; defaults to header when it is a string */
  label?: string
}

export interface DataTableProps<T> {
  columns: Column<T>[]
  rows: T[] | null | undefined
  rowKey: (row: T, index: number) => string
  /** Keyboard-activatable rows: Enter / Space trigger, Tab reaches them. */
  onRowActivate?: (row: T) => void
  selectedKey?: string | null
  rowClass?: (row: T) => string
  loading?: boolean
  error?: string | null
  empty?: ReactNode
  compact?: boolean
  /**
   * Stacked label/value cards when the table's container is too narrow for a row: `true` below 900 px
   * (queue-style tables whose every column matters), `'narrow'` on phone and small-tablet viewports below 720 px.
   * Columns hidden by `hideBelow` stay hidden in cards.
   */
  cards?: boolean | 'narrow'
  className?: string
  /** aria-label for the table */
  label?: string
  footer?: ReactNode
}

function colClass<T>(c: Column<T>): string {
  return [c.className ?? '', c.hideBelow ? `hide-lt${c.hideBelow}` : '', c.align === 'right' ? 'num' : '', c.wrap ? 'wrap' : ''].filter(Boolean).join(' ')
}

/**
 * The only table in the app. Loading, error and empty states render as a single state row so the
 * header stays put; rows that act on activation are focusable and announce selection.
 */
export function DataTable<T>(p: DataTableProps<T>) {
  const cols = p.columns
  const state = p.error ? (
    <tr className="state-row">
      <td colSpan={cols.length}>
        <span className="danger">Could not load: {p.error}</span>
      </td>
    </tr>
  ) : p.loading && !p.rows ? (
    <tr className="state-row">
      <td colSpan={cols.length}>Loading…</td>
    </tr>
  ) : p.rows && p.rows.length === 0 ? (
    <tr className="state-row">
      <td colSpan={cols.length}>{p.empty ?? 'Nothing to show'}</td>
    </tr>
  ) : null
  return (
    <div className={`table-wrap ${p.cards === 'narrow' ? 'cards-sm' : p.cards ? 'cards' : ''} ${p.className ?? ''}`}>
      <table className={`data ${p.compact ? 'compact' : ''}`} aria-label={p.label}>
        <thead>
          <tr>
            {cols.map((c) => (
              <th key={c.key} className={colClass(c)} scope="col">
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {state ??
            (p.rows ?? []).map((row, i) => {
              const k = p.rowKey(row, i)
              const act = p.onRowActivate
              const selected = p.selectedKey != null && p.selectedKey === k
              return (
                <tr
                  key={k}
                  className={`${act ? 'clickable' : ''} ${p.rowClass?.(row) ?? ''}`}
                  tabIndex={act ? 0 : undefined}
                  aria-selected={act ? selected : undefined}
                  onClick={act ? () => act(row) : undefined}
                  onKeyDown={
                    act
                      ? (e) => {
                          if (e.target !== e.currentTarget) return
                          if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault()
                            act(row)
                          }
                        }
                      : undefined
                  }
                >
                  {cols.map((c) => (
                    <td key={c.key} className={colClass(c)} data-label={c.label ?? (typeof c.header === 'string' ? c.header : undefined)}>
                      {c.render(row, i)}
                    </td>
                  ))}
                </tr>
              )
            })}
        </tbody>
        {p.footer && <tfoot>{p.footer}</tfoot>}
      </table>
    </div>
  )
}

/** Two-line cell: primary on top, secondary muted below. */
export function Cell2({ primary, secondary }: { primary: ReactNode; secondary?: ReactNode }) {
  return (
    <span className="cell-2">
      <span>{primary}</span>
      {secondary != null && secondary !== '' && <span className="secondary">{secondary}</span>}
    </span>
  )
}

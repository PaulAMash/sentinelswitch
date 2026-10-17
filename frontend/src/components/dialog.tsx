import { useEffect, useId, useRef, type ReactNode } from 'react'

export interface ConfirmDialogProps {
  open: boolean
  title: string
  /** consequential = changes state through an authorized workflow; destructive = discards state */
  tone: 'consequential' | 'destructive'
  /** what will change, on which port / VLAN / record */
  summary: ReactNode
  /** editable note sent with the request; omit when the action takes none */
  note?: { label: string; value: string; onChange: (v: string) => void }
  /** shown only when the request records an actor (plan guardrail 7) */
  actor?: string | null
  confirmLabel: string
  busy?: boolean
  error?: string | null
  onCancel: () => void
  onConfirm: () => void
}

/**
 * Native <dialog> confirmation. Focus is trapped by the browser's modal behaviour; initial focus goes
 * to Cancel for destructive dialogs and to the note (or confirm) for consequential ones; Escape
 * always cancels and never confirms; Enter submits only consequential dialogs; focus returns to the
 * opener when the dialog closes (the browser restores it for showModal()).
 */
export function ConfirmDialog(p: ConfirmDialogProps) {
  const ref = useRef<HTMLDialogElement>(null)
  const cancelRef = useRef<HTMLButtonElement>(null)
  const confirmRef = useRef<HTMLButtonElement>(null)
  const noteRef = useRef<HTMLTextAreaElement>(null)
  const titleId = useId()
  useEffect(() => {
    const d = ref.current
    if (!d) return
    if (p.open && !d.open) {
      d.showModal()
      const target = p.tone === 'destructive' ? cancelRef.current : noteRef.current ?? confirmRef.current
      target?.focus()
    } else if (!p.open && d.open) {
      d.close()
    }
  }, [p.open, p.tone])
  const onCancelEvent = (e: React.SyntheticEvent) => {
    e.preventDefault()
    if (!p.busy) p.onCancel()
  }
  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && p.tone === 'consequential' && !p.busy && !(e.target instanceof HTMLTextAreaElement)) {
      e.preventDefault()
      p.onConfirm()
    }
  }
  return (
    <dialog ref={ref} className={`confirm ${p.tone}`} aria-labelledby={titleId} aria-modal="true" onCancel={onCancelEvent} onKeyDown={onKey}>
      <div className="dlg-head">
        <h2 id={titleId}>{p.title}</h2>
      </div>
      <div className="dlg-body">
        <div className="consequence">{p.summary}</div>
        {p.note && (
          <label className="field">
            {p.note.label}
            <textarea ref={noteRef} value={p.note.value} onChange={(e) => p.note?.onChange(e.target.value)} rows={2} disabled={p.busy} />
          </label>
        )}
        {p.actor && <div className="actor">Recorded as analyst <span className="mono">{p.actor}</span> (demo identity, no sign-in).</div>}
        {p.error && <div className="error">{p.error}</div>}
      </div>
      <div className="dlg-foot">
        <button ref={cancelRef} className="btn" type="button" onClick={p.onCancel} disabled={p.busy}>
          Cancel
        </button>
        <button ref={confirmRef} className={`btn ${p.tone}`} type="button" onClick={p.onConfirm} disabled={p.busy}>
          {p.busy ? 'Working…' : p.confirmLabel}
        </button>
      </div>
    </dialog>
  )
}

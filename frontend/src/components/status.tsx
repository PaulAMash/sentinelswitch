import type { ReactNode } from 'react'
import type { AssessmentStatus, Authorization, ContainmentAction, Finding, FindingStatus, Incident } from '../lib/api'
import { title } from '../lib/format'

export type Tone = 'ok' | 'warn' | 'danger' | 'info' | 'withheld' | 'neutral' | 'accent' | 'outline'

/** Base chip. `kind` is a backend vocabulary word (status, severity, disposition) or a tone. */
export function Chip({ kind = 'neutral', children, className = '', title: t, mono = false }: { kind?: string; children?: ReactNode; className?: string; title?: string; mono?: boolean }) {
  return (
    <span className={`chip ${kind} ${mono ? 'mono' : ''} ${className}`} title={t}>
      {children ?? title(kind)}
    </span>
  )
}

/** Lifecycle / status word rendered exactly as the backend states it. */
export function StatusChip({ value, mono = false }: { value: string | null | undefined; mono?: boolean }) {
  if (!value) return <Chip kind="outline">—</Chip>
  return (
    <Chip kind={value} mono={mono}>
      {value.replace(/_/g, ' ')}
    </Chip>
  )
}

export function SeverityChip({ value }: { value: string | null | undefined }) {
  if (!value) return <Chip kind="outline">—</Chip>
  return (
    <Chip kind={value}>
      <span className={`sev-dot ${value}`} aria-hidden="true" />
      {value}
    </Chip>
  )
}
/** PASS / FAIL / UNKNOWN / STALE / RETIRED / NOT_ASSESSED exactly as reported. */
export function AssessChip({ value, className = '' }: { value: AssessmentStatus | 'NOT_ASSESSED' | null | undefined; className?: string }) {
  if (!value) return <Chip kind="outline">—</Chip>
  return (
    <Chip kind={value} className={`caps mono ${className}`}>
      {value.replace(/_/g, ' ')}
    </Chip>
  )
}

export function LifecycleChip({ value }: { value: FindingStatus | string | null | undefined }) {
  return <StatusChip value={value} />
}

/** Monospace identifier (incident, detection, control, run ids). */
export function Id({ children, dim = false, className = '' }: { children: ReactNode; dim?: boolean; className?: string }) {
  return <span className={`id ${dim ? 'dim' : ''} ${className}`}>{children}</span>
}

export function Mono({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <span className={`mono ${className}`}>{children}</span>
}

/* ---------------------------------------------------------------- response state
   One derivation shared by the incident list, the incident workspace, the overview rail and the
   review queue. It reads backend fields only; it never infers that containment happened or was
   verified from anything other than the action's own verification record. */
export type ResponseState =
  | 'in-progress'
  | 'failed'
  | 'restored-verified'
  | 'restored'
  | 'contained-verified'
  | 'executed-unverified'
  | 'withheld'
  | 'declined'
  | 'authorized'
  | 'awaiting'
  | 'suggested'

export function responseStateOf(incident: Pick<Incident, 'status' | 'disposition' | 'authorization'> | null | undefined, action: ContainmentAction | null | undefined, review?: { authorization?: Authorization | null; status?: string; incident_id?: string | null } | null, busy = false): ResponseState {
  if (busy) return 'in-progress'
  const auth = incident?.authorization ?? action?.authorization ?? review?.authorization ?? null
  if (action) {
    if (action.status === 'containment_failed' || action.verification?.ok === false) return 'failed'
    if (action.status === 'restored' || action.restored_at) return incident?.status === 'resolved' ? 'restored-verified' : 'restored'
    if (action.status === 'verified' && action.verification?.ok === true) return 'contained-verified'
    if (action.status === 'applied' || (action.applied_at && action.verification?.ok !== true)) return 'executed-unverified'
    if (action.status === 'refused' || action.status === 'not_applicable') return 'withheld'
  }
  // a review that is still open is "awaiting" even when guards withheld automation: the decision is pending
  // an analyst's rejection is a decision, not a policy guard: keep the two apart
  if (auth?.status === 'rejected' && auth.mode === 'analyst' && !(auth.guards?.length ?? 0)) return 'declined'
  if (auth?.status === 'rejected' || review?.status === 'rejected') return 'withheld'
  if (review && review.status !== 'review' && review.status !== 'approved' && !review.incident_id && (auth?.guards.length ?? 0) > 0) return 'withheld'
  if (auth?.status === 'authorized') return 'authorized'
  if (auth?.status === 'pending' || review?.status === 'review') return 'awaiting'
  return 'suggested'
}

const RESPONSE_LABEL: Record<ResponseState, { text: string; kind: string }> = {
  'in-progress': { text: 'in progress', kind: 'warn' },
  failed: { text: 'failed', kind: 'danger' },
  'restored-verified': { text: 'restored · verified', kind: 'ok' },
  restored: { text: 'restored', kind: 'ok' },
  'contained-verified': { text: 'contained · verified', kind: 'contained-verified' },
  'executed-unverified': { text: 'executed · unverified', kind: 'warn' },
  withheld: { text: 'withheld by policy', kind: 'withheld' },
  declined: { text: 'declined by analyst', kind: 'withheld' },
  authorized: { text: 'authorized', kind: 'ok' },
  awaiting: { text: 'awaiting authorization', kind: 'pending' },
  suggested: { text: 'suggested', kind: 'neutral' },
}

export function ResponseChip({ state }: { state: ResponseState }) {
  const l = RESPONSE_LABEL[state]
  return <Chip kind={l.kind}>{l.text}</Chip>
}

export function responseLabel(state: ResponseState): string {
  return RESPONSE_LABEL[state].text
}

/** Finding remediation state exactly as the backend records it. */
export function remediationLabel(f: Finding): string {
  return f.remediation.status.replace(/_/g, ' ')
}

/** Marks a decision the demo replay's scripted analyst made through the normal approval workflow. */
export function ScriptedTag() {
  return (
    <Chip kind="scripted" title="Made by the demo replay's scripted analyst through the same approval workflow as the Incidents page, and recorded as such">
      scripted demo
    </Chip>
  )
}

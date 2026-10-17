import type { Attribution, Authorization, ContainmentAction, Detection, Incident } from '../lib/api'
import { fmtTime } from '../lib/format'
import { Icon } from './Icons'

type StageState = 'done' | 'pending' | 'withheld' | 'failed' | 'none'

interface Stage {
  name: string
  state: StageState
  when: string | null
  who?: string | null
  note?: string
}

function StageIcon({ s }: { s: StageState }) {
  if (s === 'done') return <Icon.check />
  if (s === 'pending') return <Icon.pending />
  if (s === 'withheld') return <Icon.withheld />
  if (s === 'failed') return <Icon.fail />
  return <Icon.dot />
}

function deltaLabel(a: string | null, b: string | null): string | null {
  if (!a || !b) return null
  const ms = Date.parse(b) - Date.parse(a)
  if (!Number.isFinite(ms) || ms < 0) return null
  if (ms < 1000) return `+${ms} ms`
  if (ms < 60_000) return `+${(ms / 1000).toFixed(ms < 10_000 ? 2 : 1)} s`
  if (ms < 3_600_000) return `+${(ms / 60_000).toFixed(1)} min`
  return `+${(ms / 3_600_000).toFixed(1)} h`
}

/**
 * Eight-stage response ledger. Every stage is derived only from its own backend field, so a stage
 * reads "not recorded" rather than being inferred from a neighbour. Verification requires the
 * action's own read-back (`verification.ok === true`); a failed read-back is shown as failed.
 */
export function stagesOf(incident: Incident, detection: Detection | null, attribution: Attribution | null, action: ContainmentAction | null): Stage[] {
  const auth: Authorization | null = incident.authorization ?? action?.authorization ?? null
  const identified = incident.device || incident.user ? attribution?.completed_at ?? detection?.ts ?? null : null
  const recommended = incident.disposition ? attribution?.completed_at ?? detection?.ts ?? null : null
  const authorized: Stage = auth
    ? auth.status === 'authorized'
      ? { name: 'Authorized', state: 'done', when: auth.authorized_at, who: auth.mode === 'automatic' ? `policy · ${auth.authorized_by}` : auth.authorized_by }
      : auth.status === 'rejected'
        ? { name: 'Authorized', state: 'withheld', when: auth.authorized_at, who: `declined by ${auth.authorized_by}` }
        : { name: 'Authorized', state: 'pending', when: null, who: 'awaiting decision' }
    : { name: 'Authorized', state: 'none', when: null, who: 'not recorded' }
  const withheld = action ? action.status === 'refused' || action.status === 'not_applicable' : false
  const executed: Stage = action?.applied_at ? { name: 'Executed', state: 'done', when: action.applied_at, who: action.interface ? `${action.interface}${action.to_vlan ? ` → VLAN ${action.to_vlan}` : ''}` : action.action } : withheld ? { name: 'Executed', state: 'withheld', when: null, who: 'withheld by policy' } : action?.status === 'containment_failed' ? { name: 'Executed', state: 'failed', when: action.applied_at ?? null, who: 'failed' } : { name: 'Executed', state: 'none', when: null, who: 'not recorded' }
  const verified: Stage = action?.verification?.ok === true && action.verified_at ? { name: 'Verified', state: 'done', when: action.verified_at, who: 'read-back matched' } : action?.verification?.ok === false ? { name: 'Verified', state: 'failed', when: action.verified_at ?? action.verification?.checked_at ?? null, who: 'read-back failed' } : action?.applied_at ? { name: 'Verified', state: 'pending', when: null, who: 'not verified' } : { name: 'Verified', state: 'none', when: null, who: 'not recorded' }
  const restored: Stage = action?.restored_at ? { name: 'Restored', state: 'done', when: action.restored_at, who: action.restored_by ?? undefined } : { name: 'Restored', state: 'none', when: null, who: action?.applied_at ? 'still contained' : 'not recorded' }
  return [
    { name: 'Detected', state: detection?.ts ? 'done' : 'none', when: detection?.ts ?? null, who: detection?.rule ?? null },
    { name: 'Correlated', state: attribution?.completed_at ? 'done' : 'none', when: attribution?.completed_at ?? null, who: attribution ? `${attribution.steps?.length ?? 0} steps` : 'not recorded' },
    { name: 'Identified', state: identified ? 'done' : 'none', when: identified, who: [incident.device, incident.user].filter(Boolean).join(' · ') || 'not recorded' },
    { name: 'Recommended', state: recommended ? 'done' : 'none', when: recommended, who: incident.disposition?.replace(/_/g, ' ') ?? 'not recorded' },
    authorized,
    executed,
    verified,
    restored,
  ]
}

export function ResponseLedger({ incident, detection, attribution, action }: { incident: Incident; detection: Detection | null; attribution: Attribution | null; action: ContainmentAction | null }) {
  const stages = stagesOf(incident, detection, attribution, action)
  // elapsed time from the previous recorded stage; stages without a timestamp carry none
  const deltas: (string | null)[] = []
  let prev: string | null = null
  for (const s of stages) {
    deltas.push(deltaLabel(prev, s.when))
    if (s.when) prev = s.when
  }
  return (
    <ol className="ledger" aria-label="Response ledger">
      {stages.map((s, i) => {
        const delta = i > 0 ? deltas[i] : null
        return (
          <li key={s.name} className={`stage ${s.state}`}>
            {delta && <span className="delta">{delta}</span>}
            <span className="name">
              <StageIcon s={s.state} />
              {s.name}
            </span>
            <span className="when" title={s.when ?? undefined}>
              {s.when ? fmtTime(s.when) : s.state === 'pending' ? 'pending' : s.state === 'withheld' ? 'withheld' : s.state === 'failed' ? 'failed' : '—'}
            </span>
            {s.who && <span className="who" title={s.who}>{s.who}</span>}
          </li>
        )
      })}
    </ol>
  )
}

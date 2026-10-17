import type { Attribution, Step } from '../lib/api'
import { chainFromAttribution, type ChainNode } from '../lib/chain'
import { Icon } from './Icons'

type Certainty = 'confirmed' | 'inferred' | 'conflict' | 'missing' | 'none'

/** Map a correlation step status to how the trace node should be drawn. Unknown statuses draw neutrally. */
function certaintyOf(status: Step['status'] | undefined): Certainty {
  switch (status) {
    case 'resolved':
      return 'confirmed'
    case 'fallback':
      return 'inferred'
    case 'conflict':
      return 'conflict'
    case 'missing':
    case 'refused':
      return 'missing'
    default:
      return 'none'
  }
}

const CERT_LABEL: Record<Certainty, string> = { confirmed: 'confirmed', inferred: 'inferred (fallback)', conflict: 'conflict', missing: 'missing', none: '' }

function CertIcon({ c }: { c: Certainty }) {
  if (c === 'confirmed') return <Icon.check />
  if (c === 'inferred') return <Icon.pending />
  if (c === 'conflict') return <Icon.warn />
  if (c === 'missing') return <Icon.fail />
  return <Icon.dot />
}

/** Which correlation step evidences each chain node, by node label. */
const STEP_FOR: Record<string, string[]> = {
  'source ip': ['source_ip', 'ip'],
  'mac address': ['mac_lookup', 'ip_to_mac', 'mac'],
  switch: ['switch'],
  interface: ['mac_to_port', 'port_lookup', 'interface', 'port'],
  vlan: ['vlan'],
  device: ['device', 'identity', 'asset'],
  user: ['user', 'aaa', 'session'],
}

function stepFor(node: ChainNode, steps: Step[]): Step | undefined {
  const keys = STEP_FOR[node.k.toLowerCase()] ?? [node.k.toLowerCase()]
  return steps.find((s) => keys.some((k) => s.name.toLowerCase().includes(k)))
}

/**
 * Attribution trace: the chain from source IP to the containment target, each node annotated with
 * the certainty of the correlation step that produced it. The containment node is only drawn when
 * an action record exists — it never shows a target that was not actually touched.
 */
export function Trace({ attribution, toVlan, action, toNote, vertical = false }: { attribution: Attribution; toVlan?: number | null; action?: string | null; toNote?: string; vertical?: boolean }) {
  const nodes = chainFromAttribution(attribution, toVlan ?? undefined, action ?? undefined).map((n) => (n.tone === 'to' && toNote ? { ...n, s: toNote } : n))
  const steps = attribution.steps ?? []
  return (
    <div className={`trace ${vertical ? 'vertical' : ''}`} role="list" aria-label="Attribution trace">
      {nodes.map((n, i) => {
        const st = n.tone === 'to' ? undefined : stepFor(n, steps)
        const c: Certainty = n.tone === 'to' ? 'none' : st ? certaintyOf(st.status) : n.v === '—' || n.v === '' ? 'missing' : 'none'
        return (
          <div key={i} className="contents">
            {i > 0 && (
              <div className="trace-arrow" aria-hidden="true">
                <Icon.arrow />
              </div>
            )}
            <div className={`trace-node ${c} ${n.tone ?? ''}`} role="listitem" title={st ? `${st.name}: ${st.status} — ${st.detail}` : undefined}>
              <span className="k">
                <CertIcon c={c} />
                {n.k}
                {c !== 'none' && <span className="sr-only"> ({CERT_LABEL[c]})</span>}
              </span>
              <span className="v">{n.v || '—'}</span>
              {n.s && <span className="s">{n.s}</span>}
              {!n.s && st && c !== 'confirmed' && <span className="s">{CERT_LABEL[c]}</span>}
            </div>
          </div>
        )
      })}
    </div>
  )
}

export function TraceLegend() {
  return (
    <div className="legend">
      {(['confirmed', 'inferred', 'conflict', 'missing'] as Certainty[]).map((c) => (
        <span key={c} className={`trace-key ${c}`}>
          <CertIcon c={c} /> {CERT_LABEL[c]}
        </span>
      ))}
    </div>
  )
}

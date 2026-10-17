import type { Step } from '../lib/api'
import { Icon } from './Icons'
import type { ChainNode } from '../lib/chain'
import { Chip } from './status'

/** Plain attribution chain (used by media cards); the incident workspace uses `Trace`. */
export function Chain({ nodes, vertical = false }: { nodes: ChainNode[]; vertical?: boolean }) {
  return (
    <div className={`chain ${vertical ? 'vertical' : ''}`}>
      {nodes.map((n, i) => (
        <div key={i} className="contents">
          {i > 0 && (
            <div className="chain-arrow" aria-hidden="true">
              <Icon.arrow />
            </div>
          )}
          <div className={`chain-node ${n.tone ?? ''}`}>
            <span className="k">{n.k}</span>
            <span className="v">{n.v}</span>
            {n.s && <span className="s">{n.s}</span>}
          </div>
        </div>
      ))}
    </div>
  )
}

export function Steps({ steps }: { steps: Step[] }) {
  return (
    <div className="steps">
      {steps.map((s, i) => (
        <div className="step" key={i}>
          <span className="name">{s.name.replace(/_/g, ' ')}</span>
          <span className={`status ${s.status}`} title={s.status} />
          <span className="detail">
            <Chip kind={s.status === 'resolved' ? 'ok' : s.status === 'fallback' ? 'warn' : s.status === 'conflict' ? 'warn' : s.status === 'missing' || s.status === 'refused' ? 'danger' : 'neutral'} className="step-chip">
              {s.status}
            </Chip>{' '}
            {s.detail}
            <span className="src">
              {s.source} · {s.ts.slice(11, 23)}
            </span>
          </span>
        </div>
      ))}
    </div>
  )
}

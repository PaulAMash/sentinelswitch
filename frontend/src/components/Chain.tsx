import type { Step } from '../lib/api'
import { Icon } from './Icons'
import type { ChainNode } from '../lib/chain'

export function Chain({ nodes, vertical = false }: { nodes: ChainNode[]; vertical?: boolean }) {
  return (
    <div className={`chain ${vertical ? 'vertical' : ''}`}>
      {nodes.map((n, i) => (
        <div key={i} style={{ display: 'contents' }}>
          {i > 0 && (
            <div className="chain-arrow">
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
          <span className="name">{s.name.replace('_', ' ')}</span>
          <span className={`status ${s.status}`} title={s.status} />
          <span className="detail">
            <span className="chip neutral" style={{ marginRight: 8 }}>
              {s.status}
            </span>
            {s.detail}
            <span className="src">{s.source} · {s.ts.slice(11, 23)}</span>
          </span>
        </div>
      ))}
    </div>
  )
}

import { memo, useMemo, useRef, useState, type KeyboardEvent } from 'react'
import type { Sev3 } from '../../lib/telemetry'
import { HEX, hexPoints } from './hex'
import type { ClusterId, FieldModel, FieldNode, Flow } from './model'

export interface Pulse {
  key: string
  node: string
  sev: Sev3
}

const P_BODY = hexPoints(HEX * 0.93)
const P_ACT = hexPoints(HEX * 0.74)
const P_RING = hexPoints(HEX * 1.08)
const P_INSET = hexPoints(HEX * 0.56)
const P_CORE_OUT = hexPoints(HEX * 2.75)
const P_CORE_MID = hexPoints(HEX * 2.2)
const P_CORE_IN = hexPoints(HEX * 1.25)

const RESPONSE_LABEL: Record<string, string> = { contained: 'contained (quarantine VLAN)', held: 'administrative hold', review: 'awaiting authorization', incident: 'open incident', restored: 'recently restored' }

export function describeNode(n: FieldNode): string {
  const who = n.device?.hostname ?? (n.unknown ? `unregistered ${n.unknown.label}` : n.port.mode === 'trunk' ? n.port.description : null)
  const parts = [n.id, who, n.vlan !== null ? `VLAN ${n.vlan}` : n.port.mode, n.state]
  const total = n.counts.high + n.counts.medium + n.counts.low
  parts.push(total ? `${total} recent alert${total === 1 ? '' : 's'}` : n.seen ? `${n.seen} earlier alert${n.seen === 1 ? '' : 's'}` : 'no alerts so far')
  if (n.response) parts.push(RESPONSE_LABEL[n.response])
  return parts.filter(Boolean).join(' · ')
}

function arc(from: FieldNode, to: FieldNode | null, core: { x: number; y: number }, fan = 0): { d: string; ex: number; ey: number } {
  const x1 = from.x
  const y1 = from.y
  if (!to) {
    // unresolved destination: a short stub pointing away from the core, fanned out per destination
    const base = Math.atan2(y1 - core.y, x1 - core.x) + fan
    const dx = Math.cos(base)
    const dy = Math.sin(base)
    const ex = x1 + dx * HEX * 3
    const ey = y1 + dy * HEX * 3
    return { d: `M${x1.toFixed(1)},${y1.toFixed(1)} L${ex.toFixed(1)},${ey.toFixed(1)}`, ex, ey }
  }
  const x2 = to.x
  const y2 = to.y
  const mx = (x1 + x2) / 2
  const my = (y1 + y2) / 2
  const len = Math.hypot(x2 - x1, y2 - y1) || 1
  let px = -(y2 - y1) / len
  let py = (x2 - x1) / len
  // bend away from the core so arcs do not cross the switch
  if ((mx + px - core.x) ** 2 + (my + py - core.y) ** 2 < (mx - core.x) ** 2 + (my - core.y) ** 2) {
    px = -px
    py = -py
  }
  const k = Math.min(0.34 * len, HEX * 6)
  return { d: `M${x1.toFixed(1)},${y1.toFixed(1)} Q${(mx + px * k).toFixed(1)},${(my + py * k).toFixed(1)} ${x2.toFixed(1)},${y2.toFixed(1)}`, ex: x2, ey: y2 }
}

/** Label for an unattributed destination: continues outward from the stub end, anchored away from it. */
function stubLabel(from: FieldNode, g: { ex: number; ey: number }) {
  const dx = g.ex - from.x
  const dy = g.ey - from.y
  const len = Math.hypot(dx, dy) || 1
  const ux = dx / len
  const uy = dy / len
  return { x: g.ex + ux * 9, y: g.ey + uy * 9 + 4, textAnchor: (ux > 0.35 ? 'start' : ux < -0.35 ? 'end' : 'middle') as 'start' | 'end' | 'middle' }
}

export interface SignalFieldProps {
  model: FieldModel
  selectedNode: string | null
  selectedFlow: Flow | null
  selectedAlertPort: string | null
  focusCluster: ClusterId | null
  pulses: Pulse[]
  travel: Set<string>
  arrive: boolean
  /** ambient decoration runs only while playback is running */
  playing?: boolean
  onSelectNode: (id: string | null) => void
  onHoverNode: (id: string | null) => void
  onFocusCluster: (id: ClusterId | null) => void
}

/**
 * The hexagonal field. Geometry is static per layout; state arrives through classes so colour, opacity
 * and position changes are CSS transitions (no per-frame React work). Ports are focusable buttons with
 * roving tab index and arrow-key navigation; Escape clears the selection.
 */
export const SignalField = memo(function SignalField(p: SignalFieldProps) {
  const { model } = p
  const byId = useMemo(() => new Map(model.nodes.map((n) => [n.id, n])), [model.nodes])
  const [focusId, setFocusId] = useState<string | null>(null)
  const svgRef = useRef<SVGSVGElement>(null)

  // relationships that a selection makes visible
  const related = useMemo(() => {
    const s = new Set<string>()
    if (p.selectedFlow) {
      s.add(p.selectedFlow.from)
      if (p.selectedFlow.to) s.add(p.selectedFlow.to)
    } else if (p.selectedAlertPort) {
      s.add(p.selectedAlertPort)
    } else if (p.selectedNode) {
      s.add(p.selectedNode)
      for (const f of model.flows) {
        if (f.from === p.selectedNode && f.to) s.add(f.to)
        if (f.to === p.selectedNode) s.add(f.from)
      }
    }
    return s
  }, [p.selectedFlow, p.selectedAlertPort, p.selectedNode, model.flows])
  const anySel = related.size > 0
  const hotFlow = (f: Flow) => (p.selectedFlow ? f.id === p.selectedFlow.id : p.selectedNode ? f.from === p.selectedNode || f.to === p.selectedNode : false)

  const tabTarget = focusId ?? p.selectedNode ?? model.nodes.find((n) => n.heat > 0)?.id ?? model.nodes[0]?.id
  const focusNode = (id: string) => {
    setFocusId(id)
    svgRef.current?.querySelector<SVGGElement>(`[data-node="${CSS.escape(id)}"]`)?.focus()
  }
  const onKey = (e: KeyboardEvent<SVGGElement>, n: FieldNode) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      p.onSelectNode(p.selectedNode === n.id ? null : n.id)
      return
    }
    if (e.key === 'Escape') {
      p.onSelectNode(null)
      return
    }
    const dir: Record<string, [number, number]> = { ArrowRight: [1, 0], ArrowLeft: [-1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] }
    const d = dir[e.key]
    if (!d) return
    e.preventDefault()
    let best: FieldNode | null = null
    let bestScore = Infinity
    for (const m of model.nodes) {
      if (m.id === n.id) continue
      const dx = m.x - n.x
      const dy = m.y - n.y
      const along = dx * d[0] + dy * d[1]
      if (along <= 1) continue
      const across = Math.abs(dx * d[1] - dy * d[0])
      const score = along + across * 2.2
      if (score < bestScore) {
        bestScore = score
        best = m
      }
    }
    if (best) focusNode(best.id)
  }

  // distinct unattributed destinations per source port, so their stubs fan out instead of overlapping
  const stubs = new Map<string, string[]>()
  for (const f of model.flows) {
    if (f.to) continue
    if (!stubs.has(f.from)) stubs.set(f.from, [])
    const list = stubs.get(f.from)!
    if (!list.includes(f.toLabel)) list.push(f.toLabel)
  }
  const [vx, vy, vw, vh] = model.viewBox
  const pulsesByNode = new Map<string, Pulse[]>()
  for (const pu of p.pulses) {
    if (!pulsesByNode.has(pu.node)) pulsesByNode.set(pu.node, [])
    pulsesByNode.get(pu.node)!.push(pu)
  }
  return (
    <svg ref={svgRef} className={`sf ${p.arrive ? 'arrive' : ''} ${p.playing ? 'is-playing' : ''} ${anySel ? 'has-sel' : ''} ${p.focusCluster ? 'has-focus' : ''}`} viewBox={`${vx} ${vy} ${vw} ${vh}`} role="group" aria-label={`Signal field: ${model.nodes.length} SW01 interfaces grouped by VLAN`}>
      <defs>
        <radialGradient id="sf-fade" cx="50%" cy="48%" r="62%">
          <stop offset="0%" stopColor="white" stopOpacity="1" />
          <stop offset="70%" stopColor="white" stopOpacity="0.55" />
          <stop offset="100%" stopColor="white" stopOpacity="0" />
        </radialGradient>
        <pattern id="sf-hatch" width="5" height="5" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
          <rect width="5" height="5" className="hatch-bg" />
          <line x1="0" y1="0" x2="0" y2="5" className="hatch-ln" />
        </pattern>
        <pattern id="sf-hatch-warn" width="5" height="5" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
          <rect width="5" height="5" className="hatch-bg" />
          <line x1="0" y1="0" x2="0" y2="5" className="hatch-ln warn" />
        </pattern>
        <radialGradient id="sf-spot">
          <stop offset="0%" stopColor="white" stopOpacity="1" />
          <stop offset="100%" stopColor="white" stopOpacity="0" />
        </radialGradient>
        <mask id="sf-sheen-mask" maskUnits="userSpaceOnUse" x={vx} y={vy} width={vw} height={vh}>
          <ellipse className="sf-spot" cx={vx + vw * 0.3} cy={vy + vh * 0.45} rx={vw * 0.22} ry={vh * 0.4} fill="url(#sf-spot)" />
        </mask>
        <mask id="sf-mask">
          <rect x={vx} y={vy} width={vw} height={vh} fill="url(#sf-fade)" />
        </mask>
      </defs>
      <path className="sf-lattice" d={model.lattice} mask="url(#sf-mask)" aria-hidden="true" />
      <g className="sf-sheen" aria-hidden="true" mask="url(#sf-sheen-mask)">
        <path d={model.lattice} />
      </g>
      <g className="sf-guides" aria-hidden="true">
        <circle cx={model.core.x} cy={model.core.y} r={HEX * 4.2} />
        <circle cx={model.core.x} cy={model.core.y} r={HEX * 9.5} />
      </g>
      <g className="sf-spokes" aria-hidden="true">
        {model.clusters.map((c) => (
          <line key={c.id} x1={model.core.x} y1={model.core.y} x2={c.x} y2={c.y} className={`${c.mirrored ? 'mirrored' : ''} ${p.focusCluster && p.focusCluster !== c.id ? 'dim' : ''}`} />
        ))}
      </g>
      <g className="sf-flows" aria-hidden="true">
        {model.flows.map((f) => {
          const from = byId.get(f.from)
          if (!from) return null
          const to = f.to ? byId.get(f.to) ?? null : null
          const st = stubs.get(f.from)
          const si = !to && st ? st.indexOf(f.toLabel) : 0
          const g = arc(from, to, model.core, !to && st ? (si - (st.length - 1) / 2) * 0.62 : 0)
          const hot = hotFlow(f)
          const cls = ['sf-flow', `sev-${f.sev}`, hot ? 'hot' : '', p.travel.has(f.id) ? 'travel' : '', anySel && !hot ? 'dim' : '', p.focusCluster && from.cluster !== p.focusCluster && (!to || to.cluster !== p.focusCluster) ? 'dim' : ''].filter(Boolean).join(' ')
          return (
            <g key={f.id} className={cls}>
              <path d={g.d} pathLength={100} />
              {!to && <circle cx={g.ex} cy={g.ey} r={2.6} className="end open" />}
              {!to && hot && (
                <text {...stubLabel(from, g)} className="stub">
                  {f.toLabel}
                </text>
              )}
            </g>
          )
        })}
      </g>
      <g className="sf-core" transform={`translate(${model.core.x} ${model.core.y})`} aria-hidden="true">
        <polygon className="out" points={P_CORE_OUT} />
        <polygon className="mid" points={P_CORE_MID} />
        <polygon className="in" points={P_CORE_IN} />
        <text className="t1" y={-2}>
          SW01
        </text>
        <text className="t2" y={13}>
          C2960X
        </text>
      </g>
      <g className="sf-ghosts">
        {model.ghosts.map((g) => {
          const n = byId.get(g.id)
          return (
            <g key={g.id} className={`sf-ghost ${anySel && !related.has(g.id) ? 'dim' : ''}`}>
              {n && <line x1={g.x} y1={g.y} x2={n.x} y2={n.y} className="sf-moved" />}
              <polygon points={hexPoints(HEX * 0.93, g.x, g.y)} />
              <text x={g.x} y={g.y + 4}>
                {g.label}
              </text>
              <title>{`${g.id} home slot, vacated while the port is quarantined`}</title>
            </g>
          )
        })}
      </g>
      <g className="sf-nodes">
        {model.nodes.map((n) => {
          const dim = (anySel && !related.has(n.id)) || (p.focusCluster !== null && p.focusCluster !== n.cluster)
          const cls = ['hx', `ps-${n.state}`, n.maxSev ? `sev-${n.maxSev}` : '', `heat-${n.heat}`, !n.heat && n.seenSev ? `seen seen-${n.seenSev}` : '', n.response ? `rs-${n.response}` : '', p.selectedNode === n.id ? 'selected' : '', related.has(n.id) && p.selectedNode !== n.id ? 'related' : '', dim ? 'dim' : ''].filter(Boolean).join(' ')
          return (
            <g
              key={n.id}
              data-node={n.id}
              className={cls}
              style={{ transform: `translate(${n.x}px, ${n.y}px)`, ['--d' as string]: `${n.ring * 70 + Math.round(Math.hypot(n.x - model.core.x, n.y - model.core.y) / 4)}ms` }}
              role="button"
              tabIndex={n.id === tabTarget ? 0 : -1}
              aria-label={describeNode(n)}
              aria-pressed={p.selectedNode === n.id}
              onClick={() => p.onSelectNode(p.selectedNode === n.id ? null : n.id)}
              onKeyDown={(e) => onKey(e, n)}
              onFocus={() => {
                setFocusId(n.id)
                p.onHoverNode(n.id)
              }}
              onBlur={() => p.onHoverNode(null)}
              onMouseEnter={() => p.onHoverNode(n.id)}
              onMouseLeave={() => p.onHoverNode(null)}
            >
              <g className="hx-in">
                <polygon className="hx-body" points={P_BODY} />
                {(n.heat > 0 || n.seen > 0) && <polygon className="hx-act" points={P_ACT} />}
                {n.response === 'contained' && <polygon className="hx-inset" points={P_INSET} />}
                {n.response && <polygon className="hx-ring" points={P_RING} />}
                <text className="hx-label" y={4}>
                  {n.label}
                </text>
                {(pulsesByNode.get(n.id) ?? []).map((pu) => (
                  <polygon key={pu.key} className={`hx-pulse sev-${pu.sev}`} points={P_RING} />
                ))}
              </g>
            </g>
          )
        })}
      </g>
      <g className="sf-labels">
        {model.clusters.map((c) => {
          const on = p.focusCluster === c.id
          return (
            <g
              key={c.id}
              className={`sf-cl ${on ? 'on' : ''} ${p.focusCluster && !on ? 'dim' : ''}`}
              transform={`translate(${c.x} ${c.labelY})`}
              role="button"
              tabIndex={0}
              aria-pressed={on}
              aria-label={`${c.id === 'trunk' || c.id === 'other' ? c.title : `VLAN ${c.title}`} ${c.name}: ${c.count} ports${c.mirrored === true ? ', mirrored to the sensor' : c.coverage === 'FAIL' ? ', not mirrored to the sensor (sensor coverage control FAIL)' : ''}. ${on ? 'Clear focus' : 'Focus this group'}`}
              onClick={() => p.onFocusCluster(on ? null : c.id)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault()
                  p.onFocusCluster(on ? null : c.id)
                }
              }}
            >
              <text className="sf-cl-t">
                <tspan className="k">{c.title}</tspan>
                {c.name && (
                  <tspan className="n" dx={5}>
                    {c.name}
                  </tspan>
                )}
                <tspan className="c" dx={6}>
                  {c.count}
                </tspan>
                {c.mirrored === true && (
                  <tspan className="m" dx={6}>
                    SPAN
                  </tspan>
                )}
                {c.mirrored === false && c.coverage === 'FAIL' && (
                  <tspan className="u" dx={6}>
                    not mirrored
                  </tspan>
                )}
              </text>
            </g>
          )
        })}
      </g>
    </svg>
  )
})

import { useEffect, useRef, useState, type KeyboardEvent } from 'react'
import type { PortState } from '../lib/api'

const PORT_ORDER = (() => {
  const names: string[] = []
  for (let i = 1; i <= 48; i++) names.push(`Gi1/0/${i}`)
  names.push('Te1/0/1', 'Te1/0/2')
  return names
})()

/**
 * Front-panel rendering of the 48 Gigabit ports (odd ports on the top row, even below, in four
 * groups of twelve) plus the two SFP+ uplinks. Every colour comes from a CSS class; every port is a
 * focusable button with Arrow-key navigation and an accessible name. A one-shot LED pulse plays when
 * `highlight` changes.
 */
/** LED blink period for a port with `n` recorded connections in the hour: busier ports blink faster. */
function blinkPeriod(n: number): string {
  return `${Math.max(0.16, Math.min(2.2, 6 / Math.sqrt(n))).toFixed(2)}s`
}

export function SwitchPanel({ ports, selected, onSelect, highlight, hostname = 'SW01', model = 'WS-C2960X-48FPD-L', activity }: { ports: PortState[]; selected?: string | null; onSelect?: (name: string) => void; highlight?: string | null; hostname?: string; model?: string; activity?: Map<string, number> }) {
  const byName = new Map(ports.map((p) => [p.name, p]))
  const [pulse, setPulse] = useState<string | null>(null)
  const lastHl = useRef<string | null>(null)
  useEffect(() => {
    if (highlight && highlight !== lastHl.current) {
      setPulse(highlight)
      const t = setTimeout(() => setPulse(null), 700)
      lastHl.current = highlight
      return () => clearTimeout(t)
    }
    lastHl.current = highlight ?? null
  }, [highlight])
  const W = 1000
  const H = 190
  const groups = 4
  const cols = 6
  const pw = 25
  const ph = 24
  const gapX = 5
  const groupGap = 20
  const x0 = 108
  const rowY = [58, 96]
  const onKey = (e: KeyboardEvent<SVGGElement>, name: string) => {
    const idx = PORT_ORDER.indexOf(name)
    let next: string | null = null
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      onSelect?.(name)
      return
    }
    if (e.key === 'ArrowRight') next = PORT_ORDER[Math.min(PORT_ORDER.length - 1, idx + (idx < 48 ? 2 : 1))]
    else if (e.key === 'ArrowLeft') next = PORT_ORDER[Math.max(0, idx - (idx < 48 ? 2 : 1))]
    else if (e.key === 'ArrowDown' && idx < 48 && idx % 2 === 0) next = PORT_ORDER[idx + 1]
    else if (e.key === 'ArrowUp' && idx < 48 && idx % 2 === 1) next = PORT_ORDER[idx - 1]
    if (next) {
      e.preventDefault()
      ;(e.currentTarget.ownerSVGElement?.querySelector(`[data-port="${next}"]`) as SVGGElement | null)?.focus()
    }
  }
  const elems: React.ReactNode[] = []
  for (let g = 0; g < groups; g++) {
    for (let c = 0; c < cols; c++) {
      for (let r = 0; r < 2; r++) {
        const idx = g * 12 + c * 2 + r + 1
        const name = `Gi1/0/${idx}`
        const p = byName.get(name)
        if (!p) continue
        const x = x0 + g * (cols * (pw + gapX) + groupGap) + c * (pw + gapX)
        const y = rowY[r]
        const act = activity?.get(name) ?? 0
        const label = `${name} · ${p.description} · ${p.state}${p.oper_vlan ? ` · VLAN ${p.oper_vlan}` : ''}${p.device ? ` · ${p.device}` : ''}${act ? ` · ${act} recorded connections in the last hour` : ''}`
        const cls = `port ${p.state} ${selected === name ? 'selected' : ''} ${pulse === name ? 'pulse' : ''}`
        elems.push(
          <g key={name} className={cls} transform={`translate(${x},${y})`} onClick={() => onSelect?.(name)} onKeyDown={(e) => onKey(e, name)} tabIndex={onSelect ? 0 : -1} role="button" aria-label={label} aria-pressed={selected === name} data-port={name}>
            <title>{label}</title>
            <rect className="body" width={pw} height={ph} rx={2.5} />
            <rect className="slot" x={7} y={ph - 6} width={pw - 14} height={3} rx={1} />
            <circle className={`led ${act ? 'act' : ''}`} cx={5} cy={5} r={2.2} style={act ? { ['--blink' as string]: blinkPeriod(act), ['--phase' as string]: `${-((idx * 0.37) % 1).toFixed(2)}s` } : undefined} />
            {p.protected && <rect className="lock" x={pw - 8} y={3} width={5} height={4} rx={0.8} />}
            <text x={pw / 2} y={15} textAnchor="middle">
              {idx}
            </text>
          </g>,
        )
      }
    }
  }
  const teX = x0 + groups * (cols * (pw + gapX) + groupGap) + 2
  for (let i = 0; i < 2; i++) {
    const name = `Te1/0/${i + 1}`
    const p = byName.get(name)
    const x = teX + i * 40
    const label = `${name} · SFP+ · ${p?.state ?? 'disabled'}`
    elems.push(
      <g key={name} className={`port ${p?.state ?? 'disabled'} ${selected === name ? 'selected' : ''} ${pulse === name ? 'pulse' : ''}`} transform={`translate(${x},${rowY[0]})`} onClick={() => onSelect?.(name)} onKeyDown={(e) => onKey(e, name)} tabIndex={onSelect ? 0 : -1} role="button" aria-label={label} aria-pressed={selected === name} data-port={name}>
        <title>{label}</title>
        <rect className="body" width={30} height={62} rx={3} />
        <rect className="slot" x={8} y={12} width={14} height={38} rx={1.5} />
        <circle className="led" cx={5} cy={5} r={2.2} />
        <text x={15} y={58} textAnchor="middle">
          Te{i + 1}
        </text>
      </g>,
    )
  }
  return (
    <svg className="switch-panel" viewBox={`0 0 ${W} ${H}`} role="group" aria-label={`${hostname} ${model} front panel`}>
      <rect className="chassis-body" x={6} y={20} width={W - 12} height={H - 40} rx={8} />
      <rect className="chassis-rail" x={6} y={20} width={W - 12} height={5} rx={2} />
      <text className="chassis-label" x={20} y={46} fontSize={11}>
        {hostname}
      </text>
      <text className="chassis-sub" x={20} y={60} fontSize={8}>
        Catalyst 2960-X
      </text>
      <text className="chassis-mono" x={20} y={72} fontSize={8}>
        {model}
      </text>
      <g className="chassis-mono" fontSize={8}>
        <text x={20} y={100}>SYST</text>
        <text x={20} y={112}>STAT</text>
        <text x={20} y={124}>SPAN</text>
      </g>
      <circle className="chassis-led ok" cx={52} cy={97} r={2} />
      <circle className="chassis-led ok" cx={52} cy={109} r={2} />
      <circle className={`chassis-led accent ${activity && activity.size ? 'act' : ''}`} cx={52} cy={121} r={2} style={activity && activity.size ? { ['--blink' as string]: blinkPeriod([...activity.values()].reduce((a, b) => a + b, 0)) } : undefined} />
      {[0, 1, 2, 3].map((g) => (
        <text key={g} className="chassis-mono" x={x0 + g * (cols * (pw + gapX) + groupGap) + (cols * (pw + gapX)) / 2 - 3} y={rowY[1] + ph + 16} textAnchor="middle" fontSize={8}>
          {g * 12 + 1}–{g * 12 + 12}
        </text>
      ))}
      <text className="chassis-mono" x={teX + 35} y={rowY[1] + ph + 16} textAnchor="middle" fontSize={8}>
        SFP+
      </text>
      {elems}
    </svg>
  )
}

export function PortLegend() {
  const items: [string, string][] = [
    ['connected', 'connected'],
    ['trunk', 'trunk / protected'],
    ['monitor', 'SPAN destination'],
    ['quarantined', 'quarantined (VLAN 50)'],
    ['held', 'shutdown / err-disabled'],
    ['notconnect', 'not connected'],
    ['disabled', 'unused (shutdown)'],
  ]
  return (
    <div className="port-legend">
      {items.map(([k, l]) => (
        <span key={k}>
          <span className={`sw ${k}`} />
          {l}
        </span>
      ))}
    </div>
  )
}

import type { PortState } from '../lib/api'

/**
 * Front-panel inspired rendering of the 48 Gigabit ports (odd ports on the top row, even below,
 * in four groups of twelve) plus the two SFP+ uplinks. State classes drive the colours.
 */
export function SwitchPanel({ ports, selected, onSelect, highlight }: { ports: PortState[]; selected?: string | null; onSelect?: (name: string) => void; highlight?: string | null }) {
  const byName = new Map(ports.map((p) => [p.name, p]))
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
        const cls = `port ${p.state} ${selected === name ? 'selected' : ''} ${highlight === name ? 'pulse' : ''}`
        elems.push(
          <g key={name} className={cls} transform={`translate(${x},${y})`} onClick={() => onSelect?.(name)}>
            <title>{`${name} · ${p.description} · ${p.state}${p.oper_vlan ? ` · VLAN ${p.oper_vlan}` : ''}${p.device ? ` · ${p.device}` : ''}`}</title>
            <rect className="body" width={pw} height={ph} rx={2.5} />
            <rect x={7} y={ph - 6} width={pw - 14} height={3} rx={1} fill="#1f2a36" />
            <circle className="led" cx={5} cy={5} r={2.2} />
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
    elems.push(
      <g key={name} className={`port ${p?.state ?? 'disabled'} ${selected === name ? 'selected' : ''}`} transform={`translate(${x},${rowY[0]})`} onClick={() => onSelect?.(name)}>
        <title>{`${name} · SFP+ · ${p?.state ?? 'disabled'}`}</title>
        <rect className="body" width={30} height={62} rx={3} />
        <rect x={8} y={12} width={14} height={38} rx={1.5} fill="#131a22" stroke="#263241" />
        <text x={15} y={58} textAnchor="middle">
          Te{i + 1}
        </text>
      </g>,
    )
  }
  return (
    <svg className="switch-panel" viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Catalyst 2960-X front panel">
      <defs>
        <linearGradient id="chassis" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#1c2531" />
          <stop offset="1" stopColor="#141b24" />
        </linearGradient>
      </defs>
      <rect x={6} y={20} width={W - 12} height={H - 40} rx={8} fill="url(#chassis)" stroke="#34445a" />
      <rect x={6} y={20} width={W - 12} height={5} rx={2} fill="#263241" />
      <text x={20} y={46} fontFamily="var(--font)" fontSize={11} fill="#b3c0cf" fontWeight={600}>
        SW01
      </text>
      <text x={20} y={60} fontFamily="var(--font)" fontSize={8.5} fill="#7d8b9c">
        Catalyst 2960-X
      </text>
      <text x={20} y={72} fontFamily="var(--mono)" fontSize={7} fill="#56657a">
        WS-C2960X-48FPD-L
      </text>
      <g fontFamily="var(--mono)" fontSize={7} fill="#56657a">
        <text x={20} y={100}>SYST ●</text>
        <text x={20} y={112}>STAT ●</text>
        <text x={20} y={124}>SPAN ●</text>
      </g>
      <circle cx={49} cy={97} r={2} fill="#3fb950" />
      <circle cx={49} cy={109} r={2} fill="#3fb950" />
      <circle cx={49} cy={121} r={2} fill="#39c5d6" />
      {[0, 1, 2, 3].map((g) => (
        <text key={g} x={x0 + g * (cols * (pw + gapX) + groupGap) + (cols * (pw + gapX)) / 2 - 3} y={rowY[1] + ph + 16} textAnchor="middle" fontFamily="var(--mono)" fontSize={7} fill="#56657a">
          {g * 12 + 1}–{g * 12 + 12}
        </text>
      ))}
      <text x={teX + 35} y={rowY[1] + ph + 16} textAnchor="middle" fontFamily="var(--mono)" fontSize={7} fill="#56657a">
        SFP+
      </text>
      {elems}
    </svg>
  )
}

export function PortLegend() {
  const items: [string, string, string][] = [
    ['connected', '#2f9e4f', 'connected'],
    ['trunk', '#58a6ff', 'trunk / protected'],
    ['monitor', '#39c5d6', 'SPAN destination'],
    ['quarantined', '#f85149', 'quarantined (VLAN 50)'],
    ['held', '#d29922', 'shutdown / err-disabled'],
    ['notconnect', '#34445a', 'not connected'],
    ['disabled', '#263241', 'unused (shutdown)'],
  ]
  return (
    <div className="port-legend">
      {items.map(([k, c, l]) => (
        <span key={k}>
          <span className="sw" style={{ borderColor: c }} />
          {l}
        </span>
      ))}
    </div>
  )
}

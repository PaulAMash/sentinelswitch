import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { fmtBytes, fmtNum } from '../lib/format'

const AX = { stroke: '#34445a', fontSize: 11, fill: '#7d8b9c' }
const GRID = { stroke: '#263241', strokeDasharray: undefined, vertical: false }
const CURSOR = { fill: 'rgba(88,166,255,0.06)' }

function Tip({ active, payload, label, fmt }: { active?: boolean; payload?: { name: string; value: number; color?: string; dataKey?: string }[]; label?: string; fmt?: (v: number, k: string) => string }) {
  if (!active || !payload?.length) return null
  return (
    <div className="tooltip-box">
      <div className="t">{label}</div>
      {payload.map((p) => (
        <div className="r" key={p.name}>
          <span>
            <i style={{ background: p.color }} />
            {p.name}
          </span>
          <b>{fmt ? fmt(p.value, String(p.dataKey ?? p.name)) : fmtNum(p.value)}</b>
        </div>
      ))}
    </div>
  )
}

export function AlertTimeline({ data, height = 190 }: { data: { hour: string; high: number; medium: number; low: number }[]; height?: number }) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 6, right: 8, left: -18, bottom: 0 }} barCategoryGap={3}>
        <CartesianGrid {...GRID} />
        <XAxis dataKey="hour" tick={AX} tickLine={false} axisLine={{ stroke: '#34445a' }} interval={3} />
        <YAxis tick={AX} tickLine={false} axisLine={false} allowDecimals={false} />
        <Tooltip content={<Tip />} cursor={CURSOR} />
        <Bar dataKey="low" name="low" stackId="s" fill="#3987e5" maxBarSize={22} />
        <Bar dataKey="medium" name="medium" stackId="s" fill="#c99420" maxBarSize={22} />
        <Bar dataKey="high" name="high" stackId="s" fill="#e05a5a" maxBarSize={22} radius={[3, 3, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  )
}

export function TrafficArea({ data, height = 190, metric = 'bytes' }: { data: { ts: string; connections: number; bytes: number; dns: number; alerts: number; hosts: number }[]; height?: number; metric?: 'bytes' | 'connections' }) {
  const rows = data.map((d) => ({ ...d, label: d.ts.slice(11, 16) }))
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={rows} margin={{ top: 6, right: 8, left: -6, bottom: 0 }}>
        <defs>
          <linearGradient id="traffic-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#3987e5" stopOpacity={0.22} />
            <stop offset="100%" stopColor="#3987e5" stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid {...GRID} />
        <XAxis dataKey="label" tick={AX} tickLine={false} axisLine={{ stroke: '#34445a' }} interval={11} />
        <YAxis tick={AX} tickLine={false} axisLine={false} tickFormatter={(v) => (metric === 'bytes' ? fmtBytes(v) : fmtNum(v))} width={62} />
        <Tooltip content={<Tip fmt={(v, k) => (k === 'bytes' ? fmtBytes(v) : fmtNum(v))} />} cursor={{ stroke: '#58a6ff', strokeWidth: 1 }} />
        <Area type="monotone" dataKey={metric} name={metric === 'bytes' ? 'bytes (15 min)' : 'connections (15 min)'} stroke="#3987e5" strokeWidth={2} fill="url(#traffic-fill)" dot={false} activeDot={{ r: 4, stroke: '#161d26', strokeWidth: 2 }} />
      </AreaChart>
    </ResponsiveContainer>
  )
}

export function HBars({ data, height, color = '#3987e5', nameKey = 'name', valueKey = 'count' }: { data: Record<string, unknown>[]; height?: number; color?: string; nameKey?: string; valueKey?: string }) {
  const h = height ?? Math.max(120, data.length * 26 + 20)
  return (
    <ResponsiveContainer width="100%" height={h}>
      <BarChart data={data} layout="vertical" margin={{ top: 2, right: 34, left: 6, bottom: 0 }} barCategoryGap={6}>
        <CartesianGrid stroke="#263241" horizontal={false} />
        <XAxis type="number" tick={AX} tickLine={false} axisLine={false} allowDecimals={false} />
        <YAxis type="category" dataKey={nameKey} tick={{ ...AX, fill: '#b3c0cf' }} tickLine={false} axisLine={false} width={150} />
        <Tooltip content={<Tip />} cursor={CURSOR} />
        <Bar dataKey={valueKey} name="count" fill={color} maxBarSize={16} radius={[0, 3, 3, 0]} label={{ position: 'right', fill: '#b3c0cf', fontSize: 11 }}>
          {data.map((_, i) => (
            <Cell key={i} fill={color} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

export function AuthBars({ data, height = 200 }: { data: { hour: string; accept: number; reject: number; guest: number }[]; height?: number }) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 6, right: 8, left: -18, bottom: 0 }} barCategoryGap={3}>
        <CartesianGrid {...GRID} />
        <XAxis dataKey="hour" tick={AX} tickLine={false} axisLine={{ stroke: '#34445a' }} interval={3} />
        <YAxis tick={AX} tickLine={false} axisLine={false} allowDecimals={false} />
        <Tooltip content={<Tip />} cursor={CURSOR} />
        <Bar dataKey="accept" name="Access-Accept" stackId="a" fill="#2f9e4f" maxBarSize={22} />
        <Bar dataKey="guest" name="Guest VLAN" stackId="a" fill="#3987e5" maxBarSize={22} />
        <Bar dataKey="reject" name="Access-Reject" stackId="a" fill="#e05a5a" maxBarSize={22} radius={[3, 3, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  )
}

export function Legend({ items }: { items: [string, string][] }) {
  return (
    <div className="legend">
      {items.map(([label, color]) => (
        <span key={label}>
          <span className="sw" style={{ background: color }} />
          {label}
        </span>
      ))}
    </div>
  )
}

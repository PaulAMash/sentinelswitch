import { useMemo } from 'react'
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { useMedia } from '../lib/hooks'
import { fmtBytes, fmtNum } from '../lib/format'

/** Chart colours are read from the design tokens so SVG attributes stay in sync with the stylesheet. */
function token(name: string, fallback: string): string {
  if (typeof window === 'undefined') return fallback
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim()
  return v || fallback
}
export function useChartTokens() {
  return useMemo(
    () => ({
      c1: token('--chart-1', 'currentColor'),
      c2: token('--chart-2', 'currentColor'),
      c3: token('--chart-3', 'currentColor'),
      c4: token('--chart-4', 'currentColor'),
      c5: token('--chart-5', 'currentColor'),
      grid: token('--chart-grid', 'currentColor'),
      axis: token('--chart-axis', 'currentColor'),
      label: token('--chart-label', 'currentColor'),
      text2: token('--text-2', 'currentColor'),
      surface: token('--surface-1', 'transparent'),
      cursor: token('--accent-dim', 'transparent'),
      accent: token('--accent', 'currentColor'),
      sevLow: token('--sev-low', 'currentColor'),
    }),
    [],
  )
}

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
  const t = useChartTokens()
  const AX = { stroke: t.axis, fontSize: 11, fill: t.label }
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 6, right: 8, left: -18, bottom: 0 }} barCategoryGap={3}>
        <CartesianGrid stroke={t.grid} vertical={false} />
        <XAxis dataKey="hour" tick={AX} tickLine={false} axisLine={{ stroke: t.axis }} interval={3} />
        <YAxis tick={AX} tickLine={false} axisLine={false} allowDecimals={false} />
        <Tooltip content={<Tip />} cursor={{ fill: t.cursor }} />
        <Bar dataKey="low" name="low" stackId="s" fill={t.c1} maxBarSize={22} />
        <Bar dataKey="medium" name="medium" stackId="s" fill={t.c4} maxBarSize={22} />
        <Bar dataKey="high" name="high" stackId="s" fill={t.c3} maxBarSize={22} radius={[3, 3, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  )
}

export function TrafficArea({ data, height = 190, metric = 'bytes' }: { data: { ts: string; connections: number; bytes: number; dns: number; alerts: number; hosts: number }[]; height?: number; metric?: 'bytes' | 'connections' }) {
  const t = useChartTokens()
  const AX = { stroke: t.axis, fontSize: 11, fill: t.label }
  const rows = data.map((d) => ({ ...d, label: d.ts.slice(11, 16) }))
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={rows} margin={{ top: 6, right: 8, left: -6, bottom: 0 }}>
        <defs>
          <linearGradient id="traffic-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={t.c1} stopOpacity={0.22} />
            <stop offset="100%" stopColor={t.c1} stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke={t.grid} vertical={false} />
        <XAxis dataKey="label" tick={AX} tickLine={false} axisLine={{ stroke: t.axis }} interval={11} />
        <YAxis tick={AX} tickLine={false} axisLine={false} tickFormatter={(v) => (metric === 'bytes' ? fmtBytes(v) : fmtNum(v))} width={62} />
        <Tooltip content={<Tip fmt={(v, k) => (k === 'bytes' ? fmtBytes(v) : fmtNum(v))} />} cursor={{ stroke: t.c1, strokeWidth: 1 }} />
        <Area type="monotone" dataKey={metric} name={metric === 'bytes' ? 'bytes (15 min)' : 'connections (15 min)'} stroke={t.c1} strokeWidth={2} fill="url(#traffic-fill)" dot={false} activeDot={{ r: 4, stroke: t.surface, strokeWidth: 2 }} />
      </AreaChart>
    </ResponsiveContainer>
  )
}

export function HBars({ data, height, tone = 'c1', nameKey = 'name', valueKey = 'count', labelWidth = 150 }: { data: Record<string, unknown>[]; height?: number; tone?: 'c1' | 'c2' | 'c3' | 'c4' | 'c5'; nameKey?: string; valueKey?: string; labelWidth?: number }) {
  const t = useChartTokens()
  const AX = { stroke: t.axis, fontSize: 11, fill: t.label }
  const color = t[tone]
  const h = height ?? Math.max(120, data.length * 26 + 20)
  return (
    <ResponsiveContainer width="100%" height={h}>
      <BarChart data={data} layout="vertical" margin={{ top: 2, right: 34, left: 6, bottom: 0 }} barCategoryGap={6}>
        <CartesianGrid stroke={t.grid} horizontal={false} />
        <XAxis type="number" tick={AX} tickLine={false} axisLine={false} allowDecimals={false} />
        <YAxis type="category" dataKey={nameKey} tick={{ ...AX, fill: t.text2 }} tickLine={false} axisLine={false} width={labelWidth} />
        <Tooltip content={<Tip />} cursor={{ fill: t.cursor }} />
        <Bar dataKey={valueKey} name="count" fill={color} maxBarSize={16} radius={[0, 3, 3, 0]} label={{ position: 'right', fill: t.text2, fontSize: 11 }}>
          {data.map((_, i) => (
            <Cell key={i} fill={color} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

export function AuthBars({ data, height = 200 }: { data: { hour: string; accept: number; reject: number; guest: number }[]; height?: number }) {
  const t = useChartTokens()
  const AX = { stroke: t.axis, fontSize: 11, fill: t.label }
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 6, right: 8, left: -18, bottom: 0 }} barCategoryGap={3}>
        <CartesianGrid stroke={t.grid} vertical={false} />
        <XAxis dataKey="hour" tick={AX} tickLine={false} axisLine={{ stroke: t.axis }} interval={3} />
        <YAxis tick={AX} tickLine={false} axisLine={false} allowDecimals={false} />
        <Tooltip content={<Tip />} cursor={{ fill: t.cursor }} />
        <Bar dataKey="accept" name="Access-Accept" stackId="a" fill={t.c2} maxBarSize={22} />
        <Bar dataKey="guest" name="Guest VLAN" stackId="a" fill={t.c1} maxBarSize={22} />
        <Bar dataKey="reject" name="Access-Reject" stackId="a" fill={t.c3} maxBarSize={22} radius={[3, 3, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  )
}

/** Legend keyed by chart token so swatches always match the series. */
export function Legend({ items }: { items: [string, 'c1' | 'c2' | 'c3' | 'c4' | 'c5'][] }) {
  return (
    <div className="legend">
      {items.map(([label, tone]) => (
        <span key={label}>
          <span className={`sw ${tone}`} />
          {label}
        </span>
      ))}
    </div>
  )
}

/**
 * SPAN traffic as two small multiples sharing the 15-minute time axis: connections or bytes (area,
 * switchable) above, DNS queries (bars) below. Separate panels instead of a dual axis so neither
 * series is rescaled against the other.
 */
export function TrafficStack({ data, metric = 'connections', height = 210 }: { data: { ts: string; connections: number; bytes: number; dns: number; hosts?: number }[]; metric?: 'bytes' | 'connections'; height?: number }) {
  const t = useChartTokens()
  const reduce = useMedia('(prefers-reduced-motion: reduce)')
  const AX = { stroke: t.axis, fontSize: 11, fill: t.label }
  const rows = data.map((d) => ({ ...d, label: d.ts.slice(11, 16) }))
  const top = Math.round(height * 0.62)
  const fmt = (v: number) => (metric === 'bytes' ? fmtBytes(v) : fmtNum(v))
  return (
    <div className="vz-traffic">
      <ResponsiveContainer width="100%" height={top}>
        <AreaChart data={rows} syncId="span-traffic" margin={{ top: 6, right: 8, left: 0, bottom: 0 }}>
          <defs>
            <linearGradient id="span-fill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={t.accent} stopOpacity={0.28} />
              <stop offset="100%" stopColor={t.accent} stopOpacity={0.01} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke={t.grid} vertical={false} />
          <XAxis dataKey="label" hide />
          <YAxis tick={AX} tickLine={false} axisLine={false} width={58} tickFormatter={fmt} />
          <Tooltip content={<Tip fmt={(v, k) => (k === 'bytes' ? fmtBytes(v) : fmtNum(v))} />} cursor={{ stroke: t.accent, strokeWidth: 1 }} />
          <Area type="monotone" dataKey={metric} name={metric === 'bytes' ? 'bytes / 15 min' : 'connections / 15 min'} stroke={t.accent} strokeWidth={1.6} fill="url(#span-fill)" dot={false} activeDot={{ r: 3.5, stroke: t.surface, strokeWidth: 2 }} isAnimationActive={!reduce} animationDuration={700} />
        </AreaChart>
      </ResponsiveContainer>
      <ResponsiveContainer width="100%" height={height - top}>
        <BarChart data={rows} syncId="span-traffic" margin={{ top: 4, right: 8, left: 0, bottom: 0 }} barCategoryGap={1}>
          <CartesianGrid stroke={t.grid} vertical={false} />
          <XAxis dataKey="label" tick={AX} tickLine={false} axisLine={{ stroke: t.axis }} interval={11} />
          <YAxis tick={AX} tickLine={false} axisLine={false} width={58} allowDecimals={false} />
          <Tooltip content={<Tip />} cursor={{ fill: t.cursor }} />
          <Bar dataKey="dns" name="DNS queries / 15 min" fill={t.c5} isAnimationActive={!reduce} animationDuration={700} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

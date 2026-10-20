import { useMemo, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import type { AssessmentRun, ContainmentAction, Detection, Incident, Posture, Review, ValidationRow } from '../lib/api'
import { fmtSeconds } from '../lib/format'
import { technique } from '../lib/mitre'
import { SEVERITIES, type Sev3 } from '../lib/telemetry'
import { responseLabel, responseStateOf } from '../components/status'

/* ============================================================== severity ring */
export function SeverityRing({ counts, caption = 'alerts' }: { counts: Record<Sev3, number>; caption?: string }) {
  const [hot, setHot] = useState<Sev3 | null>(null)
  const total = counts.high + counts.medium + counts.low
  const R = 58
  const C = 2 * Math.PI * R
  const gap = total > 1 ? 3 : 0
  let acc = 0
  const arcs = SEVERITIES.map((s) => {
    const len = total ? (counts[s] / total) * C : 0
    const a = { s, len: Math.max(0, len - (counts[s] ? gap : 0)), off: acc }
    acc += len
    return a
  })
  const label = `${total} ${caption}: ${counts.high} high, ${counts.medium} medium, ${counts.low} low`
  return (
    <div className="vz-ring">
      <svg viewBox="0 0 150 150" role="img" aria-label={label}>
        <circle cx="75" cy="75" r={R} className="vz-ring-track" />
        <g className="vz-ring-arcs" transform="rotate(-90 75 75)">
          {total > 0 &&
            arcs.map((a) =>
              a.len > 0 ? (
                <circle key={a.s} cx="75" cy="75" r={R} className={`vz-arc ${a.s} ${hot && hot !== a.s ? 'dim' : ''}`} strokeDasharray={`${a.len} ${C}`} strokeDashoffset={-a.off} onMouseEnter={() => setHot(a.s)} onMouseLeave={() => setHot(null)} />
              ) : null,
            )}
        </g>
        <text x="75" y="76" className="vz-ring-n">
          {hot ? counts[hot] : total}
        </text>
        <text x="75" y="96" className="vz-ring-c">
          {hot ? hot : caption}
        </text>
      </svg>
      <ul className="vz-legend-list">
        {SEVERITIES.map((s) => (
          <li key={s} className={hot && hot !== s ? 'dim' : ''} onMouseEnter={() => setHot(s)} onMouseLeave={() => setHot(null)}>
            <span className={`sw ${s}`} aria-hidden="true" />
            <span className="l">{s}</span>
            <span className="v mono">{counts[s]}</span>
            <span className="p mono">{total ? `${Math.round((counts[s] / total) * 100)}%` : '—'}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

/* ============================================================== ranked / stacked bar rows */
export interface BarRow {
  key: string
  label: ReactNode
  sub?: ReactNode
  href?: string
  counts?: Record<Sev3, number>
  value?: number
}

export function BarRows({ rows, variant = 'plain', limit, empty = 'No data', unit }: { rows: BarRow[]; variant?: 'plain' | 'rank' | 'source'; limit?: number; empty?: string; unit?: string }) {
  const shown = limit ? rows.slice(0, limit) : rows
  const totals = shown.map((r) => r.value ?? (r.counts ? r.counts.high + r.counts.medium + r.counts.low : 0))
  const max = Math.max(1, ...totals)
  if (!shown.length) return <div className="vz-empty">{empty}</div>
  return (
    <ol className={`vz-bars ${variant}`}>
      {shown.map((r, i) => {
        const t = totals[i]
        const body = (
          <>
            {variant === 'rank' && <span className="rk mono">{String(i + 1).padStart(2, '0')}</span>}
            <span className="lb">
              <span className="clip">{r.label}</span>
              {r.sub && <span className="sb clip">{r.sub}</span>}
            </span>
            <span className="tr" aria-hidden="true">
              <span className="fill" style={{ width: `${(t / max) * 100}%`, ['--i' as string]: i }}>
                {r.counts ? SEVERITIES.map((s) => (r.counts![s] ? <span key={s} className={`seg ${s}`} style={{ flexGrow: r.counts![s] }} /> : null)) : <span className="seg one" style={{ flexGrow: 1 }} />}
              </span>
            </span>
            <span className="vl mono">
              {t}
              {unit ? <span className="u"> {unit}</span> : null}
            </span>
          </>
        )
        const aria = r.counts ? `${t}: ${r.counts.high} high, ${r.counts.medium} medium, ${r.counts.low} low` : `${t}`
        return (
          <li key={r.key} title={typeof r.label === 'string' ? `${r.label} · ${aria}` : aria}>
            {r.href ? (
              <Link to={r.href} className="vz-bar-row">
                {body}
              </Link>
            ) : (
              <div className="vz-bar-row">{body}</div>
            )}
          </li>
        )
      })}
    </ol>
  )
}

/* ============================================================== response outcome flow */
type FlowNode = { id: string; label: string; col: 0 | 1 | 2; value: number; tone: string }
type FlowLink = { from: string; to: string; value: number; tone: string }

const DISP_LABEL: Record<string, string> = { automatic_containment: 'automatic containment', manual_review: 'manual review', monitor: 'monitor only' }
const DISP_TONE: Record<string, string> = { automatic_containment: 'accent', manual_review: 'warn', monitor: 'steel' }

/** Outcome of one detection, derived only from the incident, action and review records it links to. */
export function outcomeOf(d: Detection, incidents: Incident[], actions: ContainmentAction[], reviews: Review[]): { label: string; tone: string } {
  if (d.disposition === 'monitor') return { label: 'monitored · no action', tone: 'steel' }
  const review = reviews.find((r) => r.detection_id === d.id)
  const incId = d.incident_id ?? review?.incident_id ?? null
  if (incId) {
    const inc = incidents.find((i) => i.id === incId) ?? null
    const acts = actions.filter((a) => a.incident_id === incId)
    const act = acts.find((a) => ['verified', 'restored', 'containment_failed'].includes(a.status)) ?? acts[0] ?? null
    const st = responseStateOf(inc, act)
    const tone = st === 'contained-verified' || st === 'restored-verified' || st === 'restored' ? 'ok' : st === 'failed' ? 'danger' : st === 'executed-unverified' || st === 'awaiting' ? 'warn' : st === 'withheld' ? 'withheld' : 'steel'
    return { label: responseLabel(st), tone }
  }
  if (review) {
    if (review.status === 'review') return { label: 'awaiting authorization', tone: 'warn' }
    if (review.authorization?.status === 'rejected') return { label: 'declined by analyst', tone: 'withheld' }
    return { label: review.status.replace(/_/g, ' '), tone: 'steel' }
  }
  return { label: 'no response record', tone: 'steel' }
}

export function ResponseFlow({ detections, incidents, actions, reviews }: { detections: Detection[]; incidents: Incident[]; actions: ContainmentAction[]; reviews: Review[] }) {
  const [hot, setHot] = useState<string | null>(null)
  const { nodes, links } = useMemo(() => {
    const disp = new Map<string, number>()
    const out = new Map<string, { n: number; tone: string }>()
    const lk = new Map<string, FlowLink>()
    for (const d of detections) {
      const k = d.disposition ?? 'unknown'
      disp.set(k, (disp.get(k) ?? 0) + 1)
      const o = outcomeOf(d, incidents, actions, reviews)
      out.set(o.label, { n: (out.get(o.label)?.n ?? 0) + 1, tone: o.tone })
      const key = `${k}→${o.label}`
      const cur = lk.get(key)
      if (cur) cur.value += 1
      else lk.set(key, { from: `d:${k}`, to: `o:${o.label}`, value: 1, tone: o.tone })
    }
    const order = ['automatic_containment', 'manual_review', 'monitor']
    const nodes: FlowNode[] = [{ id: 'all', label: 'detections', col: 0, value: detections.length, tone: 'accent' }]
    const dk = [...disp.keys()].sort((a, b) => (order.indexOf(a) + 99) % 99 - ((order.indexOf(b) + 99) % 99))
    for (const k of dk) nodes.push({ id: `d:${k}`, label: DISP_LABEL[k] ?? k.replace(/_/g, ' '), col: 1, value: disp.get(k)!, tone: DISP_TONE[k] ?? 'steel' })
    // outcomes ordered to keep ribbons from crossing: by the disposition that feeds them
    const outs = [...out.entries()].sort((a, b) => {
      const fa = [...lk.values()].find((l) => l.to === `o:${a[0]}`)!.from
      const fb = [...lk.values()].find((l) => l.to === `o:${b[0]}`)!.from
      return dk.indexOf(fa.slice(2)) - dk.indexOf(fb.slice(2)) || b[1].n - a[1].n
    })
    for (const [k, v] of outs) nodes.push({ id: `o:${k}`, label: k, col: 2, value: v.n, tone: v.tone })
    const links: FlowLink[] = dk.map((k) => ({ from: 'all', to: `d:${k}`, value: disp.get(k)!, tone: DISP_TONE[k] ?? 'steel' }))
    // second-stage links ordered like their targets
    const second = [...lk.values()].sort((a, b) => nodes.findIndex((n) => n.id === a.to) - nodes.findIndex((n) => n.id === b.to))
    return { nodes, links: [...links, ...second] }
  }, [detections, incidents, actions, reviews])

  const total = detections.length
  if (!total) return <div className="vz-empty">No detections recorded for this day.</div>
  const W = 640
  const H = 200
  const colX = [6, 262, 470]
  const bw = 6
  const gapPx = 16
  const pos = new Map<string, { y: number; h: number; inY: number; outY: number }>()
  for (const col of [0, 1, 2] as const) {
    const ns = nodes.filter((n) => n.col === col)
    const avail = H - gapPx * (ns.length - 1)
    let y = 0
    for (const n of ns) {
      const h = Math.max(4, (n.value / total) * avail)
      pos.set(n.id, { y, h, inY: y, outY: y })
      y += h + gapPx
    }
  }
  const scale = (v: number, col: 0 | 1 | 2) => {
    const ns = nodes.filter((n) => n.col === col)
    return (v / total) * (H - gapPx * (ns.length - 1))
  }
  const ribbons = links.map((l) => {
    const a = pos.get(l.from)!
    const b = pos.get(l.to)!
    const ca = nodes.find((n) => n.id === l.from)!.col
    const cb = nodes.find((n) => n.id === l.to)!.col
    const ha = scale(l.value, ca)
    const hb = scale(l.value, cb)
    const x0 = colX[ca] + bw
    const x1 = colX[cb]
    const y0 = a.outY
    const y1 = b.inY
    a.outY += ha
    b.inY += hb
    const mx = (x0 + x1) / 2
    const d = `M${x0},${y0} C${mx},${y0} ${mx},${y1} ${x1},${y1} L${x1},${y1 + hb} C${mx},${y1 + hb} ${mx},${y0 + ha} ${x0},${y0 + ha} Z`
    return { l, d }
  })
  const on = (id: string) => !hot || hot === id || links.some((l) => (l.from === hot && l.to === id) || (l.to === hot && l.from === id))
  return (
    <div className="vz-flow">
      <svg viewBox={`-2 -14 ${W + 4} ${H + 28}`} role="img" aria-label={`Response outcomes for ${total} detections: ${nodes.filter((n) => n.col === 2).map((n) => `${n.value} ${n.label}`).join(', ')}`}>
        {ribbons.map(({ l, d }, i) => (
          <path key={i} d={d} className={`vz-rib ${l.tone} ${hot && !(hot === l.from || hot === l.to) ? 'dim' : ''}`} style={{ ['--i' as string]: i }} />
        ))}
        {nodes.map((n) => {
          const p = pos.get(n.id)!
          const x = colX[n.col]
          const right = n.col < 2
          return (
            <g key={n.id} className={`vz-fn ${n.tone} ${on(n.id) ? '' : 'dim'}`} onMouseEnter={() => setHot(n.id)} onMouseLeave={() => setHot(null)}>
              <rect x={x} y={p.y} width={bw} height={p.h} />
              {n.col === 0 ? (
                <text x={x + bw + 8} y={p.y + 14} className="lbl">
                  <tspan className="v">{n.value}</tspan>
                  <tspan dx={6}>{n.label}</tspan>
                </text>
              ) : (
                <text x={right ? x + bw + 8 : x + bw + 8} y={p.y + Math.min(p.h / 2 + 4, p.h + 4)} className="lbl">
                  <tspan className="v">{n.value}</tspan>
                  <tspan dx={6}>{n.label}</tspan>
                </text>
              )}
            </g>
          )
        })}
      </svg>
    </div>
  )
}

/* ============================================================== ATT&CK technique tiles */
export function TechniqueTiles({ detections }: { detections: Detection[] }) {
  const items = useMemo(() => {
    const m = new Map<string, number>()
    for (const d of detections) for (const t of new Set(d.mitre)) m.set(t, (m.get(t) ?? 0) + 1)
    return [...m.entries()].map(([id, n]) => ({ ...technique(id), n })).sort((a, b) => b.n - a.n || a.id.localeCompare(b.id))
  }, [detections])
  const tagged = detections.filter((d) => d.mitre.length).length
  if (!items.length) return <div className="vz-empty">No ATT&CK technique tags on today&apos;s detections.</div>
  const max = Math.max(...items.map((i) => i.n))
  return (
    <div className="vz-tiles-wrap">
      <ul className="vz-tiles">
        {items.map((t, i) => (
          <li key={t.id} className="vz-tile" style={{ ['--k' as string]: (t.n / max).toFixed(2), ['--i' as string]: i }} title={`${t.id}${t.name ? ` ${t.name}` : ''}: tagged on ${t.n} of ${detections.length} detections`}>
            <span className="tid mono">{t.id}</span>
            <span className="tn">{t.name ?? 'technique'}</span>
            <span className="tt">{t.tactics.length ? `${t.tactics[0]}${t.tactics.length > 1 ? ` +${t.tactics.length - 1}` : ''}` : '—'}</span>
            <span className="tc mono">{t.n}</span>
          </li>
        ))}
      </ul>
      <div className="vz-foot">
        {tagged} of {detections.length} detections carry technique tags; a detection with several tags counts once per technique. This is what the rules labelled, not framework coverage or confirmed adversary behaviour.
      </div>
    </div>
  )
}

/* ============================================================== response stage timing */
export function StageTiming({ rows }: { rows: ValidationRow[] }) {
  const cols: { k: 'ttd' | 'tta' | 'ttc'; label: string; hint: string }[] = [
    { k: 'ttd', label: 'detect', hint: 'first anomalous event → detection' },
    { k: 'tta', label: 'attribute', hint: 'detection → identity resolved' },
    { k: 'ttc', label: 'contain', hint: 'detection → containment verified' },
  ]
  const max = Object.fromEntries(cols.map((c) => [c.k, Math.max(0.001, ...rows.map((r) => r[c.k] ?? 0))])) as Record<'ttd' | 'tta' | 'ttc', number>
  if (!rows.length) return <div className="vz-empty">No validation results recorded.</div>
  return (
    <div className="vz-stage" role="table" aria-label="Response stage timing per validation scenario (simulated clock)">
      <div className="vz-stage-row head" role="row">
        <span role="columnheader">scenario</span>
        {cols.map((c) => (
          <span key={c.k} role="columnheader" title={c.hint}>
            {c.label} <span className="dim mono">max {fmtSeconds(max[c.k])}</span>
          </span>
        ))}
      </div>
      {rows.map((r, i) => (
        <div key={r.scenario_id} className="vz-stage-row" role="row" style={{ ['--i' as string]: i }}>
          <span role="rowheader" className="clip" title={r.name}>
            {r.name}
          </span>
          {cols.map((c) => {
            const v = r[c.k]
            if (v == null) {
              return (
                <span key={c.k} role="cell" className="cell">
                  {c.k === 'ttc' && r.response === 'withheld' ? <span className="chip withheld">withheld by policy</span> : <span className="faint">—</span>}
                </span>
              )
            }
            return (
              <span key={c.k} role="cell" className={`cell ${c.k}`}>
                <span className="bar" aria-hidden="true">
                  <span style={{ width: `${Math.max(2, (v / max[c.k]) * 100)}%` }} />
                </span>
                <span className="mono v">{fmtSeconds(v)}</span>
              </span>
            )
          })}
        </div>
      ))}
      <div className="vz-foot">Measured on each scenario&apos;s simulated clock by the validation harness. Each column has its own scale; a withheld scenario has no containment time because policy kept automation away from the target.</div>
    </div>
  )
}

/* ============================================================== posture: category stack */
const ST = ['PASS', 'FAIL', 'UNKNOWN', 'STALE'] as const
export function CategoryStack({ rows }: { rows: { category: string; pass: number; fail: number; unknown: number; stale: number }[] }) {
  if (!rows.length) return <div className="vz-empty">No assessments recorded.</div>
  const sorted = [...rows].sort((a, b) => b.fail + b.stale + b.unknown - (a.fail + a.stale + a.unknown) || b.pass - a.pass)
  const max = Math.max(...rows.map((r) => r.pass + r.fail + r.unknown + r.stale))
  return (
    <ol className="vz-cat">
      {sorted.map((r, i) => {
        const v = { PASS: r.pass, FAIL: r.fail, UNKNOWN: r.unknown, STALE: r.stale }
        const t = r.pass + r.fail + r.unknown + r.stale
        return (
          <li key={r.category} style={{ ['--i' as string]: i }} title={`${r.category}: ${r.pass} pass, ${r.fail} fail, ${r.unknown} unknown, ${r.stale} stale`}>
            <span className="lb">{r.category}</span>
            <span className="tr">
              <span className="fill" style={{ width: `${(t / max) * 100}%` }}>
                {ST.map((s) => (v[s] ? <span key={s} className={`seg ${s}`} style={{ flexGrow: v[s] }} /> : null))}
              </span>
            </span>
            <span className="vl mono">
              {r.pass}
              <span className="dim">/{t}</span>
              {r.fail ? <span className="f"> {r.fail} fail</span> : null}
              {r.stale ? <span className="s"> {r.stale} stale</span> : null}
              {r.unknown ? <span className="u"> {r.unknown} unknown</span> : null}
            </span>
          </li>
        )
      })}
    </ol>
  )
}

/* ============================================================== posture: CSF wheel */
const FN_ORDER = ['GV', 'ID', 'PR', 'DE', 'RS', 'RC']
const FN_NAME: Record<string, string> = { GV: 'Govern', ID: 'Identify', PR: 'Protect', DE: 'Detect', RS: 'Respond', RC: 'Recover' }
export function CsfWheel({ csf }: { csf: Posture['csf'] }) {
  const [hot, setHot] = useState<string | null>(null)
  if (!csf.length) return <div className="vz-empty">No assessed controls map to a CSF subcategory yet.</div>
  const items = [...csf].sort((a, b) => FN_ORDER.indexOf(a.function) - FN_ORDER.indexOf(b.function) || a.id.localeCompare(b.id))
  const fns = FN_ORDER.filter((f) => items.some((i) => i.function === f))
  const gapDeg = 6
  const per = (360 - gapDeg * fns.length) / items.length
  const R0 = 52
  const R1 = 80
  const pt = (r: number, deg: number) => {
    const a = ((deg - 90) * Math.PI) / 180
    return [100 + r * Math.cos(a), 100 + r * Math.sin(a)]
  }
  const seg = (a0: number, a1: number, r0: number, r1: number) => {
    const [x0, y0] = pt(r1, a0)
    const [x1, y1] = pt(r1, a1)
    const [x2, y2] = pt(r0, a1)
    const [x3, y3] = pt(r0, a0)
    const large = a1 - a0 > 180 ? 1 : 0
    return `M${x0},${y0} A${r1},${r1} 0 ${large} 1 ${x1},${y1} L${x2},${y2} A${r0},${r0} 0 ${large} 0 ${x3},${y3} Z`
  }
  let deg = gapDeg / 2
  const arcs: { id: string; fn: string; d: string; state: string; mid: number }[] = []
  const fnArcs: { fn: string; a0: number; a1: number }[] = []
  for (const f of fns) {
    const start = deg
    for (const c of items.filter((i) => i.function === f)) {
      const state = c.fail ? 'FAIL' : c.stale ? 'STALE' : c.unknown ? 'UNKNOWN' : 'PASS'
      arcs.push({ id: c.id, fn: f, d: seg(deg + 0.8, deg + per - 0.8, R0, R1), state, mid: deg + per / 2 })
      deg += per
    }
    fnArcs.push({ fn: f, a0: start, a1: deg })
    deg += gapDeg
  }
  const cur = hot ? items.find((i) => i.id === hot) : null
  return (
    <div className="vz-wheel">
      <svg viewBox="0 0 200 200" role="img" aria-label={`NIST CSF 2.0 subcategories referenced by controls: ${items.length} across ${fns.length} functions`}>
        {fnArcs.map((f) => {
          const [lx, ly] = pt(R1 + 12, (f.a0 + f.a1) / 2)
          return (
            <g key={f.fn}>
              <path d={seg(f.a0, f.a1, R1 + 3, R1 + 5)} className="vz-wheel-fn" />
              <text x={lx} y={ly + 4} className="vz-wheel-fl">
                {f.fn}
              </text>
            </g>
          )
        })}
        {arcs.map((a) => (
          <path key={a.id} d={a.d} className={`vz-wheel-seg ${a.state} ${hot && hot !== a.id ? 'dim' : ''}`} onMouseEnter={() => setHot(a.id)} onMouseLeave={() => setHot(null)}>
            <title>{a.id}</title>
          </path>
        ))}
        <text x="100" y="98" className="vz-wheel-c1">
          {cur ? cur.id : items.length}
        </text>
        <text x="100" y="114" className="vz-wheel-c2">
          {cur ? `${cur.pass} pass · ${cur.fail} fail` : 'subcategories'}
        </text>
      </svg>
      <ul className="vz-wheel-list">
        {fns.map((f) => (
          <li key={f}>
            <span className="fnk mono">{f}</span>
            <span className="fnn">{FN_NAME[f] ?? f}</span>
            <span className="ids">
              {items
                .filter((i) => i.function === f)
                .map((i) => (
                  <span key={i.id} className={`sid mono ${i.fail ? 'FAIL' : i.stale ? 'STALE' : i.unknown ? 'UNKNOWN' : 'PASS'} ${hot === i.id ? 'on' : ''}`} onMouseEnter={() => setHot(i.id)} onMouseLeave={() => setHot(null)} title={`${i.id}: ${i.text} — ${i.pass} pass, ${i.fail} fail, ${i.unknown} unknown, ${i.stale} stale`}>
                    {i.id.split('.')[1]}
                  </span>
                ))}
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}

/* ============================================================== posture: run ledger */
export function RunLedger({ runs }: { runs: AssessmentRun[] }) {
  if (!runs.length) return <div className="vz-empty">No assessment runs recorded.</div>
  const ordered = [...runs].sort((a, b) => a.assessed_at.localeCompare(b.assessed_at))
  const max = Math.max(...ordered.map((r) => r.assessments))
  return (
    <div className="vz-runs">
      <ol className="scroll-x">
        {ordered.map((r, i) => {
          const c = r.counts
          const nonpass = (c.FAIL ?? 0) + (c.UNKNOWN ?? 0) + (c.STALE ?? 0)
          return (
            <li key={r.run_id} style={{ ['--i' as string]: i }} title={`${r.run_id}: ${r.assessments} assessments · ${c.PASS ?? 0} pass · ${c.FAIL ?? 0} fail · ${c.UNKNOWN ?? 0} unknown · ${c.STALE ?? 0} stale · ${r.findings_open} findings open`}>
              <span className="np mono">{nonpass} non-pass</span>
              <span className="area">
                <span className="col" style={{ height: `${(r.assessments / max) * 100}%` }}>
                  {(['STALE', 'UNKNOWN', 'FAIL', 'PASS'] as const).map((s) => (c[s] ? <span key={s} className={`seg ${s}`} style={{ flexGrow: c[s] }} /> : null))}
                </span>
              </span>
              <span className="tg">{r.trigger}</span>
              <span className="tm mono">
                {r.assessed_at.slice(11, 16)} · {r.assessments}
              </span>
            </li>
          )
        })}
      </ol>
      <div className="vz-foot">
        {runs.length} run{runs.length === 1 ? '' : 's'} recorded in the run ledger, oldest first. Column height: assessments evaluated; segments: PASS · FAIL · UNKNOWN · STALE.
      </div>
    </div>
  )
}

/* ============================================================== findings lifecycle */
const LIFECYCLE = ['open', 'reopened', 'remediation_requested', 'remediated', 'remediation_failed', 'verified', 'closed']
export function LifecycleStrip({ byStatus }: { byStatus: Record<string, number> }) {
  const total = Object.values(byStatus).reduce((a, b) => a + b, 0)
  if (!total) return <div className="vz-empty">No findings recorded.</div>
  const keys = [...LIFECYCLE, ...Object.keys(byStatus).filter((k) => !LIFECYCLE.includes(k))]
  return (
    <div className="vz-life">
      <div className="bar" role="img" aria-label={keys.filter((k) => byStatus[k]).map((k) => `${byStatus[k]} ${k.replace(/_/g, ' ')}`).join(', ')}>
        {keys.map((k) => (byStatus[k] ? <span key={k} className={`seg ${k}`} style={{ flexGrow: byStatus[k] }} title={`${k.replace(/_/g, ' ')}: ${byStatus[k]}`} /> : null))}
      </div>
      <ol className="stages">
        {keys.map((k) => (
          <li key={k} className={byStatus[k] ? 'on' : ''}>
            <span className={`sw ${k}`} aria-hidden="true" />
            <span className="k">{k.replace(/_/g, ' ')}</span>
            <span className="v mono">{byStatus[k] ?? 0}</span>
          </li>
        ))}
      </ol>
    </div>
  )
}

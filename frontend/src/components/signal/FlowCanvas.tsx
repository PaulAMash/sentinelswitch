import { useEffect, useMemo, useRef } from 'react'
import type { Alert, ContainmentAction } from '../../lib/api'
import { ms, sev3 } from '../../lib/telemetry'
import { FAMILIES, upper, type Family, type Wire } from '../../lib/wire'
import { HEX } from './hex'
import { PLAYBACK_CLOCK, type FlowClock } from './clock'
import type { FieldModel } from './model'

/**
 * Recorded traffic drawn over the signal field. Every particle is one Zeek connection whose recorded
 * time the playhead just passed, travelling from the originating port through the switch to the
 * responding port (into the switch itself for another private address, out through the uplink trunk
 * for a public one). Particles run beneath the ports so they never cover a number. Rings mark
 * RADIUS results, syslog lines and alerts at the port they name. Nothing is drawn that is not a record;
 * busy moments draw a sample of their connections, and every connection still lights its ports.
 *
 * The canvas is driven by the shared playback clock: it advances only while playback runs, freezes when
 * it pauses and clears on a seek or loop.
 */

const MAX_PARTICLES = 160
/** particles drawn per real second at most; busier moments draw an even sample (every connection still lights its ports) */
const PARTICLES_PER_SECOND = 80
const PARTICLE_BURST = 6
/** a playhead move larger than this between frames is a jump (seek, window change), not playback */
const JUMP_MS = 30 * 60_000
const HALO_HALF_LIFE = 650
const CORE_HALF_LIFE = 900

interface Particle {
  ax: number
  ay: number
  cx: number
  cy: number
  bx: number
  by: number
  born: number
  dur: number
  fam: number
  r: number
}
interface Ring {
  x: number
  y: number
  born: number
  dur: number
  color: string
  r0: number
  r1: number
  w: number
}
interface Pt {
  x: number
  y: number
}

export interface FlowCanvasProps {
  model: FieldModel
  wire: Wire
  /** alerts that pass the field's filters, ascending by time */
  alerts: Alert[]
  families: Set<Family>
  /** defaults to the shared playback clock */
  clock?: FlowClock
  /** only connections to or from these addresses (all when omitted) */
  hosts?: Set<string>
  /** recorded containment actions: a lock-down wave when one is applied, a green wave when it is restored */
  actions?: ContainmentAction[]
}

function cssColor(name: string, fallback: string): string {
  if (typeof document === 'undefined') return fallback
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback
}

const PRIVATE = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/

export function FlowCanvas(p: FlowCanvasProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const props = useRef(p)
  useEffect(() => {
    props.current = p
  })

  // where each recorded host enters the field: its port, else the uplink trunk (it is reached through it)
  const geom = useMemo(() => {
    const pos = new Map<string, Pt>()
    const ipNode = new Map<string, string>()
    for (const n of p.model.nodes) {
      pos.set(n.id, { x: n.x, y: n.y })
      if (n.ip) ipNode.set(n.ip, n.id)
    }
    const trunks = p.model.nodes.filter((n) => n.port.mode === 'trunk')
    const uplink = trunks.find((n) => /uplink|core|dist/i.test(n.port.description ?? '')) ?? trunks[0] ?? null
    // an address on a SW01 port enters at that port; another private address ends at the switch itself
    // (it is not attached here); a public address leaves through the uplink trunk
    const anchor: (string | null)[] = p.wire.hosts.map((ip) => ipNode.get(ip) ?? (PRIVATE.test(ip) || !uplink ? null : uplink.id))
    const external = p.wire.hosts.map((ip) => !PRIVATE.test(ip))
    const only = p.hosts ? p.wire.hosts.map((ip) => p.hosts!.has(ip)) : null
    return { pos, anchor, external, only, uplink: uplink?.id ?? null, core: p.model.core }
  }, [p.model.nodes, p.model.core, p.wire, p.hosts])
  const geomRef = useRef(geom)
  useEffect(() => {
    geomRef.current = geom
  }, [geom])

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return
    const famColor = FAMILIES.map((f) => cssColor(`--svc-${f}`, 'transparent'))
    const col = {
      ok: cssColor('--ok', 'transparent'),
      bad: cssColor('--danger', 'transparent'),
      guest: cssColor('--info', 'transparent'),
      warn: cssColor('--warn', 'transparent'),
      infra: cssColor('--svc-infra', 'transparent'),
      accent: cssColor('--accent', 'transparent'),
      high: cssColor('--sev-high', 'transparent'),
      medium: cssColor('--sev-medium', 'transparent'),
      low: cssColor('--sev-low', 'transparent'),
    }
    const parts: Particle[] = []
    const rings: Ring[] = []
    const halo = new Map<string, { v: number; fam: number }>()
    let coreV = 0
    let spin = 0
    let budget = PARTICLE_BURST
    let clock = 0 // particle clock: real ms elapsed while playing
    let lastReal: number | null = null
    let lastT: number | null = null
    let view = { s: 1, ox: 0, oy: 0, dpr: 1 }

    const fit = () => {
      const svg = canvas.parentElement?.querySelector<SVGSVGElement>('svg.sf')
      const box = canvas.getBoundingClientRect()
      const dpr = Math.min(2, window.devicePixelRatio || 1)
      canvas.width = Math.max(1, Math.round(box.width * dpr))
      canvas.height = Math.max(1, Math.round(box.height * dpr))
      const [vx, vy, vw, vh] = props.current.model.viewBox
      const sb = svg?.getBoundingClientRect() ?? box
      // the SVG letterboxes its viewBox (xMidYMid meet) inside its own box
      const s = Math.min(sb.width / vw, sb.height / vh)
      const ox = sb.left - box.left + (sb.width - vw * s) / 2 - vx * s
      const oy = sb.top - box.top + (sb.height - vh * s) / 2 - vy * s
      view = { s: s * dpr, ox: ox * dpr, oy: oy * dpr, dpr }
      draw()
    }
    const X = (x: number) => view.ox + x * view.s
    const Y = (y: number) => view.oy + y * view.s

    const at = (id: string | null): Pt | null => (id ? geomRef.current.pos.get(id) ?? null : null)
    const bump = (id: string | null, fam: number, by = 0.35) => {
      if (!id) return
      const h = halo.get(id)
      if (h) {
        h.v = Math.min(1.6, h.v + by)
        h.fam = fam
      } else halo.set(id, { v: by, fam })
    }
    const ring = (pt: Pt | null, color: string, big = false) => {
      if (!pt || rings.length > 160) return
      rings.push({ x: pt.x, y: pt.y, born: clock, dur: big ? 1500 : 900, color, r0: HEX * (big ? 1.0 : 0.95), r1: HEX * (big ? 3.6 : 2.0), w: big ? 2.2 : 1.2 })
    }
    /** containment: three slow concentric waves, staggered, much wider than an alert */
    const wave = (pt: Pt | null, color: string) => {
      if (!pt) return
      for (let k = 0; k < 3; k++) rings.push({ x: pt.x, y: pt.y, born: clock + k * 380, dur: 2600, color, r0: HEX * 1.1, r1: HEX * (6 + k * 1.5), w: 3 - k * 0.6 })
    }

    const spawn = (t0: number, t1: number) => {
      const { wire, alerts, families } = props.current
      const g = geomRef.current
      const core = g.core
      const i0 = upper(wire.t, t0)
      const i1 = upper(wire.t, t1)
      const total = i1 - i0
      const allowed = Math.min(Math.floor(budget), MAX_PARTICLES - parts.length)
      const stride = allowed > 0 ? Math.max(1, total / allowed) : Infinity
      let next = 0
      for (let k = 0; k < total; k++) {
        const i = i0 + k
        const fam = wire.fam[i]
        if (!families.has(FAMILIES[fam])) continue
        if (g.only && !g.only[wire.o[i]] && !g.only[wire.r[i]]) continue
        const aId = g.anchor[wire.o[i]]
        const bId = g.anchor[wire.r[i]]
        bump(aId, fam)
        bump(bId, fam)
        coreV = Math.min(6, coreV + 0.035)
        if (k < next || budget < 1 || parts.length >= MAX_PARTICLES) continue
        next = k + stride
        budget -= 1
        const a = at(aId) ?? core
        const b = at(bId) ?? core
        if (a === b) continue
        const len = Math.hypot(b.x - a.x, b.y - a.y)
        parts.push({ ax: a.x, ay: a.y, cx: core.x, cy: core.y, bx: b.x, by: b.y, born: clock, dur: 1100 + len * 1.6, fam, r: 0.8 + Math.min(1.2, Math.log10(1 + wire.b[i]) / 3.5) })
      }
      for (let ai = upper(wire.authT, t0); ai < upper(wire.authT, t1); ai++) {
        const a = wire.auth[ai]
        ring(at(a.port), a.result === 'Access-Accept' ? col.ok : a.result === 'Access-Reject' ? col.bad : col.guest)
        bump(a.port, FAMILIES.indexOf('dir'), 0.5)
      }
      for (let si = upper(wire.syslogT, t0); si < upper(wire.syslogT, t1); si++) {
        const s = wire.syslog[si]
        const pt = at(s.port) ?? (s.severity <= 4 ? core : null)
        ring(pt, s.severity <= 3 ? col.bad : s.severity === 4 ? col.warn : col.infra)
      }
      for (const al of alerts) {
        const x = ms(al.ts)
        if (x <= t0 || x > t1) continue
        const sv = sev3(al.severity)
        const pt = at(al.interface)
        ring(pt, col[sv], true)
        ring(pt, col[sv], false)
      }
      for (const ac of props.current.actions ?? []) {
        const ap = ac.applied_at ? ms(ac.applied_at) : null
        const re = ac.restored_at ? ms(ac.restored_at) : null
        if (ap != null && ap > t0 && ap <= t1) wave(at(ac.interface), ac.action === 'quarantine_vlan' ? col.bad : col.warn)
        if (re != null && re > t0 && re <= t1) wave(at(ac.interface), col.ok)
      }
    }

    const quad = (pt: Particle, u: number): Pt => {
      const v = 1 - u
      return { x: v * v * pt.ax + 2 * v * u * pt.cx + u * u * pt.bx, y: v * v * pt.ay + 2 * v * u * pt.cy + u * u * pt.by }
    }
    const hexPath = (x: number, y: number, r: number) => {
      ctx.beginPath()
      for (let i = 0; i < 6; i++) {
        const a = ((60 * i - 30) * Math.PI) / 180
        const px = X(x + r * Math.cos(a))
        const py = Y(y + r * Math.sin(a))
        if (i) ctx.lineTo(px, py)
        else ctx.moveTo(px, py)
      }
      ctx.closePath()
    }

    function draw() {
      ctx!.setTransform(1, 0, 0, 1, 0, 0)
      ctx!.clearRect(0, 0, canvas!.width, canvas!.height)
      ctx!.globalCompositeOperation = 'lighter'
      const g = geomRef.current
      // port halos: every recorded connection lights the ports it touched
      for (const [id, h] of halo) {
        const pt = g.pos.get(id)
        if (!pt || h.v < 0.02) continue
        hexPath(pt.x, pt.y, HEX * 1.16)
        ctx!.strokeStyle = famColor[h.fam]
        ctx!.globalAlpha = Math.min(0.6, h.v * 0.45)
        ctx!.lineWidth = (0.8 + Math.min(1.2, h.v)) * view.dpr
        ctx!.stroke()
      }
      // switch fabric: throughput ring around the core
      const cx = X(g.core.x)
      const cy = Y(g.core.y)
      const R = HEX * 3.15 * view.s
      ctx!.lineWidth = 2 * view.dpr
      ctx!.strokeStyle = col.accent
      for (let k = 0; k < 3; k++) {
        const a0 = spin + (k * Math.PI * 2) / 3
        ctx!.globalAlpha = Math.min(0.6, 0.1 + coreV * 0.1)
        ctx!.beginPath()
        ctx!.arc(cx, cy, R, a0, a0 + 0.35 + Math.min(1.2, coreV * 0.22))
        ctx!.stroke()
      }
      // rings: RADIUS results, syslog, alerts
      for (const r of rings) {
        if (clock < r.born) continue
        const u = Math.min(1, (clock - r.born) / r.dur)
        const e = 1 - (1 - u) ** 3
        hexPath(r.x, r.y, r.r0 + (r.r1 - r.r0) * e)
        ctx!.strokeStyle = r.color
        ctx!.globalAlpha = (1 - u) * 0.9
        ctx!.lineWidth = r.w * view.dpr
        ctx!.stroke()
      }
      // particles with short trails
      for (const pt of parts) {
        const u = Math.min(1, (clock - pt.born) / pt.dur)
        const e = u < 0.5 ? 2 * u * u : 1 - (-2 * u + 2) ** 2 / 2
        const c = famColor[pt.fam]
        ctx!.strokeStyle = c
        ctx!.lineWidth = pt.r * 0.9 * view.dpr
        let prev = quad(pt, e)
        for (let k = 1; k <= 4; k++) {
          const q = quad(pt, Math.max(0, e - k * 0.03))
          ctx!.globalAlpha = 0.42 * (1 - k / 5)
          ctx!.beginPath()
          ctx!.moveTo(X(prev.x), Y(prev.y))
          ctx!.lineTo(X(q.x), Y(q.y))
          ctx!.stroke()
          prev = q
        }
        const h = quad(pt, e)
        ctx!.fillStyle = c
        ctx!.globalAlpha = 0.16
        ctx!.beginPath()
        ctx!.arc(X(h.x), Y(h.y), pt.r * 2.2 * view.dpr, 0, Math.PI * 2)
        ctx!.fill()
        ctx!.globalAlpha = 0.85
        ctx!.beginPath()
        ctx!.arc(X(h.x), Y(h.y), pt.r * view.dpr, 0, Math.PI * 2)
        ctx!.fill()
      }
      ctx!.globalAlpha = 1
      ctx!.globalCompositeOperation = 'source-over'
    }

    const clear = () => {
      parts.length = 0
      rings.length = 0
      halo.clear()
      coreV = 0
    }

    const clk = props.current.clock ?? PLAYBACK_CLOCK
    const onFrame = (pos: number) => {
      const playing = clk.isPlaying()
      const now = performance.now()
      if (!playing) {
        // paused: hold the picture; a seek clears it so nothing in flight belongs to another time
        if (lastT != null && pos !== lastT) clear()
        lastT = pos
        lastReal = null
        draw()
        return
      }
      const dt = lastReal == null ? 0 : Math.min(64, now - lastReal)
      lastReal = now
      clock += dt
      spin += dt * (0.0003 + Math.min(6, coreV) * 0.00025)
      budget = Math.min(PARTICLE_BURST, budget + (dt * PARTICLES_PER_SECOND) / 1000)
      const decay = (half: number) => Math.pow(0.5, dt / half)
      const hd = decay(HALO_HALF_LIFE)
      for (const [id, h] of halo) {
        h.v *= hd
        if (h.v < 0.02) halo.delete(id)
      }
      coreV *= decay(CORE_HALF_LIFE)
      if (lastT != null && (pos < lastT || pos - lastT > JUMP_MS)) clear()
      else if (lastT != null && pos > lastT) spawn(lastT, pos)
      lastT = pos
      for (let i = parts.length - 1; i >= 0; i--) if (clock - parts[i].born >= parts[i].dur) parts.splice(i, 1)
      for (let i = rings.length - 1; i >= 0; i--) if (clock - rings[i].born >= rings[i].dur) rings.splice(i, 1)
      draw()
    }

    fit()
    const ro = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(fit) : null
    ro?.observe(canvas)
    canvas.addEventListener('refit', fit)
    const unsub = clk.subscribeFrame(onFrame)
    const unsubSnap = clk.subscribe(() => {
      if (!clk.isPlaying()) lastReal = null
    })
    return () => {
      ro?.disconnect()
      canvas.removeEventListener('refit', fit)
      unsub()
      unsubSnap()
    }
  }, [])

  // a different layout (wide/tall) changes the viewBox: refit
  useEffect(() => {
    const c = canvasRef.current
    if (c) c.dispatchEvent(new Event('refit'))
  }, [p.model.viewBox])

  return <canvas ref={canvasRef} className="sf-flowcanvas" aria-hidden="true" />
}

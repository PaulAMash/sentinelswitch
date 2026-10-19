import type { Alert, AssessmentStatus, ContainmentAction, Device, Incident, PortState, Review, SwitchState, UnknownDevice } from '../../lib/api'
import { responseStateOf, type ResponseState } from '../status'
import { inWindow, ms, portNumber, portOrder, sev3, type AlertFilter, type Sev3, type Window } from '../../lib/telemetry'
import { HEX, SQ3, hexPath, spiral, toPixel, type Axial } from './hex'

/**
 * The Network Signal Field model. One hexagon per SW01 interface, grouped into colonies by the
 * interface's operational VLAN (trunks and unused ports have their own colonies). Everything a node
 * shows comes from the switch twin (/api/switch), the inventory (/api/devices), alerts (/api/alerts),
 * incidents, containment actions and manual reviews. The layout itself is schematic: colony positions
 * are fixed anchors on the lattice, not physical locations.
 */

export type Preset = 'wide' | 'tall'
export type ClusterId = 'core' | 'v10' | 'v20' | 'v30' | 'v40' | 'v50' | 'v99' | 'trunk' | 'unused' | 'other'

const CAPACITY: Record<ClusterId, number> = { core: 7, v10: 7, v20: 37, v30: 7, v40: 7, v50: 7, v99: 7, trunk: 7, unused: 19, other: 7 }

/* Anchors chosen offline by a greedy packer so every colony keeps at least one empty lattice cell
   between itself and its neighbours at full capacity (two around the core). */
const ANCHORS: Record<Preset, Record<ClusterId, Axial>> = {
  wide: { core: [0, 0], v20: [-7, 0], v50: [-5, 6], v30: [7, -2], trunk: [2, -5], v99: [-2, -6], v10: [7, -6], v40: [1, 5], unused: [8, 3], other: [-7, -6] },
  tall: { core: [3, -7], v20: [-3, 4], v50: [5, -1], v30: [-4, -1], trunk: [0, -9], v99: [8, -8], v10: [9, -5], v40: [1, -2], unused: [-3, 12], other: [-11, 12] },
}

export type NodeResponse = 'contained' | 'held' | 'review' | 'incident'

export interface FieldNode {
  id: string
  label: string
  port: PortState
  cluster: ClusterId
  x: number
  y: number
  ring: number
  device: Device | null
  unknown: UnknownDevice | null
  ip: string | null
  macs: string[]
  vlan: number | null
  alerts: Alert[]
  counts: Record<Sev3, number>
  maxSev: Sev3 | null
  heat: 0 | 1 | 2 | 3
  response: NodeResponse | null
  incident: Incident | null
  incidentState: ResponseState | null
  review: Review | null
}

export interface FieldCluster {
  id: ClusterId
  title: string
  name: string
  vlan: number | null
  x: number
  y: number
  labelY: number
  count: number
  mirrored: boolean | null
  /** CTL-SENSOR-COVERAGE result for this VLAN, when that control assessed it */
  coverage: AssessmentStatus | null
}

export interface Flow {
  id: string
  from: string
  to: string | null
  toLabel: string
  sev: Sev3
  t: number
  alert: Alert
}

/** A slot a quarantined port vacated in its home colony. */
export interface Ghost {
  id: string
  label: string
  x: number
  y: number
}

export interface FieldModel {
  preset: Preset
  ghosts: Ghost[]
  viewBox: [number, number, number, number]
  core: { x: number; y: number }
  nodes: FieldNode[]
  clusters: FieldCluster[]
  flows: Flow[]
  lattice: string
}

export interface FieldInputs {
  sw: SwitchState
  devices: Device[]
  unknown: UnknownDevice[]
  alerts: Alert[]
  incidents: Incident[]
  actions: ContainmentAction[]
  reviews: Review[]
  /** VLAN → result of the sensor-coverage control (is the VLAN mirrored to the sensor), when assessed */
  coverage?: Map<number, AssessmentStatus>
}

function clusterOf(p: PortState): ClusterId {
  if (p.mode === 'trunk') return 'trunk'
  return clusterOfVlan(p.oper_vlan ?? p.access_vlan)
}

/** The colony a port belongs to when it is not quarantined: its original VLAN while quarantined. */
function homeOf(p: PortState): ClusterId {
  if (p.quarantined && p.original_vlan != null) return clusterOfVlan(p.original_vlan)
  return clusterOf(p)
}

function clusterOfVlan(v: number | null): ClusterId {
  switch (v) {
    case 10:
      return 'v10'
    case 20:
      return 'v20'
    case 30:
      return 'v30'
    case 40:
      return 'v40'
    case 50:
      return 'v50'
    case 99:
      return 'v99'
    case 999:
      return 'unused'
    default:
      return 'other'
  }
}

const OPEN_INCIDENT = (i: Incident) => i.status !== 'resolved' && i.status !== 'closed'

export function passes(a: Alert, f: AlertFilter): boolean {
  return f.severities.has(sev3(a.severity)) && f.sources.has(a.source)
}

/** Static geometry: node positions, colonies and the decorative lattice. Depends only on port→VLAN membership. */
export function layoutField(sw: SwitchState, preset: Preset, coverage?: Map<number, AssessmentStatus>) {
  const anchors = ANCHORS[preset]
  // slots are assigned by home colony so a port that moves (quarantine) never re-flows its neighbours
  const home = new Map<ClusterId, PortState[]>()
  const current = new Map<ClusterId, PortState[]>()
  for (const p of sw.interfaces) {
    const h = homeOf(p)
    const c = clusterOf(p)
    if (!home.has(h)) home.set(h, [])
    home.get(h)!.push(p)
    if (!current.has(c)) current.set(c, [])
    current.get(c)!.push(p)
  }
  const pos = new Map<string, { x: number; y: number; ring: number; cluster: ClusterId; cell: Axial }>()
  const ghosts: Ghost[] = []
  const occupied = new Set<string>()
  const clusters: FieldCluster[] = []
  const coreCells = spiral(anchors.core, CAPACITY.core)
  for (const c of coreCells) occupied.add(c.join(','))
  const ids = new Set<ClusterId>([...home.keys(), ...current.keys()])
  for (const cid of ids) {
    const natives = (home.get(cid) ?? []).sort((a, b) => portOrder(a.name, b.name))
    const visitors = (current.get(cid) ?? []).filter((p) => homeOf(p) !== cid).sort((a, b) => portOrder(a.name, b.name))
    const slots = [...natives, ...visitors]
    const cells = spiral(anchors[cid], Math.max(CAPACITY[cid], slots.length))
    let minY = Infinity
    let sx = 0
    let sy = 0
    let n = 0
    slots.forEach((p, i) => {
      const cell = cells[i]
      const [x, y] = toPixel(cell)
      occupied.add(cell.join(','))
      if (clusterOf(p) !== cid) {
        ghosts.push({ id: p.name, label: portNumber(p.name), x, y })
        return
      }
      const ringIdx = i === 0 ? 0 : i < 7 ? 1 : i < 19 ? 2 : 3
      pos.set(p.name, { x, y, ring: ringIdx, cluster: cid, cell })
      minY = Math.min(minY, y)
      sx += x
      sy += y
      n += 1
    })
    if (!n) continue
    const vlan = cid === 'trunk' || cid === 'other' ? null : cid === 'unused' ? 999 : Number(cid.slice(1))
    const info = vlan !== null ? sw.vlans[String(vlan)] : null
    const mirrored = vlan !== null && vlan !== 999 ? sw.span.source_vlans.includes(vlan) : null
    clusters.push({
      id: cid,
      title: cid === 'trunk' ? 'TRUNKS' : cid === 'other' ? 'OTHER' : String(vlan),
      name: cid === 'trunk' ? '' : info?.name ?? '',
      coverage: vlan !== null ? coverage?.get(vlan) ?? null : null,
      vlan,
      x: sx / n,
      y: sy / n,
      labelY: minY - HEX * 1.55,
      count: n,
      mirrored,
    })
  }
  const [cx, cy] = toPixel(anchors.core)
  // bounds of everything drawn, padded for labels and stubs
  const xs = [...pos.values()].map((p) => p.x).concat(cx, ...ghosts.map((g) => g.x))
  const ys = [...pos.values()].map((p) => p.y).concat(cy, ...ghosts.map((g) => g.y), ...clusters.map((c) => c.labelY))
  const pad = HEX * 3.2
  const x0 = Math.min(...xs) - pad
  const x1 = Math.max(...xs) + pad
  const y0 = Math.min(...ys) - pad * 0.7
  const y1 = Math.max(...ys) + pad
  // decorative lattice: every cell inside the frame that no node or the core occupies
  const parts: string[] = []
  const r0 = Math.floor((y0 - HEX) / (HEX * 1.5))
  const r1 = Math.ceil((y1 + HEX) / (HEX * 1.5))
  for (let r = r0; r <= r1; r++) {
    const qa = Math.floor((x0 - HEX) / (HEX * SQ3) - r / 2)
    const qb = Math.ceil((x1 + HEX) / (HEX * SQ3) - r / 2)
    for (let q = qa; q <= qb; q++) {
      if (occupied.has(`${q},${r}`)) continue
      const [x, y] = toPixel([q, r])
      // only whole cells inside the frame, so the lattice never extends past the drawing
      if (x - HEX * 0.82 < x0 || x + HEX * 0.82 > x1 || y - HEX < y0 || y + HEX > y1) continue
      parts.push(hexPath(HEX * 0.94, x, y))
    }
  }
  return { pos, ghosts, clusters, core: { x: cx, y: cy }, viewBox: [x0, y0, x1 - x0, y1 - y0] as [number, number, number, number], lattice: parts.join('') }
}

/** Per-node state for the current window and filters. */
export function buildField(inp: FieldInputs, geo: ReturnType<typeof layoutField>, preset: Preset, w: Window, f: AlertFilter): FieldModel {
  const devByPort = new Map(inp.devices.map((d) => [d.interface, d]))
  const unkByPort = new Map(inp.unknown.map((u) => [u.interface, u]))
  const ipByPort = new Map<string, string>()
  for (const b of inp.sw.dhcp_bindings) if (!ipByPort.has(b.interface)) ipByPort.set(b.interface, b.ip)
  const portByIp = new Map(inp.sw.dhcp_bindings.map((b) => [b.ip, b.interface]))
  for (const d of inp.devices) if (d.ip && !portByIp.has(d.ip) && !d.via_trunk) portByIp.set(d.ip, d.interface)
  const macsByPort = new Map<string, string[]>()
  for (const m of inp.sw.mac_table) {
    if (!macsByPort.has(m.interface)) macsByPort.set(m.interface, [])
    macsByPort.get(m.interface)!.push(m.mac)
  }
  const actionFor = new Map<string, ContainmentAction>()
  for (const a of inp.actions) {
    if (!a.incident_id) continue
    const cur = actionFor.get(a.incident_id)
    if (!cur || ['verified', 'restored', 'containment_failed'].includes(a.status)) actionFor.set(a.incident_id, a)
  }
  const incidentByPort = new Map<string, Incident>()
  for (const i of inp.incidents) {
    if (!i.interface) continue
    const cur = incidentByPort.get(i.interface)
    // an open incident outranks a resolved one; otherwise the most recent wins
    if (!cur || (OPEN_INCIDENT(i) && !OPEN_INCIDENT(cur)) || (OPEN_INCIDENT(i) === OPEN_INCIDENT(cur) && ms(i.opened_at) > ms(cur.opened_at))) incidentByPort.set(i.interface, i)
  }
  const reviewByPort = new Map<string, Review>()
  for (const r of inp.reviews) if (r.status === 'review' && r.attribution?.interface) reviewByPort.set(r.attribution.interface, r)

  const visible = inp.alerts.filter((a) => inWindow(a, w) && passes(a, f))
  const alertsByPort = new Map<string, Alert[]>()
  for (const a of visible) {
    if (!a.interface) continue
    if (!alertsByPort.has(a.interface)) alertsByPort.set(a.interface, [])
    alertsByPort.get(a.interface)!.push(a)
  }

  const nodes: FieldNode[] = inp.sw.interfaces.map((p) => {
    const g = geo.pos.get(p.name)!
    const alerts = (alertsByPort.get(p.name) ?? []).sort((a, b) => ms(b.ts) - ms(a.ts))
    const counts: Record<Sev3, number> = { high: 0, medium: 0, low: 0 }
    for (const a of alerts) counts[sev3(a.severity)] += 1
    const maxSev: Sev3 | null = counts.high ? 'high' : counts.medium ? 'medium' : counts.low ? 'low' : null
    const n = alerts.length
    const incident = incidentByPort.get(p.name) ?? null
    const review = reviewByPort.get(p.name) ?? null
    const held = p.hold || p.state === 'held' || p.state === 'err-disabled'
    const response: NodeResponse | null = p.quarantined ? 'contained' : held ? 'held' : review ? 'review' : incident && OPEN_INCIDENT(incident) ? 'incident' : null
    return {
      id: p.name,
      label: portNumber(p.name),
      port: p,
      cluster: g.cluster,
      x: g.x,
      y: g.y,
      ring: g.ring,
      device: devByPort.get(p.name) ?? null,
      unknown: unkByPort.get(p.name) ?? null,
      ip: ipByPort.get(p.name) ?? null,
      macs: macsByPort.get(p.name) ?? p.macs.map((m) => m.mac),
      vlan: p.mode === 'trunk' ? null : p.oper_vlan ?? p.access_vlan,
      alerts,
      counts,
      maxSev,
      heat: n === 0 ? 0 : n === 1 ? 1 : n <= 3 ? 2 : 3,
      response,
      incident,
      incidentState: incident ? responseStateOf(incident, actionFor.get(incident.id) ?? null) : null,
      review,
    }
  })

  const flows: Flow[] = []
  for (const a of visible) {
    if (!a.dest_ip || !a.interface) continue
    const to = portByIp.get(a.dest_ip) ?? null
    if (to === a.interface) continue
    flows.push({ id: a.id, from: a.interface, to, toLabel: a.dest_ip + (a.dest_port ? `:${a.dest_port}` : ''), sev: sev3(a.severity), t: ms(a.ts), alert: a })
  }

  return { preset, ghosts: geo.ghosts, viewBox: geo.viewBox, core: geo.core, nodes, clusters: geo.clusters, flows, lattice: geo.lattice }
}

/** Visible alerts for the stream, newest first, honouring the colony (VLAN) focus. */
export function streamAlerts(inp: FieldInputs, nodesById: Map<string, FieldNode>, w: Window, f: AlertFilter, focus: ClusterId | null): Alert[] {
  return inp.alerts
    .filter((a) => inWindow(a, w) && passes(a, f) && (!focus || (a.interface && nodesById.get(a.interface)?.cluster === focus)))
    .sort((a, b) => ms(b.ts) - ms(a.ts))
}

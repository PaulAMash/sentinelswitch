import type { Attribution } from './api'
import { vlanName } from './format'

export interface ChainNode {
  k: string
  v: string
  s?: string
  tone?: 'from' | 'to' | ''
}

export function chainFromAttribution(a: Attribution | null, toVlan?: number | null, action?: string | null): ChainNode[] {
  if (!a) return []
  const nodes: ChainNode[] = []
  if (a.ip) nodes.push({ k: 'source ip', v: a.ip, s: a.binding ? 'DHCP snooping binding' : 'no binding' })
  if (a.mac) nodes.push({ k: 'mac address', v: a.mac, s: a.vendor ?? undefined })
  nodes.push({ k: 'switch', v: a.switch, s: 'Catalyst 2960-X' })
  if (a.interface) nodes.push({ k: 'interface', v: a.interface, s: a.port_class ?? undefined })
  if (a.vlan !== null) nodes.push({ k: 'vlan', v: vlanName(a.vlan), s: a.device ?? a.port_owner ?? undefined, tone: 'from' })
  if (action === 'quarantine_vlan' && toVlan) nodes.push({ k: 'quarantine', v: vlanName(toVlan), s: 'automated', tone: 'to' })
  if (action === 'port_shutdown') nodes.push({ k: 'containment', v: 'shutdown', s: 'administrative hold', tone: 'to' })
  return nodes
}

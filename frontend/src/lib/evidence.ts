/** What each evidence-bundle artifact contains, as written by evidence/bundle.py, and how to group them. */
export const ARTIFACTS: Record<string, { group: string; about: string }> = {
  'README.md': { group: 'Report', about: 'generated human-readable report' },
  'incident.json': { group: 'Incident', about: 'incident record, detection, metrics, attribution chain' },
  'timeline.json': { group: 'Incident', about: 'ordered phases from first telemetry to evidence' },
  'alerts.json': { group: 'Incident', about: 'source detections with raw Suricata/Zeek/RADIUS/syslog records' },
  'network-context.json': { group: 'Network context', about: 'attribution, VLANs, SPAN session, port intent' },
  'dhcp-binding.json': { group: 'Network context', about: 'DHCP snooping binding used for IP → MAC' },
  'mac-table.json': { group: 'Network context', about: 'MAC address table entries and observation history' },
  'switch-port.json': { group: 'Network context', about: 'interface state before/after with show output' },
  'containment.json': { group: 'Response', about: 'policy decision and executed action with transcript' },
  'related-connections.json': { group: 'Related telemetry', about: 'Zeek conn records for the actor around the incident' },
  'related-dns.json': { group: 'Related telemetry', about: 'Zeek dns records for the actor around the incident' },
}
export const ARTIFACT_GROUPS = ['Report', 'Incident', 'Network context', 'Response', 'Related telemetry', 'Other']

export function describeArtifact(name: string): string {
  return ARTIFACTS[name]?.about ?? ''
}

export function groupArtifacts<T extends { name: string }>(files: T[]): { group: string; files: T[] }[] {
  const by = new Map<string, T[]>()
  for (const f of files) {
    const g = ARTIFACTS[f.name]?.group ?? 'Other'
    if (!by.has(g)) by.set(g, [])
    by.get(g)!.push(f)
  }
  return ARTIFACT_GROUPS.filter((g) => by.has(g)).map((g) => ({ group: g, files: by.get(g)! }))
}

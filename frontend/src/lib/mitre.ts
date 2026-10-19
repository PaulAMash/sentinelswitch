/**
 * Names and tactics for the ATT&CK Enterprise technique ids that SentinelSwitch rules emit. Used only
 * to label ids the API returned; an id missing from this table is shown as the bare id.
 */
export const TECHNIQUES: Record<string, { name: string; tactics: string[] }> = {
  T1018: { name: 'Remote System Discovery', tactics: ['Discovery'] },
  T1046: { name: 'Network Service Discovery', tactics: ['Discovery'] },
  'T1021.001': { name: 'Remote Desktop Protocol', tactics: ['Lateral Movement'] },
  'T1021.002': { name: 'SMB/Windows Admin Shares', tactics: ['Lateral Movement'] },
  'T1036.005': { name: 'Match Legitimate Name or Location', tactics: ['Defense Evasion'] },
  'T1071.004': { name: 'Application Layer Protocol: DNS', tactics: ['Command and Control'] },
  T1078: { name: 'Valid Accounts', tactics: ['Initial Access', 'Persistence', 'Privilege Escalation', 'Defense Evasion'] },
  T1110: { name: 'Brute Force', tactics: ['Credential Access'] },
  T1200: { name: 'Hardware Additions', tactics: ['Initial Access'] },
  T1498: { name: 'Network Denial of Service', tactics: ['Impact'] },
  T1557: { name: 'Adversary-in-the-Middle', tactics: ['Credential Access', 'Collection'] },
  'T1557.002': { name: 'ARP Cache Poisoning', tactics: ['Credential Access', 'Collection'] },
  'T1568.002': { name: 'Domain Generation Algorithms', tactics: ['Command and Control'] },
}

export function technique(id: string): { id: string; name: string | null; tactics: string[] } {
  const t = TECHNIQUES[id]
  return { id, name: t?.name ?? null, tactics: t?.tactics ?? [] }
}

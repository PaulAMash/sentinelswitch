import type { TimelineEntry } from '../lib/api'

const LABEL: Record<string, string> = { telemetry: 'telemetry', alert: 'detect', switch: 'switch', aaa: 'aaa', detection: 'detection', incident: 'incident', correlation: 'correlate', policy: 'policy', containment: 'contain', verification: 'verify', evidence: 'evidence', resolution: 'restore' }

export function Timeline({ entries, phases, compact = false }: { entries: TimelineEntry[]; phases?: string[]; compact?: boolean }) {
  const rows = phases ? entries.filter((e) => phases.includes(e.phase)) : entries
  return (
    <div className="timeline">
      {rows.map((e, i) => (
        <div key={i} className={`tl-item ${e.phase}`}>
          <span className="tl-ts">{e.ts.slice(11, 23)}</span>
          <span className="tl-dot" />
          <div className="tl-body">
            <span className={`tl-phase ${e.phase}`}>{LABEL[e.phase] ?? e.phase}</span>
            <span className="tl-msg">{compact && e.message.length > 150 ? e.message.slice(0, 147) + '…' : e.message}</span>
          </div>
        </div>
      ))}
    </div>
  )
}

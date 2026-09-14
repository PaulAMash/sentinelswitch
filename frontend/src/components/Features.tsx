import type { Feature } from '../lib/api'

export function Confidence({ value, base }: { value: number; base?: number }) {
  return (
    <div className="confidence">
      <span className="num">{value.toFixed(2)}</span>
      <div className="bar-track">
        <span style={{ width: `${value * 100}%` }} />
      </div>
      {base !== undefined && <span className="dim small">base {base.toFixed(2)}</span>}
    </div>
  )
}

export function Features({ features }: { features: Feature[] }) {
  return (
    <div className="features">
      {features.map((f) => (
        <div key={f.id} className={`feature ${f.matched ? 'matched' : ''}`}>
          <div>
            <div>{f.label}</div>
            {f.evidence && <div className="ev">{f.evidence}</div>}
          </div>
          <span className={`w ${f.weight < 0 ? 'neg' : ''}`}>
            {f.matched ? (f.weight > 0 ? '+' : '') + f.weight.toFixed(2) : '—'}
          </span>
        </div>
      ))}
    </div>
  )
}

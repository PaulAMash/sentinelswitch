export function Mark({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden="true">
      <rect x="4" y="4" width="56" height="56" rx="12" fill="#131a22" stroke="#39c5d6" strokeWidth="3" />
      <path d="M32 14 L48 21 V34 C48 43 41 49 32 52 C23 49 16 43 16 34 V21 Z" fill="none" stroke="#e6edf3" strokeWidth="3" strokeLinejoin="round" />
      <rect x="24" y="30" width="16" height="7" rx="1.5" fill="#39c5d6" />
      <circle cx="27.5" cy="33.5" r="1.4" fill="#0e1218" />
      <circle cx="32" cy="33.5" r="1.4" fill="#0e1218" />
      <circle cx="36.5" cy="33.5" r="1.4" fill="#0e1218" />
    </svg>
  )
}

export function Wordmark({ size = 28, sub = true }: { size?: number; sub?: boolean }) {
  return (
    <div className="brand" style={{ padding: 0 }}>
      <Mark size={size} />
      <div className="brand-text">
        <span className="brand-name" style={{ fontSize: size * 0.55 }}>
          Sentinel<span style={{ color: 'var(--accent-2)' }}>Switch</span>
        </span>
        {sub && <span className="brand-sub" style={{ fontSize: Math.max(9, size * 0.34) }}>Autonomous NDR Lab</span>}
      </div>
    </div>
  )
}

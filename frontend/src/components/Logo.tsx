/** Brand mark; colours come from tokens via currentColor and CSS classes (no literals). */
export function Mark({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden="true" className="mark">
      <rect x="4" y="4" width="56" height="56" rx="12" className="mark-bg" />
      <path d="M32 14 L48 21 V34 C48 43 41 49 32 52 C23 49 16 43 16 34 V21 Z" className="mark-shield" />
      <rect x="24" y="30" width="16" height="7" rx="1.5" className="mark-port" />
      <circle cx="27.5" cy="33.5" r="1.4" className="mark-pin" />
      <circle cx="32" cy="33.5" r="1.4" className="mark-pin" />
      <circle cx="36.5" cy="33.5" r="1.4" className="mark-pin" />
    </svg>
  )
}

export function Wordmark({ size = 28, sub = true }: { size?: number; sub?: boolean }) {
  return (
    <div className="brand">
      <Mark size={size} />
      <div className="brand-text">
        <span className="brand-name">
          Sentinel<span className="accent">Switch</span> <span className="brand-ver">2.0</span>
        </span>
        {sub && <span className="brand-sub">Evidence-driven NDR lab</span>}
      </div>
    </div>
  )
}

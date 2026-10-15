const P = { fill: 'none', stroke: 'currentColor', strokeWidth: 1.7, strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const }

export const Icon = {
  overview: () => (
    <svg viewBox="0 0 24 24" {...P}><rect x="3" y="3" width="7" height="9" rx="1.5" /><rect x="14" y="3" width="7" height="5" rx="1.5" /><rect x="14" y="12" width="7" height="9" rx="1.5" /><rect x="3" y="16" width="7" height="5" rx="1.5" /></svg>
  ),
  alerts: () => (
    <svg viewBox="0 0 24 24" {...P}><path d="M12 3l9 16H3z" /><path d="M12 10v4M12 17h.01" /></svg>
  ),
  incidents: () => (
    <svg viewBox="0 0 24 24" {...P}><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z" /><path d="M9.5 12l2 2 3.5-4" /></svg>
  ),
  devices: () => (
    <svg viewBox="0 0 24 24" {...P}><rect x="3" y="4" width="18" height="12" rx="2" /><path d="M8 20h8M12 16v4" /></svg>
  ),
  switch: () => (
    <svg viewBox="0 0 24 24" {...P}><rect x="2" y="7" width="20" height="10" rx="2" /><path d="M6 12h.01M9.5 12h.01M13 12h.01M16.5 12h.01" /></svg>
  ),
  auth: () => (
    <svg viewBox="0 0 24 24" {...P}><rect x="5" y="11" width="14" height="10" rx="2" /><path d="M8 11V8a4 4 0 018 0v3" /></svg>
  ),
  coverage: () => (
    <svg viewBox="0 0 24 24" {...P}><path d="M4 12l4 4L20 6" /><path d="M4 20h16" /></svg>
  ),
  drift: () => (
    <svg viewBox="0 0 24 24" {...P}><path d="M4 6h10M4 12h16M4 18h7" /><circle cx="18" cy="6" r="2" /><circle cx="15" cy="18" r="2" /></svg>
  ),
  evidence: () => (
    <svg viewBox="0 0 24 24" {...P}><path d="M6 3h8l4 4v14H6z" /><path d="M14 3v4h4M9 12h6M9 16h6" /></svg>
  ),
  about: () => (
    <svg viewBox="0 0 24 24" {...P}><circle cx="12" cy="12" r="9" /><path d="M12 11v5M12 8h.01" /></svg>
  ),
  arrow: () => (
    <svg viewBox="0 0 24 24" {...P}><path d="M5 12h14M13 6l6 6-6 6" /></svg>
  ),
  lock: () => (
    <svg viewBox="0 0 24 24" {...P}><rect x="5" y="11" width="14" height="10" rx="2" /><path d="M8 11V8a4 4 0 018 0v3" /></svg>
  ),
  play: () => (
    <svg viewBox="0 0 24 24" {...P}><path d="M7 5l12 7-12 7z" /></svg>
  ),
  reset: () => (
    <svg viewBox="0 0 24 24" {...P}><path d="M4 12a8 8 0 1 0 2.3-5.7" /><path d="M4 4v5h5" /></svg>
  ),
  posture: () => (
    <svg viewBox="0 0 24 24" {...P}><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z" /><path d="M8 12h8M12 8v8" /></svg>
  ),
  findings: () => (
    <svg viewBox="0 0 24 24" {...P}><circle cx="11" cy="11" r="6" /><path d="M20 20l-4.5-4.5M11 8v3l2 1" /></svg>
  ),
  close: () => (
    <svg viewBox="0 0 24 24" {...P}><path d="M6 6l12 12M18 6L6 18" /></svg>
  ),
}

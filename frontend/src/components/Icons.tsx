const P = { fill: 'none', stroke: 'currentColor', strokeWidth: 1.7, strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const }

/** Inline SVG icons (16 px grid). No icon font, no emoji. */
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
  pause: () => (
    <svg viewBox="0 0 24 24" {...P}><path d="M8 5v14M16 5v14" /></svg>
  ),
  restart: () => (
    <svg viewBox="0 0 24 24" {...P}><path d="M6 5v14" /><path d="M18 5l-9 7 9 7z" /></svg>
  ),
  loop: () => (
    <svg viewBox="0 0 24 24" {...P}><path d="M17 2l3 3-3 3" /><path d="M4 11V9a4 4 0 014-4h12" /><path d="M7 22l-3-3 3-3" /><path d="M20 13v2a4 4 0 01-4 4H4" /></svg>
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
  menu: () => (
    <svg viewBox="0 0 24 24" {...P}><path d="M4 7h16M4 12h16M4 17h16" /></svg>
  ),
  chevron: () => (
    <svg viewBox="0 0 24 24" {...P}><path d="M9 6l6 6-6 6" /></svg>
  ),
  chevronDown: () => (
    <svg viewBox="0 0 24 24" {...P}><path d="M6 9l6 6 6-6" /></svg>
  ),
  info: () => (
    <svg viewBox="0 0 24 24" {...P}><circle cx="12" cy="12" r="9" /><path d="M12 11v5M12 8h.01" /></svg>
  ),
  check: () => (
    <svg viewBox="0 0 24 24" {...P}><path d="M5 12.5l4.5 4.5L19 7" /></svg>
  ),
  pending: () => (
    <svg viewBox="0 0 24 24" {...P}><circle cx="12" cy="12" r="8" strokeDasharray="3 3" /></svg>
  ),
  withheld: () => (
    <svg viewBox="0 0 24 24" {...P}><circle cx="12" cy="12" r="8" /><path d="M6.5 6.5l11 11" /></svg>
  ),
  fail: () => (
    <svg viewBox="0 0 24 24" {...P}><circle cx="12" cy="12" r="8" /><path d="M9 9l6 6M15 9l-6 6" /></svg>
  ),
  dot: () => (
    <svg viewBox="0 0 24 24" {...P}><circle cx="12" cy="12" r="4" fill="currentColor" stroke="none" /></svg>
  ),
  copy: () => (
    <svg viewBox="0 0 24 24" {...P}><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V6a2 2 0 012-2h9" /></svg>
  ),
  external: () => (
    <svg viewBox="0 0 24 24" {...P}><path d="M14 4h6v6M20 4l-9 9" /><path d="M19 14v5a1 1 0 01-1 1H5a1 1 0 01-1-1V6a1 1 0 011-1h5" /></svg>
  ),
  terminal: () => (
    <svg viewBox="0 0 24 24" {...P}><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M7 9l3 3-3 3M12 15h5" /></svg>
  ),
  clock: () => (
    <svg viewBox="0 0 24 24" {...P}><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></svg>
  ),
  report: () => (
    <svg viewBox="0 0 24 24" {...P}><path d="M6 3h8l4 4v14H6z" /><path d="M14 3v4h4M9 13h6M9 17h4" /></svg>
  ),
  warn: () => (
    <svg viewBox="0 0 24 24" {...P}><path d="M12 3l9 16H3z" /><path d="M12 10v4M12 17h.01" /></svg>
  ),
  bolt: () => (
    <svg viewBox="0 0 24 24" {...P}><path d="M13 2L4 14h7l-1 8 9-12h-7z" /></svg>
  ),
}

import { NavLink, Route, Routes, useLocation } from 'react-router-dom'
import { Wordmark } from './components/Logo'
import { Icon } from './components/Icons'
import { useApi } from './lib/hooks'
import { endpoints } from './lib/api'
import { Overview } from './pages/Overview'
import { Alerts } from './pages/Alerts'
import { Incidents } from './pages/Incidents'
import { IncidentDetail } from './pages/IncidentDetail'
import { Devices } from './pages/Devices'
import { SwitchPage } from './pages/Switch'
import { Authentication } from './pages/Authentication'
import { Coverage } from './pages/Coverage'
import { Drift } from './pages/Drift'
import { Evidence } from './pages/Evidence'
import { About } from './pages/About'
import { Media } from './pages/Media'
import { Posture } from './pages/Posture'
import { Controls } from './pages/Controls'
import { Findings } from './pages/Findings'
import { Reports } from './pages/Reports'

const NAV = [
  // Assurance (SentinelSwitch 2.0)
  { to: '/', label: 'Posture', icon: Icon.posture, end: true, group: 'assurance' },
  { to: '/controls', label: 'Controls', icon: Icon.coverage, group: 'assurance' },
  { to: '/findings', label: 'Findings & Remediation', icon: Icon.findings, group: 'assurance' },
  { to: '/incidents', label: 'Incidents', icon: Icon.incidents, group: 'assurance' },
  { to: '/reports', label: 'Evidence & Reports', icon: Icon.evidence, group: 'assurance' },
  // Operations (original SOC views)
  { to: '/operations', label: 'SOC Overview', icon: Icon.overview, group: 'operations' },
  { to: '/alerts', label: 'Alerts', icon: Icon.alerts, group: 'operations' },
  { to: '/devices', label: 'Assets', icon: Icon.devices, group: 'operations' },
  { to: '/switch', label: 'Network / Switch', icon: Icon.switch, group: 'operations' },
  { to: '/authentication', label: 'Authentication', icon: Icon.auth, group: 'operations' },
  { to: '/coverage', label: 'Detection Coverage', icon: Icon.coverage, group: 'operations' },
  { to: '/drift', label: 'Configuration Drift', icon: Icon.drift, group: 'operations' },
  { to: '/evidence', label: 'Evidence Bundles', icon: Icon.evidence, group: 'operations' },
  { to: '/about', label: 'Architecture', icon: Icon.about, group: 'operations' },
]

function Shell() {
  const loc = useLocation()
  const { data: meta } = useApi(endpoints.meta, [loc.pathname])
  const current = NAV.find((n) => (n.end ? loc.pathname === n.to : loc.pathname.startsWith(n.to)))
  const stage = meta?.demo?.stage
  return (
    <div className="shell">
      <aside className="sidebar">
        <Wordmark />
        <nav className="nav">
          <div className="nav-section">Assurance</div>
          {NAV.filter((n) => n.group === 'assurance').map((n) => (
            <NavLink key={n.to} to={n.to} end={n.end} className={({ isActive }) => (isActive ? 'active' : '')}>
              <n.icon />
              {n.label}
              {n.to === '/incidents' && meta && <span className="nav-badge">{meta.counts.incidents}</span>}
              {n.to === '/findings' && meta && meta.counts.findings_open !== undefined && <span className="nav-badge">{meta.counts.findings_open}</span>}
            </NavLink>
          ))}
          <div className="nav-section">Operations</div>
          {NAV.filter((n) => n.group === 'operations').map((n) => (
            <NavLink key={n.to} to={n.to} className={({ isActive }) => (isActive ? 'active' : '')}>
              <n.icon />
              {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-foot">
          {meta ? (
            <>
              <div>
                <b style={{ color: 'var(--text-2)' }}>{meta.switch.hostname}</b> · {meta.switch.model}
              </div>
              <div>IOS {meta.switch.ios_version} · {meta.switch.management_ip}</div>
              <div style={{ marginTop: 6 }}>Dataset day {meta.dataset.day} (UTC)</div>
              <div>SentinelSwitch {meta.version}</div>
            </>
          ) : (
            <div>connecting…</div>
          )}
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <div className="crumbs">
            {current?.label ?? 'SentinelSwitch'} {/^\/(incidents|findings|controls)\/.+/.test(loc.pathname) && <span>/ {decodeURIComponent(loc.pathname.split('/').slice(2).join('/'))}</span>}
          </div>
          <span className="chip sim">Simulation · synthetic telemetry</span>
          <div className="spacer" />
          <div className="meta">
            {stage && (
              <span className={`chip ${stage === 'contained' ? 'contained' : stage === 'restored' ? 'resolved' : 'neutral'}`}>
                {stage === 'contained' ? `${meta?.flagship_incident} contained` : stage === 'restored' ? `${meta?.flagship_incident} resolved` : 'baseline · flagship not replayed'}
              </span>
            )}
            {meta ? (
              <span>
                <span className="dot" />
                {meta.switch.hostname} reachable
              </span>
            ) : (
              <span className="dim">connecting to API…</span>
            )}
            <span className="mono">{meta?.switch.now?.replace('T', ' ').slice(0, 19)} UTC</span>
          </div>
        </header>
        <main className="content">
          <Routes>
            <Route path="/" element={<Posture />} />
            <Route path="/controls" element={<Controls />} />
            <Route path="/controls/:id" element={<Controls />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/findings/:id" element={<Findings />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/operations" element={<Overview />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/incidents/:id" element={<IncidentDetail />} />
            <Route path="/devices" element={<Devices />} />
            <Route path="/devices/:hostname" element={<Devices />} />
            <Route path="/switch" element={<SwitchPage />} />
            <Route path="/authentication" element={<Authentication />} />
            <Route path="/coverage" element={<Coverage />} />
            <Route path="/drift" element={<Drift />} />
            <Route path="/evidence" element={<Evidence />} />
            <Route path="/evidence/:id" element={<Evidence />} />
            <Route path="/about" element={<About />} />
          </Routes>
        </main>
      </div>
    </div>
  )
}

export default function App() {
  return (
    <Routes>
      <Route path="/media/:slug" element={<Media />} />
      <Route path="/*" element={<Shell />} />
    </Routes>
  )
}

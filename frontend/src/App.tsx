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

const NAV = [
  { to: '/', label: 'Overview', icon: Icon.overview, end: true },
  { to: '/alerts', label: 'Alerts', icon: Icon.alerts },
  { to: '/incidents', label: 'Incidents', icon: Icon.incidents },
  { to: '/devices', label: 'Devices', icon: Icon.devices },
  { to: '/switch', label: 'Network / Switch', icon: Icon.switch },
  { to: '/authentication', label: 'Authentication', icon: Icon.auth },
  { to: '/coverage', label: 'Detection Coverage', icon: Icon.coverage },
  { to: '/drift', label: 'Configuration Drift', icon: Icon.drift },
  { to: '/evidence', label: 'Evidence', icon: Icon.evidence },
  { to: '/about', label: 'Architecture', icon: Icon.about },
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
          <div className="nav-section">Operations</div>
          {NAV.slice(0, 6).map((n) => (
            <NavLink key={n.to} to={n.to} end={n.end} className={({ isActive }) => (isActive ? 'active' : '')}>
              <n.icon />
              {n.label}
              {n.to === '/incidents' && meta && <span className="nav-badge">{meta.counts.incidents}</span>}
            </NavLink>
          ))}
          <div className="nav-section">Assurance</div>
          {NAV.slice(6).map((n) => (
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
              <div>SentinelSwitch v{meta.version}</div>
            </>
          ) : (
            <div>connecting…</div>
          )}
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <div className="crumbs">
            {current?.label ?? 'SentinelSwitch'} {loc.pathname.startsWith('/incidents/') && <span>/ {loc.pathname.split('/')[2]}</span>}
          </div>
          <span className="chip sim">Simulation · synthetic telemetry</span>
          <div className="spacer" />
          <div className="meta">
            {stage && (
              <span className={`chip ${stage === 'contained' ? 'contained' : stage === 'restored' ? 'resolved' : 'neutral'}`}>
                {stage === 'contained' ? 'INC-2026-0042 contained' : stage === 'restored' ? 'INC-2026-0042 resolved' : 'baseline · flagship not replayed'}
              </span>
            )}
            <span>
              <span className="dot" />
              {meta?.switch.hostname ?? 'SW01'} reachable
            </span>
            <span className="mono">{meta?.switch.now?.replace('T', ' ').slice(0, 19)} UTC</span>
          </div>
        </header>
        <main className="content">
          <Routes>
            <Route path="/" element={<Overview />} />
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

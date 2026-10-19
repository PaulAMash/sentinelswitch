import { useEffect, useState } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { Icon } from './components/Icons'
import { Sidebar, Topbar, type NavItem } from './components/layout'
import { ToastProvider } from './components/toast'
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

const NAV: Omit<NavItem, 'badge' | 'attention'>[] = [
  { to: '/', label: 'Overview', icon: Icon.overview, end: true, group: 'assurance' },
  { to: '/posture', label: 'Posture', icon: Icon.posture, group: 'assurance' },
  { to: '/controls', label: 'Controls', icon: Icon.coverage, group: 'assurance' },
  { to: '/findings', label: 'Findings', icon: Icon.findings, group: 'assurance' },
  { to: '/incidents', label: 'Incidents', icon: Icon.incidents, group: 'assurance' },
  { to: '/reports', label: 'Reports', icon: Icon.report, group: 'assurance' },
  { to: '/alerts', label: 'Alerts', icon: Icon.alerts, group: 'operations' },
  { to: '/devices', label: 'Assets', icon: Icon.devices, group: 'operations' },
  { to: '/switch', label: 'Switch', icon: Icon.switch, group: 'operations' },
  { to: '/authentication', label: 'Authentication', icon: Icon.auth, group: 'operations' },
  { to: '/coverage', label: 'Coverage', icon: Icon.check, group: 'operations' },
  { to: '/drift', label: 'Drift', icon: Icon.drift, group: 'operations' },
  { to: '/evidence', label: 'Evidence', icon: Icon.evidence, group: 'operations' },
  { to: '/about', label: 'Architecture', icon: Icon.about, group: 'operations' },
]

function Shell() {
  const loc = useLocation()
  const { data: meta } = useApi(endpoints.meta, [loc.pathname])
  const [navOpen, setNavOpen] = useState(false)
  useEffect(() => {
    if (!navOpen) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setNavOpen(false)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [navOpen])
  const current = NAV.find((n) => (n.end ? loc.pathname === n.to : loc.pathname.startsWith(n.to)))
  const leaf = /^\/(incidents|findings|controls|devices|evidence)\/.+/.test(loc.pathname) ? decodeURIComponent(loc.pathname.split('/').slice(2).join('/')) : null
  const crumbs = [{ label: current?.label ?? 'SentinelSwitch', to: current?.to }, ...(leaf ? [{ label: leaf }] : [])]
  const reviewsOpen = meta?.counts.reviews_open ?? 0
  const items: NavItem[] = NAV.map((n) => {
    if (n.to === '/incidents' && meta) return { ...n, badge: reviewsOpen > 0 ? reviewsOpen : meta.counts.incidents, attention: reviewsOpen > 0 }
    if (n.to === '/findings' && meta?.counts.findings_open !== undefined) return { ...n, badge: meta.counts.findings_open }
    return n
  })
  return (
    <div className={`shell ${navOpen ? 'nav-open' : ''}`}>
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <Sidebar items={items} meta={meta} open={navOpen} onClose={() => setNavOpen(false)} />
      <div className="nav-backdrop" onClick={() => setNavOpen(false)} aria-hidden="true" />
      <div className="main">
        <Topbar crumbs={crumbs} meta={meta} onMenu={() => setNavOpen(true)} />
        <main className="content" id="main">
          <div className="page" key={loc.pathname.split('/')[1] || 'home'}>
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/posture" element={<Posture />} />
            <Route path="/operations" element={<Navigate replace to="/" />} />
            <Route path="/controls" element={<Controls />} />
            <Route path="/controls/:id" element={<Controls />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/findings/:id" element={<Findings />} />
            <Route path="/reports" element={<Reports />} />
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
          </div>
        </main>
      </div>
    </div>
  )
}

export default function App() {
  return (
    <ToastProvider>
      <Routes>
        <Route path="/media/:slug" element={<Media />} />
        <Route path="/*" element={<Shell />} />
      </Routes>
    </ToastProvider>
  )
}

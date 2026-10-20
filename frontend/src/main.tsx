import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import '@fontsource-variable/inter'
import '@fontsource-variable/jetbrains-mono'
import './styles/base.css'
import './styles/components.css'
import './styles/pages.css'
import './styles/signal.css'
import './styles/viz.css'
import App from './App'
import { endpoints } from './lib/api'

// the recorded-telemetry feed is static per dataset: start fetching it while the first view loads its data
void endpoints.telemetry().catch(() => {})

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </StrictMode>,
)

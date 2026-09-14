import { useEffect, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { endpoints } from '../lib/api'
import { useApi } from '../lib/hooks'
import { Card, Chip, Loading, Sev, Term, Ts } from '../components/ui'
import { fmtBytes } from '../lib/format'

export function Evidence() {
  const { data, error } = useApi(endpoints.evidence)
  const { id } = useParams()
  const [params, setParams] = useSearchParams()
  const file = params.get('file') ?? 'README.md'
  const [content, setContent] = useState<string>('')
  const current = data?.find((e) => e.incident.id === id) ?? data?.[0]
  useEffect(() => {
    if (!current) return
    endpoints.evidenceFile(current.incident.id, file).then((c) => setContent(typeof c === 'string' ? c : JSON.stringify(c, null, 2))).catch((e: Error) => setContent(`error: ${e.message}`))
  }, [current, file])
  if (!data) return <Loading error={error} />
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Evidence</h1>
          <p>Every contained incident writes a self-contained bundle to <code>data/incidents/&lt;id&gt;/</code>: JSON artifacts for the attribution chain, switch state, related telemetry, and a generated report.</p>
        </div>
      </div>
      <div className="grid side-main">
        <div className="stack">
          {data.map((e) => (
            <Link key={e.incident.id} to={`/evidence/${e.incident.id}`} style={{ textDecoration: 'none' }}>
              <div className={`card`} style={{ padding: 12, borderColor: current?.incident.id === e.incident.id ? 'var(--accent-2)' : undefined }}>
                <div className="row">
                  <span className="mono strong">{e.incident.id}</span>
                  <Sev s={e.incident.severity} />
                  <Chip kind={e.incident.status} />
                  {e.complete ? <Chip kind="ok">{e.files.length} artifacts</Chip> : <Chip kind="medium">{e.files.length} artifacts</Chip>}
                </div>
                <div style={{ marginTop: 6 }}>{e.incident.title}</div>
                <div className="dim small"><Ts ts={e.incident.opened_at} date /> · {e.incident.interface} · {e.path}</div>
              </div>
            </Link>
          ))}
          {data.length === 0 && <div className="empty">No incidents yet</div>}
        </div>
        {current && (
          <Card title={`${current.incident.id} / ${file}`} sub={`${current.path}`} right={<Link to={`/incidents/${current.incident.id}`}>open incident</Link>} bodyClass="tight">
            <div style={{ display: 'grid', gridTemplateColumns: '220px 1fr' }}>
              <div style={{ borderRight: '1px solid var(--border)', padding: 8 }}>
                {current.files.map((f) => (
                  <button key={f.name} className="btn sm" style={{ width: '100%', justifyContent: 'space-between', marginBottom: 4, background: f.name === file ? 'var(--panel-3)' : undefined }} onClick={() => setParams({ file: f.name })}>
                    <span className="mono">{f.name}</span>
                    <span className="dim">{fmtBytes(f.bytes)}</span>
                  </button>
                ))}
              </div>
              <div style={{ padding: 12, minWidth: 0 }}>
                <Term text={content} hl={['Access Mode VLAN', '"status": "verified"', 'VLAN 50']} />
              </div>
            </div>
          </Card>
        )}
      </div>
    </>
  )
}

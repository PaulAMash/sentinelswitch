import { useEffect, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { endpoints } from '../lib/api'
import { useApi } from '../lib/hooks'
import { ErrorState, Loading, Panel, Ts } from '../components/ui'
import { PageHeader } from '../components/layout'
import { Id, SeverityChip, StatusChip } from '../components/status'
import { Terminal } from '../components/terminal'
import { renderMarkdown } from '../lib/markdown'
import { fmtBytes, vlanName } from '../lib/format'
import { describeArtifact, groupArtifacts } from '../lib/evidence'
import { BASE } from '../lib/api'

const HL = ['Access Mode VLAN', '"status": "verified"', 'VLAN 50']

export function Evidence() {
  const { data, error, reload } = useApi(endpoints.evidence)
  const { id } = useParams()
  const [params, setParams] = useSearchParams()
  const file = params.get('file') ?? 'README.md'
  // content is tagged with the bundle/file it belongs to, so a stale response is never shown for the current file
  const [loaded, setLoaded] = useState<{ key: string; text: string; error: boolean } | null>(null)
  const [wrap, setWrap] = useState(true)
  const current = data?.find((e) => e.incident.id === id) ?? data?.[0]
  const currentId = current?.incident.id
  const key = `${currentId ?? ''}/${file}`
  useEffect(() => {
    if (!currentId) return
    let live = true
    endpoints
      .evidenceFile(currentId, file)
      .then((c) => live && setLoaded({ key, text: typeof c === 'string' ? c : JSON.stringify(c, null, 2), error: false }))
      .catch((e: Error) => live && setLoaded({ key, text: `error: ${e.message}`, error: true }))
    return () => {
      live = false
    }
  }, [currentId, file, key])
  if (error && !data) return <ErrorState error={error} retry={reload} />
  if (!data) return <Loading rows={4} />
  const content = loaded && loaded.key === key ? loaded : null
  const isMd = file.toLowerCase().endsWith('.md') && content && !content.error
  return (
    <>
      <PageHeader
        title="Evidence"
        sub="Original evidence bundles written by the pipeline when an incident is contained"
        info={
          <>
            Every contained incident writes a self-contained bundle to <code>data/incidents/&lt;id&gt;/</code>: JSON artifacts for the attribution chain, switch state, related telemetry, and a generated report. Analyst actions (authorization and resolution) live in the incident timeline; remediation evidence lives with each finding; exported reports are on the Reports page.
          </>
        }
      />
      <div className="ev-layout">
        <Panel title="Bundles" sub={`${data.length} incident${data.length === 1 ? '' : 's'}`} bodyClass="none">
          <div className="ev-list">
            {data.map((e) => {
              const on = current?.incident.id === e.incident.id
              return (
                <Link key={e.incident.id} to={`/evidence/${e.incident.id}`} className={`ev-item ${on ? 'active' : ''}`} aria-current={on ? 'true' : undefined}>
                  <span className="ev-item-top">
                    <Id>{e.incident.id}</Id>
                    <SeverityChip value={e.incident.severity} />
                  </span>
                  <span className="t">{e.incident.title}</span>
                  <span className="ev-item-meta">
                    <Ts ts={e.incident.opened_at} date ms={false} />
                    <span className="mono">{e.incident.interface}</span>
                  </span>
                  <span className="ev-item-foot">
                    <StatusChip value={e.incident.status} />
                    <span className={e.complete ? 'dim' : 'warn-ink'}>
                      {e.files.length} artifacts · {fmtBytes(e.files.reduce((n, f) => n + f.bytes, 0))}
                      {e.complete ? '' : ' · incomplete'}
                    </span>
                  </span>
                </Link>
              )
            })}
            {data.length === 0 && <div className="empty">No incidents yet</div>}
          </div>
        </Panel>
        {current ? (
          <section className="panel ev-doc" aria-label={`${current.incident.id} evidence`}>
            <header className="ev-doc-head">
              <div className="ev-doc-id">
                <span className="eyebrow">original evidence · {current.path}</span>
                <h2>
                  <Id>{current.incident.id}</Id> <span className="dim">{current.incident.title}</span>
                </h2>
              </div>
              <div className="row">
                <Link className="btn sm" to={`/incidents/${current.incident.id}`}>
                  Open incident
                </Link>
              </div>
            </header>
            <dl className="ev-context">
              <div>
                <dt>severity</dt>
                <dd>
                  <SeverityChip value={current.incident.severity} />
                </dd>
              </div>
              <div>
                <dt>status</dt>
                <dd>
                  <StatusChip value={current.incident.status} />
                </dd>
              </div>
              <div>
                <dt>confidence</dt>
                <dd className="mono">{current.incident.confidence.toFixed(2)}</dd>
              </div>
              <div>
                <dt>opened</dt>
                <dd>
                  <Ts ts={current.incident.opened_at} date ms={false} />
                </dd>
              </div>
              <div>
                <dt>endpoint</dt>
                <dd>{current.incident.device ?? 'unknown device'}</dd>
              </div>
              <div>
                <dt>port</dt>
                <dd className="mono">
                  {current.incident.switch} {current.incident.interface}
                </dd>
              </div>
              <div>
                <dt>vlan</dt>
                <dd className="mono">{current.incident.original_vlan !== current.incident.current_vlan ? `${vlanName(current.incident.original_vlan)} → ${vlanName(current.incident.current_vlan)}` : vlanName(current.incident.original_vlan)}</dd>
              </div>
            </dl>
            <nav className="ev-artifacts" aria-label="Bundle artifacts">
              {groupArtifacts(current.files).map((g) => (
                <div key={g.group} className="ev-art-group">
                  <span className="ev-art-k">{g.group}</span>
                  <div className="ev-art-list" role="tablist" aria-label={g.group}>
                    {g.files.map((f) => (
                      <button key={f.name} role="tab" type="button" aria-selected={f.name === file} className={`ev-art ${f.name === file ? 'on' : ''}`} onClick={() => setParams({ file: f.name })} title={describeArtifact(f.name)}>
                        <span className="n">{f.name}</span>
                        <span className="sz">{fmtBytes(f.bytes)}</span>
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </nav>
            <div className="ev-file-head">
              <span className="mono strong">{file}</span>
              <span className="dim small">{describeArtifact(file)}</span>
              <span className="spacer" />
              {!isMd && (
                <button className="btn sm ghost" type="button" aria-pressed={wrap} onClick={() => setWrap((w) => !w)}>
                  {wrap ? 'Wrap on' : 'Wrap off'}
                </button>
              )}
              <a className="btn sm ghost" href={`${BASE}/api/incidents/${current.incident.id}/evidence/${file}`} target="_blank" rel="noreferrer">
                Raw
              </a>
            </div>
            <div className="ev-file" key={key}>
              {content === null ? <Loading rows={4} /> : isMd ? <article className="md">{renderMarkdown(content.text)}</article> : <Terminal text={content.text} hl={HL} maxHeight={760} className={wrap ? 'wrap-lines' : ''} />}
            </div>
          </section>
        ) : (
          <Panel>
            <div className="empty">No evidence bundles yet. Bundles are written when an incident is contained.</div>
          </Panel>
        )}
      </div>
    </>
  )
}

import { useEffect, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { endpoints } from '../lib/api'
import { useApi } from '../lib/hooks'
import { ErrorState, Loading, Panel, Ts } from '../components/ui'
import { PageHeader } from '../components/layout'
import { Chip, Id, SeverityChip, StatusChip } from '../components/status'
import { Terminal } from '../components/terminal'
import { renderMarkdown } from '../lib/markdown'
import { fmtBytes } from '../lib/format'

const HL = ['Access Mode VLAN', '"status": "verified"', 'VLAN 50']

export function Evidence() {
  const { data, error, reload } = useApi(endpoints.evidence)
  const { id } = useParams()
  const [params, setParams] = useSearchParams()
  const file = params.get('file') ?? 'README.md'
  // content is tagged with the bundle/file it belongs to, so a stale response is never shown for the current file
  const [loaded, setLoaded] = useState<{ key: string; text: string; error: boolean } | null>(null)
  const [wrap, setWrap] = useState(false)
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
            {data.map((e) => (
              <Link key={e.incident.id} to={`/evidence/${e.incident.id}`} className={`ev-item ${current?.incident.id === e.incident.id ? 'active' : ''}`} aria-current={current?.incident.id === e.incident.id ? 'true' : undefined}>
                <span className="row nowrap">
                  <Id>{e.incident.id}</Id>
                  <SeverityChip value={e.incident.severity} />
                  <StatusChip value={e.incident.status} />
                </span>
                <span className="t" title={e.incident.title}>
                  {e.incident.title}
                </span>
                <span className="row nowrap small dim">
                  <Ts ts={e.incident.opened_at} date ms={false} />
                  <span className="mono">{e.incident.interface}</span>
                  <Chip kind={e.complete ? 'ok' : 'warn'}>
                    {e.files.length} artifacts · {fmtBytes(e.files.reduce((n, f) => n + f.bytes, 0))}
                  </Chip>
                </span>
              </Link>
            ))}
            {data.length === 0 && <div className="empty">No incidents yet</div>}
          </div>
        </Panel>
        {current ? (
          <Panel
            title={
              <>
                <Id>{current.incident.id}</Id> <span className="dim">/</span> <span className="mono">{file}</span>
              </>
            }
            sub={`ORIGINAL EVIDENCE · ${current.path}`}
            right={
              <>
                {!isMd && (
                  <button className="btn sm ghost" type="button" aria-pressed={wrap} onClick={() => setWrap((w) => !w)}>
                    {wrap ? 'no wrap' : 'wrap'}
                  </button>
                )}
                <Link className="btn sm" to={`/incidents/${current.incident.id}`}>
                  open incident
                </Link>
              </>
            }
            bodyClass="none"
          >
            <div className="file-tabs" role="tablist" aria-label="Bundle files">
              {current.files.map((f) => (
                <button key={f.name} role="tab" type="button" aria-selected={f.name === file} className={f.name === file ? 'active' : ''} onClick={() => setParams({ file: f.name })}>
                  {f.name}
                  <span className="sz">{fmtBytes(f.bytes)}</span>
                </button>
              ))}
            </div>
            {content === null ? (
              <Loading rows={4} />
            ) : isMd ? (
              <div className="md">{renderMarkdown(content.text)}</div>
            ) : (
              <div className="panel-body">
                <Terminal text={content.text} hl={HL} maxHeight={720} className={wrap ? 'wrap-lines' : ''} />
              </div>
            )}
          </Panel>
        ) : (
          <Panel>
            <div className="empty">No evidence bundles yet. Bundles are written when an incident is contained.</div>
          </Panel>
        )}
      </div>
    </>
  )
}

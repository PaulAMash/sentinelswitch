import { useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { SEVERITIES, SOURCES, type Window } from '../../lib/telemetry'
import { SignalField, describeNode } from './SignalField'
import { buildField, layoutField, type FieldInputs, type Preset } from './model'

const ALL = { severities: new Set(SEVERITIES), sources: new Set<string>(SOURCES) }
const NONE = new Set<string>()

/**
 * The signal field without its console, focused on one port: the port and every port it exchanged
 * alert traffic with stay lit, everything else recedes. Used where a single entity is under
 * investigation (incident workspace).
 */
export function MiniField({ inputs, window: w, focus, caption }: { inputs: FieldInputs; window: Window; focus: string | null; caption?: string }) {
  const [sel, setSel] = useState<string | null>(focus)
  const [hover, setHover] = useState<string | null>(null)
  const [preset, setPreset] = useState<Preset>('wide')
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const el = ref.current
    if (!el || typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(([e]) => setPreset(e.contentRect.width < 520 ? 'tall' : 'wide'))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  const geo = useMemo(() => layoutField(inputs.sw, preset, inputs.coverage), [inputs.sw, preset, inputs.coverage])
  const model = useMemo(() => buildField(inputs, geo, preset, w, ALL), [inputs, geo, preset, w])
  const byId = new Map(model.nodes.map((n) => [n.id, n]))
  const shown = hover ? byId.get(hover) : sel ? byId.get(sel) : null
  return (
    <div className="mini-field" ref={ref}>
      <SignalField model={model} selectedNode={sel} selectedFlow={null} selectedAlertPort={null} focusCluster={null} pulses={[]} travel={NONE} arrive={false} onSelectNode={(id) => setSel(id ?? focus)} onHoverNode={setHover} onFocusCluster={() => undefined} />
      <div className="mini-cap">
        <span className="mono small">{shown ? describeNode(shown) : caption}</span>
        <Link to="/" className="small">
          open the signal field
        </Link>
      </div>
    </div>
  )
}

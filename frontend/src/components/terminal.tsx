import { useEffect, useMemo, useRef, useState, type CSSProperties } from 'react'
import { Icon } from './Icons'

/** Read-only terminal output: prompt lines in accent, highlighted lines in warn ink. */
export function Terminal({ text, hl = [], maxHeight, copy = true, className = '' }: { text: string; hl?: string[]; maxHeight?: number; copy?: boolean; className?: string }) {
  const lines = text.split('\n')
  const style = maxHeight ? ({ '--term-max': `${maxHeight}px` } as CSSProperties) : undefined
  const [copied, setCopied] = useState(false)
  const doCopy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1200)
    } catch {
      /* clipboard unavailable: nothing to do */
    }
  }
  return (
    <div className={`terminal ${className}`}>
      <pre style={style}>
        {lines.map((l, i) => {
          const isPrompt = /^[A-Za-z0-9-]+[#>]/.test(l)
          const isHl = hl.some((h) => h && l.includes(h))
          return (
            <span key={i} className={isPrompt ? 'prompt' : isHl ? 'hl' : undefined}>
              {l}
              {'\n'}
            </span>
          )
        })}
      </pre>
      {copy && text && (
        <button className="btn sm icon ghost copy" type="button" onClick={doCopy} aria-label="Copy output" title={copied ? 'Copied' : 'Copy'}>
          {copied ? <Icon.check /> : <Icon.copy />}
        </button>
      )}
    </div>
  )
}

interface Entry {
  cmd: string
  out: string
  error?: boolean
}

/**
 * Interactive IOS console. The typed string is sent unchanged to `run` (the existing
 * GET /api/switch/show, which enforces the `show` prefix server-side). Suggestions come only from the
 * `commands` list the server provides; history lives in component memory for the session.
 */
export function Console({ hostname, commands, run, initial, hl = [], height = 340 }: { hostname: string; commands: string[]; run: (cmd: string) => Promise<string>; initial?: Entry | null; hl?: string[]; height?: number }) {
  const [entries, setEntries] = useState<Entry[]>(initial ? [initial] : [])
  const [value, setValue] = useState('')
  const [history, setHistory] = useState<string[]>(initial ? [initial.cmd] : [])
  const [hIdx, setHIdx] = useState<number | null>(null)
  const [selRaw, setSel] = useState(0)
  const [busy, setBusy] = useState(false)
  const outRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const suggestions = useMemo(() => {
    const q = value.trim().toLowerCase()
    if (!q) return []
    return commands.filter((c) => c.toLowerCase().startsWith(q) && c.toLowerCase() !== q).slice(0, 8)
  }, [value, commands])
  // the highlighted suggestion is clamped to the current list instead of being reset in an effect
  const sel = suggestions.length ? Math.min(selRaw, suggestions.length - 1) : 0
  useEffect(() => {
    outRef.current?.scrollTo({ top: outRef.current.scrollHeight })
  }, [entries])

  const submit = async (cmd: string) => {
    const c = cmd.trim()
    if (!c || busy) return
    setBusy(true)
    setValue('')
    setSel(0)
    setHIdx(null)
    setHistory((h) => (h[h.length - 1] === c ? h : [...h, c]))
    try {
      const out = await run(c)
      setEntries((e) => [...e, { cmd: c, out }])
    } catch (err) {
      setEntries((e) => [...e, { cmd: c, out: (err as Error).message, error: true }])
    } finally {
      setBusy(false)
      inputRef.current?.focus()
    }
  }
  const onKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault()
      submit(suggestions.length && sel < suggestions.length && e.altKey ? suggestions[sel] : value)
    } else if (e.key === 'Tab' && suggestions.length) {
      e.preventDefault()
      setValue(suggestions[sel] ?? suggestions[0])
    } else if (e.key === 'ArrowDown' && suggestions.length) {
      e.preventDefault()
      setSel((s) => (s + 1) % suggestions.length)
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      if (suggestions.length) setSel((s) => (s - 1 + suggestions.length) % suggestions.length)
      else if (history.length) {
        const idx = hIdx === null ? history.length - 1 : Math.max(0, hIdx - 1)
        setHIdx(idx)
        setValue(history[idx])
      }
    } else if (e.key === 'ArrowDown' && !suggestions.length && hIdx !== null) {
      e.preventDefault()
      const idx = hIdx + 1
      if (idx >= history.length) {
        setHIdx(null)
        setValue('')
      } else {
        setHIdx(idx)
        setValue(history[idx])
      }
    } else if (e.key === 'Escape') {
      setValue('')
    }
  }
  const renderOut = (text: string, error?: boolean) =>
    text.split('\n').map((l, i) => {
      const isPrompt = /^[A-Za-z0-9-]+[#>]/.test(l)
      const isHl = hl.some((h) => h && l.includes(h))
      return (
        <span key={i} className={error ? 'err' : isPrompt ? 'prompt' : isHl ? 'hl' : undefined}>
          {l}
          {'\n'}
        </span>
      )
    })
  return (
    <div className="console" style={{ '--console-h': `${height}px` } as CSSProperties}>
      <div className="out" ref={outRef} aria-live="polite">
        {entries.length === 0 && <span className="cmd-echo">{hostname}# (type a show command — Tab completes, ↑/↓ recall history)</span>}
        {entries.map((e, i) => (
          <span key={i}>
            {!e.out.startsWith(`${hostname}#`) && (
              <span>
                <span className="prompt">{hostname}#</span>
                {e.cmd}
                {'\n'}
              </span>
            )}
            {renderOut(e.out, e.error)}
            {'\n'}
          </span>
        ))}
      </div>
      <div className="in">
        <span className="ps">{hostname}#</span>
        <input ref={inputRef} value={value} onChange={(e) => setValue(e.target.value)} onKeyDown={onKey} placeholder="show …" aria-label="IOS show command" autoComplete="off" spellCheck={false} disabled={busy} />
        <button className="btn sm primary" type="button" onClick={() => submit(value)} disabled={busy || !value.trim()}>
          run
        </button>
        {suggestions.length > 0 && (
          <div className="suggest" role="listbox">
            {suggestions.map((s, i) => (
              <button key={s} type="button" role="option" aria-selected={i === sel} className={i === sel ? 'active' : ''} onMouseDown={(e) => e.preventDefault()} onClick={() => submit(s)}>
                {s}
              </button>
            ))}
          </div>
        )}
      </div>
      <div className="hintbar">
        <span>read-only · only `show` commands are accepted by the twin</span>
        <span>{commands.length} known commands</span>
        {busy && <span>running…</span>}
      </div>
    </div>
  )
}

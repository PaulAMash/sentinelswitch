import { useCallback, useEffect, useRef, useState } from 'react'

const BASE = import.meta.env.VITE_API_BASE ?? ''

/** Global refresh counter bumped by Server-Sent Events so every view re-fetches on state changes. */
const listeners = new Set<() => void>()
let stream: EventSource | null = null

export function ensureStream() {
  if (stream || typeof EventSource === 'undefined') return
  try {
    stream = new EventSource(`${BASE}/api/events/stream`)
    const bump = () => listeners.forEach((l) => l())
    for (const kind of ['state', 'incident', 'alert', 'validation', 'assessment', 'finding']) stream.addEventListener(kind, bump)
    stream.onerror = () => {
      /* browser retries automatically */
    }
  } catch {
    stream = null
  }
}

/**
 * Fetch `loader()` and re-fetch on dependency changes and server events.
 *
 * Every request carries a sequence number and only the newest one may write state, so a slow
 * response from an earlier request can never overwrite a newer one. Results are tagged with the
 * dependency key they were requested for: `fresh` is false while the data on hand belongs to a
 * previous key (for example the previous filter), so views can show a loading state instead of
 * presenting old rows as the answer to the new question. Server-event refreshes keep the same key,
 * so they update in place without a loading flash.
 */
export function useApi<T>(loader: () => Promise<T>, deps: unknown[] = []) {
  const key = JSON.stringify(deps)
  const [state, setState] = useState<{ data: T | null; key: string | null }>({ data: null, key: null })
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const alive = useRef(true)
  const seq = useRef(0)
  const load = useCallback(() => {
    const mine = ++seq.current
    const requestedFor = key
    loader()
      .then((d) => {
        if (!alive.current || mine !== seq.current) return
        setState({ data: d, key: requestedFor })
        setError(null)
        setLoading(false)
      })
      .catch((e: Error) => {
        if (!alive.current || mine !== seq.current) return
        setError(e.message)
        setLoading(false)
      })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)
  useEffect(() => {
    alive.current = true
    setLoading(true)
    setError(null)
    load()
    ensureStream()
    listeners.add(load)
    return () => {
      alive.current = false
      listeners.delete(load)
    }
  }, [load])
  return { data: state.data, fresh: state.key === key, error, loading, reload: load }
}

export function useLocalState<T>(key: string, initial: T): [T, (v: T) => void] {
  const [v, setV] = useState<T>(() => {
    try {
      const raw = localStorage.getItem(key)
      return raw ? (JSON.parse(raw) as T) : initial
    } catch {
      return initial
    }
  })
  const set = (nv: T) => {
    setV(nv)
    try {
      localStorage.setItem(key, JSON.stringify(nv))
    } catch {
      /* ignore */
    }
  }
  return [v, set]
}

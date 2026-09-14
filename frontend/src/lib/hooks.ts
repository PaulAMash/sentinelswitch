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
    for (const kind of ['state', 'incident', 'alert', 'validation']) stream.addEventListener(kind, bump)
    stream.onerror = () => {
      /* browser retries automatically */
    }
  } catch {
    stream = null
  }
}

export function useApi<T>(loader: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const alive = useRef(true)
  const load = useCallback(() => {
    loader()
      .then((d) => {
        if (!alive.current) return
        setData(d)
        setError(null)
        setLoading(false)
      })
      .catch((e: Error) => {
        if (!alive.current) return
        setError(e.message)
        setLoading(false)
      })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)
  useEffect(() => {
    alive.current = true
    setLoading(true)
    load()
    ensureStream()
    listeners.add(load)
    return () => {
      alive.current = false
      listeners.delete(load)
    }
  }, [load])
  return { data, error, loading, reload: load }
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

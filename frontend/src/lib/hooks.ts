import { useCallback, useEffect, useRef, useState } from 'react'

const BASE = import.meta.env.VITE_API_BASE ?? ''

/** Global refresh counter bumped by Server-Sent Events so every view re-fetches on state changes. */
const listeners = new Set<() => void>()
let stream: EventSource | null = null

/* ---------------------------------------------------------------- connection health
   Derived only from facts the client can observe: the EventSource ready state and the time and
   outcome of the last API fetch. Nothing here polls the switch or claims liveness of telemetry. */
export type ConnectionStatus = 'connected' | 'stale' | 'unavailable'
interface Health {
  streamOpen: boolean
  lastFetchAt: number | null
  lastFetchOk: boolean | null
  lastEventAt: number | null
}
const health: Health = { streamOpen: false, lastFetchAt: null, lastFetchOk: null, lastEventAt: null }
const healthListeners = new Set<() => void>()
function notifyHealth() {
  healthListeners.forEach((l) => l())
}
function recordFetch(ok: boolean) {
  health.lastFetchAt = Date.now()
  health.lastFetchOk = ok
  notifyHealth()
}
const STALE_AFTER_MS = 60_000

export function connectionStatus(now = Date.now()): ConnectionStatus {
  if (health.lastFetchOk === false) return 'unavailable'
  if (health.lastFetchOk === null) return 'stale'
  const fresh = health.lastFetchAt !== null && now - health.lastFetchAt < STALE_AFTER_MS
  if (health.streamOpen && fresh) return 'connected'
  return 'stale'
}

export function useConnection(): { status: ConnectionStatus; lastFetchAt: number | null; lastEventAt: number | null; sinceFetchS: number | null } {
  const snapshot = () => {
    const now = Date.now()
    return { status: connectionStatus(now), lastFetchAt: health.lastFetchAt, lastEventAt: health.lastEventAt, sinceFetchS: health.lastFetchAt ? Math.round((now - health.lastFetchAt) / 1000) : null }
  }
  const [state, setState] = useState(snapshot)
  useEffect(() => {
    const bump = () => setState(snapshot())
    healthListeners.add(bump)
    const timer = setInterval(bump, 10_000)
    return () => {
      healthListeners.delete(bump)
      clearInterval(timer)
    }
  }, [])
  return state
}

export function ensureStream() {
  if (stream || typeof EventSource === 'undefined') return
  try {
    stream = new EventSource(`${BASE}/api/events/stream`)
    const bump = () => {
      health.lastEventAt = Date.now()
      listeners.forEach((l) => l())
    }
    for (const kind of ['state', 'incident', 'alert', 'validation', 'assessment', 'finding']) stream.addEventListener(kind, bump)
    stream.onopen = () => {
      health.streamOpen = true
      notifyHealth()
    }
    stream.onerror = () => {
      /* the browser retries automatically; report the gap honestly meanwhile */
      health.streamOpen = false
      notifyHealth()
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
        recordFetch(true)
        if (!alive.current || mine !== seq.current) return
        setState({ data: d, key: requestedFor })
        setError(null)
        setLoading(false)
      })
      .catch((e: Error) => {
        recordFetch(false)
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

/** Matches a CSS media query and re-renders when it changes. */
export function useMedia(query: string): boolean {
  const get = () => (typeof window !== 'undefined' && 'matchMedia' in window ? window.matchMedia(query).matches : false)
  const [m, setM] = useState(get)
  useEffect(() => {
    const mq = window.matchMedia(query)
    const on = () => setM(mq.matches)
    mq.addEventListener('change', on)
    return () => mq.removeEventListener('change', on)
  }, [query])
  return m
}

import { useCallback, useEffect, useRef, useState } from 'react'

const BASE = import.meta.env.VITE_API_BASE ?? ''

/** Global refresh counter bumped by Server-Sent Events so every view re-fetches on state changes. */
const listeners = new Set<() => void>()
let stream: EventSource | null = null

/* ---------------------------------------------------------------- connection health
   Two separate facts the client can actually observe:
   - API reachability: the outcome of the most recent API request (any view, plus a light GET
     /api/meta every 60 s while the tab is visible). It is never inferred from data held in memory and
     never marked stale because nothing needed fetching.
   - Event stream: the EventSource ready state (live, connecting, reconnecting after an error).
   Neither says anything about the simulated dataset clock, which is shown separately. */
export type ApiStatus = 'checking' | 'reachable' | 'errors' | 'unreachable'
export type StreamStatus = 'connecting' | 'live' | 'reconnecting' | 'unsupported'
interface Health {
  streamOpen: boolean
  streamEverOpen: boolean
  lastFetchAt: number | null
  lastFetchOk: boolean | null
  lastOkAt: number | null
  lastEventAt: number | null
  /** most recent HTTP error response (the server answered, but with an error) */
  lastError: { at: number; message: string } | null
}
const health: Health = { streamOpen: false, streamEverOpen: false, lastFetchAt: null, lastFetchOk: null, lastOkAt: null, lastEventAt: null, lastError: null }
const healthListeners = new Set<() => void>()
function notifyHealth() {
  healthListeners.forEach((l) => l())
}
/** ok: a response arrived. An HTTP error still proves the server is reachable; only a network failure does not. */
function recordFetch(ok: boolean, error?: unknown) {
  health.lastFetchAt = Date.now()
  const message = error instanceof Error ? error.message : error ? String(error) : ''
  const httpError = !ok && /^\d{3}\b/.test(message)
  health.lastFetchOk = ok || httpError
  if (ok || httpError) health.lastOkAt = health.lastFetchAt
  if (httpError) health.lastError = { at: health.lastFetchAt, message }
  notifyHealth()
}
const ERROR_WINDOW_MS = 60_000
const PING_MS = 60_000

function apiStatus(): ApiStatus {
  if (health.lastFetchOk === null) return 'checking'
  if (!health.lastFetchOk) return 'unreachable'
  if (health.lastError && Date.now() - health.lastError.at < ERROR_WINDOW_MS) return 'errors'
  return 'reachable'
}
function streamStatus(): StreamStatus {
  if (typeof EventSource === 'undefined') return 'unsupported'
  if (health.streamOpen) return 'live'
  return health.streamEverOpen ? 'reconnecting' : 'connecting'
}

let pinger: ReturnType<typeof setInterval> | null = null
function ping() {
  if (typeof document !== 'undefined' && document.hidden) return
  fetch(`${BASE}/api/meta`, { cache: 'no-store' })
    .then((r) => recordFetch(r.ok, r.ok ? undefined : `${r.status} ${r.statusText}`))
    .catch((e) => recordFetch(false, e))
}

export interface Connection {
  api: ApiStatus
  stream: StreamStatus
  /** seconds since the last API response (client clock), if any */
  sinceOkS: number | null
  /** the most recent HTTP error within the last minute */
  lastError: string | null
}

export function useConnection(): Connection {
  const snapshot = (): Connection => ({
    api: apiStatus(),
    stream: streamStatus(),
    sinceOkS: health.lastOkAt ? Math.round((Date.now() - health.lastOkAt) / 1000) : null,
    lastError: health.lastError && Date.now() - health.lastError.at < ERROR_WINDOW_MS ? health.lastError.message : null,
  })
  const [state, setState] = useState(snapshot)
  useEffect(() => {
    const bump = () => setState(snapshot())
    healthListeners.add(bump)
    const timer = setInterval(bump, 15_000)
    if (!pinger) pinger = setInterval(ping, PING_MS)
    const onVis = () => !document.hidden && ping()
    document.addEventListener('visibilitychange', onVis)
    return () => {
      healthListeners.delete(bump)
      clearInterval(timer)
      document.removeEventListener('visibilitychange', onVis)
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
      const reconnect = health.streamEverOpen
      health.streamOpen = true
      health.streamEverOpen = true
      notifyHealth()
      if (reconnect) {
        /* events may have been missed during the gap: re-read mounted views (GETs only) and re-check the API */
        ping()
        listeners.forEach((l) => l())
      }
    }
    stream.onerror = () => {
      /* the browser retries automatically; report the gap honestly meanwhile */
      const wasOpen = health.streamOpen
      health.streamOpen = false
      notifyHealth()
      if (wasOpen) ping()
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
        recordFetch(false, e)
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

import { useEffect, useSyncExternalStore } from 'react'
import type { Window } from './telemetry'

/**
 * Playback of the recorded dataset day: one controller for the whole application.
 *
 * Playback is strictly observational. It moves a simulated playhead through timestamps that the API
 * already returned; it never generates events, never calls the API and never triggers a response.
 * The clock is a single requestAnimationFrame loop that runs only while it is playing, at least one
 * view is attached and the tab is visible, so loops cannot accumulate across navigation. Simulated
 * time does not advance while the tab is hidden or no view shows playback; it resumes from the same
 * position (no catch-up jump) when a view is visible again.
 */
export const PLAYBACK = {
  /** Real seconds for one pass through the selected window at 1×. Change the demo pacing here. */
  WINDOW_SECONDS: 75,
  /** User-selectable multipliers of that baseline. */
  SPEEDS: [0.5, 1, 2, 4] as const,
  /** Number of published steps per pass; React views re-render at most this often per loop. */
  STEPS_PER_PASS: 1500,
  /** Longest frame gap applied at once (a stalled frame never skips minutes of simulated time). */
  MAX_FRAME_MS: 250,
}

export type WindowPreset = 'day' | '4h' | '1h' | 'custom'
export type ChangeKind = 'init' | 'tick' | 'seek' | 'loop' | 'window' | 'restart'

export interface PlaybackSnapshot {
  ready: boolean
  domain: Window | null
  window: Window | null
  preset: WindowPreset
  /** simulated playhead (epoch ms, UTC), quantized to one published step */
  t: number
  playing: boolean
  speed: number
  loops: number
  /** what moved the playhead last, so views can tell a natural advance from a jump */
  change: ChangeKind
  /** simulated milliseconds per real second at the current speed */
  rate: number
}

type Listener = () => void
type FrameListener = (pos: number) => void

let snap: PlaybackSnapshot = { ready: false, domain: null, window: null, preset: 'day', t: 0, playing: false, speed: 1, loops: 0, change: 'init', rate: 0 }
let pos = 0
let lastFrame: number | null = null
let raf: number | null = null
let attached = 0
let initialized = false
let latestEnd: number | null = null
const listeners = new Set<Listener>()
const frameListeners = new Set<FrameListener>()

function span(w: Window | null) {
  return w ? Math.max(1, w.end - w.start) : 1
}
function rateOf(w: Window | null, speed: number) {
  return (span(w) / PLAYBACK.WINDOW_SECONDS) * speed
}
function quantum(w: Window | null) {
  return Math.max(1000, span(w) / PLAYBACK.STEPS_PER_PASS)
}
function publish(patch: Partial<PlaybackSnapshot>) {
  const next = { ...snap, ...patch }
  next.rate = rateOf(next.window, next.speed)
  snap = next
  listeners.forEach((l) => l())
}
function emitFrame() {
  frameListeners.forEach((f) => f(pos))
}

function canRun() {
  return snap.playing && snap.ready && attached > 0 && !(typeof document !== 'undefined' && document.hidden)
}
function schedule() {
  if (raf == null && canRun()) {
    lastFrame = null
    raf = requestAnimationFrame(frame)
  }
}
function halt() {
  if (raf != null) cancelAnimationFrame(raf)
  raf = null
  lastFrame = null
}
function frame(now: number) {
  raf = null
  if (!canRun() || !snap.window) {
    lastFrame = null
    return
  }
  const w = snap.window
  const dt = lastFrame == null ? 0 : Math.min(now - lastFrame, PLAYBACK.MAX_FRAME_MS)
  lastFrame = now
  pos += (dt / 1000) * snap.rate
  let change: ChangeKind = 'tick'
  let loops = snap.loops
  if (pos >= w.end) {
    pos = w.start + ((pos - w.end) % span(w))
    loops += 1
    change = 'loop'
  }
  const q = quantum(w)
  const t = Math.min(w.end, w.start + Math.floor((pos - w.start) / q) * q)
  if (t !== snap.t || change === 'loop') publish({ t, loops, change })
  emitFrame()
  raf = requestAnimationFrame(frame)
}

if (typeof document !== 'undefined') {
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) halt()
    else schedule()
  })
}

function presetWindow(preset: WindowPreset, domain: Window, end: number): Window {
  // windows end on the 15-minute grid the timeline uses
  const grid = 15 * 60_000
  const e = Math.min(domain.end, Math.max(domain.start + grid, domain.start + Math.ceil((end - domain.start) / grid) * grid))
  if (preset === '4h') return { start: Math.max(domain.start, e - 4 * 3600_000), end: e }
  if (preset === '1h') return { start: Math.max(domain.start, e - 3600_000), end: e }
  return { start: domain.start, end: e }
}

function setPos(p: number, change: ChangeKind) {
  const w = snap.window
  if (!w) return
  pos = Math.max(w.start, Math.min(w.end, p))
  const q = quantum(w)
  publish({ t: Math.min(w.end, w.start + Math.floor((pos - w.start) / q) * q), change })
  emitFrame()
}

export const playback = {
  /**
   * Provide the dataset bounds. `recordedEnd` is the latest simulated time with data (switch clock or
   * newest record); preset windows end there because nothing is recorded after it. The first call
   * starts playback at the beginning of the default window; later calls (server refreshes, a reset)
   * keep the playhead where it is when it is still inside the window.
   */
  configure(domain: Window, recordedEnd: number, autoplay = true) {
    latestEnd = recordedEnd
    if (!initialized) {
      initialized = true
      const w = presetWindow('day', domain, recordedEnd)
      pos = w.start
      publish({ ready: true, domain, window: w, preset: 'day', t: w.start, playing: autoplay, change: 'init' })
      schedule()
      return
    }
    const sameDomain = snap.domain && snap.domain.start === domain.start && snap.domain.end === domain.end
    const w = snap.preset === 'custom' && sameDomain && snap.window ? snap.window : presetWindow(snap.preset, domain, recordedEnd)
    if (sameDomain && snap.window && w.start === snap.window.start && w.end === snap.window.end) return
    const inside = pos >= w.start && pos <= w.end
    if (!inside) pos = w.start
    publish({ domain, window: w, change: inside ? snap.change : 'window' })
    setPos(pos, inside ? snap.change : 'window')
  },
  play() {
    if (!snap.ready) return
    if (snap.window && pos >= snap.window.end) pos = snap.window.start
    publish({ playing: true })
    schedule()
  },
  pause() {
    halt()
    publish({ playing: false })
  },
  toggle() {
    if (snap.playing) playback.pause()
    else playback.play()
  },
  /** Jump to a simulated time. Seeking always pauses; Play resumes from the new position. */
  seek(t: number) {
    playback.pause()
    setPos(t, 'seek')
  },
  restart() {
    if (snap.window) setPos(snap.window.start, 'restart')
  },
  setSpeed(speed: number) {
    publish({ speed })
  },
  setWindow(w: Window, preset: WindowPreset = 'custom') {
    if (!snap.domain) return
    const win = { start: Math.max(snap.domain.start, w.start), end: Math.min(snap.domain.end, w.end) }
    publish({ window: win, preset })
    // keep the playhead when it is inside the new window; otherwise start the new window from its beginning
    setPos(pos >= win.start && pos <= win.end ? pos : win.start, 'window')
  },
  setPreset(preset: Exclude<WindowPreset, 'custom'>) {
    if (!snap.domain) return
    playback.setWindow(presetWindow(preset, snap.domain, latestEnd ?? snap.domain.end), preset)
  },
  /** Exact playhead for per-frame DOM updates (avoids React renders at 60 fps). */
  position() {
    return pos
  },
  subscribe(l: Listener) {
    listeners.add(l)
    return () => {
      listeners.delete(l)
    }
  },
  subscribeFrame(f: FrameListener) {
    frameListeners.add(f)
    return () => {
      frameListeners.delete(f)
    }
  },
  getSnapshot() {
    return snap
  },
  attach() {
    attached += 1
    schedule()
    return () => {
      attached = Math.max(0, attached - 1)
      if (!attached) halt()
    }
  },
}

/** Subscribe a view to playback; mounting it lets the clock run, unmounting stops it. */
export function usePlayback(): PlaybackSnapshot {
  useEffect(() => playback.attach(), [])
  return useSyncExternalStore(playback.subscribe, playback.getSnapshot, playback.getSnapshot)
}

import { playback } from '../../lib/playback'

/** What drives the canvas: the shared playback clock by default, or a local loop (incident view). */
export interface FlowClock {
  subscribeFrame(f: (pos: number) => void): () => void
  subscribe(l: () => void): () => void
  isPlaying(): boolean
}
export const PLAYBACK_CLOCK: FlowClock = {
  subscribeFrame: (f) => playback.subscribeFrame(f),
  subscribe: (l) => playback.subscribe(l),
  isPlaying: () => playback.getSnapshot().playing,
}

/**
 * A clock that loops over a fixed span of recorded time at `rate` simulated ms per real second while
 * something listens and the tab is visible. Used to replay the traffic around one incident.
 */
export class LoopClock implements FlowClock {
  pos: number
  readonly start: number
  readonly end: number
  readonly rate: number
  private frames = new Set<(pos: number) => void>()
  private raf: number | null = null
  private last: number | null = null
  constructor(start: number, end: number, rate: number) {
    this.start = start
    this.end = end
    this.rate = rate
    this.pos = start
  }
  private tick = (now: number) => {
    this.raf = null
    if (!this.frames.size || document.hidden) {
      this.last = null
      return
    }
    const dt = this.last == null ? 0 : Math.min(250, now - this.last)
    this.last = now
    this.pos += (dt / 1000) * this.rate
    if (this.pos > this.end) this.pos = this.start
    this.frames.forEach((f) => f(this.pos))
    this.raf = requestAnimationFrame(this.tick)
  }
  private run() {
    if (this.raf == null && this.frames.size && !document.hidden) this.raf = requestAnimationFrame(this.tick)
  }
  private onVis = () => (document.hidden ? this.stop() : this.run())
  private stop() {
    if (this.raf != null) cancelAnimationFrame(this.raf)
    this.raf = null
    this.last = null
  }
  subscribeFrame(f: (pos: number) => void) {
    if (!this.frames.size) document.addEventListener('visibilitychange', this.onVis)
    this.frames.add(f)
    this.run()
    return () => {
      this.frames.delete(f)
      if (!this.frames.size) {
        this.stop()
        document.removeEventListener('visibilitychange', this.onVis)
      }
    }
  }
  subscribe() {
    return () => {}
  }
  isPlaying() {
    return true
  }
}

import { useEffect, useRef } from 'react'
import { PLAYBACK, playback, type PlaybackSnapshot } from '../../lib/playback'
import { fmtClock, fmtEnd, fmtSpan } from '../../lib/telemetry'
import { Icon } from '../Icons'

/**
 * Transport for the recorded dataset day: play/pause, back to the window start, speed and window
 * presets, with the simulated clock. The clock text updates every frame through a ref.
 */
export function PlaybackBar({ s, disabled, note }: { s: PlaybackSnapshot; disabled?: boolean; note?: string }) {
  const clockRef = useRef<HTMLSpanElement>(null)
  useEffect(() => {
    const show = (pos: number) => {
      if (clockRef.current) clockRef.current.textContent = new Date(pos).toISOString().slice(11, 19)
    }
    show(playback.position())
    return playback.subscribeFrame(show)
  }, [])
  const w = s.window
  const state = disabled ? 'idle' : s.playing ? 'playing' : 'paused'
  const perSecond = s.rate ? fmtSpan(s.rate * s.pace) : '—'
  const fast = s.playing && s.pace > 1
  const slow = s.playing && s.pace < 1
  return (
    <div className={`pb ${state}`} role="group" aria-label="Playback of the recorded dataset day">
      <button
        type="button"
        className="pb-play"
        onClick={() => playback.toggle()}
        disabled={disabled}
        aria-label={s.playing ? 'Pause playback' : 'Play'}
        aria-pressed={s.playing}
        title={s.playing ? 'Pause (Space on the timeline)' : 'Play'}
      >
        {s.playing ? <Icon.pause /> : <Icon.play />}
      </button>
      <button type="button" className="btn sm icon ghost" onClick={() => playback.restart()} disabled={disabled} aria-label="Back to the start of the window" title="Back to the start of the window">
        <Icon.restart />
      </button>
      <div className="pb-clock" aria-live="off">
        <span className="pb-time mono" ref={clockRef}>
          {fmtClock(s.t, true)}
        </span>
        <span className="pb-sub">
          <span className={`pb-state ${state}`}>{state === 'idle' ? 'no data' : state}</span>
          <span className="pb-loop" title="Playback loops to the start of the window">
            <Icon.loop /> {s.loops ? `loop ${s.loops + 1}` : 'loops'}
          </span>
          {fast && (
            <span className="pb-pace" title="Few records here: the clock runs faster until activity picks up. Times shown are still the recorded times.">
              ×{s.pace} quiet
            </span>
          )}
          {slow && (
            <span className="pb-pace slow" title="A recorded alert or containment action is near: the clock slows so it can be followed. Times shown are still the recorded times.">
              slow-motion
            </span>
          )}
        </span>
      </div>
      <div className="pb-group" role="group" aria-label="Playback speed">
        {PLAYBACK.SPEEDS.map((sp) => (
          <button key={sp} type="button" className={`pb-seg ${s.speed === sp ? 'on' : ''}`} aria-pressed={s.speed === sp} onClick={() => playback.setSpeed(sp)} disabled={disabled}>
            {sp}×
          </button>
        ))}
      </div>
      <button
        type="button"
        className={`pb-seg pb-skip ${s.autoPace ? 'on' : ''}`}
        aria-pressed={s.autoPace}
        onClick={() => playback.setAutoPace(!s.autoPace)}
        disabled={disabled}
        title="Auto pace: fast-forward (up to 10×) through stretches with few records and slow down around alerts and containment. The clock always shows the recorded time."
      >
        auto pace
      </button>
      <div className="pb-group" role="group" aria-label="Time window">
        {(
          [
            ['day', 'Day'],
            ['4h', '4 h'],
            ['1h', '1 h'],
          ] as const
        ).map(([id, label]) => (
          <button key={id} type="button" className={`pb-seg ${s.preset === id ? 'on' : ''}`} aria-pressed={s.preset === id} onClick={() => playback.setPreset(id)} disabled={disabled}>
            {label}
          </button>
        ))}
        {s.preset === 'custom' && <span className="pb-seg on static">custom</span>}
      </div>
      <div className="pb-meta">
        {w ? (
          <span className="mono">
            {fmtClock(w.start)}–{fmtEnd(w.start, w.end)} UTC
          </span>
        ) : (
          <span>—</span>
        )}
        <span className="dim">{note ?? `${perSecond} of recorded time per second${fast ? ' (quiet stretch)' : slow ? ' (around a recorded alert)' : ''}`}</span>
      </div>
    </div>
  )
}

import { useEffect, useRef, useState, type ReactNode } from 'react'

/**
 * Data-driven motion primitives. Numbers count to the value the API returned (from 0 on first show,
 * from the previous value on a change); the final frame is always the exact value. Under
 * prefers-reduced-motion the value is shown at once.
 */

const DURATION = 900

function reducedMotion(): boolean {
  return typeof window !== 'undefined' && !!window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
}

function useCountUp(target: number, duration = DURATION): number {
  const reduce = reducedMotion()
  const [shown, setShown] = useState(() => (reduce ? target : 0))
  const from = useRef(reduce ? target : 0)
  useEffect(() => {
    if (reduce || !Number.isFinite(target)) {
      from.current = target
      return
    }
    const start = performance.now()
    const a = from.current
    let raf = 0
    const step = (now: number) => {
      const u = Math.min(1, (now - start) / duration)
      const e = 1 - (1 - u) ** 3
      const v = u >= 1 ? target : a + (target - a) * e
      setShown(v)
      from.current = v
      if (u < 1) raf = requestAnimationFrame(step)
    }
    raf = requestAnimationFrame(step)
    return () => cancelAnimationFrame(raf)
  }, [target, duration, reduce])
  return reduce || !Number.isFinite(target) ? target : shown
}

/** A number that counts to `value`, printed with the same number of decimals. */
export function CountUp({ value, decimals, format }: { value: number; decimals?: number; format?: (n: number) => string }) {
  const v = useCountUp(value)
  const d = decimals ?? (Number.isInteger(value) ? 0 : String(value).split('.')[1]?.length ?? 0)
  return <>{format ? format(v) : v.toFixed(d)}</>
}

const NUMERIC = /^(-?\d+(?:\.\d+)?)(.*)$/s

/**
 * Animate a metric value when it is a number or a string that starts with one ("98.1%", "10.446 s");
 * any other value (a ratio, a chip, a word) is shown as given.
 */
export function AnimatedValue({ value }: { value: ReactNode }) {
  if (typeof value === 'number') return <CountUp value={value} />
  if (typeof value === 'string') {
    const m = value.match(NUMERIC)
    if (m) {
      const decimals = m[1].split('.')[1]?.length ?? 0
      return (
        <>
          <CountUp value={Number(m[1])} decimals={decimals} />
          {m[2]}
        </>
      )
    }
  }
  return <>{value}</>
}

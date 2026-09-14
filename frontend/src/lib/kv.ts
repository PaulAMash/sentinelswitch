import type { ReactNode } from 'react'

export type KVRow = [string, ReactNode]

/** Build a KV row; keeps JSX out of array literals so React key linting stays quiet. */
export function kv(label: string, value: ReactNode): KVRow {
  return [label, value]
}

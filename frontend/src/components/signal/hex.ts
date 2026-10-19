/** Pointy-top hexagon geometry on an axial lattice (q, r). */
export const HEX = 17
export const SQ3 = Math.sqrt(3)

export type Axial = [number, number]

const DIRS: Axial[] = [
  [1, 0],
  [1, -1],
  [0, -1],
  [-1, 0],
  [-1, 1],
  [0, 1],
]

export function toPixel([q, r]: Axial, s = HEX): [number, number] {
  return [s * SQ3 * (q + r / 2), s * 1.5 * r]
}

export function hexPoints(s: number, cx = 0, cy = 0): string {
  const pts: string[] = []
  for (let i = 0; i < 6; i++) {
    const a = ((60 * i - 30) * Math.PI) / 180
    pts.push(`${(cx + s * Math.cos(a)).toFixed(2)},${(cy + s * Math.sin(a)).toFixed(2)}`)
  }
  return pts.join(' ')
}

export function hexPath(s: number, cx: number, cy: number): string {
  return `M${hexPoints(s, cx, cy).split(' ').join('L')}Z`
}

export function ring(c: Axial, k: number): Axial[] {
  if (k === 0) return [c]
  const out: Axial[] = []
  let q = c[0] + DIRS[4][0] * k
  let r = c[1] + DIRS[4][1] * k
  for (let i = 0; i < 6; i++) {
    for (let j = 0; j < k; j++) {
      out.push([q, r])
      q += DIRS[i][0]
      r += DIRS[i][1]
    }
  }
  return out
}

export function spiral(c: Axial, n: number): Axial[] {
  const out: Axial[] = []
  for (let k = 0; out.length < n; k++) out.push(...ring(c, k))
  return out.slice(0, n)
}

export function hexDistance(a: Axial, b: Axial): number {
  const dq = a[0] - b[0]
  const dr = a[1] - b[1]
  return Math.max(Math.abs(dq), Math.abs(dr), Math.abs(dq + dr))
}

/** Axial cell that contains the pixel point (cube rounding). */
export function fromPixel(x: number, y: number, s = HEX): Axial {
  const q = ((SQ3 / 3) * x - y / 3) / s
  const r = ((2 / 3) * y) / s
  let rx = Math.round(q)
  let rz = Math.round(r)
  const ry = Math.round(-q - r)
  const dx = Math.abs(rx - q)
  const dy = Math.abs(ry - (-q - r))
  const dz = Math.abs(rz - r)
  if (dx > dy && dx > dz) rx = -ry - rz
  else if (dy <= dz) rz = -rx - ry
  return [rx, rz]
}

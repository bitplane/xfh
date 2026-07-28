/** Extract one file from an AmigaDOS volume (optionally a partition slice). */
import { readFileSync, writeFileSync } from 'node:fs'
const [img, want, out, secS, blkS] = process.argv.slice(2)
const BS = 512
const raw = new Uint8Array(readFileSync(img!))
const first = secS ? parseInt(secS, 10) : 0
const nb = blkS ? parseInt(blkS, 10) : Math.floor(raw.length / BS) - first
const b = raw.subarray(first * BS, (first + nb) * BS)
const dv = new DataView(b.buffer, b.byteOffset, b.byteLength)
const u32 = (bl: number, o: number): number => dv.getUint32(bl * BS + o, false)
const i32 = (bl: number, o: number): number => dv.getInt32(bl * BS + o, false)
const nm = (bl: number, o: number): string => {
  const base = bl * BS + o, len = Math.min(b[base] ?? 0, 30)
  let s = ''
  for (let i = 1; i <= len; i++) s += String.fromCharCode(b[base + i]!)
  return s
}
const blocks = Math.floor(b.length / BS)
const ffs = (b[3] ?? 0) & 1
const seen = new Set<number>()
let hit: number | null = null
const walk = (dir: number, pre: string): void => {
  if (seen.has(dir) || hit !== null) return
  seen.add(dir)
  for (let s = 0; s < 72 && hit === null; s++) {
    let x = u32(dir, 24 + s * 4)
    while (x > 0 && x < blocks && !seen.has(x) && hit === null) {
      const st = i32(x, 508), p = pre === '' ? nm(x, 432) : `${pre}/${nm(x, 432)}`
      if (st === 2) walk(x, p)
      else { seen.add(x); if (p.toLowerCase() === want!.toLowerCase()) hit = x }
      x = u32(x, 496)
    }
  }
}
walk(Math.floor(blocks / 2), '')
if (hit === null) { console.error('not found'); process.exit(1) }
const size = u32(hit, 324)
const outBuf = Buffer.alloc(size)
let pos = 0, blk: number = hit
const chain = new Set<number>()
while (blk > 0 && blk < blocks && !chain.has(blk)) {
  chain.add(blk)
  const high = u32(blk, 8)
  for (let i = 0; i < high && pos < size; i++) {
    const d = u32(blk, 308 - i * 4)
    if (d <= 0 || d >= blocks) continue
    const off = ffs ? 0 : 24
    const avail = ffs ? BS : Math.min(u32(d, 12), BS - 24)
    const n = Math.min(avail, size - pos)
    outBuf.set(b.subarray(d * BS + off, d * BS + off + n), pos)
    pos += n
  }
  blk = u32(blk, 504)
}
writeFileSync(out!, outBuf)
console.error(`${size} bytes -> ${out}`)

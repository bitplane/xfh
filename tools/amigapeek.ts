/** Print the first bytes of every file whose path matches, from an AmigaDOS volume. */
import { readFileSync } from 'node:fs'
const [file, want, secS, blkS] = process.argv.slice(2)
const BS = 512
const raw = new Uint8Array(readFileSync(file!))
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
const seen = new Set<number>()
const walk = (dir: number, pre: string): void => {
  if (seen.has(dir)) return
  seen.add(dir)
  for (let s = 0; s < 72; s++) {
    let x = u32(dir, 24 + s * 4)
    while (x > 0 && x < blocks && !seen.has(x)) {
      const st = i32(x, 508), p = pre === '' ? nm(x, 432) : `${pre}/${nm(x, 432)}`
      if (st === 2) walk(x, p)
      else {
        seen.add(x)
        if (st === -3 && p.toLowerCase().includes(want!.toLowerCase())) {
          const d = u32(x, 16) // first_data
          const head = b.subarray(d * BS, d * BS + 24)
          let txt = ''
          for (const c of head) txt += c >= 32 && c < 127 ? String.fromCharCode(c) : '.'
          console.log(`${String(u32(x, 324)).padStart(8)}  ${p.padEnd(26)}  ${txt}`)
        }
      }
      x = u32(x, 496)
    }
  }
}
walk(Math.floor(blocks / 2), '')

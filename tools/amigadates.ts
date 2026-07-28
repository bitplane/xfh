/**
 * Walk an AmigaDOS volume and print every file with its real datestamp.
 *
 * The header block of a file or directory carries the date at offset 420:
 * days since 1 Jan 1978 (long), minutes past midnight (long), ticks at
 * 1/50 s (long). unadf prints it to the second; this keeps the ticks.
 *
 *   amigadates <image> [--sector FIRST] [--blocks N]
 */
import { readFileSync } from 'node:fs'

const argv = process.argv.slice(2)
const file = argv[0]!
const opt = (n: string, d: number): number => {
  const i = argv.indexOf(n)
  return i >= 0 ? parseInt(argv[i + 1]!, 10) : d
}
const BS = 512
const raw = new Uint8Array(readFileSync(file))
const first = opt('--sector', 0)
const nblocks = opt('--blocks', Math.floor(raw.length / BS) - first)
const bytes = raw.subarray(first * BS, (first + nblocks) * BS)
const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
const u32 = (b: number, o: number): number => dv.getUint32(b * BS + o, false)
const i32 = (b: number, o: number): number => dv.getInt32(b * BS + o, false)
const name = (b: number, o: number): string => {
  const base = b * BS + o
  const len = Math.min(bytes[base] ?? 0, 30)
  let s = ''
  for (let i = 1; i <= len; i++) s += String.fromCharCode(bytes[base + i]!)
  return s
}
const EPOCH = Date.UTC(1978, 0, 1)
const stamp = (b: number): string => {
  const days = u32(b, 420), mins = u32(b, 424), ticks = u32(b, 428)
  if (days > 40000) return '(bad)'
  const d = new Date(EPOCH + days * 86400_000 + mins * 60_000 + Math.floor(ticks / 50) * 1000)
  const p = (n: number, w = 2): string => String(n).padStart(w, '0')
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ` +
    `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}.${p(ticks % 50)}`
}

const blocks = Math.floor(bytes.length / BS)
const root = Math.floor(blocks / 2)
const seen = new Set<number>()
const out: string[] = []
const walk = (dir: number, prefix: string): void => {
  if (seen.has(dir)) return
  seen.add(dir)
  for (let off = 24; off <= 308; off += 4) {
    let b = u32(dir, off)
    while (b > 0 && b < blocks && !seen.has(b)) {
      const sec = i32(b, 508)
      const path = prefix === '' ? name(b, 432) : `${prefix}/${name(b, 432)}`
      if (sec === 2) walk(b, path)
      else {
        seen.add(b)
        out.push(`${stamp(b)}  ${String(u32(b, 324)).padStart(8)}  ${path}${sec === -3 ? '' : '  (link)'}`)
      }
      b = u32(b, 496)
    }
  }
}
console.log(`# ${file} @${first} : ${name(root, 432)} — root stamp ${stamp(root)}`)
walk(root, '')
out.sort()
for (const l of out) console.log(l)

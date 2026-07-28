/** Render an AMOS sprite/icon bank (.abk) to PNGs, one per image. */
import { readFileSync, writeFileSync } from 'node:fs'
import { BinReader } from '/home/gaz/src/tmp/amos/amos-ts/src/loader/binreader'
const file = process.argv[2]!
const prefix = process.argv[3]!
const r = new BinReader(new Uint8Array(readFileSync(file)))
let magic = r.str(4)
// AMOS writes "AmBs" + a bank count when a file holds more than one bank;
// the first bank's own magic follows. Step over the wrapper.
if (magic === 'AmBs') { r.u16(); magic = r.str(4) }
if (magic !== 'AmSp' && magic !== 'AmIc') throw new Error(`not a sprite bank: ${magic}`)
const count = r.u16()
const imgs: Array<{ w: number; h: number; d: number; data: Uint8Array }> = []
for (let i = 0; i < count; i++) {
  const ww = r.u16(), h = r.u16(), d = r.u16()
  r.u16(); r.u16() // hotspot
  imgs.push({ w: ww * 16, h, d, data: r.raw(ww * 2 * h * d) })
}
const pal: number[] = []
for (let i = 0; i < 32; i++) pal.push(r.u16())
// RGB4 -> RGB8
const rgb = pal.map((c) => [((c >> 8) & 15) * 17, ((c >> 4) & 15) * 17, (c & 15) * 17])
console.error(`${magic}: ${count} images, palette ${pal.length}`)
imgs.forEach((im, n) => {
  const bytesPerRow = im.w / 8
  const px = Buffer.alloc(im.w * im.h * 3)
  for (let y = 0; y < im.h; y++) {
    for (let x = 0; x < im.w; x++) {
      let idx = 0
      for (let p = 0; p < im.d; p++) {
        // planes are stored one after another, each a full bitplane
        const off = p * bytesPerRow * im.h + y * bytesPerRow + (x >> 3)
        const bit = (im.data[off]! >> (7 - (x & 7))) & 1
        idx |= bit << p
      }
      const c = rgb[idx] ?? [255, 0, 255]
      const o = (y * im.w + x) * 3
      px[o] = c[0]!; px[o + 1] = c[1]!; px[o + 2] = c[2]!
    }
  }
  writeFileSync(`${prefix}${n}.ppm`, Buffer.concat([Buffer.from(`P6\n${im.w} ${im.h}\n255\n`), px]))
  console.error(`  ${n}: ${im.w}x${im.h}x${im.d}`)
})

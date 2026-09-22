/** Render an AMOS sprite/icon bank (.abk) to PNGs, one per image. */
import { readFileSync, writeFileSync } from 'node:fs'
import { deflateSync } from 'node:zlib'
const file = process.argv[2]!
const prefix = process.argv[3]!
if (!file || !prefix) throw new Error('usage: node abk2png.ts INPUT OUTPUT_PREFIX')
const source = readFileSync(file)
let position = 0
const raw = (length: number): Buffer => {
  if (!Number.isSafeInteger(length) || length < 0 || position + length > source.length) {
    throw new Error('truncated AMOS bank')
  }
  const result = source.subarray(position, position + length)
  position += length
  return result
}
const r = {
  raw,
  u16: (): number => raw(2).readUInt16BE(),
  str: (length: number): string => raw(length).toString('latin1'),
}

const crcTable = Array.from({ length: 256 }, (_, byte) => {
  let crc = byte
  for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0)
  return crc >>> 0
})
const pngChunk = (type: string, data: Buffer): Buffer => {
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data])
  let crc = 0xffffffff
  for (const byte of body) crc = (crc >>> 8) ^ crcTable[(crc ^ byte) & 255]!
  const length = Buffer.alloc(4), checksum = Buffer.alloc(4)
  length.writeUInt32BE(data.length)
  checksum.writeUInt32BE((crc ^ 0xffffffff) >>> 0)
  return Buffer.concat([length, body, checksum])
}
const png = (width: number, height: number, pixels: Buffer): Buffer => {
  const header = Buffer.alloc(13)
  header.writeUInt32BE(width, 0)
  header.writeUInt32BE(height, 4)
  header[8] = 8 // bits per channel
  header[9] = 2 // RGB
  const stride = width * 3
  const rows = Buffer.alloc((stride + 1) * height)
  for (let y = 0; y < height; y++) pixels.copy(rows, y * (stride + 1) + 1, y * stride, (y + 1) * stride)
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    pngChunk('IHDR', header), pngChunk('IDAT', deflateSync(rows)), pngChunk('IEND', Buffer.alloc(0)),
  ])
}
let magic = r.str(4)
// AMOS writes "AmBs" + a bank count when a file holds more than one bank;
// the first bank's own magic follows. Step over the wrapper.
if (magic === 'AmBs') { r.u16(); magic = r.str(4) }
if (magic !== 'AmSp' && magic !== 'AmIc') throw new Error(`not a sprite bank: ${magic}`)
const count = r.u16()
const imgs: Array<{ w: number; h: number; d: number; data: Uint8Array }> = []
for (let i = 0; i < count; i++) {
  const ww = r.u16(), h = r.u16(), d = r.u16()
  if (!ww || !h || d < 1 || d > 5) throw new Error("unsupported AMOS image dimensions or depth")
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
  writeFileSync(`${prefix}${n}.png`, png(im.w, im.h, px))
  console.error(`  ${n}: ${im.w}x${im.h}x${im.d}`)
})

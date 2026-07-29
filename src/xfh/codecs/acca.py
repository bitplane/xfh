"""XPK ACCA decompression.

Derived from Ancient's ACCADecompressor, Copyright (c) 2017-2025
Teemu Suutari, under the BSD 2-Clause License.
"""

from xfh.codecs import register
from xfh.codecs._streams import BitReader, ByteInput, copy_forward
from xfh.errors import CorruptDataError

_STATIC_BYTES = (
    0x00,
    0x01,
    0x02,
    0x03,
    0x04,
    0x08,
    0x10,
    0x20,
    0x40,
    0x55,
    0x60,
    0x80,
    0xAA,
    0xC0,
    0xE0,
    0xFF,
)


@register("ACCA")
def decompress_acca(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode Andre's code compression algorithm."""

    del previous
    source = ByteInput(payload)
    bits = BitReader(source.word, 16)
    output = bytearray()
    while len(output) < output_size:
        if not bits.read(1):
            output.append(source.byte())
            continue
        control = source.byte()
        count = control & 15
        code = control >> 4
        repeat: int | None = None
        if code == 0:
            repeat = source.byte()
            count += 3
        elif code == 14:
            repeat = 0
            count += 3
        elif code == 1:
            count = (count | (source.byte() << 4)) + 19
            repeat = source.byte()
        elif code == 2:
            repeat = _STATIC_BYTES[count]
            count = 2
        elif code == 15:
            distance = (count | (source.byte() << 4)) + 3
            count = source.byte() + 14
        else:
            distance = (count | (source.byte() << 4)) + 3
            count = code
        if len(output) + count > output_size:
            raise CorruptDataError("ACCA run exceeds declared size")
        if repeat is not None:
            output.extend(bytes((repeat,)) * count)
        else:
            copy_forward(output, distance, count, output_size)
    return bytes(output)

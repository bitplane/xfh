"""Small historical XPK LZ codecs.

Derived from Ancient's LZBSDecompressor, SLZ3Decompressor, and
TDCSDecompressor, Copyright (c) 2017-2025 Teemu Suutari, under the BSD
2-Clause License.
"""

from xfh.codecs import register
from xfh.codecs._streams import BitReader, ByteInput, copy_forward
from xfh.errors import CorruptDataError


def _reverse(value: int, count: int) -> int:
    result = 0
    for _ in range(count):
        result = (result << 1) | (value & 1)
        value >>= 1
    return result


@register("LZBS")
def decompress_lzbs(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode the CyberYAFA LZBS format."""

    del previous
    if not payload or payload[0] > 32:
        raise CorruptDataError("invalid LZBS distance width")
    maximum_bits = payload[0]
    source = ByteInput(payload, 1)
    stream = BitReader(source.word, 8)

    def bits(count: int) -> int:
        return _reverse(stream.read(count), count)

    output = bytearray()
    distance_bits = 0
    while len(output) < output_size:
        if not bits(1):
            output.append(bits(8))
            continue
        count = bits(8) + 2
        if count == 2:
            count = bits(12)
            if not count:
                raise CorruptDataError("invalid LZBS literal run")
            # Some versions of the original low-mode packer leave the final
            # literal run rounded up past the advertised chunk size.  The
            # Amiga depacker stops when the output buffer is full.
            count = min(count, output_size - len(output))
            output.extend(bits(8) for _ in range(count))
            continue
        while len(output) >= 1 << distance_bits and distance_bits < maximum_bits:
            distance_bits += 1
        copy_forward(output, bits(distance_bits), count, output_size)
    return bytes(output)


@register("SLZ3")
def decompress_slz3(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode the CyberYAFA SLZ3 format."""

    del previous
    source = ByteInput(payload)
    bits = BitReader(source.word, 8)
    output = bytearray()
    while len(output) < output_size:
        if not bits.read(1):
            output.append(source.byte())
            continue
        control = source.byte()
        if not control:
            raise CorruptDataError("invalid SLZ3 match control")
        distance = ((control & 0xF0) << 4) | source.byte()
        count = (control & 15) + 2
        copy_forward(output, distance, count, output_size)
    return bytes(output)


@register("TDCS")
def decompress_tdcs(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode TDCS LZ77 data."""

    del previous
    source = ByteInput(payload)
    bits = BitReader(source.word, 32)
    output = bytearray()
    while len(output) < output_size:
        mode = bits.read(2)
        if mode == 0:
            output.append(source.byte())
            continue
        encoded = source.word(2)
        if mode == 1:
            count = (encoded & 3) + 3
            distance = ((encoded >> 2) ^ 0x3FFF) + 1
        elif mode == 2:
            count = (encoded & 15) + 3
            distance = ((encoded >> 4) ^ 0xFFF) + 1
        else:
            if not encoded:
                raise CorruptDataError("invalid TDCS zero distance")
            distance = (encoded ^ 0xFFFF) + 1
            count = source.byte() + 3
        copy_forward(output, distance, count, output_size)
    return bytes(output)

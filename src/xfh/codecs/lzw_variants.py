"""CyberYAFA XPK LZW2, LZW3, LZW4, and LZW5 decompression.

Despite their names, these formats are control-bit LZ variants rather than
dictionary-based LZW streams.

Derived from Ancient's LZW2Decompressor, LZW4Decompressor, and
LZW5Decompressor, Copyright (c) 2017-2025 Teemu Suutari, under the BSD
2-Clause License.
"""

from xfh.codecs import register
from xfh.codecs._streams import BitReader, ByteInput, copy_forward
from xfh.errors import CorruptDataError


def _decode_lzw23(payload: bytes, output_size: int) -> bytes:
    source = ByteInput(payload)
    bits = BitReader(source.word, 32, lsb=True)
    output = bytearray()
    while len(output) < output_size:
        if not bits.read(1):
            output.append(source.byte())
            continue
        encoded = source.word(2)
        if not encoded:
            raise CorruptDataError("invalid LZW2/3 zero distance")
        distance = 0x10000 - encoded
        count = source.byte() + 4
        copy_forward(output, distance, count, output_size)
    return bytes(output)


@register("LZW2")
def decompress_lzw2(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode an LZW2 stream."""

    del previous
    return _decode_lzw23(payload, output_size)


@register("LZW3")
def decompress_lzw3(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode an LZW3 stream, whose packed representation matches LZW2."""

    del previous
    return _decode_lzw23(payload, output_size)


@register("LZW4")
def decompress_lzw4(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode an LZW4 stream."""

    del previous
    source = ByteInput(payload)
    bits = BitReader(source.word, 32)
    output = bytearray()
    while len(output) < output_size:
        if not bits.read(1):
            output.append(source.byte())
            continue
        encoded = source.word(2)
        if not encoded:
            raise CorruptDataError("invalid LZW4 zero distance")
        distance = 0x10000 - encoded
        count = source.byte() + 3
        copy_forward(output, distance, count, output_size)
    return bytes(output)


@register("LZW5")
def decompress_lzw5(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode an LZW5 stream."""

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
        if not encoded:
            raise CorruptDataError("invalid LZW5 zero distance")
        if mode == 1:
            count = (encoded & 3) + 2
            distance = 0x4000 - (encoded >> 2)
        elif mode == 2:
            count = (encoded & 15) + 2
            distance = 0x1000 - (encoded >> 4)
        else:
            count = source.byte() + 3
            distance = 0x10000 - encoded
        copy_forward(output, distance, count, output_size)
    return bytes(output)

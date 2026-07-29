"""XPK ILZR decompression.

Derived from Ancient's ILZRDecompressor, Copyright (c) 2017-2025
Teemu Suutari, under the BSD 2-Clause License.
"""

from xfh.codecs import register
from xfh.codecs._streams import BitReader, ByteInput, copy_forward
from xfh.errors import CorruptDataError


@register("ILZR")
def decompress_ilzr(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode incremental Lempel-Ziv-Renau data."""

    del previous
    if len(payload) < 2:
        raise CorruptDataError("truncated ILZR stream")
    declared_size = int.from_bytes(payload[:2], "big")
    if not declared_size or declared_size != output_size:
        raise CorruptDataError("invalid ILZR output size")
    source = ByteInput(payload, 2)
    bits = BitReader(source.word, 8)
    output = bytearray()
    position_bits = 8
    while len(output) < output_size:
        if bits.read(1):
            output.append(bits.read(8))
            continue
        while len(output) > 1 << position_bits:
            position_bits += 1
        position = bits.read(position_bits)
        count = bits.read(4) + 3
        if position >= len(output):
            raise CorruptDataError("invalid ILZR source position")
        copy_forward(output, len(output) - position, count, output_size)
    return bytes(output)

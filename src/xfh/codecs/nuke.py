"""XPK NUKE decompression.

Derived from Ancient's NUKEDecompressor, Copyright (c) 2017-2025
Teemu Suutari, under the BSD 2-Clause License.
"""

from xfh.codecs import register
from xfh.codecs._streams import BitReader, CoupledInput, copy_forward
from xfh.errors import CorruptDataError


def _distance_offsets() -> tuple[tuple[int, int], ...]:
    specifications = (4, 6, 8, 9, -4, 7, 9, 11, 13, 14, -5, 7, 9, 11, 13, 14)
    length = 0
    result: list[tuple[int, int]] = []
    for specification in specifications:
        bits = abs(specification)
        if specification < 0:
            length = 1 << bits
            offset = 0
        else:
            offset = length
            length += 1 << bits
        result.append((offset, bits))
    return tuple(result)


_DISTANCES = _distance_offsets()


@register("NUKE")
def decompress_nuke(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode one NUKE chunk."""

    del previous
    streams = CoupledInput(payload)
    bit1 = BitReader(streams.forward, 16)
    bit2 = BitReader(streams.forward, 16)
    bit4 = BitReader(streams.forward, 32, lsb=True)
    bitx = BitReader(streams.forward, 16)
    output = bytearray()

    while True:
        if not bit1.read(1):
            count = 0
            if bit1.read(1):
                count = 1
            else:
                while True:
                    value = bit2.read(2)
                    count += 5 - value if value else 3
                    if value:
                        break
            if len(output) + count > output_size:
                raise CorruptDataError("literal run exceeds declared chunk size")
            for _ in range(count):
                output.append(streams.backward_byte())

        if len(output) == output_size:
            break
        if len(output) > output_size:
            raise CorruptDataError("decoded chunk exceeds declared size")

        distance_index = bit4.read(4)
        try:
            offset, bits = _DISTANCES[distance_index]
        except IndexError as error:
            raise CorruptDataError("invalid NUKE distance class") from error
        distance = offset + bitx.read(bits)

        if distance_index < 4:
            count = 2
        elif distance_index < 10:
            count = 3
        else:
            value = bit2.read(2)
            if value:
                count = 7 - value
            else:
                count = 6
                while True:
                    value = bit4.read(4)
                    count += 16 - value if value else 15
                    if value:
                        break
        copy_forward(output, distance, count, output_size)

    return bytes(output)

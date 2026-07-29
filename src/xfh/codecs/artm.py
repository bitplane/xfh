"""XPK ARTM arithmetic decompression.

Derived from Ancient's ARTMDecompressor and RangeDecoder,
Copyright (c) 2017-2025 Teemu Suutari, under the BSD 2-Clause License.
"""

from xfh.codecs import register
from xfh.codecs._streams import BitReader, ByteInput
from xfh.errors import CorruptDataError

_MASK16 = 0xFFFF


def _reverse16(value: int) -> int:
    result = 0
    for _ in range(16):
        result = (result << 1) | (value & 1)
        value >>= 1
    return result


class _RangeDecoder:
    def __init__(self, bits: BitReader):
        self.bits = bits
        self.low = 0
        self.high = _MASK16
        self.stream = _reverse16(bits.read(16))

    def decode(self, total: int) -> int:
        return ((self.stream - self.low + 1) * total - 1) // (self.high - self.low + 1)

    def scale(self, new_low: int, new_high: int, total: int) -> None:
        interval = self.high - self.low + 1
        self.high = (interval * new_high) // total + self.low - 1
        self.low = (interval * new_low) // total + self.low
        while True:
            if self.high < 0x8000:
                decrement = 0
            elif self.low >= 0x8000:
                decrement = 0x8000
            elif self.low >= 0x4000 and self.high < 0xC000:
                decrement = 0x4000
            else:
                break
            self.low = ((self.low - decrement) << 1) & _MASK16
            self.high = (((self.high - decrement) << 1) | 1) & _MASK16
            self.stream = (((self.stream - decrement) << 1) | self.bits.read(1)) & _MASK16


@register("ARTM")
def decompress_artm(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode ARTM's adaptive arithmetic stream."""

    del previous
    if len(payload) < 2:
        raise CorruptDataError("truncated ARTM stream")
    # The historical decoder explicitly permits three zero bits/bytes of
    # arithmetic-coder overrun at the end of a valid payload.
    source = ByteInput(payload + b"\0\0\0")
    bits = BitReader(source.word, 8, lsb=True)
    decoder = _RangeDecoder(bits)
    frequencies = [1] * 257
    characters = [(256 - index) & 0xFF for index in range(257)]
    output = bytearray()
    while len(output) < output_size:
        total = sum(frequencies)
        value = decoder.decode(total)
        cumulative = 0
        symbol = 0
        for index, frequency in enumerate(frequencies):
            if value < cumulative + frequency:
                symbol = index
                break
            cumulative += frequency
        else:
            raise CorruptDataError("invalid ARTM arithmetic value")
        if not symbol:
            raise CorruptDataError("unexpected ARTM terminator")
        decoder.scale(cumulative, cumulative + frequencies[symbol], total)
        output.append(characters[symbol])

        if total == 0x3FFF:
            for index in range(1, 257):
                frequencies[index] = (frequencies[index] + 1) >> 1
        target = symbol
        while target < 256 and frequencies[target + 1] == frequencies[target]:
            target += 1
        if target != symbol:
            characters[symbol], characters[target] = characters[target], characters[symbol]
        frequencies[target] += 1
    return bytes(output)

"""XPK LZCB decompression.

Derived from Ancient's LZCBDecompressor and RangeDecoder,
Copyright (c) 2017-2026 Teemu Suutari, under the BSD 2-Clause License.
"""

from collections.abc import Callable

from xfh.codecs import register
from xfh.codecs._range import RangeDecoder
from xfh.codecs._streams import BitReader, ByteInput, copy_forward
from xfh.errors import CorruptDataError


class _FrequencyDecoder:
    def __init__(self, decoder: RangeDecoder, symbol_limit: int):
        self.decoder = decoder
        self.frequencies = [0] * (symbol_limit + 1)
        self.threshold = 1

    def decode(self, read_new: Callable[[], int]) -> int:
        known_total = sum(self.frequencies)
        total = self.threshold + known_total
        value = self.decoder.decode(total)
        if value < self.threshold:
            self.decoder.scale(0, self.threshold, total)
            symbol = read_new()
            if not 0 <= symbol < len(self.frequencies):
                raise CorruptDataError("invalid new LZCB symbol")
            # Preserve the original encoder's zero-symbol escape bug.
            if symbol == 0 and self.frequencies[0]:
                symbol = len(self.frequencies) - 1
            self.threshold += 1
        else:
            target = value - self.threshold
            low = 0
            for candidate, frequency in enumerate(self.frequencies):
                if target < low + frequency:
                    symbol = candidate
                    break
                low += frequency
            else:
                raise CorruptDataError("invalid LZCB frequency symbol")
            self.decoder.scale(
                self.threshold + low,
                self.threshold + low + frequency,
                total,
            )
            if frequency == 1 and self.threshold > 1:
                self.threshold -= 1

        self.frequencies[symbol] += 1
        if self.threshold + sum(self.frequencies) >= 0x3FFD:
            self.frequencies = [frequency >> 1 for frequency in self.frequencies]
            self.threshold = (self.threshold >> 1) + 1
        return symbol


@register("LZCB")
def decompress_lzcb(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode one LZCB range-coded LZ chunk."""

    del previous
    if len(payload) < 2 or not output_size:
        raise CorruptDataError("truncated LZCB stream")

    # The historical implementation permits seven bytes of arithmetic-coder
    # overrun. Supplying explicit zero padding keeps reads bounded in Python.
    source = ByteInput(payload + bytes(7))
    bits = BitReader(source.word, 32)
    decoder = RangeDecoder(bits)

    def uniform(limit: int) -> int:
        value = decoder.decode(limit)
        decoder.scale(value, value + 1, limit)
        return value

    base_literal = _FrequencyDecoder(decoder, 256)
    repeat_count = _FrequencyDecoder(decoder, 257)
    literal_count = _FrequencyDecoder(decoder, 257)
    distance_high = _FrequencyDecoder(decoder, 256)
    literal_contexts: dict[int, _FrequencyDecoder] = {}

    character = base_literal.decode(lambda: uniform(0x100)) & 0xFF
    output = bytearray((character,))
    last_was_literal = True
    while len(output) < output_size:
        count = repeat_count.decode(lambda: uniform(0x101))
        if count:
            if count == 0x100:
                while True:
                    extension = uniform(0x100)
                    count += extension
                    if extension != 0xFF:
                        break
            count += 5 if last_was_literal else 4
            distance = (distance_high.decode(lambda: uniform(0x100)) << 8) | uniform(0x100)
            copy_forward(output, distance, count, output_size)
            character = output[-1]
            last_was_literal = False
            continue

        while True:
            count = literal_count.decode(lambda: uniform(0x101))
            if not count:
                raise CorruptDataError("invalid zero LZCB literal count")
            if len(output) + count > output_size:
                raise CorruptDataError("decoded LZCB chunk exceeds declared size")
            for _ in range(count):
                context = literal_contexts.get(character)
                if context is None:
                    context = literal_contexts[character] = _FrequencyDecoder(decoder, 256)
                character = (
                    context.decode(lambda: base_literal.decode(lambda: uniform(0x100))) & 0xFF
                )
                output.append(character)
            if count != 0x100:
                break
        last_was_literal = True
    return bytes(output)

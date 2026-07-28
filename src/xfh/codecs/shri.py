"""XPK SHRI decompression.

Derived from Ancient's SHRXDecompressor, Copyright (c) 2017-2025
Teemu Suutari, under the BSD 2-Clause License.
"""

from dataclasses import dataclass

from xfh.codecs import register
from xfh.codecs._streams import copy_forward
from xfh.errors import CorruptDataError

_MASK32 = 0xFFFF_FFFF


@dataclass(slots=True)
class ShriState:
    """Adaptive model carried by SHRI version 2 continuation chunks."""

    vlen: int
    vnext: int
    shift: int
    probabilities: list[int]


class _ShriDecoder:
    def __init__(self, data: bytes, output_size: int, state: ShriState | None):
        if len(data) < 8:
            raise CorruptDataError("truncated SHRI stream")
        version = data[0]
        if version not in (1, 2):
            raise CorruptDataError(f"unsupported SHRI stream version {version}")

        if data[2] & 0x80:
            declared_size = (-int.from_bytes(data[2:6], "big")) & _MASK32
            self.offset = 6
        else:
            declared_size = int.from_bytes(data[2:4], "big")
            self.offset = 4
        if declared_size != output_size:
            raise CorruptDataError(
                f"SHRI stream declares {declared_size} bytes, expected {output_size}"
            )

        self.data = data
        if version == 1:
            self.ar = [0] * 999
            for index in range(256):
                self.ar[index + 499] = 1 if index < 32 or index > 126 else 3
            self._resume()
            self._update(498, 1)
            self.vlen = 0
            self.vnext = 0
            self.shift = 0x8000_0000
        else:
            if state is None:
                raise CorruptDataError("SHRI version 2 chunk has no preceding model state")
            self.ar = state.probabilities.copy()
            self.vlen = state.vlen
            self.vnext = state.vnext
            self.shift = state.shift
        self.stream = self._read_u32()

    def _read_byte(self) -> int:
        if self.offset >= len(self.data):
            raise CorruptDataError("truncated SHRI arithmetic stream")
        value = self.data[self.offset]
        self.offset += 1
        return value

    def _read_u32(self) -> int:
        if self.offset + 4 > len(self.data):
            raise CorruptDataError("truncated SHRI arithmetic stream")
        value = int.from_bytes(self.data[self.offset : self.offset + 4], "big")
        self.offset += 4
        return value

    def _resume(self) -> None:
        for index in range(498, 0, -1):
            self.ar[index] = self.ar[index * 2] + self.ar[index * 2 + 1]

    def _update(self, index: int, increment: int) -> None:
        if index >= 499:
            return
        index += 499
        while index:
            self.ar[index] += increment
            index >>= 1
        if self.ar[1] >= 0x2000:
            for index in range(499, 998):
                if self.ar[index]:
                    self.ar[index] = (self.ar[index] >> 1) + 1
            self._resume()

    @staticmethod
    def _scale(part: int, total: int, interval: int) -> int:
        if not total:
            raise CorruptDataError("invalid SHRI probability total")
        high = (part << 16) // total
        low = (((part << 16) % total) << 16) // total
        return (
            ((interval & 0xFFFF) * high >> 16)
            + ((interval >> 16) * low >> 16)
            + (interval >> 16) * high
        ) & _MASK32

    def _refill(self) -> None:
        while self.shift < 0x100_0000:
            self.stream = ((self.stream << 8) | self._read_byte()) & _MASK32
            self.shift = (self.shift << 8) & _MASK32

    def _symbol(self) -> int:
        divisor = self.shift >> 16
        if not divisor:
            raise CorruptDataError("invalid SHRI arithmetic interval")
        value = (self.stream // divisor) & 0xFFFF
        threshold = (self.ar[1] * value) >> 16
        tree_index = 1
        cumulative = 0
        while True:
            tree_index <<= 1
            candidate = self.ar[tree_index] + cumulative
            if threshold >= candidate:
                cumulative = candidate
                tree_index += 1
            if tree_index >= 499:
                break

        new_value = self._scale(cumulative, self.ar[1], self.shift)
        if new_value > self.stream:
            while new_value > self.stream:
                tree_index -= 1
                if tree_index < 499:
                    tree_index += 499
                cumulative -= self.ar[tree_index]
                new_value = self._scale(cumulative, self.ar[1], self.shift)
        else:
            cumulative += self.ar[tree_index]
            while cumulative < self.ar[1]:
                compare = self._scale(cumulative, self.ar[1], self.shift)
                if self.stream < compare:
                    break
                tree_index += 1
                if tree_index >= 998:
                    tree_index -= 499
                cumulative += self.ar[tree_index]
                new_value = compare

        self.stream = (self.stream - new_value) & _MASK32
        self.shift = self._scale(self.ar[tree_index], self.ar[1], self.shift)
        addition = (self.ar[1] >> 10) + 3
        tree_index -= 499
        self._update(tree_index, addition)
        self._refill()
        return tree_index

    def _bits(self, count: int) -> int:
        result = 0
        for _ in range(count):
            result <<= 1
            self.shift >>= 1
            if self.stream >= self.shift:
                result += 1
                self.stream -= self.shift
            self._refill()
        return result

    def _upgrade(self) -> None:
        updates1 = (358, 359, 386, 387, 414, 415)
        updates2 = (442, 456, 470, 484)
        if self.vnext >= 65532:
            self.vnext = _MASK32
        elif not self.vlen:
            self.vnext = 1
        else:
            value = self.vnext - 1
            if value < 48:
                self._update(value + 256, 1)
            bits = 0
            compare = 4
            while value >= compare:
                value -= compare
                compare <<= 1
                bits += 1
            if bits >= 14:
                self.vnext = _MASK32
            else:
                if not value:
                    if bits < 7:
                        for index in range(304, 308):
                            self._update((bits << 2) + index, 1)
                    if bits < 13:
                        for index in range(332, 334):
                            self._update((bits << 1) + index, 1)
                    for index in updates1:
                        self._update((bits << 1) + index, 1)
                    for index in updates2:
                        self._update(bits + index, 1)
                if self.vnext < 49:
                    self.vnext += 1
                elif self.vnext == 49:
                    self.vnext = 61
                else:
                    self.vnext = (self.vnext << 1) + 3

    @staticmethod
    def _distance_addition(index: int) -> int:
        return ((1 << (index + 2)) - 1) & ~3

    def decompress(self, output_size: int, previous: bytes) -> bytes:
        output = bytearray()
        while len(output) < output_size:
            while self.vlen >= self.vnext:
                self._upgrade()
            code = self._symbol()
            if code < 256:
                output.append(code)
                self.vlen += 1
                continue

            if code < 304:
                count = 2
                distance = code - 255
            elif code < 332:
                value = code - 304
                extra = self._bits(value >> 2)
                distance = ((extra << 2) | (value & 3)) + self._distance_addition(value >> 2) + 1
                count = 3
            elif code < 442:
                bases = ((332, 4), (358, 5), (386, 6), (414, 7))
                base, count = next(item for item in reversed(bases) if code >= item[0])
                value = code - base
                extra = self._bits((value >> 1) + 1)
                distance = ((extra << 1) | (value & 1)) + self._distance_addition(value >> 1) + 1
            elif code < 498:
                value = code - 442
                count_index, distance_index = divmod(value, 14)
                count = self._bits(count_index + 2) + self._distance_addition(count_index) + 8
                distance = (
                    self._bits(distance_index + 2) + self._distance_addition(distance_index) + 1
                )
            else:
                count = self._bits(16)
                distance = self._bits(16)

            if not count:
                raise CorruptDataError("invalid zero-length SHRI match")
            self.vlen += count
            if distance > len(output):
                needed = distance - len(output)
                if needed > len(previous):
                    raise CorruptDataError("invalid SHRI backward reference")
                prefix = previous[-needed:]
                combined = bytearray(prefix)
                combined.extend(output)
                start = len(combined) - distance
                for _ in range(count):
                    if len(output) >= output_size:
                        raise CorruptDataError("SHRI output exceeds declared size")
                    value = combined[start]
                    start += 1
                    combined.append(value)
                    output.append(value)
            else:
                copy_forward(output, distance, count, output_size)

        return bytes(output)

    def state(self) -> ShriState:
        return ShriState(self.vlen, self.vnext, self.shift, self.ar.copy())


def decompress_shri_chunk(
    payload: bytes,
    output_size: int,
    previous: bytes,
    state: ShriState | None,
) -> tuple[bytes, ShriState]:
    """Decode one SHRI chunk and return its continuation model."""

    decoder = _ShriDecoder(payload, output_size, state)
    return decoder.decompress(output_size, previous), decoder.state()


@register("SHRI")
def decompress_shri(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode one independently initialized SHRI chunk."""

    decoded, _state = decompress_shri_chunk(payload, output_size, previous, None)
    return decoded

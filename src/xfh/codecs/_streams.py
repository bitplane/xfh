"""Bounded byte and bit streams used by historical XPK codecs.

The stream behavior is derived from Ancient, Copyright (c) 2017-2025
Teemu Suutari, under the BSD 2-Clause License.
"""

from collections.abc import Callable

from xfh.errors import CorruptDataError


class CoupledInput:
    """Forward word reads and backward byte reads sharing one payload."""

    def __init__(self, data: bytes):
        self.data = data
        self.front = 0
        self.back = len(data)

    def forward(self, size: int) -> int:
        if size < 0 or self.front + size > self.back:
            raise CorruptDataError("packed streams overlap")
        value = int.from_bytes(self.data[self.front : self.front + size], "big")
        self.front += size
        return value

    def forward_byte(self) -> int:
        return self.forward(1)

    def backward_word(self, size: int) -> int:
        if size < 0 or self.back - size < self.front:
            raise CorruptDataError("packed streams overlap")
        self.back -= size
        return int.from_bytes(self.data[self.back : self.back + size], "big")

    def backward_byte(self) -> int:
        if self.back <= self.front:
            raise CorruptDataError("packed streams overlap")
        self.back -= 1
        return self.data[self.back]


class ByteInput:
    """A bounded forward byte stream."""

    def __init__(self, data: bytes, offset: int = 0):
        self.data = data
        self.offset = offset

    def word(self, size: int) -> int:
        if size < 0 or self.offset + size > len(self.data):
            raise CorruptDataError("truncated packed stream")
        value = int.from_bytes(self.data[self.offset : self.offset + size], "big")
        self.offset += size
        return value

    def byte(self) -> int:
        return self.word(1)


class BitReader:
    """Read most- or least-significant bits from fixed-width words."""

    def __init__(self, source: Callable[[int], int], word_size: int, *, lsb: bool = False):
        self.source = source
        self.word_size = word_size
        self.lsb = lsb
        self.content = 0
        self.length = 0

    def read(self, count: int) -> int:
        if not 0 <= count <= 32:
            raise CorruptDataError("invalid bit count")
        result = 0
        position = 0
        while count:
            if not self.length:
                self.content = self.source(self.word_size // 8)
                self.length = self.word_size
            take = min(count, self.length)
            if self.lsb:
                result |= (self.content & ((1 << take) - 1)) << position
                self.content >>= take
                position += take
            else:
                self.length -= take
                result = (result << take) | ((self.content >> self.length) & ((1 << take) - 1))
            if self.lsb:
                self.length -= take
            count -= take
        return result


def copy_forward(output: bytearray, distance: int, count: int, output_size: int) -> None:
    """Copy an overlapping LZ match within a bounded output buffer."""

    if distance <= 0 or distance > len(output):
        raise CorruptDataError("invalid backward reference")
    if count < 0 or len(output) + count > output_size:
        raise CorruptDataError("decoded chunk exceeds declared size")
    for _ in range(count):
        output.append(output[-distance])

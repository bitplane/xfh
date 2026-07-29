"""Shared 16-bit arithmetic range decoder."""

from xfh.codecs._streams import BitReader
from xfh.errors import CorruptDataError

_MASK16 = 0xFFFF


class RangeDecoder:
    """Decode integer ranges using the historical XPK 16-bit coder."""

    def __init__(self, bits: BitReader, initial: int | None = None):
        self.bits = bits
        self.low = 0
        self.high = _MASK16
        self.stream = bits.read(16) if initial is None else initial

    def decode(self, total: int) -> int:
        if not 0 < total <= 0xFFFF:
            raise CorruptDataError("invalid arithmetic probability total")
        return ((self.stream - self.low + 1) * total - 1) // (self.high - self.low + 1)

    def scale(self, new_low: int, new_high: int, total: int) -> None:
        if not 0 <= new_low < new_high <= total <= 0xFFFF:
            raise CorruptDataError("invalid arithmetic probability range")
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

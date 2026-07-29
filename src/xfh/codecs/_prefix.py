"""Small prefix-code helpers shared by XPK codecs."""

from collections.abc import Iterable

from xfh.errors import CorruptDataError


class PrefixDecoder:
    """Decode explicit most-significant-bit-first prefix codes."""

    def __init__(self, codes: Iterable[tuple[int, int, int]], *, maximum: int = 32):
        self.codes: dict[tuple[int, int], int] = {}
        self.maximum = maximum
        for length, code, value in codes:
            if not 1 <= length <= maximum or code >= 1 << length:
                raise CorruptDataError("invalid prefix code")
            key = (length, code)
            if key in self.codes:
                raise CorruptDataError("duplicate prefix code")
            self.codes[key] = value

    def decode(self, bits: object) -> int:
        """Decode one value from an object exposing ``read(count)``."""

        code = 0
        for length in range(1, self.maximum + 1):
            code = (code << 1) | bits.read(1)  # type: ignore[attr-defined]
            value = self.codes.get((length, code))
            if value is not None:
                return value
        raise CorruptDataError("invalid prefix code")


def variable_length(bits: object, specifications: tuple[int, ...], index: int) -> int:
    """Decode an indexed variable-length integer with cumulative bases."""

    if not 0 <= index < len(specifications):
        raise CorruptDataError("invalid variable-length class")
    base = sum(1 << count for count in specifications[:index])
    count = specifications[index]
    return base + bits.read(count)  # type: ignore[attr-defined]

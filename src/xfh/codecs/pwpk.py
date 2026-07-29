"""XPK PowerPacker (PWPK) decompression."""

from xfh.codecs import register
from xfh.errors import CorruptDataError

_MODES = (
    (9, 9, 9, 9),
    (9, 10, 10, 10),
    (9, 10, 11, 11),
    (9, 10, 12, 12),
    (9, 10, 12, 13),
)


def _reverse(value: int, count: int) -> int:
    result = 0
    for _ in range(count):
        result = (result << 1) | (value & 1)
        value >>= 1
    return result


class _BackwardBits:
    def __init__(self, data: bytes, end: int):
        self.data = data
        self.offset = end
        self.content = 0
        self.length = 0

    def read(self, count: int) -> int:
        result = 0
        position = 0
        remaining = count
        while remaining:
            if not self.length:
                if self.offset < 4:
                    raise CorruptDataError("truncated PWPK stream")
                self.offset -= 4
                self.content = int.from_bytes(self.data[self.offset : self.offset + 4], "big")
                self.length = 32
            take = min(remaining, self.length)
            result |= (self.content & ((1 << take) - 1)) << position
            self.content >>= take
            self.length -= take
            position += take
            remaining -= take
        return _reverse(result, count)


@register("PWPK")
def decompress_pwpk(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode a PowerPacker chunk."""

    del previous
    if len(payload) < 8:
        raise CorruptDataError("truncated PWPK stream")
    mode = int.from_bytes(payload[-4:], "big")
    if mode >= len(_MODES):
        raise CorruptDataError("invalid PWPK mode")
    data_end = len(payload) - 8
    marker = int.from_bytes(payload[data_end : data_end + 4], "big")
    if marker >> 8 != output_size or marker & 0xFF >= 32:
        raise CorruptDataError("invalid PWPK output marker")
    bits = _BackwardBits(payload, data_end)
    bits.read(marker & 0xFF)
    output = bytearray(output_size)
    position = output_size

    def write(value: int) -> None:
        nonlocal position
        if not position:
            raise CorruptDataError("PWPK output overflow")
        position -= 1
        output[position] = value

    while position:
        if not bits.read(1):
            count = 1
            while True:
                value = bits.read(2)
                count += value
                if value < 3:
                    break
            for _ in range(count):
                write(bits.read(8))
        if not position:
            break
        mode_index = bits.read(2)
        if mode_index == 3:
            distance = bits.read(_MODES[mode][3] if bits.read(1) else 7) + 1
            count = 5
            while True:
                value = bits.read(3)
                count += value
                if value < 7:
                    break
        else:
            count = mode_index + 2
            distance = bits.read(_MODES[mode][mode_index]) + 1
        if count > position or position + distance > output_size:
            raise CorruptDataError("invalid PWPK backward reference")
        for _ in range(count):
            write(output[position + distance - 1])
    return bytes(output)

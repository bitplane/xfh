"""XPK File Imploder decompression."""

from xfh.codecs import register
from xfh.codecs._streams import BitReader
from xfh.errors import CorruptDataError


class _ImplInput:
    def __init__(self, data: bytes, end: int):
        self.data = data
        self.offset = end
        self.end = 0
        self.reference = end
        if end + 17 >= len(data):
            raise CorruptDataError("truncated IMPL tables")
        if not data[end + 16] & 0x80:
            if not self.offset:
                raise CorruptDataError("invalid IMPL stream")
            self.offset -= 1

    def byte(self) -> int:
        if self.offset <= self.end:
            raise CorruptDataError("truncated IMPL stream")
        self.offset -= 1
        index = self.offset
        if index < 4:
            index += self.reference + 8
        elif index < 8:
            index += self.reference
        elif index < 12:
            index += self.reference - 8
        if index >= len(self.data):
            raise CorruptDataError("invalid IMPL byte permutation")
        return self.data[index]


def _unary(bits: BitReader, maximum: int) -> int:
    value = 0
    while value < maximum and bits.read(1):
        value += 1
    return value


@register("IMPL")
def decompress_impl(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode an XPK-wrapped File Imploder stream."""

    del previous
    if len(payload) < 46 or payload[:4] != b"IMP!":
        raise CorruptDataError("invalid IMPL stream")
    raw_size = int.from_bytes(payload[4:8], "big")
    end = int.from_bytes(payload[8:12], "big")
    if raw_size != output_size or end < 12 or end & 1 or end + 46 > len(payload):
        raise CorruptDataError("invalid IMPL sizes")
    source = _ImplInput(payload, end)
    bits = BitReader(lambda _: source.byte(), 8)
    anchor = payload[end + 17]
    for index in range(7):
        if anchor & (1 << index):
            bits.content = anchor >> (index + 1)
            bits.length = 7 - index
            break

    distance_values = [
        [
            int.from_bytes(
                payload[end + 18 + (row * 4 + col) * 2 : end + 20 + (row * 4 + col) * 2],
                "big",
            )
            for col in range(4)
        ]
        for row in range(2)
    ]
    distance_bits = [[payload[end + 34 + row * 4 + col] for col in range(4)] for row in range(3)]
    literal_lengths = (6, 10, 10, 18)
    literal_bits = ((1, 1, 1, 1), (2, 3, 3, 4), (4, 5, 7, 14))
    literal_count = int.from_bytes(payload[end + 12 : end + 16], "big")
    output = bytearray(output_size)
    position = output_size

    def write(value: int) -> None:
        nonlocal position
        if not position:
            raise CorruptDataError("IMPL output overflow")
        position -= 1
        output[position] = value

    while True:
        for _ in range(literal_count):
            write(source.byte())
        if not position:
            break
        first = _unary(bits, 5)
        selector = min(first, 3)
        count = first + 2
        if count == 6:
            count += bits.read(3)
        elif count == 7:
            count = source.byte()
            if not count:
                raise CorruptDataError("invalid IMPL match length")
        second = 0 if not bits.read(1) else 1 + bits.read(1)
        literal_count = second * 2
        if literal_count == 4:
            literal_count = literal_lengths[selector]
        literal_count += bits.read(literal_bits[second][selector])
        third = 0 if not bits.read(1) else 1 + bits.read(1)
        base = distance_values[third - 1][selector] if third else 0
        distance = 1 + base + bits.read(distance_bits[third][selector])
        if count > position or position + distance > output_size:
            raise CorruptDataError("invalid IMPL backward reference")
        for _ in range(count):
            write(output[position + distance - 1])
    return bytes(output)

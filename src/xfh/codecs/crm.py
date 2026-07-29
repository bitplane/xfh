"""Crunch-Mania XPK codecs."""

from xfh.codecs import register
from xfh.errors import CorruptDataError


class _Bits:
    def __init__(self, data: bytes, start: int, end: int, content: int, length: int):
        self.data, self.start, self.offset = data, start, end
        self.content, self.length = content, length

    def read(self, count: int) -> int:
        result = 0
        shift = 0
        while count:
            if not self.length:
                if self.offset <= self.start:
                    raise CorruptDataError("truncated CRM stream")
                self.offset -= 1
                self.content = self.data[self.offset]
                self.length = 8
            take = min(count, self.length)
            result |= (self.content & ((1 << take) - 1)) << shift
            self.content >>= take
            self.length -= take
            shift += take
            count -= take
        return result


def _table(bits: _Bits, width: int) -> dict[tuple[int, int], int]:
    depth_max = bits.read(4)
    if not depth_max:
        raise CorruptDataError("invalid CRM Huffman table")
    counts = [bits.read(min(depth + 1, width)) for depth in range(depth_max)]
    result = {}
    code = 0
    for depth, count in enumerate(counts, 1):
        for _ in range(count):
            result[depth, code >> (depth_max - depth)] = bits.read(width)
            code += 1 << (depth_max - depth)
    return result


def _symbol(bits: _Bits, table: dict[tuple[int, int], int]) -> int:
    code = 0
    for depth in range(1, 16):
        code = (code << 1) | bits.read(1)
        if (depth, code) in table:
            return table[depth, code]
    raise CorruptDataError("invalid CRM Huffman code")


def _decompress(payload: bytes, output_size: int) -> bytes:
    if len(payload) < 20 or payload[:4] not in (b"CrM!", b"Crm!", b"CrM2", b"Crm2"):
        raise CorruptDataError("invalid CRM2 stream")
    lzh = payload[3] == ord("2")
    sampled = payload[2] == ord("m")
    raw_size = int.from_bytes(payload[6:10], "big")
    packed_size = int.from_bytes(payload[10:14], "big")
    if raw_size != output_size or packed_size < 6 or packed_size + 14 > len(payload):
        raise CorruptDataError("invalid CRM2 sizes")
    tail = packed_size + 8
    content = int.from_bytes(payload[tail : tail + 4], "big")
    shift = int.from_bytes(payload[tail + 4 : tail + 6], "big")
    if shift > 16:
        raise CorruptDataError("invalid CRM2 bit anchor")
    bits = _Bits(payload, 14, tail, content >> (16 - shift), shift + 16)
    output = bytearray(output_size)
    position = output_size

    def write(value: int) -> None:
        nonlocal position
        if not position:
            raise CorruptDataError("CRM2 output overflow")
        position -= 1
        output[position] = value & 0xFF

    if lzh:
        more = 1
        while more:
            lengths = _table(bits, 9)
            distances = _table(bits, 4)
            for _ in range(bits.read(16) + 1):
                count = _symbol(bits, lengths)
                if count & 0x100:
                    write(count)
                    continue
                count += 3
                distance_bits = _symbol(bits, distances)
                distance = (
                    bits.read(1) + 1
                    if not distance_bits
                    else (bits.read(distance_bits) | (1 << distance_bits)) + 1
                )
                if count > position or position + distance > output_size:
                    raise CorruptDataError("invalid CRM2 backward reference")
                for _ in range(count):
                    write(output[position + distance - 1])
            more = bits.read(1)
    else:
        length_bits, length_offsets = (1, 2, 4, 8), (0, 2, 6, 22)
        distance_bits, distance_offsets = (5, 9, 14), (0, 32, 544)
        while position:
            if bits.read(1):
                write(bits.read(8))
                continue
            length_index = _symbol(
                bits,
                {(1, 0): 0, (2, 2): 1, (3, 6): 2, (3, 7): 3},
            )
            count = length_offsets[length_index] + bits.read(length_bits[length_index]) + 2
            if count == 23:
                literal_count = bits.read(5 if bits.read(1) else 14) + 15
                for _ in range(literal_count):
                    write(bits.read(8))
                continue
            if count > 23:
                count -= 1
            distance_index = _symbol(bits, {(1, 0): 1, (2, 2): 0, (2, 3): 2})
            distance = distance_offsets[distance_index] + bits.read(distance_bits[distance_index])
            if count > position or position + distance > output_size:
                raise CorruptDataError("invalid CRM2 backward reference")
            for _ in range(count):
                write(output[position + distance - 1])
    if position:
        raise CorruptDataError("CRM2 stream ended early")
    if sampled:
        accumulator = 0
        for index, value in enumerate(output):
            accumulator = (accumulator + value) & 0xFF
            output[index] = accumulator
    return bytes(output)


@register("CRM2")
def decompress_crm2(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    del previous
    return _decompress(payload, output_size)


@register("CRMS")
def decompress_crms(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    del previous
    return _decompress(payload, output_size)

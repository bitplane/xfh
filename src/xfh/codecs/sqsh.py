"""XPK SQSH decompression."""

from xfh.codecs import register
from xfh.codecs._prefix import PrefixDecoder, variable_length
from xfh.codecs._streams import BitReader, ByteInput, copy_forward
from xfh.errors import CorruptDataError

_MOD = PrefixDecoder(((1, 1, 0), (2, 0, 1), (3, 2, 2), (4, 6, 3), (4, 7, 4)))
_LENGTH = PrefixDecoder(((1, 0, 0), (2, 2, 1), (3, 6, 2), (4, 14, 3), (4, 15, 4)))
_DISTANCE = PrefixDecoder(((1, 1, 1), (2, 0, 0), (2, 1, 2)))
_BIT_LENGTHS = (
    (2, 3, 4, 5, 6, 7, 8, 0),
    (3, 2, 4, 5, 6, 7, 8, 0),
    (4, 3, 5, 2, 6, 7, 8, 0),
    (5, 4, 6, 2, 3, 7, 8, 0),
    (6, 5, 7, 2, 3, 4, 8, 0),
    (7, 6, 8, 2, 3, 4, 5, 0),
    (8, 7, 6, 2, 3, 4, 5, 0),
)


def _signed(bits: BitReader, count: int) -> int:
    value = bits.read(count)
    sign = 1 << (count - 1)
    return value - (sign << 1) if value & sign else value


def _condition(bit_count: int, accumulator2: int) -> tuple[int, int]:
    if bit_count != 8:
        return 5, accumulator2 + 8
    if accumulator2 < 20:
        return 1, accumulator2
    return 2, accumulator2 + 8


def _table(previous_bits: int, new_bits: int, accumulator2: int) -> tuple[int, int, int]:
    if previous_bits < 2 or new_bits == 0:
        raise CorruptDataError("invalid SQSH bit-length transition")
    bit_count = _BIT_LENGTHS[previous_bits - 2][new_bits - 1]
    if not bit_count:
        raise CorruptDataError("invalid SQSH bit length")
    count, accumulator2 = _condition(bit_count, accumulator2)
    return bit_count, count, accumulator2


@register("SQSH")
def decompress_sqsh(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode an SQSH sample-prediction and LZ stream."""

    del previous
    if len(payload) < 3:
        raise CorruptDataError("truncated SQSH stream")
    if int.from_bytes(payload[:2], "big") != output_size or not output_size:
        raise CorruptDataError("invalid SQSH output size")
    source = ByteInput(payload, 2)
    bits = BitReader(source.word, 8)
    current = source.byte()
    output = bytearray((current,))
    accumulator1 = 0
    accumulator2 = 0
    previous_bits = 0

    while len(output) < output_size:
        bit_count = 0
        count = 0
        repeat = False

        if accumulator1 >= 8:
            mode = _MOD.decode(bits)
            if mode == 0:
                if previous_bits == 8:
                    bit_count = 8
                    count, accumulator2 = _condition(bit_count, accumulator2)
                else:
                    bit_count = previous_bits
                    count = 5
                    accumulator2 += 8
            elif mode == 1:
                repeat = True
            elif mode == 2:
                bit_count, count, accumulator2 = _table(previous_bits, 2, accumulator2)
            elif mode == 3:
                bit_count, count, accumulator2 = _table(previous_bits, 3, accumulator2)
            else:
                bit_count, count, accumulator2 = _table(
                    previous_bits, bits.read(2) + 4, accumulator2
                )
        elif bits.read(1):
            repeat = True
        else:
            count = 1
            bit_count = 8

        if repeat:
            count = variable_length(bits, (1, 1, 1, 3, 5), _LENGTH.decode(bits)) + 2
            if count >= 3 and accumulator1:
                accumulator1 -= 1
                if count > 3 and accumulator1:
                    accumulator1 -= 1
            distance = variable_length(bits, (8, 12, 14), _DISTANCE.decode(bits)) + 1
            count = min(count, output_size - len(output))
            copy_forward(output, distance, count, output_size)
            current = output[-1]
        else:
            count = min(count, output_size - len(output))
            for _ in range(count):
                current = (current - _signed(bits, bit_count)) & 0xFF
                output.append(current)
            accumulator1 = min(accumulator1 + 1, 31)
            previous_bits = bit_count
        accumulator2 -= accumulator2 >> 3
    return bytes(output)

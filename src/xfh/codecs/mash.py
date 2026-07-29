"""XPK MASH decompression."""

from xfh.codecs import register
from xfh.codecs._prefix import PrefixDecoder, variable_length
from xfh.codecs._streams import BitReader, ByteInput, copy_forward
from xfh.errors import CorruptDataError

_LITERAL_LENGTH = PrefixDecoder(
    ((1, 0, 0), (2, 2, 1), (3, 6, 2), (4, 14, 3), (5, 30, 4), (6, 62, 5), (6, 63, 6))
)
_DISTANCES = (5, 7, 9, 10, 11, 12, 13, 14)


@register("MASH")
def decompress_mash(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode a MASH mixed literal and LZ stream."""

    del previous
    source = ByteInput(payload)
    bits = BitReader(source.word, 8)
    output = bytearray()
    while len(output) < output_size:
        literal_count = _LITERAL_LENGTH.decode(bits)
        if literal_count == 6:
            count_bits = 1
            while bits.read(1):
                count_bits += 1
                if count_bits == 17:
                    raise CorruptDataError("invalid MASH literal length")
            literal_count = bits.read(count_bits) + (1 << count_bits) + 4
        if len(output) + literal_count > output_size:
            raise CorruptDataError("MASH literal run exceeds declared size")
        for _ in range(literal_count):
            output.append(source.byte())

        if bits.read(1):
            count_bits = 1
            while bits.read(1):
                count_bits += 1
                if count_bits == 16:
                    raise CorruptDataError("invalid MASH match length")
            count = bits.read(count_bits) + (1 << count_bits) + 2
            distance = variable_length(bits, _DISTANCES, bits.read(3))
        elif bits.read(1):
            distance = variable_length(bits, _DISTANCES, bits.read(3))
            count = 3
        else:
            distance = bits.read(9)
            count = 2
        if distance == 0 and len(output) == output_size:
            break
        count = min(count, output_size - len(output))
        copy_forward(output, distance, count, output_size)
    return bytes(output)

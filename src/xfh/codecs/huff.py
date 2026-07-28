"""XPK HUFF decompression."""

from dataclasses import dataclass

from xfh.codecs import register
from xfh.codecs._streams import BitReader, ByteInput
from xfh.errors import CorruptDataError


@dataclass(frozen=True, slots=True)
class _Code:
    length: int
    bits: int
    symbol: int


@register("HUFF")
def decompress_huff(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode one HUFF chunk."""

    del previous
    if len(payload) < 6 or payload[:2] != b"\0\0":
        raise CorruptDataError("invalid HUFF version")
    if payload[2:6] != b"\xab\xad\xca\xfe":
        raise CorruptDataError("unsupported HUFF password marker")
    source = ByteInput(payload, 6)
    codes: dict[tuple[int, int], int] = {}
    for symbol in range(256):
        length = (source.byte() + 1) & 0xFF
        if not length:
            continue
        if length > 32:
            raise CorruptDataError("invalid HUFF code length")
        byte_count = (length + 7) // 8
        code = source.word(byte_count)
        code >>= byte_count * 8 - length
        key = (length, code)
        if key in codes:
            raise CorruptDataError("duplicate HUFF code")
        codes[key] = symbol
    bits = BitReader(source.word, 8)
    output = bytearray()
    while len(output) < output_size:
        code = 0
        for length in range(1, 33):
            code = (code << 1) | bits.read(1)
            symbol = codes.get((length, code))
            if symbol is not None:
                output.append(symbol)
                break
        else:
            raise CorruptDataError("invalid HUFF bit code")
    return bytes(output)

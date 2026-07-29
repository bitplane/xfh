"""XPK HFMN decompression."""

from xfh.codecs import register
from xfh.codecs._prefix import PrefixDecoder
from xfh.codecs._streams import BitReader, ByteInput
from xfh.errors import CorruptDataError


def _reverse(value: int, count: int) -> int:
    result = 0
    for _ in range(count):
        result = (result << 1) | (value & 1)
        value >>= 1
    return result


@register("HFMN")
def decompress_hfmn(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode an HFMN dynamic Huffman stream."""

    del previous
    if len(payload) < 4:
        raise CorruptDataError("truncated HFMN stream")
    field = int.from_bytes(payload[:2], "big")
    if field % 4:
        raise CorruptDataError("invalid HFMN header alignment")
    header_size = field & 0x1FF
    if header_size + 4 > len(payload):
        raise CorruptDataError("truncated HFMN header")
    raw_size = int.from_bytes(payload[header_size + 2 : header_size + 4], "big")
    if not raw_size or raw_size != output_size:
        raise CorruptDataError("invalid HFMN output size")
    body_offset = header_size + 4
    tree_source = ByteInput(payload[2:body_offset])
    tree_bits = BitReader(tree_source.word, 8)
    codes: list[tuple[int, int, int]] = []
    code = 1
    code_bits = 1
    while True:
        if not tree_bits.read(1):
            codes.append((code_bits, code, _reverse(tree_bits.read(8), 8)))
            while code_bits and not code & 1:
                code_bits -= 1
                code >>= 1
            if not code_bits:
                break
            code -= 1
        else:
            code = (code << 1) + 1
            code_bits += 1
            if code_bits > 32:
                raise CorruptDataError("HFMN tree is too deep")
    decoder = PrefixDecoder(codes)
    source = ByteInput(payload, body_offset)
    bits = BitReader(source.word, 8)
    return bytes(decoder.decode(bits) for _ in range(output_size))

"""XPK SMPL decompression."""

from xfh.codecs import register
from xfh.codecs._prefix import PrefixDecoder
from xfh.codecs._streams import BitReader, ByteInput
from xfh.errors import CorruptDataError


@register("SMPL")
def decompress_smpl(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode a static Huffman stream followed by byte delta prediction."""

    del previous
    if len(payload) < 2 or int.from_bytes(payload[:2], "big") != 1:
        raise CorruptDataError("invalid SMPL version")
    source = ByteInput(payload, 2)
    bits = BitReader(source.word, 8)
    codes: list[tuple[int, int, int]] = []
    for symbol in range(256):
        length = bits.read(4)
        if not length:
            continue
        if length == 15:
            length += bits.read(4)
        codes.append((length, bits.read(length), symbol))
    decoder = PrefixDecoder(codes)
    output = bytearray()
    accumulator = 0
    while len(output) < output_size:
        accumulator = (accumulator + decoder.decode(bits)) & 0xFF
        output.append(accumulator)
    return bytes(output)

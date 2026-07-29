"""XPK wrappers around the classic Amiga LZX archiver."""

from xfh.codecs import register
from xfh.codecs.amiga_lzx import decompress_archive


@register("ELZX")
def decompress_elzx(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode an Amiga LZX archive embedded by xpkELZX."""

    del previous
    return decompress_archive(payload, output_size)


@register("SLZX")
def decompress_slzx(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode xpkSLZX's Amiga LZX member and cumulative-byte transform."""

    del previous
    decoded = bytearray(decompress_archive(payload, output_size))
    accumulator = 0
    for index, value in enumerate(decoded):
        accumulator = (accumulator + value) & 0xFF
        decoded[index] = accumulator
    return bytes(decoded)

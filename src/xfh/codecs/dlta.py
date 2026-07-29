"""XPK DLTA decompression."""

from xfh.codecs import register
from xfh.errors import CorruptDataError


@register("DLTA")
def decompress_dlta(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode DLTA's byte-delta transform."""

    del previous
    if len(payload) != output_size:
        raise CorruptDataError("DLTA payload size differs from declared output size")
    output = bytearray()
    accumulator = 0
    for value in payload:
        accumulator = (accumulator + value) & 0xFF
        output.append(accumulator)
    return bytes(output)

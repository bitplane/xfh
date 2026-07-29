"""XPK FBR2 decompression.

Derived from Ancient's FBR2Decompressor, Copyright (c) 2017-2025
Teemu Suutari, under the BSD 2-Clause License.
"""

from xfh.codecs import register
from xfh.codecs._streams import ByteInput
from xfh.errors import CorruptDataError

_WIDTHS = {33: 4, 67: 2, 100: 1}


@register("FBR2")
def decompress_fbr2(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode CyberYAFA FBR2 byte runs."""

    del previous
    source = ByteInput(payload)
    mode = source.byte()
    try:
        width = _WIDTHS[mode]
    except KeyError as error:
        raise CorruptDataError(f"invalid FBR2 mode {mode}") from error
    sign = 1 << (width * 8 - 1)
    modulus = 1 << (width * 8)
    output = bytearray()
    while len(output) < output_size:
        encoded = source.word(width)
        literal = bool(encoded & sign)
        count = (modulus - encoded if literal else encoded) + 1
        # Several original FBR2 packers round their final literal run beyond
        # the declared raw size. The Amiga decoder stops at the output buffer;
        # clamp equivalently without permitting an out-of-bounds write.
        count = min(count, output_size - len(output))
        if literal:
            output.extend(source.byte() for _ in range(count))
        else:
            output.extend(bytes((source.byte(),)) * count)
    return bytes(output)

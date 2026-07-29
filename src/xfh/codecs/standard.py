"""XPK wrappers around standardized compression streams."""

import bz2
import zlib

from xfh.codecs import register
from xfh.errors import CorruptDataError


def _bzp2(payload: bytes, limit: int) -> bytes:
    decoder = bz2.BZ2Decompressor()
    output = decoder.decompress(payload, max_length=limit + 1)
    if not decoder.eof:
        if len(output) > limit or decoder.needs_input:
            raise ValueError("incomplete or oversized bzip2 stream")
        output += decoder.decompress(b"", max_length=limit + 1 - len(output))
    if decoder.unused_data:
        raise ValueError("trailing bzip2 data")
    return output


def _gzip(payload: bytes, limit: int) -> bytes:
    decoder = zlib.decompressobj()
    output = decoder.decompress(payload, limit + 1)
    if decoder.unconsumed_tail or len(output) > limit:
        raise ValueError("oversized zlib stream")
    output += decoder.flush(limit + 1 - len(output))
    if not decoder.eof or decoder.unused_data or len(output) > limit:
        raise ValueError("incomplete or trailing zlib stream")
    return output


def _checked(codec: str, payload: bytes, output_size: int, function) -> bytes:
    try:
        output = function(payload, output_size)
    except (OSError, EOFError, ValueError, zlib.error) as error:
        raise CorruptDataError(f"invalid {codec} stream") from error
    if len(output) != output_size:
        raise CorruptDataError(f"{codec} stream has the wrong output size")
    return output


@register("BZP2")
def decompress_bzp2(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode an XPK-wrapped bzip2 stream."""

    del previous
    return _checked("BZP2", payload, output_size, _bzp2)


@register("GZIP")
def decompress_gzip(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode GZIP's zlib-format payload."""

    del previous
    return _checked("GZIP", payload, output_size, _gzip)

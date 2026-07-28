"""The XPK NONE storage codec."""

from xfh.codecs import register
from xfh.errors import CorruptDataError


@register("NONE")
def decompress_none(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Return a raw NONE chunk after validating its declared size."""

    del previous
    if len(payload) != output_size:
        raise CorruptDataError("NONE chunk size does not match its output size")
    return payload

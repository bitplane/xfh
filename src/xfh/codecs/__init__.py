"""XPK codec registry."""

from collections.abc import Callable

from xfh.errors import UnsupportedCodecError

Decoder = Callable[[bytes, int, bytes], bytes]
_DECODERS: dict[str, Decoder] = {}


def register(codec: str) -> Callable[[Decoder], Decoder]:
    """Register a decoder by its four-character XPK identifier."""

    def decorator(function: Decoder) -> Decoder:
        _DECODERS[codec] = function
        return function

    return decorator


def decode(codec: str, payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode one packed XPK chunk."""

    try:
        decoder = _DECODERS[codec]
    except KeyError as error:
        raise UnsupportedCodecError(codec) from error
    return decoder(payload, output_size, previous)


def supported_codecs() -> frozenset[str]:
    """Return codec identifiers implemented by this build."""

    return frozenset(_DECODERS)


from xfh.codecs import fast as _fast  # noqa: E402,F401
from xfh.codecs import huff as _huff  # noqa: E402,F401
from xfh.codecs import none as _none  # noqa: E402,F401
from xfh.codecs import nuke as _nuke  # noqa: E402,F401
from xfh.codecs import rake as _rake  # noqa: E402,F401
from xfh.codecs import shri as _shri  # noqa: E402,F401

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


from xfh.codecs import acca as _acca  # noqa: E402,F401
from xfh.codecs import artm as _artm  # noqa: E402,F401
from xfh.codecs import blzw as _blzw  # noqa: E402,F401
from xfh.codecs import dlta as _dlta  # noqa: E402,F401
from xfh.codecs import fast as _fast  # noqa: E402,F401
from xfh.codecs import fbr2 as _fbr2  # noqa: E402,F401
from xfh.codecs import hfmn as _hfmn  # noqa: E402,F401
from xfh.codecs import huff as _huff  # noqa: E402,F401
from xfh.codecs import ilzr as _ilzr  # noqa: E402,F401
from xfh.codecs import lhlb as _lhlb  # noqa: E402,F401
from xfh.codecs import lz_small as _lz_small  # noqa: E402,F401
from xfh.codecs import lzw_variants as _lzw_variants  # noqa: E402,F401
from xfh.codecs import mash as _mash  # noqa: E402,F401
from xfh.codecs import none as _none  # noqa: E402,F401
from xfh.codecs import nuke as _nuke  # noqa: E402,F401
from xfh.codecs import rake as _rake  # noqa: E402,F401
from xfh.codecs import rdcn as _rdcn  # noqa: E402,F401
from xfh.codecs import rle as _rle  # noqa: E402,F401
from xfh.codecs import shri as _shri  # noqa: E402,F401
from xfh.codecs import smpl as _smpl  # noqa: E402,F401
from xfh.codecs import sqsh as _sqsh  # noqa: E402,F401
from xfh.codecs import wrappers as _wrappers  # noqa: E402,F401
from xfh.codecs import zeno as _zeno  # noqa: E402,F401

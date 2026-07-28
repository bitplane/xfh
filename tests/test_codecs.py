import pytest

from xfh.codecs import decode, supported_codecs
from xfh.errors import CorruptDataError


def test_fast_literal_stream() -> None:
    # FAST takes literals from the front and control bits from a word at the back.
    assert decode("FAST", b"hello\0\0", 5) == b"hello"


def test_huff_single_symbol_stream() -> None:
    table = bytearray()
    for symbol in range(256):
        if symbol == ord("A"):
            table += b"\0\0"  # one-bit code 0
        else:
            table += b"\xff"  # wrapped length zero: symbol absent
    payload = b"\0\0\xab\xad\xca\xfe" + table + b"\0"
    assert decode("HUFF", payload, 6) == b"A" * 6


def test_initial_codec_set() -> None:
    assert {"NONE", "NUKE", "FAST", "RAKE", "HUFF", "SHRI"} <= supported_codecs()


@pytest.mark.parametrize(
    ("codec", "payload"),
    [
        ("RAKE", b""),
        ("RAKE", b"\0" * 8),
        ("SHRI", b""),
        ("SHRI", b"\2\0\0\1" + b"\0" * 4),
        ("SHRI", b"\1\0\0\2" + b"\0" * 4),
    ],
)
def test_new_codecs_reject_malformed_streams(codec: str, payload: bytes) -> None:
    with pytest.raises(CorruptDataError):
        decode(codec, payload, 1)

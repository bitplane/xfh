from pathlib import Path

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
    assert {
        "NONE",
        "NUKE",
        "FAST",
        "RAKE",
        "HUFF",
        "SHRI",
        "CBR0",
        "RLEN",
        "FRLE",
        "RDCN",
        "BLZW",
        "DUKE",
        "DLTA",
        "SMPL",
        "HFMN",
        "MASH",
        "SQSH",
    } <= supported_codecs()


@pytest.mark.parametrize(
    ("codec", "payload"),
    [
        ("RAKE", b""),
        ("RAKE", b"\0" * 8),
        ("SHRI", b""),
        ("SHRI", b"\2\0\0\1" + b"\0" * 4),
        ("SHRI", b"\1\0\0\2" + b"\0" * 4),
        ("CBR0", b""),
        ("RLEN", b"\0"),
        ("FRLE", b""),
        ("RDCN", b""),
        ("BLZW", b""),
        ("DUKE", b""),
        ("DLTA", b""),
        ("SMPL", b""),
        ("HFMN", b""),
        ("MASH", b""),
        ("SQSH", b""),
    ],
)
def test_new_codecs_reject_malformed_streams(codec: str, payload: bytes) -> None:
    with pytest.raises(CorruptDataError):
        decode(codec, payload, 1)


def test_duke_applies_delta_after_nuke() -> None:
    root = Path(__file__).parent / "fixtures" / "oracle"
    packed = bytes.fromhex((root / "nuke050-repeat1k.hex").read_text())
    payload = packed[44:100]
    nuke = decode("NUKE", payload, 1024)
    expected = bytearray()
    accumulator = 0
    for value in nuke:
        accumulator = (accumulator + value) & 0xFF
        expected.append(accumulator)
    assert decode("DUKE", payload, 1024) == expected


def test_smpl_single_symbol_delta_stream() -> None:
    # Version 1, symbol zero has one-bit code 0; every other symbol is absent.
    bit_string = "0001" + "0" + "0000" * 255
    bit_string += "0" * (-len(bit_string) % 8)
    payload = b"\0\1" + int(bit_string, 2).to_bytes(len(bit_string) // 8, "big")
    assert decode("SMPL", payload, 4) == bytes(4)


def test_blzw_width_change_and_dictionary_reset() -> None:
    fields = [
        (65, 9),
        (66, 9),
        (258, 9),
        (67, 10),
        (257, 10),
        (68, 9),
        (69, 9),
    ]
    bit_string = "".join(f"{value:0{width}b}" for value, width in fields)
    bit_string += "0" * (-len(bit_string) % 8)
    payload = b"\0\x0a\0\x10" + int(bit_string, 2).to_bytes(len(bit_string) // 8, "big")
    assert decode("BLZW", payload, 5) == b"ABCDE"

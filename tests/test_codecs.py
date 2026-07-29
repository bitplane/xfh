from pathlib import Path

import pytest

from xfh.codecs import decode, supported_codecs
from xfh.codecs._prefix import PrefixDecoder, variable_length
from xfh.codecs._streams import BitReader, ByteInput
from xfh.container import parse
from xfh.errors import CorruptDataError
from xfh.limits import DEFAULT_LIMITS


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
        "CBR1",
        "FRHT",
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


def test_compatibility_aliases_use_the_historical_stream_format() -> None:
    assert decode("CBR1", b"\x02ABC", 3) == decode("CBR0", b"\x02ABC", 3)
    root = Path(__file__).parent / "fixtures" / "oracle"
    packed = bytes.fromhex((root / "rake100-repeat1k.hex").read_text())
    payload = parse(packed, DEFAULT_LIMITS).chunks[0].payload
    assert decode("FRHT", payload, 1024) == decode("RAKE", payload, 1024)


def test_prefix_helpers_reject_invalid_tables_and_classes() -> None:
    with pytest.raises(CorruptDataError, match="duplicate"):
        PrefixDecoder(((1, 0, 1), (1, 0, 2)))
    bits = BitReader(ByteInput(b"\0").word, 8)
    with pytest.raises(CorruptDataError, match="class"):
        variable_length(bits, (1,), 1)


@pytest.mark.parametrize(
    ("codec", "payload", "output_size", "message"),
    [
        ("SMPL", b"\0\1", 1, "truncated"),
        ("HFMN", b"\0\1\0\0", 1, "alignment"),
        ("MASH", b"\xff\xff\xff", 1, "literal length"),
        ("SQSH", b"\0\2A", 1, "output size"),
        ("SQSH", b"\0\2A\0", 2, "truncated"),
    ],
)
def test_new_codec_structural_failures(
    codec: str, payload: bytes, output_size: int, message: str
) -> None:
    with pytest.raises(CorruptDataError, match=message):
        decode(codec, payload, output_size)


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

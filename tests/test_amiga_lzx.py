from pathlib import Path
from zlib import crc32

import pytest

from xfh.codecs import decode
from xfh.codecs.amiga_lzx import decompress_archive
from xfh.errors import CorruptDataError

_ROOT = Path(__file__).parent / "fixtures"


def _fixture(name: str) -> bytes:
    return bytes.fromhex((_ROOT / "amiga_lzx" / name).read_text())


def _stored_archive(data: bytes) -> bytes:
    filename = b"x"
    fixed = bytearray(31)
    fixed[2:6] = len(data).to_bytes(4, "little")
    fixed[6:10] = len(data).to_bytes(4, "little")
    fixed[11] = 0
    fixed[22:26] = crc32(data).to_bytes(4, "little")
    fixed[30] = len(filename)
    fixed[26:30] = crc32(fixed + filename).to_bytes(4, "little")
    return b"LZX\0" + bytes(6) + fixed + filename + data


def _refresh_header_crc(archive: bytearray) -> None:
    filename_size = archive[40]
    comment_size = archive[24]
    header_end = 41 + filename_size + comment_size
    archive[36:40] = bytes(4)
    archive[36:40] = crc32(archive[10:header_end]).to_bytes(4, "little")


@pytest.mark.parametrize(
    ("archive", "source"),
    [
        ("quick-text.hex", "oracle/text.hex"),
        ("normal-repeat.hex", "oracle/repeat1k.hex"),
        ("max-bytes.hex", "oracle/bytes.hex"),
    ],
)
def test_rust_generated_archives_cross_check(archive: str, source: str) -> None:
    expected = (_ROOT / source).read_bytes()
    assert decompress_archive(_fixture(archive), len(expected)) == expected


def test_elzx_decodes_embedded_stored_archive() -> None:
    expected = bytes(range(256))
    assert decode("ELZX", _stored_archive(expected), len(expected)) == expected


def test_slzx_applies_cumulative_byte_delta() -> None:
    expected = (b"Amiga LZX recovery!" * 10)[:157]
    previous = 0
    encoded = bytearray()
    for value in expected:
        encoded.append((value - previous) & 0xFF)
        previous = value
    assert decode("SLZX", _stored_archive(encoded), len(expected)) == expected


def test_amiga_lzx_rejects_header_and_data_crc_damage() -> None:
    archive = bytearray(_stored_archive(b"recovery data"))
    archive[10] ^= 1
    with pytest.raises(CorruptDataError, match="header checksum"):
        decompress_archive(bytes(archive), 13)

    archive = bytearray(_stored_archive(b"recovery data"))
    archive[-1] ^= 1
    with pytest.raises(CorruptDataError, match="data checksum"):
        decompress_archive(bytes(archive), 13)


def test_amiga_lzx_rejects_every_fixture_truncation() -> None:
    archive = _fixture("normal-repeat.hex")
    expected_size = len((_ROOT / "oracle/repeat1k.hex").read_bytes())
    for length in range(len(archive)):
        with pytest.raises(CorruptDataError):
            decompress_archive(archive[:length], expected_size)


@pytest.mark.parametrize(
    ("offset", "value", "message"),
    [
        (21, 9, "pack mode"),
        (22, 1, "merged"),
    ],
)
def test_amiga_lzx_rejects_unsupported_archive_modes(offset: int, value: int, message: str) -> None:
    archive = bytearray(_stored_archive(b"x"))
    archive[offset] = value
    _refresh_header_crc(archive)
    with pytest.raises(CorruptDataError, match=message):
        decompress_archive(bytes(archive), 1)

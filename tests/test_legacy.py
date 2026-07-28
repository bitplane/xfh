from pathlib import Path

import pytest

import xfh
from xfh.errors import CorruptDataError
from xfh.models import FileFormat

SAMPLES = Path(__file__).parents[1] / "samples"
FIXTURES = Path(__file__).parent / "fixtures" / "diskexpander"


def _hex_fixture(name: str) -> bytes:
    return bytes.fromhex((FIXTURES / name).read_text())


def test_diskexpander_nuke_known_pair_is_recovered_exactly() -> None:
    packed = _hex_fixture("cancel-packed.hex")
    expected = _hex_fixture("cancel-plain.hex")

    info = xfh.inspect(packed)
    assert info.format is FileFormat.LEGACY
    assert info.codec == "NUKE"
    assert info.packed_size == 130
    assert info.unpacked_size == 204
    assert len(info.chunks) == 1
    assert info.chunks[0].offset == 24
    assert info.chunks[0].header_size == 2
    assert info.chunks[0].packed_size == 96
    assert xfh.decompress(packed) == expected


@pytest.mark.parametrize("name", ["matt1.info", "wombat", "wombat1.pic", "wombat2"])
def test_private_provenance_samples_are_detected_and_bounded(name: str) -> None:
    path = SAMPLES / name
    if not path.exists():
        pytest.skip("private recovery corpus is not present")
    data = path.read_bytes()
    info = xfh.inspect(data)
    assert info.format is FileFormat.LEGACY
    assert info.codec == "NUKE"
    assert info.packed_size == len(data)
    assert info.unpacked_size > 0


def test_legacy_length_tampering_is_rejected() -> None:
    path = SAMPLES / "matt1.info"
    if not path.exists():
        pytest.skip("private recovery corpus is not present")
    data = bytearray(path.read_bytes())
    data[15] ^= 1
    with pytest.raises(CorruptDataError, match="length"):
        xfh.inspect(data)

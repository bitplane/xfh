from pathlib import Path

import pytest

import xfh
from tests.helpers import xpkf
from xfh.errors import CorruptDataError, InvalidFormatError, ResourceLimitError
from xfh.limits import Limits
from xfh.models import FileFormat


def test_none_round_trip() -> None:
    expected = b"FORM" + bytes(range(32))
    packed = xpkf("NONE", [(0, expected, len(expected))], expected)
    assert xfh.detect(packed) is FileFormat.XPKF
    assert xfh.inspect(packed).codec == "NONE"
    assert xfh.decompress(packed) == expected


def test_atomic_file_output(tmp_path: Path) -> None:
    packed = xpkf("NONE", [(0, b"recovered", 9)], b"recovered")
    source, target = tmp_path / "in.xpk", tmp_path / "out"
    source.write_bytes(packed)
    xfh.decompress_file(source, target)
    assert target.read_bytes() == b"recovered"
    with pytest.raises(FileExistsError):
        xfh.decompress_file(source, target)


@pytest.mark.parametrize("cut", [0, 1, 8, 35, 36, 39])
def test_truncation_is_rejected(cut: int) -> None:
    packed = xpkf("NONE", [(0, b"abcd", 4)], b"abcd")
    with pytest.raises((InvalidFormatError, CorruptDataError)):
        xfh.decompress(packed[:cut])


def test_checksums_and_trailing_data_are_rejected() -> None:
    packed = bytearray(xpkf("NONE", [(0, b"abcd", 4)], b"abcd"))
    packed[46] ^= 1
    with pytest.raises(CorruptDataError, match="checksum"):
        xfh.decompress(packed)


def test_output_limit_is_checked_before_decode() -> None:
    packed = xpkf("NONE", [(0, b"abcd", 4)], b"abcd")
    with pytest.raises(ResourceLimitError):
        xfh.decompress(packed, limits=Limits(max_output_size=3))


def test_salvage_never_hides_parse_failure() -> None:
    result = xfh.salvage(b"not xpk")
    assert result.data == b""
    assert not result.complete
    assert result.issues


@pytest.mark.parametrize("dangling", [False, True])
def test_atomic_output_preserves_existing_entries(tmp_path, dangling):
    from xfh.api import _write_atomic

    target = tmp_path / "out"
    if dangling:
        target.symlink_to(tmp_path / "missing")
    else:
        target.write_bytes(b"original")
    with pytest.raises(FileExistsError):
        _write_atomic(target, b"new", overwrite=False)
    assert target.is_symlink() if dangling else target.read_bytes() == b"original"


def test_atomic_output_preserves_concurrent_writer(tmp_path, monkeypatch):
    import os

    from xfh.api import _write_atomic

    target = tmp_path / "out"
    real_link = os.link

    def publish(source, destination):
        target.write_bytes(b"concurrent")
        return real_link(source, destination)

    monkeypatch.setattr(os, "link", publish)
    with pytest.raises(FileExistsError):
        _write_atomic(target, b"new", overwrite=False)
    assert target.read_bytes() == b"concurrent"
    assert list(tmp_path.iterdir()) == [target]


def test_atomic_output_explicit_overwrite(tmp_path):
    from xfh.api import _write_atomic

    target = tmp_path / "out"
    target.write_bytes(b"old")
    _write_atomic(target, b"new", overwrite=True)
    assert target.read_bytes() == b"new"


def test_salvage_rejects_initial_plaintext_mismatch():
    packed = xpkf("NONE", [(0, b"bad!", 4)], b"good")
    with pytest.raises(CorruptDataError, match="initial bytes"):
        xfh.decompress(packed)
    result = xfh.salvage(packed)
    assert result.data == b"bad!"
    assert not result.complete
    assert result.issues[0].offset == 16
    assert "initial bytes" in result.issues[0].message

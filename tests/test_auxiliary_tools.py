"""Exercise standalone recovery helpers with small synthetic inputs."""

import shutil
import struct
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]


@pytest.fixture
def node():
    executable = shutil.which("node")
    if executable is None:
        pytest.skip("Node.js is unavailable")
    help_text = subprocess.run([executable, "--help"], capture_output=True, text=True, check=True)
    if "--experimental-strip-types" not in help_text.stdout:
        pytest.skip("Node.js does not support TypeScript stripping")
    return [executable, "--experimental-strip-types"]


@pytest.mark.parametrize("damage", [None, "missing", "cycle", "count", "oversized"])
def test_amigaget_rejects_incomplete_files(node, tmp_path, damage):
    image = bytearray(512 * 10)

    def field(block, offset, value):
        struct.pack_into(">I", image, block * 512 + offset, value)

    image[:4] = b"DOS\1"
    field(5, 24, 2)
    field(2, 508, 0xFFFFFFFD)
    field(2, 324, 5)
    field(2, 8, 1)
    field(2, 308, 3)
    image[2 * 512 + 432 : 2 * 512 + 436] = b"\3foo"
    image[3 * 512 : 3 * 512 + 5] = b"hello"
    if damage == "missing":
        field(2, 308, 0)
    elif damage == "cycle":
        field(2, 324, 1024)
        field(2, 504, 2)
    elif damage == "count":
        field(2, 8, 73)
    elif damage == "oversized":
        field(2, 324, 0xFFFFFFFF)
    source, output = tmp_path / "disk", tmp_path / "out"
    source.write_bytes(image)
    result = subprocess.run(
        [*node, str(ROOT / "tools/amigaget.ts"), str(source), "foo", str(output)],
        capture_output=True,
        timeout=10,
    )
    if damage is None:
        assert result.returncode == 0, result.stderr
        assert output.read_bytes() == b"hello"
    else:
        assert result.returncode != 0
        assert not output.exists()


@pytest.mark.parametrize("status", [0, 1, 5])
def test_coverage_script_preserves_pytest_failure(tmp_path, status):
    activation = tmp_path / ".venv/bin"
    activation.mkdir(parents=True)
    (activation / "activate").write_text(f'pytest() {{ echo "test output"; return {status}; }}\n')
    result = subprocess.run(
        ["bash", str(ROOT / "scripts/coverage.sh"), "xfh"],
        cwd=tmp_path,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == status
    assert "test output" in (tmp_path / "htmlcov/coverage_report.txt").read_text()


@pytest.mark.parametrize("truncated", [False, True])
def test_abk2png_is_portable_and_writes_valid_png(node, tmp_path, truncated):
    import zlib

    bank = b"AmSp" + struct.pack(">6H", 1, 1, 1, 1, 0, 0) + b"\x80\0"
    bank += struct.pack(">32H", 0, 0xF00, *([0] * 30))
    source = tmp_path / "sprites.abk"
    source.write_bytes(bank[:-1] if truncated else bank)
    prefix = tmp_path / "sprite"
    result = subprocess.run(
        [*node, str(ROOT / "tools/abk2png.ts"), str(source), str(prefix)],
        cwd=tmp_path,
        capture_output=True,
        timeout=10,
    )
    target = tmp_path / "sprite0.png"
    if truncated:
        assert result.returncode != 0
        assert not target.exists()
        return
    assert result.returncode == 0, result.stderr
    data = target.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    offset = 8
    chunks = {}
    while offset < len(data):
        length = int.from_bytes(data[offset : offset + 4], "big")
        kind = data[offset + 4 : offset + 8]
        payload = data[offset + 8 : offset + 8 + length]
        checksum = int.from_bytes(data[offset + 8 + length : offset + 12 + length], "big")
        assert zlib.crc32(kind + payload) == checksum
        chunks[kind] = payload
        offset += length + 12
    assert struct.unpack(">II", chunks[b"IHDR"][:8]) == (16, 1)
    assert zlib.decompress(chunks[b"IDAT"]) == b"\0\xff\0\0" + bytes(45)
    assert chunks[b"IEND"] == b""

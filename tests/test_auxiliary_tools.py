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

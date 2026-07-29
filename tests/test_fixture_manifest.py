import hashlib
import json
from pathlib import Path

import pytest

import xfh
from tools.verify_fixture_manifest import verify_manifest


def _artifact(root: Path, name: str, content: bytes) -> dict[str, object]:
    (root / name).write_bytes(content)
    return {
        "path": name,
        "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def _manifest(tmp_path: Path) -> Path:
    fixture = {
        "id": "none-0-text",
        "codec": "NONE",
        "mode": 0,
        "status": "success",
        "input": _artifact(tmp_path, "input.bin", b"hello"),
        "packed": _artifact(tmp_path, "packed.bin", b"packed"),
        "unpacked": _artifact(tmp_path, "unpacked.bin", b"hello"),
    }
    path = tmp_path / "manifest.json"
    path.write_text(
        json.dumps({"schema_version": 1, "redistributable": True, "fixtures": [fixture]})
    )
    return path


def test_valid_manifest(tmp_path: Path) -> None:
    verify_manifest(_manifest(tmp_path))


@pytest.mark.parametrize("field", ["size", "sha256"])
def test_artifact_tampering_is_rejected(tmp_path: Path, field: str) -> None:
    path = _manifest(tmp_path)
    manifest = json.loads(path.read_text())
    manifest["fixtures"][0]["packed"][field] = 99 if field == "size" else "0" * 64
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="mismatch"):
        verify_manifest(path)


def test_parent_path_is_rejected(tmp_path: Path) -> None:
    path = _manifest(tmp_path)
    manifest = json.loads(path.read_text())
    manifest["fixtures"][0]["packed"]["path"] = "../packed.bin"
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="unsafe"):
        verify_manifest(path)


def test_unknown_evidence_label_is_rejected(tmp_path: Path) -> None:
    path = _manifest(tmp_path)
    manifest = json.loads(path.read_text())
    manifest["fixtures"][0]["evidence"] = ["made-up"]
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="evidence"):
        verify_manifest(path)


def test_hex_encoded_artifact_is_hashed_after_decoding(tmp_path: Path) -> None:
    path = _manifest(tmp_path)
    manifest = json.loads(path.read_text())
    (tmp_path / "packed.hex").write_text("7061636b6564\n")
    manifest["fixtures"][0]["packed"] = {
        "path": "packed.hex",
        "encoding": "hex",
        "size": 6,
        "sha256": hashlib.sha256(b"packed").hexdigest(),
    }
    path.write_text(json.dumps(manifest))
    verify_manifest(path)


def test_public_oracle_fixtures() -> None:
    root = Path(__file__).parent / "fixtures" / "oracle"
    manifest = json.loads((root / "manifest.json").read_text())
    verify_manifest(root / "manifest.json")
    for fixture in manifest["fixtures"]:
        packed = bytes.fromhex((root / fixture["packed"]["path"]).read_text())
        expected = bytes.fromhex((root / fixture["unpacked"]["path"]).read_text())
        assert xfh.decompress(packed) == expected


def test_manifest_covers_every_compact_public_xpk_fixture() -> None:
    root = Path(__file__).parent / "fixtures" / "oracle"
    manifest = json.loads((root / "manifest.json").read_text())
    listed = {fixture["packed"]["path"] for fixture in manifest["fixtures"]}
    containers = {
        path.name
        for path in root.glob("*.hex")
        if bytes.fromhex(path.read_text()).startswith(b"XPKF")
        and path.name != "shri100-repeat64k.hex"
    }
    assert listed == containers


def test_shri_continuation_chunk_oracle() -> None:
    root = Path(__file__).parent / "fixtures" / "oracle"
    packed = bytes.fromhex((root / "shri100-repeat64k.hex").read_text())
    assert xfh.decompress(packed) == bytes(range(64)) * 1024


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        ("cbr0050-zero256.hex", bytes(256)),
        ("rlen050-text.hex", b"XFH recovery oracle\r\n" * 4),
        ("frle016-zero256.hex", bytes(256)),
        ("rdcn100-repeat1k.hex", (b"Amiga XPK!" * 128)[:1024]),
        ("blzw060-zero256.hex", bytes(256)),
        ("duke050-bytes.hex", bytes(range(256))),
        ("dlta100-text.hex", b"XFH recovery oracle\r\n" * 4),
        ("hfmn000-text.hex", b"XFH recovery oracle\r\n" * 4),
        ("mash100-repeat1k.hex", (b"Amiga XPK!" * 128)[:1024]),
        ("sqsh100-repeat1k.hex", (b"Amiga XPK!" * 128)[:1024]),
    ],
)
def test_additional_codec_oracles(fixture: str, expected: bytes) -> None:
    root = Path(__file__).parent / "fixtures" / "oracle"
    packed = bytes.fromhex((root / fixture).read_text())
    assert xfh.decompress(packed) == expected

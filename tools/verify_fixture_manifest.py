"""Validate public original-code fixture manifests and their artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath

SCHEMA_VERSION = 1
MAX_PUBLIC_ARTIFACT_SIZE = 64 * 1024
PROHIBITED_SUFFIXES = {".adf", ".hdf", ".img", ".library", ".rom"}
ARTIFACT_FIELDS = ("input", "packed", "unpacked")
PUBLIC_CODECS = {
    "BLFH",
    "NONE",
    "NUKE",
    "DUKE",
    "ELZX",
    "FAST",
    "RAKE",
    "HUFF",
    "SHRI",
    "CBR0",
    "RLEN",
    "FRLE",
    "RDCN",
    "BLZW",
    "DLTA",
    "HFMN",
    "MASH",
    "SQSH",
    "ACCA",
    "FBR2",
    "ILZR",
    "LZW2",
    "LZW3",
    "LZW4",
    "LZW5",
    "ZENO",
    "LZBS",
    "LZCB",
    "SLZ3",
    "SLZX",
    "SDHC",
    "LHLB",
    "BZP2",
    "GZIP",
    "IMPL",
    "PWPK",
    "PPMQ",
    "SASC",
    "SHSC",
    "CRM2",
    "CRMS",
}
EVIDENCE = {
    "original-amiga-roundtrip",
    "xfh-decoded",
    "ancient-cross-checked",
    "independent-cross-checked",
    "source-derived",
    "synthetic-malformed",
}


def _artifact_path(root: Path, value: str) -> Path:
    relative = PurePosixPath(value)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise ValueError(f"unsafe artifact path: {value!r}")
    if relative.suffix.lower() in PROHIBITED_SUFFIXES:
        raise ValueError(f"prohibited public artifact type: {value!r}")
    path = root.joinpath(*relative.parts)
    if not path.is_file():
        raise ValueError(f"missing artifact: {value!r}")
    return path


def _artifact_bytes(path: Path, encoding: str) -> bytes:
    content = path.read_bytes()
    if encoding == "raw":
        return content
    if encoding == "hex":
        try:
            return bytes.fromhex(content.decode("ascii"))
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError(f"{path.name}: invalid hexadecimal fixture") from error
    raise ValueError(f"{path.name}: unsupported artifact encoding {encoding!r}")


def _verify_artifact(root: Path, artifact: object) -> None:
    if not isinstance(artifact, dict):
        raise ValueError("artifact entry must be an object")
    required = {"path", "size", "sha256"}
    if not required <= set(artifact) or set(artifact) - required - {"encoding"}:
        raise ValueError("artifact entry has missing or unknown fields")
    path = _artifact_path(root, artifact["path"])
    content = _artifact_bytes(path, artifact.get("encoding", "raw"))
    size = len(content)
    if size != artifact["size"]:
        raise ValueError(f"{artifact['path']}: size mismatch")
    if size > MAX_PUBLIC_ARTIFACT_SIZE:
        raise ValueError(f"{artifact['path']}: public artifact exceeds 64 KiB")
    digest = hashlib.sha256(content).hexdigest()
    if digest != artifact["sha256"]:
        raise ValueError(f"{artifact['path']}: SHA-256 mismatch")


def verify_manifest(path: Path) -> None:
    manifest = json.loads(path.read_text())
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported fixture manifest schema")
    if manifest.get("redistributable") is not True:
        raise ValueError("public fixture manifest must declare redistributable=true")
    fixtures = manifest.get("fixtures")
    if not isinstance(fixtures, list):
        raise ValueError("fixtures must be an array")
    identifiers: set[str] = set()
    for fixture in fixtures:
        if not isinstance(fixture, dict):
            raise ValueError("fixture entry must be an object")
        identifier = fixture.get("id")
        if not isinstance(identifier, str) or not identifier:
            raise ValueError("fixture id must be a non-empty string")
        if identifier in identifiers:
            raise ValueError(f"duplicate fixture id: {identifier}")
        identifiers.add(identifier)
        if fixture.get("codec") not in PUBLIC_CODECS:
            raise ValueError(f"{identifier}: codec is outside the public oracle set")
        if not isinstance(fixture.get("mode"), int):
            raise ValueError(f"{identifier}: mode must be an integer")
        if fixture.get("status") != "success":
            raise ValueError(f"{identifier}: public fixtures must have status=success")
        evidence = fixture.get("evidence")
        if evidence is not None and (
            not isinstance(evidence, list)
            or not evidence
            or any(item not in EVIDENCE for item in evidence)
        ):
            raise ValueError(f"{identifier}: invalid evidence labels")
        for field in ARTIFACT_FIELDS:
            _verify_artifact(path.parent, fixture.get(field))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    arguments = parser.parse_args()
    try:
        verify_manifest(arguments.manifest)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

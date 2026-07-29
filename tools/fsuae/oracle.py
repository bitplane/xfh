"""Prepare and validate the isolated FS-UAE XPK oracle workspace."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import subprocess
from pathlib import Path

SCHEMA_VERSION = 1
SEED = 0x584648
MODE_RANGES = {
    "NONE": ((0, 100),),
    "NUKE": ((0, 100),),
    "FAST": ((0, 79), (80, 100)),
    "RAKE": ((0, 25), (26, 50), (51, 75), (76, 100)),
    "HUFF": ((0, 100),),
    "SHRI": ((0, 14), (15, 28), (29, 42), (43, 56), (57, 70), (71, 84), (85, 100)),
    "CBR0": ((0, 100),),
    "RLEN": ((0, 100),),
    "FRLE": ((0, 100),),
    "RDCN": ((0, 100),),
    "BLZW": ((0, 14), (15, 28), (29, 42), (43, 57), (58, 71), (72, 85), (86, 100)),
    "DUKE": ((0, 100),),
    "DLTA": ((0, 100),),
    "SMPL": ((0, 100),),
    "HFMN": ((0, 100),),
    "MASH": ((0, 100),),
    "SQSH": ((0, 100),),
    "ACCA": ((0, 100),),
    "FBR2": ((0, 0), (1, 33), (34, 67), (68, 100)),
    "ILZR": ((0, 100),),
    "LZW2": ((0, 2), (3, 8), (9, 18), (19, 33), (34, 51), (52, 73), (74, 100)),
    "LZW3": ((0, 2), (3, 8), (9, 18), (19, 33), (34, 51), (52, 73), (74, 100)),
    "LZW4": ((0, 2), (3, 8), (9, 18), (19, 33), (34, 51), (52, 73), (74, 100)),
    "LZW5": ((0, 2), (3, 8), (9, 18), (19, 33), (34, 51), (52, 73), (74, 100)),
    "ZENO": ((0, 33), (34, 66), (67, 100)),
    "LZBS": (
        (0, 0),
        (1, 10),
        (11, 20),
        (21, 30),
        (31, 40),
        (41, 50),
        (51, 60),
        (61, 70),
        (71, 80),
        (81, 90),
        (91, 100),
    ),
    "SLZ3": ((0, 100),),
    "LHLB": ((0, 100),),
    "SDHC": (
        (0, 7),
        (8, 15),
        (16, 23),
        (24, 31),
        (32, 39),
        (40, 47),
        (48, 55),
        (56, 63),
        (64, 71),
        (72, 79),
        (80, 87),
        (88, 100),
    ),
    "CYB2": ((0, 100),),
    "CYB1": ((0, 100),),
    "DHUF": ((0, 100),),
    "DMCB": ((0, 100),),
    "LZCB": ((0, 10), (11, 90), (91, 100)),
    "PPMQ": ((0, 100),),
    "SASC": ((0, 33), (34, 66), (67, 100)),
    "SHSC": ((0, 33), (34, 66), (67, 100)),
    "BZP2": (
        (0, 19),
        (20, 29),
        (30, 39),
        (40, 49),
        (50, 59),
        (60, 69),
        (70, 79),
        (80, 89),
        (90, 100),
    ),
    "GZIP": (
        (0, 9),
        (10, 19),
        (20, 29),
        (30, 39),
        (40, 49),
        (50, 59),
        (60, 69),
        (70, 79),
        (80, 89),
        (90, 100),
    ),
    "IMPL": ((0, 10), (11, 30), (31, 50), (51, 75), (76, 98), (99, 100)),
}
DEFAULT_MODES = {
    "NONE": 50,
    "NUKE": 50,
    "FAST": 50,
    "RAKE": 100,
    "HUFF": 50,
    "SHRI": 100,
    "CBR0": 50,
    "RLEN": 50,
    "FRLE": 16,
    "RDCN": 100,
    "BLZW": 60,
    "DUKE": 50,
    "DLTA": 100,
    "SMPL": 50,
    "HFMN": 0,
    "MASH": 100,
    "SQSH": 100,
    "ACCA": 100,
    "FBR2": 100,
    "ILZR": 50,
    "LZW2": 100,
    "LZW3": 100,
    "LZW4": 100,
    "LZW5": 100,
    "ZENO": 50,
    "LZBS": 100,
    "SLZ3": 100,
    "LHLB": 50,
    "SDHC": 50,
    "CYB2": 50,
    "CYB1": 100,
    "DHUF": 50,
    "DMCB": 100,
    "LZCB": 50,
    "PPMQ": 50,
    "SASC": 0,
    "SHSC": 0,
    "BZP2": 40,
    "GZIP": 65,
    "IMPL": 100,
}
EXHAUSTIVE_MODE_CODECS = {"NONE", "NUKE", "FAST", "RAKE", "HUFF", "SHRI"}
UNSAFE_CASES = {
    ("DLTA", "one"): "original packer hangs on a one-byte input",
    ("HFMN", "bytes"): "original packer hangs on the ascending-byte vector",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _vectors() -> dict[str, bytes]:
    random_source = random.Random(SEED)
    return {
        "empty": b"",
        "one": b"X",
        "two": b"XY",
        "three": b"XYZ",
        "text": b"XFH recovery oracle\r\n" * 4,
        "bytes": bytes(range(256)),
        "zero255": bytes(255),
        "zero256": bytes(256),
        "zero257": bytes(257),
        "repeat1k": (b"Amiga XPK!" * 128)[:1024],
        "random1k": random_source.randbytes(1024),
        "repeat64k": (bytes(range(64)) * 1024)[:65536],
        "random64k": random_source.randbytes(65536),
    }


def prepare(workspace: Path, *, force: bool) -> None:
    if workspace.exists() and any(workspace.iterdir()) and not force:
        raise SystemExit(f"{workspace}: refusing to reuse a non-empty workspace")
    workspace.mkdir(parents=True, exist_ok=True)
    inputs = workspace / "shared" / "inputs"
    outputs = workspace / "shared" / "outputs"
    metadata = workspace / "metadata"
    for directory in (inputs, outputs, metadata):
        directory.mkdir(parents=True, exist_ok=True)
    for identifier, content in _vectors().items():
        (inputs / identifier).write_bytes(content)
    vector_manifest = {
        "schema_version": SCHEMA_VERSION,
        "seed": SEED,
        "vectors": [
            {
                "id": identifier,
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
            for identifier, content in _vectors().items()
        ],
    }
    (metadata / "vectors.json").write_text(
        json.dumps(vector_manifest, indent=2, sort_keys=True) + "\n"
    )


def inventory(workspace: Path, binaries: list[Path]) -> None:
    guest_root = workspace / "guest-root"
    destination = guest_root / "Libs"
    compressors = destination / "compressors"
    commands = guest_root / "C"
    compressors.mkdir(parents=True, exist_ok=True)
    commands.mkdir(parents=True, exist_ok=True)
    records = []
    for source in binaries:
        if not source.is_file():
            raise SystemExit(f"{source}: binary not found")
        if source.name.lower() == "xpkmaster.library":
            target_directory = destination
        elif source.suffix.lower() == ".library":
            target_directory = compressors
        else:
            target_directory = commands
        target = target_directory / source.name
        shutil.copyfile(source, target)
        records.append(
            {
                "name": source.name,
                "size": source.stat().st_size,
                "sha256": _sha256(source),
                "source_class": "recovered-private",
            }
        )
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "redistributable": False,
        "binaries": sorted(records, key=lambda item: item["name"].lower()),
    }
    path = workspace / "metadata" / "private-binaries.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def extract_workbench(workspace: Path, adf: Path) -> None:
    if not adf.is_file():
        raise SystemExit(f"{adf}: Workbench ADF not found")
    guest_root = workspace / "guest-root"
    guest_root.mkdir(parents=True, exist_ok=True)
    subprocess.run(["unadf", str(adf)], cwd=guest_root, check=True)


def write_config(workspace: Path, *, fs_uae: Path, kickstart: Path, workbench_adf: Path) -> None:
    for path in (fs_uae, kickstart, workbench_adf):
        if not path.is_file():
            raise SystemExit(f"{path}: required file not found")
    config = f"""[fs-uae]
amiga_model = A1200
fast_memory = 8192
warp_mode = 1
kickstart_file = {kickstart}
hard_drive_0 = {workspace / "guest-root"}
hard_drive_0_label = ORACLE
hard_drive_1 = {workspace / "shared"}
hard_drive_1_label = SHARED
network_card = 0
fullscreen = 0
window_width = 960
window_height = 720
"""
    (workspace / "oracle.fs-uae").write_text(config)
    metadata = {
        "schema_version": SCHEMA_VERSION,
        "fs_uae": str(fs_uae),
        "fs_uae_sha256": _sha256(fs_uae),
        "kickstart_sha256": _sha256(kickstart),
        "workbench_sha256": _sha256(workbench_adf),
        "model": "A1200",
        "network_card": "none",
    }
    (workspace / "metadata" / "environment.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n"
    )


def _representative_modes(codec: str) -> tuple[int, ...]:
    values = {DEFAULT_MODES[codec]}
    for lower, upper in MODE_RANGES[codec]:
        values.update((lower, upper))
    return tuple(sorted(values))


def render_matrix(
    workspace: Path,
    *,
    codecs: set[str] | None = None,
    vectors: set[str] | None = None,
    resume: bool = False,
) -> None:
    vectors = [
        item["id"]
        for item in json.loads((workspace / "metadata" / "vectors.json").read_text())["vectors"]
        if vectors is None or item["id"] in vectors
    ]
    cases: list[dict[str, object]] = []
    lines = ["FailAt 21", "MakeDir RAM:matrix"]
    if not resume:
        lines.append("Delete SHARED:outputs/matrix-status.txt QUIET")
    for codec in MODE_RANGES:
        modes_by_vector = {
            "text": (
                range(101) if codec in EXHAUSTIVE_MODE_CODECS else _representative_modes(codec)
            ),
            **{vector: _representative_modes(codec) for vector in vectors if vector != "text"},
        }
        for vector, modes in modes_by_vector.items():
            for mode in modes:
                identifier = f"{codec.lower()}{mode:03d}-{vector}"
                unsafe_reason = UNSAFE_CASES.get((codec, vector))
                case = {"id": identifier, "codec": codec, "mode": mode, "vector": vector}
                if unsafe_reason:
                    case["excluded_reason"] = unsafe_reason
                cases.append(case)
                if codecs is not None and codec not in codecs:
                    continue
                if unsafe_reason:
                    continue
                result_path = workspace / "shared" / "outputs" / f"{identifier}.unpacked"
                if resume and result_path.is_file():
                    continue
                lines.extend(
                    (
                        f"Copy SHARED:inputs/{vector} RAM:matrix/source QUIET",
                        f"C:xpk -f -s -m {codec}.{mode} RAM:matrix/source "
                        f">SHARED:outputs/{identifier}.log",
                        f'Echo "{identifier} packrc=$RC" >>SHARED:outputs/matrix-status.txt',
                        f"Copy RAM:matrix/source.xpk SHARED:outputs/{identifier}.packed QUIET",
                        "Delete RAM:matrix/source QUIET",
                        f"C:xpk -u -s RAM:matrix/source.xpk >>SHARED:outputs/{identifier}.log",
                        f'Echo "{identifier} unpackrc=$RC" >>SHARED:outputs/matrix-status.txt',
                        f"Copy RAM:matrix/source.xpk SHARED:outputs/{identifier}.unpacked QUIET",
                        "Delete RAM:matrix/source.xpk QUIET",
                    )
                )
    lines.append('Echo "matrix-complete" >SHARED:outputs/matrix.done')
    control = workspace / "shared" / "control"
    control.mkdir(parents=True, exist_ok=True)
    (control / "oracle-stage").write_text("\n".join(lines) + "\n")
    (workspace / "metadata" / "matrix-cases.json").write_text(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "mode_ranges": MODE_RANGES,
                "default_modes": DEFAULT_MODES,
                "unsafe_cases": [
                    {"codec": codec, "vector": vector, "reason": reason}
                    for (codec, vector), reason in sorted(UNSAFE_CASES.items())
                ],
                "cases": cases,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def analyze_matrix(workspace: Path) -> None:
    metadata = json.loads((workspace / "metadata" / "matrix-cases.json").read_text())
    vectors = {
        item["id"]: item
        for item in json.loads((workspace / "metadata" / "vectors.json").read_text())["vectors"]
    }
    output_root = workspace / "shared" / "outputs"
    results = []
    counts: dict[str, int] = {}
    for case in metadata["cases"]:
        identifier = case["id"]
        if "excluded_reason" in case:
            results.append({**case, "status": "excluded"})
            counts["excluded"] = counts.get("excluded", 0) + 1
            continue
        packed = output_root / f"{identifier}.packed"
        unpacked = output_root / f"{identifier}.unpacked"
        log = output_root / f"{identifier}.log"
        vector = vectors[case["vector"]]
        if packed.is_file() and unpacked.is_file():
            unpacked_hash = _sha256(unpacked)
            if case["vector"] == "empty" and packed.read_bytes() == unpacked.read_bytes():
                status = "original_tool_empty_bug"
            else:
                status = "success" if unpacked_hash == vector["sha256"] else "mismatch"
            result = {
                **case,
                "status": status,
                "packed_size": packed.stat().st_size,
                "packed_sha256": _sha256(packed),
                "unpacked_size": unpacked.stat().st_size,
                "unpacked_sha256": unpacked_hash,
                "container_prefix": packed.read_bytes()[:16].hex(),
            }
        else:
            status = "hung" if log.is_file() else "not_run"
            result = {**case, "status": status}
            if log.is_file():
                result["log_sha256"] = _sha256(log)
        counts[status] = counts.get(status, 0) + 1
        results.append(result)
    report = {
        "schema_version": SCHEMA_VERSION,
        "oracle": json.loads((workspace / "metadata" / "environment.json").read_text()),
        "binary_inventory_sha256": _sha256(workspace / "metadata" / "private-binaries.json"),
        "counts": counts,
        "results": results,
    }
    (workspace / "metadata" / "matrix-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    if counts.get("mismatch"):
        raise SystemExit(f"matrix contains {counts['mismatch']} round-trip mismatches")


def verify_python(workspace: Path) -> None:
    """Decode completed matrix containers with xfh and compare original output."""

    import xfh

    metadata = json.loads((workspace / "metadata" / "matrix-cases.json").read_text())
    output_root = workspace / "shared" / "outputs"
    results = []
    failures = 0
    for case in metadata["cases"]:
        packed = output_root / f"{case['id']}.packed"
        unpacked = output_root / f"{case['id']}.unpacked"
        if "excluded_reason" in case or not packed.is_file() or not unpacked.is_file():
            continue
        try:
            decoded = xfh.decompress(packed.read_bytes())
            matches = decoded == unpacked.read_bytes()
            error = None
        except xfh.XfhError as exception:
            matches = False
            error = str(exception)
        failures += not matches
        results.append({**case, "matches": matches, "error": error})
    report = {
        "schema_version": SCHEMA_VERSION,
        "checked": len(results),
        "failures": failures,
        "results": results,
    }
    (workspace / "metadata" / "python-comparison.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    if failures:
        raise SystemExit(f"Python comparison contains {failures} failures")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("workspace", type=Path)
    prepare_parser.add_argument("--force", action="store_true")
    inventory_parser = subparsers.add_parser("inventory")
    inventory_parser.add_argument("workspace", type=Path)
    inventory_parser.add_argument("binary", nargs="+", type=Path)
    extract_parser = subparsers.add_parser("extract-workbench")
    extract_parser.add_argument("workspace", type=Path)
    extract_parser.add_argument("adf", type=Path)
    config_parser = subparsers.add_parser("write-config")
    config_parser.add_argument("workspace", type=Path)
    config_parser.add_argument("--fs-uae", required=True, type=Path)
    config_parser.add_argument("--kickstart", required=True, type=Path)
    config_parser.add_argument("--workbench-adf", required=True, type=Path)
    matrix_parser = subparsers.add_parser("render-matrix")
    matrix_parser.add_argument("workspace", type=Path)
    matrix_parser.add_argument(
        "--codec", action="append", choices=tuple(MODE_RANGES), dest="codecs"
    )
    matrix_parser.add_argument("--vector", action="append", choices=tuple(_vectors()))
    matrix_parser.add_argument("--resume", action="store_true")
    analyze_parser = subparsers.add_parser("analyze")
    analyze_parser.add_argument("workspace", type=Path)
    compare_parser = subparsers.add_parser("verify-python")
    compare_parser.add_argument("workspace", type=Path)
    arguments = parser.parse_args()
    if arguments.command == "prepare":
        prepare(arguments.workspace, force=arguments.force)
    elif arguments.command == "inventory":
        inventory(arguments.workspace, arguments.binary)
    elif arguments.command == "extract-workbench":
        extract_workbench(arguments.workspace, arguments.adf)
    elif arguments.command == "write-config":
        write_config(
            arguments.workspace,
            fs_uae=arguments.fs_uae,
            kickstart=arguments.kickstart,
            workbench_adf=arguments.workbench_adf,
        )
    elif arguments.command == "render-matrix":
        render_matrix(
            arguments.workspace,
            codecs=set(arguments.codecs) if arguments.codecs else None,
            vectors=set(arguments.vector) if arguments.vector else None,
            resume=arguments.resume,
        )
    elif arguments.command == "analyze":
        analyze_matrix(arguments.workspace)
    else:
        verify_python(arguments.workspace)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

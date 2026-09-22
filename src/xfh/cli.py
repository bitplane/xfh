"""Command-line interface."""

import argparse
import getpass
import json
import os
import sys
import warnings
from dataclasses import asdict
from enum import Enum
from pathlib import Path

from xfh.api import _write_atomic, decompress_file, inspect, salvage
from xfh.errors import UnsupportedCodecError, XfhError
from xfh.limits import Limits


def _password_for(data: bytes, limits: Limits, *, recovery: bool = False) -> str | None:
    """Obtain a password only when the stream declares that it needs one."""

    from xfh.container import parse

    try:
        flags = parse(data, limits, salvage=recovery).info.flags
    except XfhError:
        if not recovery:
            raise
        # Let salvage return a structured issue for an unreadable global header.
        return None
    if not flags & 2:
        return None
    if "XFH_PASSWORD" in os.environ:
        return os.environ["XFH_PASSWORD"]
    if not sys.stdin.isatty():
        from xfh.errors import PasswordRequiredError

        raise PasswordRequiredError(
            "password required; set XFH_PASSWORD when no terminal is available"
        )
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            return getpass.getpass("XPK password: ")
        except (EOFError, getpass.GetPassWarning) as error:
            from xfh.errors import PasswordRequiredError

            raise PasswordRequiredError(
                "password required; set XFH_PASSWORD when secure prompting is unavailable"
            ) from error


def _json_default(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, bytes):
        return value.hex()
    raise TypeError(f"cannot encode {type(value).__name__}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="xfh", description="Recover historical Amiga XPK files")
    subparsers = parser.add_subparsers(dest="command", required=True)

    info = subparsers.add_parser("info", help="inspect a compressed stream")
    info.add_argument("file", type=Path)
    info.add_argument("--json", action="store_true")

    verify = subparsers.add_parser("verify", help="strictly verify and decompress a stream")
    verify.add_argument("file", type=Path)
    verify.add_argument("--max-output-size", type=int, default=256 * 1024 * 1024)

    unpack = subparsers.add_parser("unpack", help="decompress a stream")
    unpack.add_argument("file", type=Path)
    unpack.add_argument("output", type=Path)
    unpack.add_argument("--force", action="store_true")
    unpack.add_argument("--max-output-size", type=int, default=256 * 1024 * 1024)
    unpack.add_argument("--salvage", action="store_true")
    unpack.add_argument("--report", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return its process status."""

    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "info":
            info = inspect(arguments.file.read_bytes())
            if arguments.json:
                print(json.dumps(asdict(info), default=_json_default, indent=2))
            else:
                print(f"format: {info.format.value}")
                print(f"codec: {info.codec}")
                print(f"packed size: {info.packed_size}")
                print(f"unpacked size: {info.unpacked_size}")
                print(f"chunks: {len(info.chunks)}")
            return 0

        limits = Limits(max_output_size=arguments.max_output_size)
        if arguments.command == "verify":
            from xfh.api import decompress

            data = arguments.file.read_bytes()
            decompress(data, password=_password_for(data, limits), limits=limits)
            print(f"{arguments.file}: verified")
            return 0

        if arguments.salvage:
            data = arguments.file.read_bytes()
            result = salvage(
                data, password=_password_for(data, limits, recovery=True), limits=limits
            )
            _write_atomic(arguments.output, result.data, overwrite=arguments.force)
            report = {
                "complete": result.complete,
                "recovered_size": len(result.data),
                "issues": [asdict(issue) for issue in result.issues],
            }
            if arguments.report:
                _write_atomic(
                    arguments.report,
                    (json.dumps(report, indent=2) + "\n").encode(),
                    overwrite=arguments.force,
                )
            return 0 if result.complete else 4

        decompress_file(
            arguments.file,
            arguments.output,
            overwrite=arguments.force,
            password=_password_for(arguments.file.read_bytes(), limits),
            limits=limits,
        )
        return 0
    except FileExistsError as error:
        print(f"xfh: refusing to overwrite {error}", file=sys.stderr)
        return 1
    except UnsupportedCodecError as error:
        print(f"xfh: {error}", file=sys.stderr)
        return 3
    except (OSError, XfhError, ValueError) as error:
        print(f"xfh: {error}", file=sys.stderr)
        return 1

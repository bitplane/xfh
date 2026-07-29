"""Public recovery API."""

import os
import tempfile
from pathlib import Path

from xfh.codecs import decode
from xfh.container import ParsedFile, detect_format, parse
from xfh.errors import CorruptDataError, PasswordRequiredError, XfhError
from xfh.limits import DEFAULT_LIMITS, Limits
from xfh.models import FileFormat, FileInfo, RecoveryIssue, RecoveryResult


def _bytes(data: bytes | bytearray | memoryview) -> bytes:
    try:
        return bytes(data)
    except (TypeError, ValueError) as error:
        raise TypeError("data must be bytes-like") from error


def detect(data: bytes | bytearray | memoryview) -> FileFormat:
    """Detect an XPK container variant."""

    return detect_format(_bytes(data))


def inspect(data: bytes | bytearray | memoryview, *, limits: Limits = DEFAULT_LIMITS) -> FileInfo:
    """Parse and validate stream metadata without decompressing it."""

    return parse(_bytes(data), limits).info


def _decompress_parsed(parsed: ParsedFile) -> bytes:
    if parsed.info.flags & 2:
        raise PasswordRequiredError("password-protected XPK streams are not implemented")
    output = bytearray()
    shri_state = None
    for chunk in parsed.chunks:
        if chunk.info.type == 15:
            continue
        if chunk.info.type == 0:
            decoded = chunk.payload
        elif parsed.info.codec in {"SHRI", "SHR3"}:
            from xfh.codecs.shri import decompress_shri_chunk

            decoded, shri_state = decompress_shri_chunk(
                chunk.payload,
                chunk.info.unpacked_size,
                bytes(output),
                shri_state,
                shr3=parsed.info.codec == "SHR3",
            )
        else:
            decoded = decode(
                parsed.info.codec,
                chunk.payload,
                chunk.info.unpacked_size,
                bytes(output),
            )
        if len(decoded) != chunk.info.unpacked_size:
            raise CorruptDataError(
                f"chunk {chunk.info.index} produced {len(decoded)} bytes, "
                f"expected {chunk.info.unpacked_size}"
            )
        output.extend(decoded)
    if len(output) != parsed.info.unpacked_size:
        raise CorruptDataError(
            f"stream produced {len(output)} bytes, expected {parsed.info.unpacked_size}"
        )
    if parsed.info.initial and output[: len(parsed.info.initial)] != parsed.info.initial:
        raise CorruptDataError("decompressed data does not match XPKF initial bytes")
    return bytes(output)


def decompress(
    data: bytes | bytearray | memoryview,
    *,
    password: str | bytes | None = None,
    limits: Limits = DEFAULT_LIMITS,
) -> bytes:
    """Strictly decompress one complete stream."""

    del password
    return _decompress_parsed(parse(_bytes(data), limits))


def salvage(
    data: bytes | bytearray | memoryview, *, limits: Limits = DEFAULT_LIMITS
) -> RecoveryResult:
    """Recover verified chunks until the first decoding failure."""

    raw = _bytes(data)
    try:
        parsed = parse(raw, limits)
    except XfhError as error:
        return RecoveryResult(b"", False, (RecoveryIssue(0, str(error)),))
    output = bytearray()
    shri_state = None
    issues: list[RecoveryIssue] = []
    for chunk in parsed.chunks:
        if chunk.info.type == 15:
            continue
        try:
            if chunk.info.type == 0:
                decoded = chunk.payload
            elif parsed.info.codec in {"SHRI", "SHR3"}:
                from xfh.codecs.shri import decompress_shri_chunk

                decoded, shri_state = decompress_shri_chunk(
                    chunk.payload,
                    chunk.info.unpacked_size,
                    bytes(output),
                    shri_state,
                    shr3=parsed.info.codec == "SHR3",
                )
            else:
                decoded = decode(
                    parsed.info.codec,
                    chunk.payload,
                    chunk.info.unpacked_size,
                    bytes(output),
                )
            if len(decoded) != chunk.info.unpacked_size:
                raise CorruptDataError("decoded chunk has the wrong size")
            output.extend(decoded)
        except XfhError as error:
            issues.append(RecoveryIssue(chunk.info.offset, str(error)))
            break
    complete = not issues and len(output) == parsed.info.unpacked_size
    return RecoveryResult(bytes(output), complete, tuple(issues))


def decompress_file(
    source: str | os.PathLike[str],
    destination: str | os.PathLike[str],
    *,
    overwrite: bool = False,
    password: str | bytes | None = None,
    limits: Limits = DEFAULT_LIMITS,
) -> FileInfo:
    """Decompress to an atomic destination path."""

    source_path = Path(source)
    destination_path = Path(destination)
    if destination_path.exists() and not overwrite:
        raise FileExistsError(destination_path)
    data = source_path.read_bytes()
    parsed = parse(data, limits)
    output = _decompress_parsed(parsed)
    _write_atomic(destination_path, output, overwrite=overwrite)
    del password
    return parsed.info


def _write_atomic(path: Path, data: bytes, *, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        if path.exists() and not overwrite:
            raise FileExistsError(path)
        os.replace(temporary_path, path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise

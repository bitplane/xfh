"""Strict parsers for historical XPK stream containers."""

from dataclasses import dataclass
from itertools import pairwise
from struct import unpack_from

from xfh.errors import CorruptDataError, InvalidFormatError, ResourceLimitError
from xfh.limits import Limits
from xfh.models import ChunkInfo, FileFormat, FileInfo

XPKF_MAGIC = b"XPKF"
LEGACY_MAGIC = b"\x01\x80ch\x05a\x01\n"


@dataclass(frozen=True, slots=True)
class ParsedChunk:
    """Internal chunk metadata and its encoded bytes."""

    info: ChunkInfo
    payload: bytes


@dataclass(frozen=True, slots=True)
class ParsedFile:
    """Internal parsed stream."""

    info: FileInfo
    chunks: tuple[ParsedChunk, ...]


def _xor8(data: bytes) -> int:
    result = 0
    for value in data:
        result ^= value
    return result


def _xor16(data: bytes) -> int:
    high = 0
    low = 0
    for index, value in enumerate(data):
        if index & 1:
            low ^= value
        else:
            high ^= value
    return (high << 8) | low


def detect_format(data: bytes) -> FileFormat:
    """Detect a supported container without parsing it."""

    if data.startswith(XPKF_MAGIC):
        return FileFormat.XPKF
    if data.startswith(LEGACY_MAGIC):
        return FileFormat.LEGACY
    raise InvalidFormatError("not a recognized XPK stream")


def parse(data: bytes, limits: Limits) -> ParsedFile:
    """Parse and validate one complete stream."""

    format_ = detect_format(data)
    if format_ is FileFormat.XPKF:
        return _parse_xpkf(data, limits)
    return _parse_legacy(data, limits)


def _validate_output_size(size: int, limits: Limits) -> None:
    if size > limits.max_output_size:
        raise ResourceLimitError(
            f"declared output size {size} exceeds limit {limits.max_output_size}"
        )


def _parse_xpkf(data: bytes, limits: Limits) -> ParsedFile:
    if len(data) < 36:
        raise CorruptDataError("truncated XPKF global header")
    packed_after_prefix, unpacked_size = unpack_from(">I4xI", data, 4)
    total_size = packed_after_prefix + 8
    if total_size != len(data):
        raise CorruptDataError(
            f"XPKF length field describes {total_size} bytes, input has {len(data)}"
        )
    _validate_output_size(unpacked_size, limits)
    try:
        codec = data[8:12].decode("ascii")
    except UnicodeDecodeError as error:
        raise CorruptDataError("XPKF codec identifier is not ASCII") from error
    if len(codec) != 4 or not codec.isprintable():
        raise CorruptDataError("invalid XPKF codec identifier")

    flags = data[32]
    long_headers = bool(flags & 1)
    if flags & ~0x07:
        raise CorruptDataError(f"unsupported XPKF stream flags 0x{flags:02x}")
    header_size = 36
    if flags & 4:
        if len(data) < 38:
            raise CorruptDataError("truncated XPKF extended-header length")
        header_size = 38 + int.from_bytes(data[36:38], "big")
        if header_size > len(data):
            raise CorruptDataError("XPKF extended header exceeds input")
    if _xor8(data[:36]):
        raise CorruptDataError("XPKF global header checksum mismatch")

    chunk_header_size = 12 if long_headers else 8
    chunks: list[ParsedChunk] = []
    offset = header_size
    unpacked_total = 0
    found_end = False
    while offset < len(data):
        if len(chunks) >= limits.max_chunks:
            raise ResourceLimitError("stream exceeds configured chunk count")
        if offset + chunk_header_size > len(data):
            raise CorruptDataError(f"truncated XPKF chunk header at offset {offset}")
        header = data[offset : offset + chunk_header_size]
        if _xor8(header):
            raise CorruptDataError(f"XPKF chunk header checksum mismatch at offset {offset}")
        chunk_type = header[0]
        checksum = int.from_bytes(header[2:4], "big")
        if long_headers:
            packed_size = int.from_bytes(header[4:8], "big")
            raw_size = int.from_bytes(header[8:12], "big")
        else:
            packed_size = int.from_bytes(header[4:6], "big")
            raw_size = int.from_bytes(header[6:8], "big")
        payload_offset = offset + chunk_header_size
        payload_end = payload_offset + packed_size
        if payload_end > len(data):
            raise CorruptDataError(f"XPKF chunk at offset {offset} exceeds input")
        payload = data[payload_offset:payload_end]
        if payload and _xor16(payload) != checksum:
            raise CorruptDataError(f"XPKF chunk checksum mismatch at offset {offset}")
        if chunk_type not in (0, 1, 15):
            raise CorruptDataError(f"unknown XPKF chunk type {chunk_type} at offset {offset}")
        if chunk_type == 15:
            if packed_size or raw_size:
                raise CorruptDataError("XPKF end chunk is not empty")
            found_end = True
        elif chunk_type == 0 and packed_size != raw_size:
            raise CorruptDataError("raw XPKF chunk has differing packed and unpacked sizes")

        info = ChunkInfo(
            index=len(chunks),
            type=chunk_type,
            offset=offset,
            header_size=chunk_header_size,
            packed_size=packed_size,
            unpacked_size=raw_size,
            checksum=checksum,
        )
        chunks.append(ParsedChunk(info, payload))
        unpacked_total += raw_size
        offset = payload_end + ((-packed_size) & 3)
        if offset > len(data):
            raise CorruptDataError("XPKF chunk padding exceeds input")
        if any(data[payload_end:offset]):
            raise CorruptDataError("nonzero XPKF alignment padding")
        if found_end:
            break

    if not found_end:
        raise CorruptDataError("XPKF stream has no end chunk")
    if offset != len(data):
        raise CorruptDataError("trailing bytes after XPKF end chunk")
    if unpacked_total != unpacked_size:
        raise CorruptDataError(
            f"XPKF chunks produce {unpacked_total} bytes, expected {unpacked_size}"
        )

    file_info = FileInfo(
        format=FileFormat.XPKF,
        codec=codec,
        mode=None,
        packed_size=len(data),
        unpacked_size=unpacked_size,
        flags=flags,
        sub_version=data[34],
        master_version=data[35],
        initial=data[16 : 16 + min(16, unpacked_size)],
        chunks=tuple(chunk.info for chunk in chunks),
    )
    return ParsedFile(file_info, tuple(chunks))


def _parse_legacy(data: bytes, limits: Limits) -> ParsedFile:
    if len(data) < 32:
        raise CorruptDataError("truncated legacy XPK header")
    unpacked_size, table_offset = unpack_from(">II", data, 8)
    if table_offset < 26 or table_offset > len(data) - 8:
        raise CorruptDataError(f"legacy length field gives invalid table offset {table_offset}")
    table_size = len(data) - table_offset
    if table_size % 4:
        raise CorruptDataError("legacy chunk table is not longword-aligned")
    _validate_output_size(unpacked_size, limits)
    method = data[16:24].rstrip(b"\0")
    if not method.startswith(b"xpk") or len(method) != 7:
        raise CorruptDataError("invalid legacy XPK method name")
    try:
        codec = method[3:].decode("ascii")
    except UnicodeDecodeError as error:
        raise CorruptDataError("legacy codec identifier is not ASCII") from error

    boundaries = tuple(
        unpack_from(">I", data, offset)[0] for offset in range(table_offset, len(data), 4)
    )
    if boundaries[0] != 24 or boundaries[-1] != table_offset:
        raise CorruptDataError("invalid legacy chunk table endpoints")
    if any(left >= right for left, right in pairwise(boundaries)):
        raise CorruptDataError("legacy chunk table is not strictly increasing")
    if len(boundaries) - 1 > limits.max_chunks:
        raise ResourceLimitError("stream exceeds configured chunk count")

    chunks: list[ParsedChunk] = []
    remaining = unpacked_size
    for index, (start, end) in enumerate(pairwise(boundaries)):
        if end > table_offset or start + 2 > end:
            raise CorruptDataError("legacy chunk boundary is out of range")
        declared_size = unpack_from(">H", data, start)[0]
        stored_size = end - start - 2
        chunk_type = 0 if declared_size == 0xFFFF else 1
        if chunk_type == 0:
            if stored_size != 10_000:
                raise CorruptDataError(f"legacy raw chunk {index} is not 10,000 bytes")
        elif declared_size != stored_size:
            raise CorruptDataError(f"legacy chunk {index} length does not match its table boundary")
        chunk_output_size = min(10_000, remaining)
        if not chunk_output_size:
            raise CorruptDataError("legacy stream has too many chunks")
        info = ChunkInfo(
            index=index,
            type=chunk_type,
            offset=start,
            header_size=2,
            packed_size=stored_size,
            unpacked_size=chunk_output_size,
            checksum=None,
        )
        chunks.append(ParsedChunk(info, data[start + 2 : end]))
        remaining -= chunk_output_size
    if remaining:
        raise CorruptDataError(
            f"legacy chunks leave {remaining} bytes of declared output uncovered"
        )

    file_info = FileInfo(
        format=FileFormat.LEGACY,
        codec=codec,
        mode=None,
        packed_size=len(data),
        unpacked_size=unpacked_size,
        flags=0,
        sub_version=None,
        master_version=None,
        initial=b"",
        chunks=tuple(chunk.info for chunk in chunks),
    )
    return ParsedFile(file_info, tuple(chunks))

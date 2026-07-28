"""Immutable metadata returned by the public API."""

from dataclasses import dataclass
from enum import Enum


class FileFormat(str, Enum):
    """Known XPK stream container variants."""

    XPKF = "xpkf"
    LEGACY = "legacy"


@dataclass(frozen=True, slots=True)
class ChunkInfo:
    """Metadata for one encoded stream chunk."""

    index: int
    type: int
    offset: int
    header_size: int
    packed_size: int
    unpacked_size: int
    checksum: int | None


@dataclass(frozen=True, slots=True)
class FileInfo:
    """Parsed stream metadata."""

    format: FileFormat
    codec: str
    mode: int | None
    packed_size: int
    unpacked_size: int
    flags: int
    sub_version: int | None
    master_version: int | None
    initial: bytes
    chunks: tuple[ChunkInfo, ...]


@dataclass(frozen=True, slots=True)
class RecoveryIssue:
    """One reason why salvage output is incomplete."""

    offset: int
    message: str


@dataclass(frozen=True, slots=True)
class RecoveryResult:
    """Partial or complete output from explicit salvage mode."""

    data: bytes
    complete: bool
    issues: tuple[RecoveryIssue, ...]

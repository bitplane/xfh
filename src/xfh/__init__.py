"""Recover files compressed with historical Amiga XPK tools."""

from xfh.api import decompress, decompress_file, detect, inspect, salvage
from xfh.errors import (
    CorruptDataError,
    IncorrectPasswordError,
    InvalidFormatError,
    PasswordRequiredError,
    ResourceLimitError,
    UnsupportedCodecError,
    XfhError,
)
from xfh.limits import DEFAULT_LIMITS, Limits
from xfh.models import FileFormat, FileInfo, RecoveryIssue, RecoveryResult

__all__ = [
    "DEFAULT_LIMITS",
    "CorruptDataError",
    "FileFormat",
    "FileInfo",
    "IncorrectPasswordError",
    "InvalidFormatError",
    "Limits",
    "PasswordRequiredError",
    "RecoveryIssue",
    "RecoveryResult",
    "ResourceLimitError",
    "UnsupportedCodecError",
    "XfhError",
    "decompress",
    "decompress_file",
    "detect",
    "inspect",
    "salvage",
]

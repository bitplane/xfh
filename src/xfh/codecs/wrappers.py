"""Nested and transform XPK codecs.

Derived from Ancient's CYB2Decoder and SDHCDecompressor,
Copyright (c) 2017-2025 Teemu Suutari, under the BSD 2-Clause License.
"""

from xfh.codecs import decode, register
from xfh.errors import CorruptDataError


@register("CYB2")
def decompress_cyb2(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode a CYB2 wrapper around another XPK codec payload."""

    if len(payload) <= 10:
        raise CorruptDataError("truncated CYB2 wrapper")
    try:
        codec = payload[:4].decode("ascii")
    except UnicodeDecodeError as error:
        raise CorruptDataError("invalid CYB2 inner codec") from error
    if codec == "CYB2":
        raise CorruptDataError("recursive CYB2 wrapper")
    return decode(codec, payload[10:], output_size, previous)


def _delta8(data: bytearray, length: int) -> None:
    accumulator = 0
    for index in range(length):
        accumulator = (accumulator + data[index]) & 0xFF
        data[index] = accumulator


def _delta16(data: bytearray, length: int, *, stereo: bool) -> None:
    accumulators = [0, 0]
    step = 4 if stereo else 2
    for offset in range(0, length, step):
        channels = 2 if stereo else 1
        for channel in range(channels):
            index = offset + channel * 2
            value = int.from_bytes(data[index : index + 2], "big")
            accumulators[channel] = (accumulators[channel] + value) & 0xFFFF
            data[index : index + 2] = accumulators[channel].to_bytes(2, "big")


@register("SDHC")
def decompress_sdhc(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode SDHC's optional nested stream and sample delta transform."""

    del previous
    if len(payload) < 2:
        raise CorruptDataError("truncated SDHC stream")
    mode = int.from_bytes(payload[:2], "big")
    source = payload[2:]
    if mode & 0x8000:
        from xfh.api import decompress
        from xfh.limits import Limits

        decoded = bytearray(
            decompress(source, limits=Limits(max_output_size=output_size, max_chunks=1024))
        )
        if len(decoded) != output_size:
            raise CorruptDataError("nested SDHC stream has the wrong output size")
    else:
        if len(source) != output_size:
            raise CorruptDataError("SDHC raw payload has the wrong size")
        decoded = bytearray(source)

    length = output_size & ~3
    transform = mode & 15
    if transform in (0, 1):
        _delta8(decoded, length)
        if transform == 1:
            _delta8(decoded, length)
    elif transform in (2, 3):
        _delta16(decoded, length, stereo=False)
        if transform == 3:
            _delta16(decoded, length, stereo=False)
    elif transform in (10, 11):
        _delta16(decoded, length, stereo=True)
        if transform == 11:
            _delta16(decoded, length, stereo=True)
    else:
        raise CorruptDataError(f"unsupported SDHC transform {transform}")
    return bytes(decoded)

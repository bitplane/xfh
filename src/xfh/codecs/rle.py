"""XPK byte-run codecs.

Derived from Ancient's CBR0, FRLE, and RLEN decompressors,
Copyright (c) 2017-2025 Teemu Suutari, under the BSD 2-Clause License.
"""

from collections.abc import Callable

from xfh.codecs import register
from xfh.codecs._streams import ByteInput
from xfh.errors import CorruptDataError


def _decode_runs(
    payload: bytes,
    output_size: int,
    run: Callable[[int], tuple[bool, int]],
) -> bytes:
    source = ByteInput(payload)
    output = bytearray()
    while len(output) < output_size:
        repeated, count = run(source.byte())
        if count <= 0 or len(output) + count > output_size:
            raise CorruptDataError("invalid byte-run length")
        if repeated:
            output.extend(bytes((source.byte(),)) * count)
        else:
            output.extend(source.byte() for _ in range(count))
    return bytes(output)


@register("CBR1")
@register("CBR0")
def decompress_cbr0(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode Commodore ByteRun-style CBR0/CBR1 data."""

    del previous

    def run(control: int) -> tuple[bool, int]:
        return (False, control + 1) if control < 128 else (True, 257 - control)

    return _decode_runs(payload, output_size, run)


@register("RLEN")
def decompress_rlen(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode XPK RLEN data."""

    del previous

    def run(control: int) -> tuple[bool, int]:
        if control < 128:
            return False, control
        return True, 256 - control

    return _decode_runs(payload, output_size, run)


@register("FRLE")
def decompress_frle(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode cache-oriented XPK FRLE data."""

    del previous

    def run(control: int) -> tuple[bool, int]:
        count = (32 - (control & 0x1F)) + (control & 0x60)
        return (False, count) if control < 128 else (True, count + 1)

    return _decode_runs(payload, output_size, run)

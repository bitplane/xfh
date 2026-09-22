from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import xfh
from xfh.codecs import decode
from xfh.errors import XfhError
from xfh.limits import Limits


@given(st.binary(max_size=512))
@settings(deadline=None, max_examples=500)
def test_arbitrary_input_fails_safely(data: bytes) -> None:
    try:
        output = xfh.decompress(data, limits=Limits(max_output_size=4096, max_chunks=128))
    except XfhError:
        return
    assert len(output) <= 4096


@given(st.binary(min_size=1, max_size=64), st.binary(min_size=1, max_size=64))
def test_damaged_later_chunk_preserves_verified_prefix(first: bytes, second: bytes) -> None:
    from tests.helpers import xpkf

    packed = bytearray(
        xpkf("NONE", [(0, first, len(first)), (0, second, len(second))], first + second)
    )
    second_header = 44 + len(first) + (-len(first) & 3)
    packed[second_header + 8] ^= 1
    result = xfh.salvage(packed)
    assert not result.complete
    assert result.data == first
    assert result.issues[0].offset == second_header


_ORACLE_FILES = [
    path
    for path in sorted((Path(__file__).parent / "fixtures/oracle").glob("*.hex"))
    if bytes.fromhex(path.read_text()).startswith(b"XPKF")
]


@given(
    st.sampled_from(_ORACLE_FILES), st.integers(min_value=0, max_value=65535), st.integers(1, 255)
)
@settings(deadline=None, max_examples=150)
def test_valid_container_with_mutated_codec_payload_stays_in_error_model(path, index, mask):
    from tests.helpers import xpkf
    from xfh.container import parse
    from xfh.limits import DEFAULT_LIMITS

    parsed = parse(bytes.fromhex(path.read_text()), DEFAULT_LIMITS)
    chunks = [chunk for chunk in parsed.chunks if chunk.info.type == 1 and chunk.payload]
    if not chunks:
        return
    chunk = chunks[index % len(chunks)]
    payload = bytearray(chunk.payload)
    payload[index % len(payload)] ^= mask
    # Rebuild header and payload checksums so mutations reach the decoder.
    packed = xpkf(
        parsed.info.codec,
        [(1, bytes(payload), chunk.info.unpacked_size)],
        parsed.info.initial,
        long_headers=True,
    )
    limits = Limits(max_output_size=65536, max_chunks=128, max_depth=8)
    try:
        output = xfh.decompress(packed, password="recovery-test", limits=limits)
    except XfhError:
        pass
    else:
        assert len(output) == chunk.info.unpacked_size
    result = xfh.salvage(packed, password="recovery-test", limits=limits)
    assert len(result.data) <= chunk.info.unpacked_size


@pytest.mark.parametrize(
    "codec",
    [
        "DLTA",
        "SMPL",
        "HFMN",
        "MASH",
        "SQSH",
        "SHR3",
        "LZW2",
        "LZW3",
        "LZW4",
        "LZW5",
        "ACCA",
        "ARTM",
        "FBR2",
        "ILZR",
        "ZENO",
        "LZBS",
        "SLZ3",
        "TDCS",
        "LHLB",
        "SDHC",
        "CYB2",
        "BZP2",
        "GZIP",
        "IMPL",
        "PWPK",
        "CRM2",
        "CRMS",
    ],
)
@given(st.binary(max_size=96), st.integers(min_value=0, max_value=96))
@settings(deadline=None, max_examples=100)
def test_new_codec_inputs_stay_inside_the_public_error_model(
    codec: str, payload: bytes, output_size: int
) -> None:
    try:
        output = decode(codec, payload, output_size)
    except XfhError:
        return
    assert len(output) == output_size

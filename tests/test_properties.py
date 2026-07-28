from hypothesis import given, settings
from hypothesis import strategies as st

import xfh
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


@given(st.binary(min_size=4, max_size=256), st.integers(min_value=0, max_value=255))
def test_single_byte_mutations_do_not_escape_error_model(data: bytes, value: int) -> None:
    mutated = bytearray(data)
    mutated[len(mutated) // 2] = value
    result = xfh.salvage(mutated, limits=Limits(max_output_size=4096, max_chunks=128))
    assert len(result.data) <= 4096

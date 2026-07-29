"""XPK BLZW decompression.

Derived from Ancient's BLZWDecompressor and LZWDecoder,
Copyright (c) 2017-2025 Teemu Suutari, under the BSD 2-Clause License.
"""

from xfh.codecs import register
from xfh.codecs._streams import BitReader, ByteInput
from xfh.errors import CorruptDataError


@register("BLZW")
def decompress_blzw(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode Bryan Ford's XPK BLZW format."""

    del previous
    if len(payload) < 6:
        raise CorruptDataError("truncated BLZW stream")
    maximum_bits = int.from_bytes(payload[:2], "big")
    if not 9 <= maximum_bits <= 20:
        raise CorruptDataError(f"invalid BLZW dictionary width {maximum_bits}")
    stack_limit = int.from_bytes(payload[2:4], "big") + 5
    maximum_code = 1 << maximum_bits
    source = ByteInput(payload, 4)
    bits = BitReader(source.word, 8)
    output = bytearray()
    prefixes: dict[int, int] = {}
    suffixes: dict[int, int] = {}
    code_bits = 9
    free_index = 259
    new_code = 0

    def read_code() -> int:
        return bits.read(code_bits)

    def emit(value: int) -> None:
        if len(output) >= output_size:
            raise CorruptDataError("BLZW output exceeds declared size")
        output.append(value)

    def suffix(code: int) -> int:
        if code >= free_index:
            raise CorruptDataError("invalid BLZW dictionary reference")
        return code if code < 259 else suffixes[code]

    def write(code: int, previous_code: int, *, add_new: bool) -> int:
        nonlocal new_code
        final = new_code
        if add_new:
            code = previous_code
        new_code = suffix(code)
        stack: list[int] = []
        while code >= 259:
            if len(stack) + 1 >= stack_limit:
                raise CorruptDataError("BLZW dictionary chain exceeds stack limit")
            stack.append(new_code)
            code = prefixes[code]
            new_code = suffix(code)
        stack.append(new_code)
        for value in reversed(stack):
            emit(value)
        if add_new:
            emit(final)
        return new_code

    first_code = read_code()
    if first_code >= 256:
        raise CorruptDataError("invalid BLZW initial code")
    previous_code = first_code
    write(first_code, previous_code, add_new=False)

    while len(output) < output_size:
        code = read_code()
        if code == 256:
            raise CorruptDataError("unexpected BLZW end code")
        if code == 257:
            code_bits = 9
            free_index = 259
            prefixes.clear()
            suffixes.clear()
            first_code = read_code()
            if first_code >= 256:
                raise CorruptDataError("invalid BLZW reset code")
            previous_code = first_code
            write(first_code, previous_code, add_new=False)
            continue
        if code == 258:
            if code_bits >= maximum_bits:
                raise CorruptDataError("BLZW code width exceeds dictionary limit")
            code_bits += 1
            continue
        if code > free_index:
            raise CorruptDataError("invalid BLZW dictionary code")

        add_new = code == free_index
        write(code, previous_code, add_new=add_new)
        if free_index < maximum_code:
            suffixes[free_index] = new_code
            prefixes[free_index] = previous_code
            free_index += 1
        previous_code = code

    return bytes(output)

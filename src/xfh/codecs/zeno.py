"""XPK ZENO decompression.

Derived from Ancient's ZENODecompressor, Copyright (c) 2017-2025
Teemu Suutari, under the BSD 2-Clause License.
"""

from xfh.codecs import register
from xfh.codecs._streams import BitReader, ByteInput
from xfh.errors import CorruptDataError


@register("ZENO")
def decompress_zeno(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode ZENO's variable-width dictionary stream."""

    del previous
    if len(payload) < 6 or int.from_bytes(payload[:4], "big"):
        raise CorruptDataError("invalid ZENO password checksum")
    maximum_bits = payload[4]
    if not 9 <= maximum_bits <= 20:
        raise CorruptDataError("invalid ZENO dictionary width")
    start = payload[5] + 6
    if start >= len(payload):
        raise CorruptDataError("invalid ZENO stream offset")
    source = ByteInput(payload, start)
    bits = BitReader(source.word, 8)
    maximum_code = 1 << maximum_bits
    prefixes: dict[int, int] = {}
    suffixes: dict[int, int] = {}
    output = bytearray()
    code_bits = 9
    free_index = 259

    first = bits.read(9)
    if first >= 256:
        raise CorruptDataError("invalid ZENO initial code")
    previous_code = first
    new_code = first
    prefixes[258] = 0
    suffixes[258] = 0
    output.append(first)

    while len(output) < output_size:
        if free_index + 3 >= 1 << code_bits and code_bits < maximum_bits:
            code_bits += 1
        code = bits.read(code_bits)
        if code == 256:
            raise CorruptDataError("unexpected ZENO end code")
        if code == 257:
            code_bits = 9
            free_index = 258
            prefixes.clear()
            suffixes.clear()
            continue
        if code > free_index:
            raise CorruptDataError("invalid ZENO dictionary code")

        stack: list[int] = []
        current = code
        if current == free_index:
            stack.append(new_code)
            current = previous_code
        while current >= 258:
            if len(stack) + 1 >= 5000 or current >= free_index:
                raise CorruptDataError("invalid ZENO dictionary chain")
            stack.append(suffixes[current])
            current = prefixes[current]
        new_code = current
        stack.append(new_code)
        if len(output) + len(stack) > output_size:
            raise CorruptDataError("ZENO output exceeds declared size")
        output.extend(reversed(stack))

        if free_index < maximum_code:
            suffixes[free_index] = new_code
            prefixes[free_index] = previous_code
            free_index += 1
        previous_code = code
    return bytes(output)

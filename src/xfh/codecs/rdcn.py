"""XPK RDCN decompression.

Derived from Ancient's RDCNDecompressor, Copyright (c) 2017-2025
Teemu Suutari, under the BSD 2-Clause License.
"""

from xfh.codecs import register
from xfh.codecs._streams import BitReader, ByteInput, copy_forward
from xfh.errors import CorruptDataError


@register("RDCN")
def decompress_rdcn(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode Ross Data Compression chunks."""

    del previous
    source = ByteInput(payload)
    bits = BitReader(source.word, 16)
    output = bytearray()

    while len(output) < output_size:
        if not bits.read(1):
            output.append(source.byte())
            continue

        descriptor = source.byte()
        count = descriptor & 0x0F
        code = descriptor >> 4
        if code == 0:
            count += 3
            if len(output) + count > output_size:
                raise CorruptDataError("RDCN run exceeds declared size")
            output.extend(bytes((source.byte(),)) * count)
        elif code == 1:
            count = (count | (source.byte() << 4)) + 19
            if len(output) + count > output_size:
                raise CorruptDataError("RDCN run exceeds declared size")
            output.extend(bytes((source.byte(),)) * count)
        else:
            distance = (count | (source.byte() << 4)) + 3
            count = source.byte() + 16 if code == 2 else code
            copy_forward(output, distance, count, output_size)

    return bytes(output)

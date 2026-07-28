"""XPK FAST decompression."""

from xfh.codecs import register
from xfh.codecs._streams import BitReader, CoupledInput, copy_forward


@register("FAST")
def decompress_fast(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode one FAST chunk."""

    del previous
    streams = CoupledInput(payload)
    bits = BitReader(lambda size: streams.backward_word(size), 16)
    output = bytearray()
    while len(output) < output_size:
        if not bits.read(1):
            output.append(streams.forward_byte())
            continue
        descriptor = streams.backward_word(2)
        count = min(18 - (descriptor & 0x0F), output_size - len(output))
        copy_forward(output, descriptor >> 4, count, output_size)
    return bytes(output)

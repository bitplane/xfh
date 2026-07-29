"""XPK LHLB decompression.

Derived from Ancient's LHDecompressor and DynamicHuffmanDecoder,
Copyright (c) 2017-2025 Teemu Suutari, under the BSD 2-Clause License.
"""

from dataclasses import dataclass

from xfh.codecs import register
from xfh.codecs._prefix import variable_length
from xfh.codecs._streams import BitReader, ByteInput, copy_forward
from xfh.errors import CorruptDataError


@dataclass(slots=True)
class _Node:
    frequency: int = 0
    index: int = 0
    parent: int = 0
    left: int = 0
    right: int = 0


class _DynamicHuffman:
    maximum = 317
    root = maximum * 2 - 2

    def __init__(self) -> None:
        self.nodes = [_Node() for _ in range(self.maximum * 2 - 1)]
        self.code_map = [0] * (self.maximum * 2 - 1)
        for index in range(self.maximum):
            node = self.nodes[index]
            node.frequency = 1
            node.index = index
            node.parent = self.maximum + (index >> 1)
            self.code_map[index] = index
        for index, left in zip(
            range(self.maximum, self.maximum * 2 - 1),
            range(0, self.maximum * 2 - 2, 2),
            strict=True,
        ):
            right = left + 1
            node = self.nodes[index]
            node.frequency = self.nodes[left].frequency + self.nodes[right].frequency
            node.index = index
            node.parent = self.maximum + (index >> 1)
            node.left = left
            node.right = right
            self.code_map[index] = index

    def decode(self, bits: BitReader) -> int:
        code = self.root
        while code >= self.maximum:
            node = self.nodes[code]
            code = node.right if bits.read(1) else node.left
        return code

    def _parent_leaf(self, code: int) -> tuple[_Node, str]:
        parent = self.nodes[self.nodes[code].parent]
        return parent, "left" if parent.left == code else "right"

    def update(self, code: int) -> None:
        while code != self.root:
            node = self.nodes[code]
            node.frequency += 1
            index = node.index
            destination = index
            while (
                destination != self.root
                and node.frequency > self.nodes[self.code_map[destination + 1]].frequency
            ):
                destination += 1
            if index != destination:
                other_code = self.code_map[destination]
                other = self.nodes[other_code]
                node.index, other.index = other.index, node.index
                self.code_map[index], self.code_map[destination] = (
                    self.code_map[destination],
                    self.code_map[index],
                )
                parent1, side1 = self._parent_leaf(code)
                parent2, side2 = self._parent_leaf(other_code)
                setattr(parent1, side1, other_code)
                setattr(parent2, side2, code)
                node.parent, other.parent = other.parent, node.parent
            code = self.nodes[code].parent
        self.nodes[code].frequency += 1

    @property
    def maximum_frequency(self) -> int:
        return self.nodes[self.root].frequency


_DISTANCE_BITS = (5, 5, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 9, 9, 9, 10)


@register("LHLB")
def decompress_lhlb(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode the lh.library-compatible LHLB format."""

    del previous
    source = ByteInput(payload)
    bits = BitReader(source.word, 16)
    decoder = _DynamicHuffman()
    output = bytearray()
    while len(output) < output_size:
        code = decoder.decode(bits)
        if code == 316:
            break
        if decoder.maximum_frequency < 0x8000:
            decoder.update(code)
        if code < 256:
            output.append(code)
            continue
        distance = variable_length(bits, _DISTANCE_BITS, bits.read(4))
        count = code - 255
        if distance:
            copy_forward(output, distance, count, output_size)
        else:
            if len(output) + count > output_size:
                raise CorruptDataError("LHLB zero run exceeds declared size")
            output.extend(bytes(count))
    output.extend(bytes(output_size - len(output)))
    return bytes(output)

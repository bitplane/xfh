"""Pure-Python decoder for the classic Amiga LZX archive format.

This is the Amiga archiver format, not the unrelated Microsoft LZX format.
The implementation follows the independently documented decoder in
``amiga-lzx`` and is intentionally limited to the single-entry archives
embedded by the ELZX and SLZX XPK libraries.
"""

from dataclasses import dataclass
from zlib import crc32

from xfh.errors import CorruptDataError

_MAIN_SYMBOLS = 768
_LITERAL_SYMBOLS = 256
_ALIGNED_SYMBOLS = 8
_PRETREE_SYMBOLS = 20
_TABLE_ONE = (
    0,
    0,
    0,
    0,
    1,
    1,
    2,
    2,
    3,
    3,
    4,
    4,
    5,
    5,
    6,
    6,
    7,
    7,
    8,
    8,
    9,
    9,
    10,
    10,
    11,
    11,
    12,
    12,
    13,
    13,
    14,
    14,
)
_TABLE_TWO = (
    0,
    1,
    2,
    3,
    4,
    6,
    8,
    12,
    16,
    24,
    32,
    48,
    64,
    96,
    128,
    192,
    256,
    384,
    512,
    768,
    1024,
    1536,
    2048,
    3072,
    4096,
    6144,
    8192,
    12288,
    16384,
    24576,
    32768,
    49152,
)


class _Bits:
    """Least-significant-bit reader refilled with big-endian 16-bit words."""

    def __init__(self, data: bytes):
        self._data = data
        self._offset = 0
        self._content = 0
        self._length = 0

    def read(self, count: int) -> int:
        if not 0 <= count <= 16:
            raise CorruptDataError("invalid Amiga LZX bit count")
        result = 0
        position = 0
        while count:
            if not self._length:
                if self._offset + 2 > len(self._data):
                    raise CorruptDataError("truncated Amiga LZX bitstream")
                self._content = int.from_bytes(self._data[self._offset : self._offset + 2], "big")
                self._offset += 2
                self._length = 16
            take = min(count, self._length)
            result |= (self._content & ((1 << take) - 1)) << position
            self._content >>= take
            self._length -= take
            position += take
            count -= take
        return result


@dataclass(frozen=True, slots=True)
class _Huffman:
    codes: dict[tuple[int, int], int]
    maximum: int

    @classmethod
    def build(cls, lengths: list[int], name: str) -> "_Huffman":
        if any(length < 0 or length > 16 for length in lengths):
            raise CorruptDataError(f"invalid Amiga LZX {name} code length")
        counts = [0] * 17
        for length in lengths:
            counts[length] += 1
        if counts[0] == len(lengths):
            raise CorruptDataError(f"empty Amiga LZX {name} tree")
        # Length zero means "symbol absent", not a canonical-code level.
        counts[0] = 0

        remaining = 1
        for length in range(1, 17):
            remaining = remaining * 2 - counts[length]
            if remaining < 0:
                raise CorruptDataError(f"oversubscribed Amiga LZX {name} tree")
        if remaining:
            raise CorruptDataError(f"incomplete Amiga LZX {name} tree")

        next_code = [0] * 17
        code = 0
        for length in range(1, 17):
            code = (code + counts[length - 1]) << 1
            next_code[length] = code

        codes: dict[tuple[int, int], int] = {}
        maximum = 0
        for symbol, length in enumerate(lengths):
            if not length:
                continue
            canonical = next_code[length]
            next_code[length] += 1
            reversed_code = int(f"{canonical:0{length}b}"[::-1], 2)
            codes[(length, reversed_code)] = symbol
            maximum = max(maximum, length)
        return cls(codes, maximum)

    def decode(self, bits: _Bits) -> int:
        code = 0
        for length in range(1, self.maximum + 1):
            code |= bits.read(1) << (length - 1)
            symbol = self.codes.get((length, code))
            if symbol is not None:
                return symbol
        raise CorruptDataError("invalid Amiga LZX Huffman code")


def _decode_lengths(bits: _Bits, lengths: list[int], *, literal: bool) -> None:
    pretree_lengths = [bits.read(4) for _ in range(_PRETREE_SYMBOLS)]
    pretree = _Huffman.build(pretree_lengths, "pretree")
    short_base = 4 if literal else 3
    long_base = 20 if literal else 19
    long_bits = 5 if literal else 6
    index = 0
    while index < len(lengths):
        symbol = pretree.decode(bits)
        if symbol <= 16:
            lengths[index] = (lengths[index] - symbol) % 17
            index += 1
            continue
        if symbol == 17:
            run = short_base + bits.read(4)
            value = 0
        elif symbol == 18:
            run = long_base + bits.read(long_bits)
            value = 0
        elif symbol == 19:
            run = short_base + bits.read(1)
            delta = pretree.decode(bits)
            if delta > 16:
                raise CorruptDataError("invalid Amiga LZX pretree delta")
            value = (lengths[index] - delta) % 17
        else:  # pragma: no cover - the pretree alphabet ends at 19
            raise CorruptDataError("invalid Amiga LZX pretree symbol")
        if index + run > len(lengths):
            raise CorruptDataError("Amiga LZX code-length run exceeds its table")
        lengths[index : index + run] = [value] * run
        index += run


def _decode_stream(payload: bytes, expected: int) -> bytes:
    if not expected:
        if payload:
            raise CorruptDataError("nonempty Amiga LZX stream for empty entry")
        return b""

    bits = _Bits(payload)
    main_lengths = [0] * _MAIN_SYMBOLS
    aligned_lengths = [0] * _ALIGNED_SYMBOLS
    main_tree: _Huffman | None = None
    aligned_tree: _Huffman | None = None
    output = bytearray()
    last_distance = 1

    while len(output) < expected:
        method = bits.read(3)
        if method not in (1, 2, 3):
            raise CorruptDataError(f"unsupported Amiga LZX block type {method}")
        if method == 3:
            aligned_lengths[:] = [bits.read(3) for _ in range(_ALIGNED_SYMBOLS)]
            aligned_tree = _Huffman.build(aligned_lengths, "aligned")

        block_size = (bits.read(8) << 16) | (bits.read(8) << 8) | bits.read(8)
        if not block_size or len(output) + block_size > expected:
            raise CorruptDataError("invalid Amiga LZX block size")
        if method != 1:
            literal_lengths = main_lengths[:_LITERAL_SYMBOLS]
            match_lengths = main_lengths[_LITERAL_SYMBOLS:]
            _decode_lengths(bits, literal_lengths, literal=True)
            _decode_lengths(bits, match_lengths, literal=False)
            main_lengths[:] = literal_lengths + match_lengths
            main_tree = _Huffman.build(main_lengths, "main")
        elif main_tree is None:
            raise CorruptDataError("Amiga LZX stream reuses a missing Huffman tree")

        block_end = len(output) + block_size
        while len(output) < block_end:
            assert main_tree is not None
            symbol = main_tree.decode(bits)
            if symbol < _LITERAL_SYMBOLS:
                output.append(symbol)
                continue

            match = symbol - _LITERAL_SYMBOLS
            position_slot = match & 31
            length_slot = (match >> 5) & 15
            footer_bits = _TABLE_ONE[position_slot]
            distance = _TABLE_TWO[position_slot]
            if footer_bits >= 3 and method == 3:
                distance += bits.read(footer_bits - 3) << 3
                if aligned_tree is None:
                    raise CorruptDataError("missing Amiga LZX aligned tree")
                distance += aligned_tree.decode(bits)
            elif footer_bits:
                distance += bits.read(footer_bits)
            if not distance:
                distance = last_distance
            if not distance or distance > len(output):
                raise CorruptDataError("invalid Amiga LZX backward reference")
            last_distance = distance

            length_bits = _TABLE_ONE[length_slot]
            length = _TABLE_TWO[length_slot] + 3
            if length_bits:
                length += bits.read(length_bits)
            if len(output) + length > block_end:
                raise CorruptDataError("Amiga LZX match exceeds its block")
            for _ in range(length):
                output.append(output[-distance])

    return bytes(output)


def decompress_archive(data: bytes, output_size: int) -> bytes:
    """Decode the single-entry Amiga LZX archive embedded in an XPK chunk."""

    if len(data) < 41 or data[:4] != b"LZX\0":
        raise CorruptDataError("invalid embedded Amiga LZX archive")

    fixed = bytearray(data[10:41])
    original_size = int.from_bytes(fixed[2:6], "little")
    compressed_size = int.from_bytes(fixed[6:10], "little")
    pack_mode = fixed[11]
    merged = fixed[12]
    comment_size = fixed[14]
    data_checksum = int.from_bytes(fixed[22:26], "little")
    header_checksum = int.from_bytes(fixed[26:30], "little")
    filename_size = fixed[30]
    header_end = 41 + filename_size + comment_size
    payload_end = header_end + compressed_size

    if original_size != output_size:
        raise CorruptDataError("embedded Amiga LZX output size mismatch")
    if merged:
        raise CorruptDataError("merged Amiga LZX entry is not valid in an XPK wrapper")
    if payload_end != len(data):
        raise CorruptDataError("embedded Amiga LZX archive has invalid lengths")

    variable = data[41:header_end]
    fixed[26:30] = b"\0\0\0\0"
    if crc32(fixed + variable) != header_checksum:
        raise CorruptDataError("embedded Amiga LZX header checksum mismatch")

    payload = data[header_end:payload_end]
    if not original_size:
        decoded = b""
    elif pack_mode == 0:
        if compressed_size != original_size:
            raise CorruptDataError("invalid stored Amiga LZX entry size")
        decoded = payload
    elif pack_mode == 2:
        decoded = _decode_stream(payload, original_size)
    else:
        raise CorruptDataError(f"unsupported Amiga LZX pack mode {pack_mode}")

    if crc32(decoded) != data_checksum:
        raise CorruptDataError("embedded Amiga LZX data checksum mismatch")
    return decoded

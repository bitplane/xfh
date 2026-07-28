"""XPK RAKE decompression.

Derived from Ancient's RAKEDecompressor, Copyright (c) 2017-2025
Teemu Suutari, under the BSD 2-Clause License.
"""

from base64 import b64decode

from xfh.codecs import register
from xfh.errors import CorruptDataError

_LENGTHS = b64decode(
    "AQMFBgcJDBISEhIQEhISEhEREREQERISEA0NDQ4ODw8QEREPCwwNDQgEBgoMDQ0M"
    "DAkIBwUKCgoLEREREREREBEREREPDg4NDQkKDA0REhMTEA8QEBAQDA0QEA8PEBES"
    "EgcGCQsLCggJDA4PExMSExMSERITEw0MEhITExISExMTExIREhISExMSExMTExIT"
    "ExISExMSEhMTEhITExISERISExMSEhMTEhIREhITExISEhEREhIRERERERMTEhEQ"
    "Dw8QEA4ODAsIBwoNDw8PDwwNDxESEhAODAkLDBAQEBAPEBANCxAQDw8PDQ0NDQ8R"
    "EREREREREREREAwMDAoD"
)
_VALUES = bytes.fromhex(
    "010305090c1334c0c2c3c679c7d6d7d8a8928a826c94daca7b3639484950625e"
    "6f8387562131383d0f04081c27423a303216110b06191a182698999b9e9fa673"
    "7f8184855d4d4f453c171dff418caadbdc77637c76717d2c3b7a75556074a4ab"
    "ac0a071520241b1012334b53dddeaddfe0ae88afe1e2372eb0b1e3e4b2b3e5e6"
    "e7e8b49ab5b6b7e9eab8ebecedeeb9eff0bbbcf1f2bdbef3f4bfc1f5f6c4c5"
    "95c8c9f7f8cbccf9facdce96cfd0fbfcd1d2d39c9dd4d5a0a1a2a3a5fdfed9"
    "a76654576b684c4e28230e0d1f476458595a293e5f8ebaa9704a2a14222f7e67"
    "696551786a4625726e5b61524043443f5c93808d8b8689978f90916d2b2d351e"
    "02"
)


def _huffman_codes() -> dict[tuple[int, int], int]:
    codes: dict[tuple[int, int], int] = {}
    canonical = 0
    for length, value in zip(_LENGTHS, _VALUES, strict=True):
        codes[length, canonical >> (32 - length)] = value
        canonical += 1 << (32 - length)
    return codes


_CODES = _huffman_codes()


class _RakeBits:
    def __init__(self, data: bytes, offset: int, discarded: int):
        if discarded > 32 or offset + 4 > len(data):
            raise CorruptDataError("invalid RAKE bit-stream header")
        word = int.from_bytes(data[offset : offset + 4], "big")
        self._data = data
        self._offset = offset + 4
        self._content = word >> discarded
        self._length = 32 - discarded

    def read(self, count: int) -> int:
        result = 0
        while count:
            if not self._length:
                if self._offset + 4 > len(self._data):
                    raise CorruptDataError("truncated RAKE bit stream")
                self._content = int.from_bytes(self._data[self._offset : self._offset + 4], "big")
                self._offset += 4
                self._length = 32
            take = min(count, self._length)
            self._length -= take
            result = (result << take) | ((self._content >> self._length) & ((1 << take) - 1))
            count -= take
        return result


def _decode_length(bits: _RakeBits) -> int:
    code = 0
    for length in range(1, 20):
        code = (code << 1) | bits.read(1)
        value = _CODES.get((length, code))
        if value is not None:
            return value + 2
    raise CorruptDataError("invalid RAKE Huffman code")


@register("RAKE")
def decompress_rake(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode one RAKE chunk."""

    del previous
    if len(payload) < 8:
        raise CorruptDataError("truncated RAKE stream")
    discarded = int.from_bytes(payload[:2], "big")
    middle = int.from_bytes(payload[2:4], "big")
    bit_offset = middle + (middle & 1)
    if middle < 4 or middle >= len(payload) or bit_offset >= len(payload):
        raise CorruptDataError("invalid RAKE stream split")

    bits = _RakeBits(payload, bit_offset, discarded)
    literal_offset = middle
    output = bytearray(output_size)
    output_offset = output_size

    def literal() -> int:
        nonlocal literal_offset
        if literal_offset <= 4:
            raise CorruptDataError("truncated RAKE literal stream")
        literal_offset -= 1
        return payload[literal_offset]

    def write(value: int) -> None:
        nonlocal output_offset
        if not output_offset:
            raise CorruptDataError("RAKE output exceeds declared size")
        output_offset -= 1
        output[output_offset] = value

    while output_offset:
        if not bits.read(1):
            write(literal())
            continue

        count = _decode_length(bits)
        if not bits.read(1):
            distance = literal() + 1
        elif not bits.read(1):
            distance = (bits.read(3) << 8) | literal()
            distance += 0x101
        else:
            distance = (bits.read(6) << 8) | literal()
            distance += 0x901

        if count > output_offset or output_offset + distance > output_size:
            raise CorruptDataError(
                f"invalid RAKE backward reference distance={distance}, "
                f"count={count}, remaining={output_offset}"
            )
        for _ in range(count):
            write(output[output_offset + distance - 1])

    return bytes(output)

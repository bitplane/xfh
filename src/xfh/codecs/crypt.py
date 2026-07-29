"""Historical XPK encryption codecs.

These algorithms are provided for data recovery, not for protecting new data.
"""

from __future__ import annotations

from functools import lru_cache
from math import isqrt
from struct import unpack_from

from xfh.codecs import register_encrypted
from xfh.errors import CorruptDataError, IncorrectPasswordError, UnsupportedCodecError

_MASK16 = 0xFFFF
_MASK32 = 0xFFFFFFFF


def _wrong_password(message: str = "incorrect password or damaged encrypted data") -> None:
    raise IncorrectPasswordError(message)


@register_encrypted("ENCO")
def decompress_enco(payload: bytes, output_size: int, previous: bytes, password: bytes) -> bytes:
    """Decode the original one-byte XOR/checksum demonstration codec."""

    del previous
    if len(payload) != output_size + 1:
        raise CorruptDataError("invalid ENCO chunk length")
    key = 0
    for byte in password:
        key ^= byte
    output = bytes(byte ^ key for byte in payload[:-1])
    if sum(output) & 0xFF != payload[-1]:
        _wrong_password()
    return output


def _rol8(value: int, count: int) -> int:
    return ((value << count) | (value >> (8 - count))) & 0xFF


def _feal_f(value: int, key: int) -> int:
    a0, a1, a2, a3 = value.to_bytes(4, "big")
    b0, b1 = key.to_bytes(2, "big")
    f1 = a1 ^ a0
    f2 = a2 ^ a3
    f1 = _rol8(f1 + (f2 ^ b0) + 1, 2)
    f2 = _rol8(f2 + (f1 ^ b1), 2)
    f0 = _rol8(a0 + f1, 2)
    f3 = _rol8(a3 + f2 + 1, 2)
    return (f0 << 24) | (f1 << 16) | (f2 << 8) | f3


def _feal_password(password: bytes) -> tuple[int, int]:
    left = right = 0
    for byte in password:
        left, right = right, (((left << 9) | (left >> 23)) + byte) & _MASK32
    return left, right


def _feal_keys(password: bytes, rounds: int) -> list[int]:
    left, right = _feal_password(password)
    a, b, d = left, right, 0
    words: list[int] = []
    for _ in range(rounds // 2 + 4):
        c = _feal_f(a, b ^ d)
        d, a, b = a, b, c
        words.extend((c >> 16, c & _MASK16))
    return words


def _feal_block(block: bytes, keys: list[int], rounds: int) -> bytes:
    left, right = unpack_from(">II", block)
    left ^= (keys[rounds] << 16) | keys[rounds + 1]
    right ^= (keys[rounds + 2] << 16) | keys[rounds + 3]
    right ^= left
    for index in range(rounds):
        left, right = right, left ^ _feal_f(right, keys[index])
    left ^= right
    right ^= (keys[rounds + 4] << 16) | keys[rounds + 5]
    left ^= (keys[rounds + 6] << 16) | keys[rounds + 7]
    return right.to_bytes(4, "big") + left.to_bytes(4, "big")


@register_encrypted("FEAL")
def decompress_feal(payload: bytes, output_size: int, previous: bytes, password: bytes) -> bytes:
    """Decode FEAL-N in the sublibrary's CBC1 framing."""

    del previous
    if len(payload) < 12 or (len(payload) - 4) % 8:
        raise CorruptDataError("invalid FEAL chunk length")
    checksum, chaining_mode, rounds = unpack_from(">HBB", payload)
    if chaining_mode != 1 or rounds < 2 or rounds > 64 or rounds & 1:
        raise UnsupportedCodecError("FEAL", rounds)
    keys = _feal_keys(password, rounds)
    # The original decryptor runs the encryption primitive with this key permutation.
    keys[:rounds] = reversed(keys[:rounds])
    keys[rounds : rounds + 4], keys[rounds + 4 : rounds + 8] = (
        keys[rounds + 4 : rounds + 8],
        keys[rounds : rounds + 4],
    )
    output = bytearray()
    last_ciphertext = b"\0" * 8
    for offset in range(4, len(payload), 8):
        ciphertext = payload[offset : offset + 8]
        plaintext = bytes(
            a ^ b
            for a, b in zip(_feal_block(ciphertext, keys, rounds), last_ciphertext, strict=True)
        )
        checksum = (checksum - int.from_bytes(plaintext[:4], "big")) & _MASK16
        output.extend(plaintext)
        last_ciphertext = ciphertext
    if checksum:
        _wrong_password()
    tail = output[-1]
    if tail > 7 or len(output) - 8 + tail != output_size:
        _wrong_password()
    if any(output[-8 + tail : -1]):
        _wrong_password()
    return bytes(output[:-8] + output[-8 : -8 + tail])


def _idea_mul(left: int, right: int) -> int:
    left = 0x10000 if left == 0 else left
    right = 0x10000 if right == 0 else right
    result = left * right % 0x10001
    return 0 if result == 0x10000 else result


def _idea_mul_inv(value: int) -> int:
    source = 0x10000 if value == 0 else value
    inverse = pow(source, -1, 0x10001)
    return 0 if inverse == 0x10000 else inverse


def _idea_expand(key: bytes) -> list[int]:
    value = int.from_bytes(key, "big")
    words: list[int] = []
    while len(words) < 52:
        words.extend((value >> shift) & _MASK16 for shift in range(112, -1, -16))
        value = ((value << 25) | (value >> 103)) & ((1 << 128) - 1)
    return words[:52]


def _idea_invert(key: list[int]) -> list[int]:
    result = [
        _idea_mul_inv(key[48]),
        (-key[49]) & _MASK16,
        (-key[50]) & _MASK16,
        _idea_mul_inv(key[51]),
        key[46],
        key[47],
    ]
    for start in range(42, 0, -6):
        result.extend(
            (
                _idea_mul_inv(key[start]),
                (-key[start + 2]) & _MASK16,
                (-key[start + 1]) & _MASK16,
                _idea_mul_inv(key[start + 3]),
                key[start - 2],
                key[start - 1],
            )
        )
    result.extend(
        (
            _idea_mul_inv(key[0]),
            (-key[1]) & _MASK16,
            (-key[2]) & _MASK16,
            _idea_mul_inv(key[3]),
        )
    )
    return result


def _idea_block(block: bytes, key: list[int]) -> bytes:
    x1, x2, x3, x4 = unpack_from(">4H", block)
    position = 0
    for _ in range(8):
        y1 = _idea_mul(x1, key[position])
        y2 = (x2 + key[position + 1]) & _MASK16
        y3 = (x3 + key[position + 2]) & _MASK16
        y4 = _idea_mul(x4, key[position + 3])
        t0 = _idea_mul(y1 ^ y3, key[position + 4])
        t1 = _idea_mul(((y2 ^ y4) + t0) & _MASK16, key[position + 5])
        t0 = (t0 + t1) & _MASK16
        x1, x2, x3, x4 = y1 ^ t1, y3 ^ t1, y2 ^ t0, y4 ^ t0
        position += 6
    result = (
        _idea_mul(x1, key[48]),
        (x3 + key[49]) & _MASK16,
        (x2 + key[50]) & _MASK16,
        _idea_mul(x4, key[51]),
    )
    return b"".join(word.to_bytes(2, "big") for word in result)


def _idea_value(text: bytes, width: int) -> int:
    if not text:
        return 0
    if text.startswith(b"#"):
        digits = text[1:]
        if any(byte not in b"0123456789abcdefABCDEF" for byte in digits):
            _wrong_password("invalid IDEA password syntax")
        value = int(digits or b"0", 16)
        if value >= 1 << (width * 8):
            _wrong_password("invalid IDEA password syntax")
        return value
    if any(byte < 0x21 or byte > 0x7E for byte in text):
        _wrong_password("invalid IDEA password syntax")
    value = 0
    mask = (1 << (width * 8)) - 1
    for byte in text:
        value = (value * 94 + byte - 0x21) & mask
    return value


def _idea_password(password: bytes) -> tuple[bytes, list[bytes]]:
    fields = password.split(b":")
    key = _idea_value(fields[0], 16).to_bytes(16, "big")
    if len(fields) > 26:
        _wrong_password("invalid IDEA password syntax")
    initializers = [_idea_value(field, 8).to_bytes(8, "big") for field in fields[1:]]
    initializers.extend([b"\0" * 8] * (25 - len(initializers)))
    return key, initializers


def _idea_decrypt_payload(payload: bytes, password: bytes) -> bytes:
    if len(payload) < 10 or (len(payload) - 10) % 8:
        raise CorruptDataError("invalid IDEA chunk length")
    mode, original_size, checksum = unpack_from(">IIH", payload)
    encrypted = payload[10:]
    if original_size > len(encrypted) or len(encrypted) - original_size > 7:
        raise CorruptDataError("invalid IDEA original length")
    key_bytes, initializers = _idea_password(password)
    encryption_key = _idea_expand(key_bytes)
    blocks = [encrypted[index : index + 8] for index in range(0, len(encrypted), 8)]
    output: list[bytes] = []
    if mode <= 25:
        decryption_key = _idea_invert(encryption_key)
        output = [_idea_block(block, decryption_key) for block in blocks]
    elif mode <= 50:  # CFB
        states = mode - 25
        for index, block in enumerate(blocks):
            prior = initializers[index] if index < states else blocks[index - states]
            stream = _idea_block(prior, encryption_key)
            output.append(bytes(a ^ b for a, b in zip(block, stream, strict=True)))
    elif mode <= 75:  # OFB
        states = mode - 50
        state = initializers[:states]
        for index, block in enumerate(blocks):
            slot = index % states
            state[slot] = _idea_block(state[slot], encryption_key)
            output.append(bytes(a ^ b for a, b in zip(block, state[slot], strict=True)))
    elif mode <= 100:  # CBC
        states = mode - 75
        decryption_key = _idea_invert(encryption_key)
        for index, block in enumerate(blocks):
            prior = initializers[index] if index < states else blocks[index - states]
            decoded = _idea_block(block, decryption_key)
            output.append(bytes(a ^ b for a, b in zip(decoded, prior, strict=True)))
    else:
        raise UnsupportedCodecError("IDEA", mode)
    padded = b"".join(output)
    calculated = (
        sum(int.from_bytes(padded[index : index + 2], "big") for index in range(0, len(padded), 2))
        & _MASK16
    )
    if calculated != checksum:
        _wrong_password()
    if any(padded[original_size:]):
        _wrong_password()
    return padded[:original_size]


@register_encrypted("IDEA")
def decompress_idea(payload: bytes, output_size: int, previous: bytes, password: bytes) -> bytes:
    """Decode the XPK IDEA sublibrary's ECB and chained modes."""

    del previous
    output = _idea_decrypt_payload(payload, password)
    if len(output) != output_size:
        raise CorruptDataError("IDEA chunk produced the wrong size")
    return output


@register_encrypted("NUID")
def decompress_nuid(payload: bytes, output_size: int, previous: bytes, password: bytes) -> bytes:
    """Decode the NUKE-then-IDEA composite sublibrary."""

    from xfh.codecs.nuke import decompress_nuke

    packed = _idea_decrypt_payload(payload, password)
    return decompress_nuke(packed, output_size, previous)


def decrypt_shid(payload: bytes, password: bytes) -> bytes:
    """Remove the IDEA layer from one SHID chunk."""

    return _idea_decrypt_payload(payload, password)


@register_encrypted("SHID")
def decompress_shid(payload: bytes, output_size: int, previous: bytes, password: bytes) -> bytes:
    """Decode one independently framed SHRI-then-IDEA chunk."""

    from xfh.codecs.shri import decompress_shri

    return decompress_shri(decrypt_shid(payload, password), output_size, previous)


@lru_cache(maxsize=1)
def _pi_words() -> tuple[int, ...]:
    """Return Blowfish's standard hexadecimal digits of pi.

    Computing the public constants avoids carrying a copied implementation or
    adding a crypto dependency.  The result is cached by ``_blowfish_keys``.
    """

    digits = (18 + 4 * 256) * 8
    guard = 8
    scale = 16 ** (digits + guard)
    terms = (digits * 5 // 14) + 2
    constant = 640320**3 // 24

    def split(lower: int, upper: int) -> tuple[int, int, int]:
        if upper - lower == 1:
            if lower == 0:
                return 1, 1, 13591409
            p = (6 * lower - 5) * (2 * lower - 1) * (6 * lower - 1)
            q = lower**3 * constant
            t = p * (13591409 + 545140134 * lower)
            return p, q, -t if lower & 1 else t
        middle = (lower + upper) // 2
        p1, q1, t1 = split(lower, middle)
        p2, q2, t2 = split(middle, upper)
        return p1 * p2, q1 * q2, t1 * q2 + p1 * t2

    _, q, t = split(0, terms)
    pi = q * 426880 * isqrt(10005 * scale * scale) // t
    fraction = (pi - 3 * scale) // (16**guard)
    return tuple(
        (fraction >> (4 * (digits - index - 8))) & _MASK32 for index in range(0, digits, 8)
    )


@lru_cache(maxsize=8)
def _blowfish_keys(password: bytes) -> tuple[list[int], list[list[int]]]:
    if not password:
        password = b"\0"
    constants = _pi_words()
    p = list(constants[:18])
    boxes = [list(constants[18 + index * 256 : 18 + (index + 1) * 256]) for index in range(4)]
    position = 0
    for index in range(18):
        word = 0
        for _ in range(4):
            word = (word << 8) | password[position]
            position = (position + 1) % len(password)
        p[index] ^= word
    left = right = 0
    for index in range(0, 18, 2):
        left, right = _blowfish_encrypt_words(left, right, p, boxes)
        p[index : index + 2] = (left, right)
    for box in boxes:
        for index in range(0, 256, 2):
            left, right = _blowfish_encrypt_words(left, right, p, boxes)
            box[index : index + 2] = (left, right)
    return p, boxes


def _blowfish_f(value: int, boxes: list[list[int]]) -> int:
    return (
        ((boxes[0][value >> 24] + boxes[1][value >> 16 & 0xFF]) & _MASK32)
        ^ boxes[2][value >> 8 & 0xFF]
    ) + boxes[3][value & 0xFF] & _MASK32


def _blowfish_encrypt_words(
    left: int, right: int, p: list[int], boxes: list[list[int]]
) -> tuple[int, int]:
    for index in range(16):
        left ^= p[index]
        right ^= _blowfish_f(left, boxes)
        left, right = right, left
    left, right = right, left
    right ^= p[16]
    left ^= p[17]
    return left, right


def _blowfish_decrypt_block(block: bytes, p: list[int], boxes: list[list[int]]) -> bytes:
    left, right = unpack_from(">II", block)
    for index in range(17, 1, -1):
        left ^= p[index]
        right ^= _blowfish_f(left, boxes)
        left, right = right, left
    left, right = right, left
    right ^= p[1]
    left ^= p[0]
    return left.to_bytes(4, "big") + right.to_bytes(4, "big")


def _blowfish_encrypt_block(block: bytes, p: list[int], boxes: list[list[int]]) -> bytes:
    return b"".join(
        word.to_bytes(4, "big")
        for word in _blowfish_encrypt_words(*unpack_from(">II", block), p, boxes)
    )


def _blfh_unpack(data: bytes, output_size: int) -> bytes:
    if len(data) < 8:
        raise CorruptDataError("truncated BLFH packed stream")
    stored_checksum = int.from_bytes(data[-3:-1], "big")
    if data[-1] != 0:
        _wrong_password()
    position = 0
    output = bytearray()
    while True:
        if position + 2 > len(data) - 3:
            raise CorruptDataError("missing BLFH packed end marker")
        control = int.from_bytes(data[position : position + 2], "big")
        position += 2
        if control & 0x8000:
            used = control & 0x7FFF
            if used > 15:
                raise CorruptDataError("invalid BLFH packed end marker")
            unused = 15 - used
            if unused > len(output):
                raise CorruptDataError("invalid BLFH packed tail")
            if unused:
                del output[-unused:]
            break
        for bit in range(14, -1, -1):
            if control & (1 << bit):
                if position + 2 > len(data) - 3:
                    raise CorruptDataError("truncated BLFH packed match")
                match = int.from_bytes(data[position : position + 2], "big")
                position += 2
                length = match & 0xF or 16
                distance = match >> 4 or 4096
                if distance > len(output):
                    raise CorruptDataError("invalid BLFH packed distance")
                for _ in range(length):
                    if len(output) >= output_size + 15:
                        raise CorruptDataError("BLFH packed output exceeds its declared size")
                    output.append(output[-distance])
            else:
                if position >= len(data) - 3:
                    raise CorruptDataError("truncated BLFH packed literal")
                if len(output) >= output_size + 15:
                    raise CorruptDataError("BLFH packed output exceeds its declared size")
                output.append(data[position])
                position += 1
    if any(data[position:-3]):
        raise CorruptDataError("non-zero BLFH packed padding")
    checksum = (
        sum(int.from_bytes(data[index : index + 2], "big") for index in range(0, position, 2))
        & _MASK16
    )
    if checksum != stored_checksum:
        _wrong_password()
    if len(output) != output_size:
        raise CorruptDataError("BLFH packed stream produced the wrong size")
    return bytes(output)


@register_encrypted("BLFH")
def decompress_blfh(payload: bytes, output_size: int, previous: bytes, password: bytes) -> bytes:
    """Decode Blowfish ECB/OFB/CFB/CBC modes from BLFH 2.x."""

    del previous
    if len(payload) < 2 or payload[0] not in (0x14, 0x15):
        raise CorruptDataError("unsupported BLFH chunk version")
    mode = payload[1]
    if mode > 100:
        raise UnsupportedCodecError("BLFH", mode)
    chained = mode >= 26
    offset = 2
    initializer = b"\0" * 8
    if chained:
        if len(payload) < 10:
            raise CorruptDataError("truncated BLFH initializer")
        initializer = payload[offset : offset + 8]
        offset += 8
    packed = False
    if (len(payload) - offset) % 8 == 1:
        packing_flag = payload[offset]
        offset += 1
        if packing_flag > 1:
            raise CorruptDataError("invalid BLFH packing flag")
        packed = packing_flag == 1
    ciphertext = payload[offset:]
    if not ciphertext or len(ciphertext) % 8:
        raise CorruptDataError("invalid BLFH encrypted length")
    p, boxes = _blowfish_keys(password)
    blocks = [ciphertext[index : index + 8] for index in range(0, len(ciphertext), 8)]
    output: list[bytes] = []
    state = initializer
    if mode < 26:  # ECB
        output = [_blowfish_decrypt_block(block, p, boxes) for block in blocks]
    elif mode < 51:  # OFB
        for block in blocks:
            state = _blowfish_encrypt_block(state, p, boxes)
            output.append(bytes(a ^ b for a, b in zip(block, state, strict=True)))
    elif mode < 76:  # CFB
        for block in blocks:
            stream = _blowfish_encrypt_block(state, p, boxes)
            output.append(bytes(a ^ b for a, b in zip(block, stream, strict=True)))
            state = block
    else:  # CBC
        for block in blocks:
            decoded = _blowfish_decrypt_block(block, p, boxes)
            output.append(bytes(a ^ b for a, b in zip(decoded, state, strict=True)))
            state = block
    padded = b"".join(output)
    if packed:
        return _blfh_unpack(padded, output_size)
    # The raw form reserves two checksum bytes and a length marker, then rounds
    # the whole buffer up to a Blowfish block boundary.
    expected_padded_size = (output_size + 3 + 7) & ~7
    if len(padded) != expected_padded_size:
        _wrong_password()
    if not padded or padded[-1] != output_size & 7:
        _wrong_password()
    stored_checksum = int.from_bytes(padded[-3:-1], "big")
    checksum = (
        sum(
            int.from_bytes(padded[index : index + 2], "big")
            for index in range(0, output_size - 1, 2)
        )
        & _MASK16
    )
    if checksum != stored_checksum:
        _wrong_password()
    return padded[:output_size]

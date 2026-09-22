from pathlib import Path

import pytest

import xfh
from xfh.codecs import decode, supported_codecs
from xfh.errors import IncorrectPasswordError, PasswordRequiredError


def test_encrypted_codecs_are_advertised() -> None:
    assert {"BLFH", "ENCO", "FEAL", "IDEA", "NUID", "SHID"} <= supported_codecs()


def test_enco_password_and_checksum() -> None:
    plain = b"recover me"
    password = b"secret"
    key = 0
    for byte in password:
        key ^= byte
    payload = bytes(byte ^ key for byte in plain) + bytes((sum(plain) & 0xFF,))
    assert decode("ENCO", payload, len(plain), password=password) == plain
    with pytest.raises(PasswordRequiredError):
        decode("ENCO", payload, len(plain))
    with pytest.raises(IncorrectPasswordError):
        decode("ENCO", payload, len(plain), password=b"wrong")


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        ("blfh014-repeat1k.hex", (b"Amiga XPK!" * 128)[:1024]),
        ("blfh039-repeat1k.hex", (b"Amiga XPK!" * 128)[:1024]),
        ("blfh069-repeat1k.hex", (b"Amiga XPK!" * 128)[:1024]),
        ("blfh080-text.hex", b"XFH recovery oracle\r\n" * 4),
        ("blfh089-repeat1k.hex", (b"Amiga XPK!" * 128)[:1024]),
    ],
)
def test_genuine_blfh_oracles(fixture: str, expected: bytes) -> None:
    path = Path(__file__).parent / "fixtures" / "oracle" / fixture
    packed = bytes.fromhex(path.read_text())
    assert xfh.decompress(packed, password="recovery-test") == expected
    with pytest.raises(PasswordRequiredError):
        xfh.decompress(packed)
    with pytest.raises(IncorrectPasswordError):
        xfh.decompress(packed, password="incorrect")


@pytest.mark.parametrize("password", ["nul\0byte", "\u0100"])
def test_unrepresentable_amiga_password_is_rejected(password: str) -> None:
    with pytest.raises(ValueError, match="password"):
        xfh.decompress(b"", password=password)


def test_shid_without_encryption_flag_fails_safely():
    from tests.helpers import xpkf

    packed = xpkf("SHID", [(1, b"abc", 1)])
    with pytest.raises(PasswordRequiredError):
        xfh.decompress(packed)
    result = xfh.salvage(packed)
    assert not result.complete
    assert result.data == b""
    assert "password" in result.issues[0].message


@pytest.mark.parametrize(
    ("rounds", "ciphertext"),
    [(8, "ceef2c86f2490752"), (16, "3ade0d2ad84d0b6f"), (32, "69b0fae6dded6b0b")],
)
def test_feal_published_known_answers(monkeypatch, rounds, ciphertext):
    # Handbook of Applied Cryptography, example 7.99 (Miyaguchi vectors).
    # https://cacr.uwaterloo.ca/hac/about/chap7.pdf
    from xfh.codecs import crypt

    monkeypatch.setattr(crypt, "_feal_password", lambda _: (0x01234567, 0x89ABCDEF))
    keys = crypt._feal_keys(b"", rounds)
    if rounds == 8:
        assert b"".join(k.to_bytes(2, "big") for k in keys).hex() == (
            "df3bca36f17c1aec45a5b9c726ebad258b2aecb7ac509d4c22cd479ba8d50cb5"
        )
    assert crypt._feal_block(bytes(8), keys, rounds).hex() == ciphertext
    # One zero block is the CBC1 padding for an empty XPK chunk.
    payload = b"\0\0\1" + bytes((rounds,)) + bytes.fromhex(ciphertext)
    assert decode("FEAL", payload, 0, password=b"key") == b""


@pytest.mark.parametrize("password", [b"a", b"secret", b"recovery-test"])
def test_feal_passwords_and_cbc_framing(password):
    from xfh.codecs.crypt import _feal_block, _feal_keys

    plaintext = b"recover me"
    padded = plaintext + bytes(5) + b"\2"
    keys = _feal_keys(password, 8)
    previous = bytes(8)
    ciphertext = bytearray()
    for offset in range(0, len(padded), 8):
        block = bytes(a ^ b for a, b in zip(padded[offset : offset + 8], previous, strict=True))
        previous = _feal_block(block, keys, 8)
        ciphertext.extend(previous)
    checksum = sum(int.from_bytes(padded[i : i + 4], "big") for i in (0, 8)) & 0xFFFF
    payload = checksum.to_bytes(2, "big") + b"\1\x08" + ciphertext
    assert decode("FEAL", payload, len(plaintext), password=password) == plaintext
    with pytest.raises(IncorrectPasswordError):
        decode("FEAL", payload, len(plaintext), password=b"wrong")


def test_idea_published_known_answer():
    # Handbook of Applied Cryptography, example 7.108.
    # https://cacr.uwaterloo.ca/hac/about/chap7.pdf
    from xfh.codecs.crypt import _idea_block, _idea_expand, _idea_invert

    key = _idea_expand(bytes.fromhex("00010002000300040005000600070008"))
    plain = bytes.fromhex("0000000100020003")
    cipher = bytes.fromhex("11fbed2b01986de5")
    assert _idea_block(plain, key) == cipher
    assert _idea_block(cipher, _idea_invert(key)) == plain


def _idea_test_payload(plain, mode=0):
    """Synthetic XPK framing; this is not evidence of an original Amiga roundtrip."""
    from xfh.codecs.crypt import _idea_block, _idea_expand

    key = _idea_expand(bytes.fromhex("00010002000300040005000600070008"))
    padded = plain + bytes(-len(plain) % 8)
    checksum = sum(int.from_bytes(padded[i : i + 2], "big") for i in range(0, len(padded), 2))
    blocks = []
    states = [bytes(8)] * 25
    for index, offset in enumerate(range(0, len(padded), 8)):
        block = padded[offset : offset + 8]
        if mode <= 25:
            encrypted = _idea_block(block, key)
        else:
            width = (mode - 1) % 25 + 1
            slot = index % width
            prior = states[slot]
            if mode <= 75:
                stream = _idea_block(prior, key)
                encrypted = bytes(a ^ b for a, b in zip(block, stream, strict=True))
                states[slot] = encrypted if mode <= 50 else stream
            else:
                mixed = bytes(a ^ b for a, b in zip(block, prior, strict=True))
                encrypted = _idea_block(mixed, key)
                states[slot] = encrypted
        blocks.append(encrypted)
    return (
        mode.to_bytes(4, "big")
        + len(plain).to_bytes(4, "big")
        + (checksum & 0xFFFF).to_bytes(2, "big")
        + b"".join(blocks)
    )


_IDEA_TEST_PASSWORD = b"#00010002000300040005000600070008"


@pytest.mark.parametrize("mode", [0, 1, 25, 26, 50, 51, 75, 76, 100])
def test_idea_synthetic_chaining_modes(mode):
    plain = bytes(range(255)) * 2
    payload = _idea_test_payload(plain, mode)
    assert decode("IDEA", payload, len(plain), password=_IDEA_TEST_PASSWORD) == plain
    with pytest.raises(IncorrectPasswordError):
        decode("IDEA", payload, len(plain), password=b"wrong")


@pytest.mark.parametrize(
    ("codec", "fixture"), [("NUID", "nuke050-repeat1k.hex"), ("SHID", "shri100-repeat64k.hex")]
)
def test_idea_composites_with_synthetic_encryption(codec, fixture):
    from tests.helpers import _xor8, xpkf
    from xfh.container import parse
    from xfh.limits import DEFAULT_LIMITS

    original = bytes.fromhex((Path(__file__).parent / "fixtures/oracle" / fixture).read_text())
    parsed = parse(original, DEFAULT_LIMITS)
    chunks = [
        (
            chunk.info.type,
            _idea_test_payload(chunk.payload) if chunk.info.type == 1 else chunk.payload,
            chunk.info.unpacked_size,
        )
        for chunk in parsed.chunks
        if chunk.info.type != 15
    ]
    packed = bytearray(xpkf(codec, chunks, long_headers=True))
    packed[32] |= 2
    packed[33] = 0
    packed[33] = _xor8(packed[:36])
    assert xfh.decompress(packed, password=_IDEA_TEST_PASSWORD) == xfh.decompress(original)
    result = xfh.salvage(packed, password=_IDEA_TEST_PASSWORD)
    assert result.complete
    assert result.data == xfh.decompress(original)
    with pytest.raises(IncorrectPasswordError):
        xfh.decompress(packed, password=b"wrong")

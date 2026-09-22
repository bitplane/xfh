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

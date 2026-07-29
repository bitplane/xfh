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

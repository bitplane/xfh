from xfh.codecs import decode, supported_codecs


def test_fast_literal_stream() -> None:
    # FAST takes literals from the front and control bits from a word at the back.
    assert decode("FAST", b"hello\0\0", 5) == b"hello"


def test_huff_single_symbol_stream() -> None:
    table = bytearray()
    for symbol in range(256):
        if symbol == ord("A"):
            table += b"\0\0"  # one-bit code 0
        else:
            table += b"\xff"  # wrapped length zero: symbol absent
    payload = b"\0\0\xab\xad\xca\xfe" + table + b"\0"
    assert decode("HUFF", payload, 6) == b"A" * 6


def test_initial_codec_set() -> None:
    assert {"NONE", "NUKE", "FAST", "HUFF"} <= supported_codecs()

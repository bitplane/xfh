"""Small deterministic XPKF fixture builders."""


def xor16(data: bytes) -> int:
    high = low = 0
    for index, value in enumerate(data):
        if index & 1:
            low ^= value
        else:
            high ^= value
    return high << 8 | low


def xpkf(codec: str, chunks: list[tuple[int, bytes, int]], initial: bytes = b"") -> bytes:
    raw_size = sum(raw_size for kind, _, raw_size in chunks if kind != 15)
    body = bytearray()
    for kind, payload, chunk_raw_size in [*chunks, (15, b"", 0)]:
        header = bytearray(8)
        header[0] = kind
        header[2:4] = xor16(payload).to_bytes(2, "big")
        header[4:6] = len(payload).to_bytes(2, "big")
        header[6:8] = chunk_raw_size.to_bytes(2, "big")
        header[1] = 0
        header[1] = _xor8(header)
        body += header
        body += payload
        body += b"\0" * (-len(payload) & 3)
    header = bytearray(36)
    header[:4] = b"XPKF"
    header[8:12] = codec.encode("ascii")
    header[12:16] = raw_size.to_bytes(4, "big")
    header[16:32] = initial[: min(16, raw_size)].ljust(16, b"\0")
    header[34:36] = b"\1\2"
    header[4:8] = (len(header) + len(body) - 8).to_bytes(4, "big")
    header[33] = _xor8(header)
    return bytes(header + body)


def _xor8(data: bytes | bytearray) -> int:
    result = 0
    for value in data:
        result ^= value
    return result

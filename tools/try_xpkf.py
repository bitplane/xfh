"""Historical experiment: wrap a recovered payload in a synthetic XPKF header."""

import struct
import subprocess
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_bytes()
unpacked_size = struct.unpack(">I", source[8:12])[0]
codec = source[16:24].split(b"\0")[0][3:7]
temporary = Path("/tmp/_x.xpk")
for data_offset in (24,):
    payload = source[data_offset:]
    for header_length in (36,):
        for checksum in range(256):
            header = bytearray(b"XPKF")
            header += struct.pack(">I", header_length - 8 + len(payload))
            header += codec
            header += struct.pack(">I", unpacked_size)
            header += b"\0" * 16
            header += struct.pack(">H", 0)
            header += bytes([checksum, 0, 0, 0])
            temporary.write_bytes(bytes(header[:header_length]) + payload)
            result = subprocess.run(
                ["ancient", "identify", str(temporary)],
                capture_output=True,
                check=False,
                text=True,
            )
            diagnostic = result.stdout + result.stderr
            if "Unknown" not in diagnostic:
                print(f"HIT chk={checksum} off={data_offset} -> {diagnostic.strip()}")
                raise SystemExit(0)
print("no header checksum made it identifiable")

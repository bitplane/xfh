# 🗜️ xfh

`xfh` is a pure-Python library and command-line tool for recovering files
compressed with the Amiga XPK system, including files written transparently
through DiskExpander.

It requires Python 3.10 or newer and has no runtime dependencies.

## Install

```console
python -m pip install xfh
```

## Help

```console
xfh --help
xfh info --help
xfh verify --help
xfh unpack --help
```

You can also run the command as `python -m xfh`.

## Use

Inspect a packed file:

```console
xfh info packed-file
```

Verify that a file decompresses successfully without writing its contents:

```console
xfh verify packed-file
```

Recover a file:

```console
xfh unpack packed-file recovered-file
```

For an encrypted stream, `xfh` prompts securely for its password. In scripts,
set `XFH_PASSWORD`; passwords are deliberately not accepted as command-line
arguments because process listings can expose them.

Existing output files are not overwritten unless `--force` is supplied.
Output is limited to 256 MiB by default; use `--max-output-size` to choose a
different byte limit.

For a damaged stream, salvage mode writes the prefix recovered before the
first failing chunk. It exits with status 4 when recovery is incomplete:

```console
xfh unpack damaged-file recovered-prefix --salvage --report recovery.json
```

Keep the original packed file unchanged and validate salvaged output with
tools appropriate for its file type.

## Python

```python
from pathlib import Path

import xfh

packed = Path("packed-file").read_bytes()
info = xfh.inspect(packed)
plain = xfh.decompress(packed)  # Add password="..." for an encrypted stream.

print(info.codec, len(plain))
Path("recovered-file").write_bytes(plain)
```

`xfh.decompress_file()` provides atomic, non-overwriting file output.
`xfh.Limits` controls maximum output size, total chunk count across nested
streams, and nesting depth (16 streams by default).

## Supported codecs

`xfh` supports these XPK codec identifiers:

`ACCA`, `ARTM`, `BLFH`, `BLZW`, `BZP2`, `CBR0`, `CBR1`, `CRM2`, `CRMS`, `CYB2`,
`DLTA`, `DUKE`, `ELZX`, `ENCO`, `FAST`, `FBR2`, `FEAL`, `FRHT`, `FRLE`, `GZIP`,
`HFMN`, `HUFF`, `IDEA`, `ILZR`, `IMPL`, `LHLB`, `LZBS`, `LZCB`, `LZW2`, `LZW3`,
`LZW4`, `LZW5`, `MASH`, `NONE`, `NUID`, `NUKE`, `PPMQ`, `PWPK`, `RAKE`, `RDCN`,
`RLEN`, `SASC`, `SDHC`, `SHID`, `SHR3`, `SHRI`, `SHSC`, `SLZ3`, `SLZX`, `SMPL`,
`SQSH`, `TDCS`, and `ZENO`.

`CBR1` is an alias for `CBR0`; `FRHT` is an alias for `RAKE`.
BLFH's packed and unpacked ECB, OFB, CFB, and CBC modes are decoded. Obsolete
ciphers are included solely for recovery and must not be used to protect new
data.

# xfh

`xfh` is a pure-Python data-recovery library and command-line tool for files
compressed with the Amiga XPK system, including files written transparently
through DiskExpander.

The project is under active format-recovery work. It currently supports the
later `XPKF` container, the DiskExpander 2.1 wrapper, and 41 codec identifiers
in pure Python. Historical compatibility identifiers `CBR1` (CBR0) and `FRHT`
(RAKE) are accepted as exact stream-format aliases. See the
[codec support table](https://github.com/bitplane/xfh/blob/master/docs/codec-support.md)
for the evidence and limitations behind each codec.

## Installation

`xfh` requires Python 3.10 or newer and has no runtime dependencies. After the
first release is published to PyPI, install it with:

```console
python -m pip install xfh
```

Until then, install a checkout directly:

```console
python -m pip install .
```

## Quick start

Inspect a stream before writing anything, strictly verify it, and then unpack
it:

```console
xfh info packed-file
xfh verify packed-file
xfh unpack packed-file recovered-file
```

Existing output files are not overwritten unless `--force` is supplied.
Decompression is limited to 256 MiB by default; use `--max-output-size` to set
an appropriate byte limit for a known larger file.

For a damaged stream, salvage mode writes only the prefix decoded before the
first failing chunk. Its exit status is `4` when recovery is incomplete:

```console
xfh unpack damaged-file recovered-prefix --salvage --report recovery.json
```

The public Python API accepts bytes-like input:

```python
from pathlib import Path

import xfh

packed = Path("packed-file").read_bytes()
info = xfh.inspect(packed)
plain = xfh.decompress(packed, limits=xfh.Limits(max_output_size=512 * 1024 * 1024))
Path("recovered-file").write_bytes(plain)

print(info.codec, len(plain))
```

Use `xfh.decompress_file()` when writing to disk: it uses an atomic destination
write and refuses to replace an existing file by default.

## Recovery and stability

Strict decoding validates the container, declared sizes, checksums, chunk
output sizes, and initial-byte prefix where the format provides them. It either
returns the complete declared output or raises an `xfh.XfhError` subclass.
Password-protected streams are detected but not decoded.

Salvage is deliberately opt-in. Its output can be useful evidence, but an
incomplete result is not proof that every returned byte represents an intact
original file. Keep the source media and packed files unchanged, work on
copies, review the recovery report, and validate recovered data with tools
specific to its file type.

This is alpha software reconstructed from historical implementations and
surviving samples. Codec support varies in strength from headless-UAE packer
fixtures to source-derived decoder tests; the support table records that
distinction. The API and command-line interface may change before 1.0.

## Development

Development follows the template workflow:

```console
make dev
make test
make coverage
make lint
make dist
```

See [the original investigation](https://github.com/bitplane/xfh/blob/master/docs/research/initial-findings.md)
for the provenance of the project and
[the format notes](https://github.com/bitplane/xfh/blob/master/docs/format.md)
for current support boundaries. The
[oracle matrix](https://github.com/bitplane/xfh/blob/master/docs/oracle-matrix.md)
records results from the isolated original Amiga implementation.

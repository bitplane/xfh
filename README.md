# xfh

`xfh` is a pure-Python data-recovery library and command-line tool for files
compressed with the Amiga XPK system, including files written transparently
through DiskExpander.

The project is under active format-recovery work. It currently implements the
later `XPKF` container, the DiskExpander 2.1 wrapper, and pure-Python `NONE`,
`NUKE`, `DUKE`, `FAST`, `RAKE`, `HUFF`, `SHRI`, `CBR0`, `RLEN`, `FRLE`,
`RDCN`, `BLZW`, `DLTA`, `SMPL`, `HFMN`, `MASH`, and `SQSH` decompression.
DiskExpander NUKE recovery is proven against a known packed/plain pair.

```console
python -m xfh info packed-file
python -m xfh unpack packed-file recovered-file
```

Strict validation is the default. Partial recovery must be explicitly enabled
with `--salvage`.

Development follows the template workflow:

```console
make dev
make test
make coverage
make lint
make dist
```

See [the original investigation](docs/research/initial-findings.md) for the
provenance of the project and [the format notes](docs/format.md) for current
support boundaries. The [oracle matrix](docs/oracle-matrix.md) records results
from the isolated original Amiga implementation.

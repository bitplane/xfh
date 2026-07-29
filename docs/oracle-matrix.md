# Original-code oracle matrix

The isolated oracle uses FS-UAE 3.2.35, Workbench 3.1, xpkmaster 4.16
(21-Aug-1997), and recovered compressor libraries. ROMs, Amiga binaries,
private files, logs, and the complete workspace are not distributed.

`xQuery` reported these mode ranges:

| Codec | Default | Ranges |
| --- | ---: | --- |
| NONE | 50 | 0–100 |
| NUKE | 50 | 0–100 |
| FAST | 50 | 0–79, 80–100 |
| RAKE | 100 | 0–25, 26–50, 51–75, 76–100 |
| HUFF | 50 | 0–100 |
| SHRI | 100 | 0–14, 15–28, 29–42, 43–56, 57–70, 71–84, 85–100 |
| DLTA | 100 | 0–100 |
| SMPL | 50 | 0–100 |
| HFMN | 0 | 0–100 |
| MASH | 100 | 0–100 |
| SQSH | 100 | 0–100 |

The matrix exercised every numeric mode on a canonical text vector and every
range boundary/default on deterministic pattern and size vectors:

- 990 byte-exact pack/unpack successes;
- 36 empty-input cases exposing an original-tool defect: a 36-byte XPKF header
  is emitted, then rejected by the same master library;
- one HUFF case which hangs after reporting successful compression, followed
  by 11 deliberately unrun HUFF cases;
- zero round-trip mismatches among completed non-empty cases.

All 1,026 emitted containers begin with `XPKF`. Small representative fixtures
for all six codecs are committed as reviewable hexadecimal files and validate
the current pure-Python implementations.

A second isolated run added `CBR0`, `RLEN`, `FRLE`, `RDCN`, `BLZW`, and
`DUKE`. Across the completed non-empty cases, all 372 original packed/plain
artifacts decode byte-exactly in Python. Compact acceptance containers for
each codec are committed as hexadecimal fixtures. The historical packers are
run in separate or short-lived emulator sessions because repeated use can
crash the original Amiga process; this is an oracle limitation rather than an
accepted decoder failure.

A third set covers `DLTA`, `SMPL`, `HFMN`, `MASH`, and `SQSH`. Short isolated
runs produced 35 byte-exact original pack/unpack artifacts across modes 0,
default, and 100. Python directly decoded all 20 generated compressed DLTA,
HFMN, MASH, and SQSH containers. The SMPL packer selected raw XPK chunks for
all 15 vectors, so its decoder additionally has a source-derived synthetic
prefix-code test rather than claiming compressed oracle coverage. DLTA hangs
on a one-byte input and HFMN hangs on one broad byte-pattern input; those
original-packer defects are excluded from the safe fixture stage.

Every compact committed acceptance container is recorded in the public
manifest with its input, output, size, and SHA-256 hashes. Known hanging
packer/vector pairs are machine-readable exclusions and are never emitted
into a guest stage. `oracle.py verify-python` performs the direct comparison
and records its results as JSON.

`SHR3` and the CyberYAFA `LZW2`–`LZW5` variants are implemented from their
historical decoder definitions. No corresponding original compressor
libraries were present in the recovered collection, so these variants use
reviewable synthetic streams rather than claiming original-packer oracle
coverage. SHR3 is additionally tested by converting both packed chunks from
the 64 KiB SHRI continuation fixture to its headerless chunk representation.

FS-UAE runs behind Xvfb with Mesa software rendering, so oracle generation
does not map a window onto the host desktop.

The recovered private wrapper beginning `01 80 63 68 05 61 01 0a` was not
recognized as packed data by the original master library. That result rules
out using generated XPKF files to infer its outer framing.

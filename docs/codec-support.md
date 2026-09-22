# Codec support

`xfh` decodes 53 XPK codec identifiers in pure Python.

| Evidence | Codecs |
| --- | --- |
| Original Amiga fixture | ACCA, BLFH, BLZW, BZP2, CBR0, DLTA, DUKE, ELZX, FAST, FBR2, FRLE, GZIP, HFMN, HUFF, ILZR, IMPL, LHLB, LZBS, LZCB, LZW2, LZW3, LZW4, LZW5, MASH, NONE, NUKE, PPMQ, RAKE, RDCN, RLEN, SASC, SDHC, SHRI, SHSC, SLZ3, SLZX, SQSH, ZENO |
| Exact historical alias | CBR1, FRHT |
| Independent or source-derived fixture | ARTM, ENCO, FEAL, IDEA, NUID, SHID, CRM2, CRMS, CYB2, PWPK, SHR3, SMPL, TDCS |

The table describes evidence reproducible from the checked-in tests. Original
fixtures were packed and unpacked by preserved Amiga software under headless
UAE, then decoded byte-exactly by `xfh`. The public fixture manifest records
their provenance, sizes, and hashes.

FEAL and IDEA primitives are checked against published known-answer vectors.
ENCO, FEAL, and IDEA wrapper tests use synthetic framing; NUID and SHID tests
add synthetic IDEA encryption to original NUKE and SHRI fixtures, including
SHRI continuation chunks. These tests do not establish original Amiga
interoperability for the encryption wrappers. Original encrypted fixtures for
ENCO, FEAL, IDEA, NUID, and SHID are not checked in; their earlier placement
in the original-fixture row was not supported by the public manifest.

`BLFH`, `ENCO`, `FEAL`, `IDEA`, `NUID`, and `SHID` require a password. BLFH
supports packed and unpacked ECB, OFB, CFB, and CBC streams across modes 0–100.
These obsolete ciphers are provided only for data recovery.

## Evidence gaps

- `ARTM` and `SHR3`: no original library is available.
- `CYB2`: its preserved library does not expose a usable packing path.
- `TDCS`: no original library or packed sample is available.
- `SMPL`: the original packer emitted raw chunks for all tested inputs.
- `CRM2` and `CRMS`: verified with an independent Crunch-Mania implementation.
- `PWPK`: verified with the original PPMC utility and Ancient, but wrapped in a
  source-built XPK container.

## Unsupported preserved codecs

`CYB1`, `DHUF`, and `DMCB` are not implemented. Their preserved packers cannot
produce a compressed fixture suitable for safe decoder development:

- `CYB1` is decrunch-only.
- `DHUF` copies input instead of emitting compressed chunks.
- `DMCB` emits raw chunks for small inputs and hangs on larger probes.

Historical packed samples would allow these decoders to be completed.

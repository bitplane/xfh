# Codec support and evidence

`xfh` currently recognizes 35 XPK identifiers. “Amiga pack” means at least one
fixture was created and unpacked by the original Amiga libraries under
headless UAE, then decoded byte-exactly by Python. “Derived” means the decoder
is covered by source-derived or transformed fixtures but an original packer
artifact is not yet available.

| Evidence | Codecs |
| --- | --- |
| Original Amiga pack/unpack | ACCA, BLZW, CBR0, DLTA, DUKE, FAST, FBR2, FRLE, HFMN, HUFF, ILZR, LHLB, LZBS, LZW2, LZW3, LZW4, LZW5, MASH, NONE, NUKE, RAKE, RDCN, RLEN, SDHC, SHRI, SLZ3, SQSH, ZENO |
| Exact historical aliases | CBR1, FRHT |
| Derived or transformed | ARTM, CYB2, SHR3, SMPL, TDCS |

The important remaining evidence gaps are:

- CYB2 needs a genuine file created through XpkCybPrefs; its standalone
  library does not expose packing modes and rejects hand-built containers.
- TDCS needs an original library or authentic packed sample.
- ARTM and SHR3 need preserved original libraries.
- SMPL’s original packer selected raw chunks for every tested vector, so its
  compressed-stream test remains source-derived.

The preservation archive contains further codecs that are not implemented
yet. Wrapper/backend formats are being prioritized before encryption,
authentication, and preference-system formats.

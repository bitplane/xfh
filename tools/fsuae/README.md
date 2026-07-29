# Original-code fixture generator

This directory contains the quarantined oracle used to generate compatibility
fixtures with the original Amiga binaries. The resulting small fixtures may be
committed; the emulator, ROM, Workbench media, original binaries, private
samples, and complete matrix workspace must not be redistributed.

The guest is disposable and has no network device. A read-only host directory
contains input vectors and a separate empty directory receives results. Generate
each codec/mode over these inputs:

- empty, one byte, and short text;
- every byte value;
- repeated bytes and repeated phrases;
- deterministic pseudo-random data;
- sizes around 255, 256, 65535, and the configured chunk boundary.

Record SHA-256 hashes of the input, packed output, unpacked output, tool
versions, codec, mode, and command in `manifest.json`. Verify the unpacked
result inside the guest and again with Python before accepting a fixture.
Never attach a personal disk image to the fixture VM.

Known original-packer hangs are encoded in `UNSAFE_CASES` and omitted from
generated guest stages. They remain visible as exclusions in matrix metadata.
After a run, compare every completed container directly with the Python
implementation and write a machine-readable report:

```console
python tools/fsuae/oracle.py verify-python ~/tmp/xfh-oracle
```

The host helper creates deterministic inputs, inventories private binaries by
hash, extracts a clean Workbench directory drive, and writes an FS-UAE
configuration:

```console
python tools/fsuae/oracle.py prepare ~/tmp/xfh-oracle
python tools/fsuae/oracle.py extract-workbench ~/tmp/xfh-oracle workbench.adf
python tools/fsuae/oracle.py inventory ~/tmp/xfh-oracle xpkmaster.library xpk
python tools/fsuae/oracle.py write-config ~/tmp/xfh-oracle \
  --fs-uae /path/to/fs-uae --kickstart /path/to/kick.rom \
  --workbench-adf /path/to/workbench.adf
```

`Startup-Sequence` boots directly into the selected control stage. Query and
private-probe stages write a completion sentinel to the output directory. The
host must impose a timeout and terminate the emulator after seeing the
sentinel. The bundled runner accepts `--headless`, which places FS-UAE behind
Xvfb with Mesa software rendering so no window is mapped onto the desktop.

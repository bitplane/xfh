import json
from pathlib import Path

import pytest

from tools.fsuae.oracle import prepare, render_matrix, verify_python

from .helpers import xpkf


def test_render_matrix_records_and_skips_unsafe_original_packer_cases(tmp_path: Path) -> None:
    prepare(tmp_path, force=False)
    render_matrix(tmp_path, codecs={"DLTA"})
    metadata = json.loads((tmp_path / "metadata" / "matrix-cases.json").read_text())
    exclusions = {
        (item["codec"], item["vector"]): item["reason"] for item in metadata["unsafe_cases"]
    }
    assert ("DLTA", "one") in exclusions
    assert ("HFMN", "bytes") in exclusions
    stage = (tmp_path / "shared" / "control" / "oracle-stage").read_text()
    assert "dlta000-one" not in stage
    assert "dlta000-text" in stage


def test_python_comparison_writes_a_machine_readable_report(tmp_path: Path) -> None:
    prepare(tmp_path, force=False)
    render_matrix(tmp_path, codecs={"NONE"}, vectors={"text"})
    raw = (tmp_path / "shared" / "inputs" / "text").read_bytes()
    packed = xpkf("NONE", [(0, raw, len(raw))], initial=raw)
    output = tmp_path / "shared" / "outputs"
    (output / "none000-text.packed").write_bytes(packed)
    (output / "none000-text.unpacked").write_bytes(raw)
    verify_python(tmp_path)
    report = json.loads((tmp_path / "metadata" / "python-comparison.json").read_text())
    assert report["checked"] == 1
    assert report["failures"] == 0

    (output / "none000-text.unpacked").write_bytes(b"wrong")
    with pytest.raises(SystemExit, match="1 failures"):
        verify_python(tmp_path)

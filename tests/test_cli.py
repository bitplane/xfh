import json
from pathlib import Path

from xfh.cli import main

from .helpers import xpkf


def _packed() -> bytes:
    return xpkf("NONE", [(0, b"hello", 5)], initial=b"hello")


def test_info_text_and_json(tmp_path: Path, capsys) -> None:
    source = tmp_path / "hello.xpk"
    source.write_bytes(_packed())
    assert main(["info", str(source)]) == 0
    assert "codec: NONE" in capsys.readouterr().out
    assert main(["info", "--json", str(source)]) == 0
    assert json.loads(capsys.readouterr().out)["codec"] == "NONE"


def test_verify_and_unpack(tmp_path: Path, capsys) -> None:
    source = tmp_path / "hello.xpk"
    output = tmp_path / "hello"
    source.write_bytes(_packed())
    assert main(["verify", str(source)]) == 0
    assert "verified" in capsys.readouterr().out
    assert main(["unpack", str(source), str(output)]) == 0
    assert output.read_bytes() == b"hello"
    assert main(["unpack", str(source), str(output)]) == 1
    assert "refusing to overwrite" in capsys.readouterr().err


def test_cli_reports_unsupported_codec(tmp_path: Path, capsys) -> None:
    source = tmp_path / "unknown.xpk"
    source.write_bytes(xpkf("ZZZZ", [(1, b"x", 1)]))
    assert main(["verify", str(source)]) == 3
    assert "unsupported XPK codec: ZZZZ" in capsys.readouterr().err


def test_salvage_writes_report_for_a_decode_failure(tmp_path: Path) -> None:
    source = tmp_path / "broken.xpk"
    output = tmp_path / "partial"
    report = tmp_path / "report.json"
    source.write_bytes(xpkf("DLTA", [(1, b"", 1)]))
    assert (
        main(
            [
                "unpack",
                "--salvage",
                "--report",
                str(report),
                str(source),
                str(output),
            ]
        )
        == 4
    )
    assert output.read_bytes() == b""
    assert json.loads(report.read_text())["complete"] is False

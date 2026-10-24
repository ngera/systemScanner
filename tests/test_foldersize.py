from pathlib import Path

import pytest

from sysscan.folderadvice import classify_folder
from sysscan.foldersize import (
    build_folder_report,
    dir_size,
    format_report,
    human_size,
    level1_folder_sizes,
    resolve_folder_root,
    write_folder_reports,
)
from sysscan.report.render import render_folders_html


def test_human_size():
    assert human_size(0) == "0 B"
    assert human_size(500) == "500 B"
    assert human_size(1024) == "1.0 KB"
    assert human_size(5 * 1024 * 1024) == "5.0 MB"


def test_resolve_folder_root_precedence(tmp_path, monkeypatch):
    monkeypatch.delenv("SYSSCAN_FOLDER_ROOT", raising=False)
    assert resolve_folder_root(None, env={}) == Path(r"C:\\")
    assert resolve_folder_root(None, env={"SYSSCAN_FOLDER_ROOT": str(tmp_path)}) == tmp_path
    assert resolve_folder_root(str(tmp_path / "x"), env={"SYSSCAN_FOLDER_ROOT": "C:\\"}) == tmp_path / "x"


def test_level1_sizes(tmp_path):
    a = tmp_path / "alpha"
    b = tmp_path / "beta"
    a.mkdir()
    b.mkdir()
    (a / "big.bin").write_bytes(b"x" * 2000)
    (a / "nested").mkdir()
    (a / "nested" / "small.bin").write_bytes(b"y" * 100)
    (b / "mid.bin").write_bytes(b"z" * 500)
    (tmp_path / "loose.txt").write_text("ignore me")  # file at root — not a folder row

    rows = level1_folder_sizes(tmp_path)
    assert [r.path.name for r in rows] == ["alpha", "beta"]  # largest first
    assert rows[0].bytes == 2100
    assert rows[1].bytes == 500
    assert dir_size(a) == (2100, 0)

    text = format_report(tmp_path, rows)
    assert "alpha" in text and "beta" in text and "TOTAL" in text


def test_missing_root(tmp_path):
    with pytest.raises(FileNotFoundError):
        level1_folder_sizes(tmp_path / "nope")


def test_folder_html_report(tmp_path):
    a = tmp_path / "alpha"
    a.mkdir()
    (a / "f.bin").write_bytes(b"x" * 100)
    rows = level1_folder_sizes(tmp_path)
    report = build_folder_report(tmp_path, rows, host="test-pc")
    html = render_folders_html(report)
    assert "Folder sizes" in html and "alpha" in html and "test-pc" in html
    assert "bar" in html
    assert "Safe to clear" in html and "Cleanup advice" in html

    written = write_folder_reports(report, tmp_path / "out", ["html", "json", "md"])
    assert written["html"].exists() and written["json"].exists() and written["md"].exists()
    js = written["json"].read_text(encoding="utf-8")
    assert "alpha" in js and "safety" in js


def test_classify_folder_safety():
    assert classify_folder(Path(r"C:\Windows")).safety == "keep"
    assert classify_folder(Path(r"C:\ProgramData")).safety == "keep"
    assert classify_folder(Path(r"C:\Recovery")).safety == "caution"
    assert classify_folder(Path(r"C:\PerfLogs")).safety == "safe"
    assert classify_folder(Path(r"C:\ProgramData\NVIDIA Corporation")).safety == "caution"
    assert classify_folder(Path(r"C:\ProgramData\Microsoft")).safety == "keep"
    assert classify_folder(Path(r"D:\MyProject\Temp")).safety == "safe"
    assert classify_folder(Path(r"D:\Photos\Vacation")).safety == "unknown"


def test_parse_folder_ai_response_demotes_low_confidence_safe():
    from sysscan.folder_ai import parse_folder_response

    text = """[
      {"id": 0, "kind": "cache", "safety": "safe", "reason": "Temp cache.", "confidence": "low"},
      {"id": 1, "kind": "app", "safety": "keep", "reason": "App data.", "confidence": "high"}
    ]"""
    ans = parse_folder_response(text)
    assert ans[0].safety == "caution"  # demoted
    assert ans[1].safety == "keep"


def test_enrich_folders_with_ai_mock(tmp_path):
    from sysscan.config import AIConfig
    from sysscan.folder_ai import enrich_folders_with_ai
    from sysscan.folderadvice import FolderAdvice
    from sysscan.foldersize import FolderSize

    unknown = tmp_path / "WeirdVendorApp"
    unknown.mkdir()
    (unknown / "config.json").write_text("{}")
    folder = FolderSize(unknown, 100, 0, FolderAdvice("unknown", "No rule.", source="unknown"))

    class Fake:
        def complete(self, system, user, **_):
            assert "Classify these folders" in user
            return '[{"id":0,"kind":"app","safety":"keep","reason":"Third-party app data still needed.","confidence":"high"}]'

    updated, msgs = enrich_folders_with_ai(
        [folder], AIConfig(enabled=True), store=None,
        describer_factory=lambda _ai: Fake(),
    )
    assert updated[0].safety == "keep"
    assert updated[0].advice.source == "ai"
    assert "Third-party" in updated[0].advice.reason
    assert any("updated 1" in m for m in msgs)

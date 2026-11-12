"""Tests for the visual evidence of Python findings."""

from __future__ import annotations

from pathlib import Path

from lefiru.core.analyzers.python.python_ast import PythonCodeInspector
from lefiru.core.analyzers.python.python_evidence import PythonEvidenceRenderer


def test_render_line_generates_png(tmp_path):
    renderer = PythonEvidenceRenderer(tmp_path / "evidence", "demo")
    code = (
        "import os\n"
        "def calculate(value):\n"
        "    return eval(value)\n"
    )

    path = renderer.render_line(code, line=3, origin="demo.py", label="eval")

    assert path is not None
    file = Path(path)
    assert file.is_file()
    assert file.suffix == ".png"
    assert file.stat().st_size > 0


def test_render_line_skips_invalid_lines(tmp_path):
    renderer = PythonEvidenceRenderer(tmp_path, "demo")

    assert renderer.render_line("print('ok')\n", line=0, origin="demo.py") is None
    assert renderer.render_line("print('ok')\n", line=99, origin="demo.py") is None
    assert renderer.render_line("", line=1, origin="demo.py") is None


def test_render_file_context_screenshot_header(tmp_path):
    renderer = PythonEvidenceRenderer(tmp_path, "demo")
    code = "\n".join(f"line_{i} = {i}" for i in range(1, 20))

    path = renderer.render_file_context(code, origin="demo.py", label="no_logging")

    assert path is not None
    file = Path(path)
    assert file.is_file()
    assert "file" in file.name


def test_inspector_attaches_line_image(tmp_path):
    target = tmp_path / "fixture_python_evidence.py"
    target.write_text(
        "import os\n"
        "def execute(value):\n"
        "    password = 'SuperSecret123'\n"
        "    return eval(exec(value))\n",
        encoding="utf-8",
    )

    inspector = PythonCodeInspector(target, tmp_path / "output")
    result = inspector.analyze()

    with_line = [h for h in result["findings"] if int(h.get("line") or 0) > 0]
    assert with_line
    for finding in with_line:
        path = finding.get("evidence_image")
        assert path, finding
        assert Path(path).is_file()

    # Findings on the same line reuse the same screenshot.
    paths_same_line = {
        h["evidence_image"] for h in with_line if h.get("line") == 4
    }
    assert len(paths_same_line) == 1

    # Without a specific line, a file-context screenshot is also generated.
    without_line = [h for h in result["findings"] if int(h.get("line") or 0) == 0]
    assert without_line
    for finding in without_line:
        path = finding.get("evidence_image")
        assert path, finding
        assert Path(path).is_file()

    # All file-scope findings share the same screenshot.
    assert len({h["evidence_image"] for h in without_line}) == 1

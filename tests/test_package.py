"""Package smoke tests: version, resources and core/ui separation."""

from __future__ import annotations

import subprocess
import sys

import lefiru


def test_version_is_exposed():
    assert lefiru.__version__.count(".") >= 1


def test_packaged_resources():
    from lefiru.paths import resource

    assert resource("ui/resources/icon.png").is_file()
    assert resource("data/passwords/password_dictionary.txt").is_file()


def test_core_does_not_import_qt():
    """The engine must be usable on a server without PyQt6 installed."""
    code = (
        "import sys; import lefiru.core.orchestrator; "
        "print([m for m in sys.modules if m.split('.')[0] == 'PyQt6'])"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "[]"


def test_ensure_output_root_creates_the_folder(tmp_path, monkeypatch):
    """The output folder is created without depending on it already existing."""
    from lefiru.paths import ensure_output_root, output_root

    destination = tmp_path / "results"
    monkeypatch.setenv("LEFIRU_OUTPUT", str(destination))
    assert not destination.exists()

    assert ensure_output_root() == destination
    assert destination.is_dir()
    assert output_root() == destination


def test_output_root_in_source_code(monkeypatch):
    """From source code the root is the project one, not the current directory."""
    from lefiru.paths import output_root, project_root

    monkeypatch.delenv("LEFIRU_OUTPUT", raising=False)
    monkeypatch.setattr("lefiru.paths.is_frozen", lambda: False)

    assert output_root() == project_root() / "results"


def test_output_root_frozen_next_to_executable(tmp_path, monkeypatch):
    """In the packaged application the root sits next to the executable."""
    from lefiru.paths import output_root

    monkeypatch.delenv("LEFIRU_OUTPUT", raising=False)
    monkeypatch.setattr("lefiru.paths.is_frozen", lambda: True)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "lefiru-analyzer.exe"))

    assert output_root() == tmp_path / "results"

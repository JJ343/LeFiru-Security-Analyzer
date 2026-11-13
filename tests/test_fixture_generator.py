"""Tests for the fixture generator and the tests it should trigger.

The generator lives in ``tools/generate_fixtures.py`` and is used as a
regression tool: it creates files with known defects and checks that the
engine still detects them.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.generate_fixtures import generate_fixtures  # noqa: E402

FIXTURES_STATIC = {
    "test_simple.xlsx",
    "test_protected.xlsm",
    "test_template.xltx",
    "test_template_macro.xltm",
    "test_addin.xlam",
    "test_connections.xlsx",
    "test_secondary_logic.xlsx",
    "test_formula_protection.xlsx",
    "sample_insecure_vba.txt",
    "fixture_python_clean.py",
    "fixture_python_insecure.py",
    "test_python_suspicious.pyc",
    "test_python_bundle.exe",
    "test_python_extractable.exe",
    "test_python_non_extractable.exe",
}


@pytest.fixture(scope="module")
def fixtures(tmp_path_factory):
    destination = tmp_path_factory.mktemp("fixtures")
    generate_fixtures(destination, include_com=False)
    return destination


def _evaluate_excel(fixture: Path, destination: Path, tests: list[str]) -> dict:
    """Evaluate an Excel file in static mode without running the bypass."""
    from lefiru.core.orchestrator import AnalysisOrchestrator

    checker = AnalysisOrchestrator(
        str(fixture),
        mode="static",
        tests=tests,
        output_dir=str(destination / fixture.stem),
    )
    return checker.run_analysis(run_bypass=False)


def _analyze_python(fixture: Path, destination: Path) -> dict:
    """Run the CLI on a Python file and return the report JSON."""
    output = destination / fixture.stem
    command = [sys.executable, "-m", "lefiru", "--path", str(fixture), "-o", str(output)]
    result = subprocess.run(
        command,
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    reports = sorted((output / "python" / fixture.stem / "reports").glob("*.json"))
    assert reports, result.stdout + result.stderr
    return json.loads(reports[-1].read_text(encoding="utf-8"))


def _states(report: dict) -> dict[str, str]:
    return {
        key: section["status"]
        for key, section in report["compliance"]["tests"].items()
    }


def test_generates_all_static_fixtures(fixtures):
    for name in FIXTURES_STATIC:
        assert (fixtures / name).is_file(), name

    # Generated .py files must not start with test_ so pytest does not collect them.
    assert not list(fixtures.glob("test_python_*.py"))


def test_fixture_without_protections_triggers_structure_protection(fixtures, tmp_path):
    report = _evaluate_excel(fixtures / "test_simple.xlsx", tmp_path, ["protections"])
    assert _states(report)["structure_protection"] == "VULNERABLE"


def test_protected_fixture_is_compliant_for_protections(fixtures, tmp_path):
    report = _evaluate_excel(fixtures / "test_protected.xlsm", tmp_path, ["protections"])
    states = _states(report)
    assert states["structure_protection"] == "COMPLIANT"
    assert states["critical_sheets_protection"] == "COMPLIANT"


def test_xltx_fixture_inherits_xlsx_tests(fixtures, tmp_path):
    report = _evaluate_excel(fixtures / "test_template.xltx", tmp_path, ["protections"])
    assert _states(report)["structure_protection"] == "VULNERABLE"


def test_xltm_fixture_is_compliant_for_protections_like_xlsm(fixtures, tmp_path):
    report = _evaluate_excel(
        fixtures / "test_template_macro.xltm", tmp_path, ["protections"]
    )
    states = _states(report)
    assert states["structure_protection"] == "COMPLIANT"
    assert states["critical_sheets_protection"] == "COMPLIANT"


def test_xlam_fixture_analyzes_itself_in_static_mode(fixtures, tmp_path):
    report = _evaluate_excel(fixtures / "test_addin.xlam", tmp_path, ["protections"])
    states = _states(report)
    assert states["structure_protection"] == "COMPLIANT"
    assert states["critical_sheets_protection"] == "COMPLIANT"


def test_connections_fixture_triggers_external_connections(fixtures, tmp_path):
    report = _evaluate_excel(fixtures / "test_connections.xlsx", tmp_path, ["connections"])
    assert _states(report)["external_connections"] == "VULNERABLE"


def test_formulas_fixture_triggers_formulas(fixtures, tmp_path):
    report = _evaluate_excel(
        fixtures / "test_formula_protection.xlsx", tmp_path, ["formulas"]
    )
    assert _states(report)["formulas"] == "VULNERABLE"


def test_clean_python_fixture_is_compliant(fixtures, tmp_path):
    report = _analyze_python(fixtures / "fixture_python_clean.py", tmp_path)
    assert report["general_status"] == "COMPLIANT"
    assert set(_states(report).values()) == {"COMPLIANT"}


def test_insecure_python_fixture_triggers_tests(fixtures, tmp_path):
    report = _analyze_python(fixtures / "fixture_python_insecure.py", tmp_path)
    states = _states(report)
    for test_key in ("dynamic_execution", "dangerous_commands", "deserialization", "credentials", "connections"):
        assert states[test_key] == "VULNERABLE", test_key

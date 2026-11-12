"""Invariants of the extension catalog (Excel families).

The suffix decides the applicable set of tests, not the analyzer: OOXML
templates and add-ins inherit the family of the workbook they derive from.
"""

from __future__ import annotations

import pytest

from lefiru.core.catalog import (
    EXCEL_BINARY,
    EXCEL_WITH_MACROS,
    EXCEL_EXTENSIONS,
    EXCEL_LEGACY,
    EXCEL_OOXML,
    EXCEL_WITHOUT_MACROS,
    TESTS_BY_EXTENSION,
    PYTHON_EXTENSIONS,
)


def test_all_excel_extensions_have_applicable_tests():
    for extension in EXCEL_EXTENSIONS:
        assert TESTS_BY_EXTENSION.get(extension), extension


def test_templates_and_addins_inherit_their_family():
    assert TESTS_BY_EXTENSION[".xltx"] == TESTS_BY_EXTENSION[".xlsx"]
    assert TESTS_BY_EXTENSION[".xltm"] == TESTS_BY_EXTENSION[".xlsm"]
    assert TESTS_BY_EXTENSION[".xlam"] == TESTS_BY_EXTENSION[".xlsm"]


def test_excel_families_are_coherent():
    assert EXCEL_WITHOUT_MACROS.isdisjoint(EXCEL_WITH_MACROS)
    assert EXCEL_OOXML == EXCEL_WITHOUT_MACROS | EXCEL_WITH_MACROS
    assert EXCEL_EXTENSIONS == EXCEL_OOXML | EXCEL_BINARY
    assert not (EXCEL_EXTENSIONS & PYTHON_EXTENSIONS)
    assert not (EXCEL_LEGACY & EXCEL_EXTENSIONS)


def test_unsupported_extension_fails_fast(tmp_path):
    from lefiru.core.orchestrator import AnalysisOrchestrator

    file = tmp_path / "document.txt"
    file.write_text("this is not an Excel workbook", encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported extension"):
        AnalysisOrchestrator(str(file), mode="static")

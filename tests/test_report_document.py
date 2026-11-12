"""Tests for the single assembly of the report JSON."""

import pytest

from lefiru.reporting.report_document import ReportDocument


def _result():
    return {
        "timestamp": "2026-01-01T00:00:00",
        "analysis_mode": "STATIC",
        "analysis": {"static": {}},
        "metadata": {"name": "workbook.xlsx"},
        "compliance": {
            "general_status": "COMPLIANT",
            "tests": {
                "structure_protection": {
                    "name": "Structure protection",
                    "status": "COMPLIANT",
                    "detail": "",
                }
            },
            "recommendations": [],
        },
    }


def test_includes_only_present_sections_in_order():
    document = ReportDocument(_result()).build()

    assert list(document) == [
        "metadata",
        "timestamp",
        "analysis_mode",
        "analysis",
        "compliance",
        "tests",
        "general_status",
        "recommendations",
    ]
    assert document["general_status"] == "COMPLIANT"
    assert document["tests"] == {
        "structure_protection": {
            "name": "Structure protection",
            "status": "COMPLIANT",
            "detail": "",
        }
    }


def test_artifacts_register_themselves_without_mutating_the_result():
    result = _result()

    document = ReportDocument(result, artifacts={"json": "report.json"}).build()

    assert document["metadata"]["artifacts"] == {"json": "report.json"}
    assert "artifacts" not in result["metadata"]


def test_add_a_section_is_one_more_entry():
    class ExtendedDocument(ReportDocument):
        SECTIONS = (*ReportDocument.SECTIONS, "summary_extra")

        def _section_summary_extra(self):
            return {"ok": True}

    document = ExtendedDocument(_result()).build()

    assert document["summary_extra"] == {"ok": True}
    assert list(document)[-1] == "summary_extra"


def test_registered_section_without_method_fails():
    class IncompleteDocument(ReportDocument):
        SECTIONS = (*ReportDocument.SECTIONS, "without_method")

    with pytest.raises(AttributeError, match="_section_without_method"):
        IncompleteDocument(_result()).build()

"""Integration test with real Excel (skipped when there is no COM engine)."""

from __future__ import annotations

import pytest

from lefiru.core.analyzers.excel.com_runtime import plan_com
from lefiru.core.analyzers.excel.excel_com import LiveExcelInspector, WIN32COM_AVAILABLE

pytestmark = pytest.mark.com


def test_com_opens_a_real_workbook(tmp_path):
    if not WIN32COM_AVAILABLE:
        pytest.skip("pywin32 is not installed")

    plan = plan_com()
    if not plan.available:
        pytest.skip(f"No COM engine: {plan.reason}")

    from openpyxl import Workbook

    workbook = tmp_path / "com.xlsx"
    wb = Workbook()
    wb.active["A1"] = "lefiru"
    wb.save(workbook)

    analyzer = LiveExcelInspector(workbook, output_root=tmp_path / "output")
    try:
        data = analyzer.check_workbook_protection()
    finally:
        analyzer.close()

    assert "protected_workbook" in data

"""Tests for COM engine detection and activation flags."""

from __future__ import annotations

from pathlib import Path

import pytest

from lefiru.core.analyzers.excel import com_runtime as runtime


def test_python_bits_is_32_or_64():
    assert runtime.python_bits() in (32, 64)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (
            '"C:\\Program Files (x86)\\Microsoft Office\\Root\\Office16\\EXCEL.EXE" /automation',
            "C:\\Program Files (x86)\\Microsoft Office\\Root\\Office16\\EXCEL.EXE",
        ),
        (
            "C:\\Program Files (x86)\\Microsoft Office\\Root\\Office16\\EXCEL.EXE /automation",
            "C:\\Program Files (x86)\\Microsoft Office\\Root\\Office16\\EXCEL.EXE",
        ),
        ("C:\\WINDOWS\\system32\\EXCEL.EXE", "C:\\WINDOWS\\system32\\EXCEL.EXE"),
        ("", ""),
    ],
)
def test_separate_server(value, expected):
    assert runtime._separate_server(value) == expected


def test_detect_engines_ignores_non_excel_servers(monkeypatch):
    monkeypatch.setattr(
        runtime,
        "servers_registered",
        lambda: [
            {
                "bits": 64,
                "exe": Path("C:/WPS/office6/et.exe"),
                "view": "HKCU 64 bits",
                "value": "C:/WPS/office6/et.exe /Automation",
            },
            {
                "bits": 32,
                "exe": Path("C:/Program Files (x86)/Microsoft Office/EXCEL.EXE"),
                "view": "HKLM 32 bits",
                "value": '"C:/Program Files (x86)/Microsoft Office/EXCEL.EXE" /automation',
            },
        ],
    )

    engines = runtime.detect_engines()

    assert len(engines) == 1
    assert engines[0].bits == 32
    assert engines[0].exe.name.lower() == "excel.exe"


@pytest.mark.parametrize(
    ("engine_bits", "client_bits", "expected"),
    [
        (64, 64, runtime.CLSCTX_LOCAL_SERVER),
        (32, 32, runtime.CLSCTX_LOCAL_SERVER),
        (32, 64, runtime.CLSCTX_LOCAL_SERVER | runtime.CLSCTX_ACTIVATE_32_BIT_SERVER),
        (64, 32, runtime.CLSCTX_LOCAL_SERVER | runtime.CLSCTX_ACTIVATE_64_BIT_SERVER),
    ],
)
def test_clsctx_for(engine_bits, client_bits, expected):
    assert runtime.clsctx_for(engine_bits, client_bits) == expected


def test_clsctx_is_always_local():
    for bits in (32, 64):
        assert runtime.clsctx_for(bits) & runtime.CLSCTX_LOCAL_SERVER


def test_plan_direct_when_bitness_matches(monkeypatch):
    engine = runtime.OfficeEngine(64, Path("C:/Office/EXCEL.EXE"), "HKLM 64 bits")
    monkeypatch.setattr(runtime, "detect_engines", lambda: [engine])
    monkeypatch.setattr(runtime, "python_bits", lambda: 64)

    plan = runtime.plan_com()

    assert plan.type == "direct"
    assert plan.available
    assert plan.engine == engine


def test_plan_direct_even_when_bitness_differs(monkeypatch):
    engine = runtime.OfficeEngine(32, Path("C:/Office/EXCEL.EXE"), "HKLM 32 bits")
    monkeypatch.setattr(runtime, "detect_engines", lambda: [engine])
    monkeypatch.setattr(runtime, "python_bits", lambda: 64)

    plan = runtime.plan_com()

    assert plan.type == "direct"
    assert plan.engine == engine
    assert "0x40004" in plan.reason


def test_plan_prefers_engine_of_same_bitness(monkeypatch):
    engine32 = runtime.OfficeEngine(32, Path("C:/Office32/EXCEL.EXE"), "HKLM 32 bits")
    engine64 = runtime.OfficeEngine(64, Path("C:/Office64/EXCEL.EXE"), "HKLM 64 bits")
    monkeypatch.setattr(runtime, "detect_engines", lambda: [engine32, engine64])
    monkeypatch.setattr(runtime, "python_bits", lambda: 64)

    plan = runtime.plan_com()

    assert plan.engine == engine64


def test_plan_no_available_without_engines(monkeypatch):
    monkeypatch.setattr(runtime, "detect_engines", lambda: [])
    monkeypatch.setattr(runtime, "describe_servers", lambda: "WPS only")

    plan = runtime.plan_com()

    assert plan.type == "no_available"
    assert not plan.available
    assert "WPS only" in plan.reason


def test_create_analyzer_fails_without_engine(tmp_path):
    plan = runtime.ComPlan(type="no_available", reason="no Excel")

    with pytest.raises(runtime.ComNotAvailableError, match="no Excel"):
        runtime.create_analyzer_com(tmp_path / "workbook.xlsx", tmp_path, plan=plan)


def test_create_analyzer_uses_the_com_analyzer(tmp_path, monkeypatch):
    from lefiru.core.analyzers.excel import excel_com

    engine = runtime.OfficeEngine(32, Path("C:/Office/EXCEL.EXE"), "HKLM 32 bits")
    plan = runtime.ComPlan(type="direct", engine=engine, reason="test")

    class AnalyzerFalse:
        def __init__(self, file_path, output_root, password=None):
            self.args = (file_path, output_root, password)

    monkeypatch.setattr(excel_com, "LiveExcelInspector", AnalyzerFalse)
    monkeypatch.setattr(excel_com, "WIN32COM_AVAILABLE", True)

    analyzer = runtime.create_analyzer_com(
        tmp_path / "workbook.xlsx", tmp_path, password="x", plan=plan
    )

    assert isinstance(analyzer, AnalyzerFalse)
    assert analyzer.args[2] == "x"

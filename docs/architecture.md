# Architecture

The `lefiru` package is organized into layers with a strict dependency rule:
**lower layers never import upper layers**.

```
ui/          PyQt6: window, widgets and pages
   │
   ├── reporting/   JSON and LaTeX/PDF report
   │
   ├── cli/         argument parsing and exit codes
   │      │
   │      └── core/            orchestrator and test catalog
   │             │
   │             └── core/analyzers/   one analyzer per format/family
   │                    ├── excel/     .xlsx / .xlsm / .xlsb / .xltx / .xltm / .xlam
   │                    └── python/    .py / .pyc / .exe
   │
   └── paths.py     resources and output folder
```

## Rules

1. `core/` does not import `PyQt6` or `lefiru.ui`. This is verified by
   `tests/test_package.py::test_core_no_importa_qt`.
2. No module computes paths with `Path(__file__).parents[N]`; use
   `lefiru.paths.resource()` and `lefiru.paths.output_root()`.
3. `ui/` consumes the engine through `AnalysisOrchestrator` and the catalog; it does not
   reimplement business rules.
4. COM (`pywin32`) and Excel are **optional at import time**:
   `analyzers/excel/excel_com.py` uses deferred annotations and degrades to
   `WIN32COM_AVAILABLE = False`.

## Lifecycle of a run

```
cli/main.py
  └── AnalysisOrchestrator(file_path, tests)
        ├── analyzers                → findings
        ├── consolidation            → compliance per test
        ├── ReportDocument           → JSON document (one section per method)
        └── AnalysisReportWriter   → JSON + LaTeX/PDF
```

`ReportDocument` (`reporting/report_document.py`) is the only place that defines
the JSON keys and order. To add a section, create
`_section_<key>()` and add `<key>` to `SECTIONS`.

## Stable identifiers

Test slugs (`structure_protection`, `credentials`, …) and report JSON keys are
**public API**: the GUI, the LaTeX/PDF report and external consumers depend on them. They
have no numbering: adding a test does not renumber the existing ones.

# AGENTS.md

Context guide for AI agents working on **LeFiru Security Analyzer**.

## 1. What this project is

Security analysis tool for Excel and Python files.
It analyzes **Excel** and **Python** files looking for integrity, security and
traceability risks, generates findings per test, calculates a compliance status
and produces a JSON report + a LaTeX/PDF report (`.tex` + `.pdf`).

- **Version:** 1.0.1 (single source: `src/lefiru/__init__.py`)
- **Domain language:** English (variables, functions, logs, messages, documentation)
- **File and module language:** English
- **Target platform:** Windows (Excel COM via `pywin32`; desktop GUI)
- **License:** Apache-2.0
- **Python:** 3.11 or higher

Two usage modes, with the same business logic:

| Entry point | Command | Use |
|---|---|---|
| CLI | `lefiru` / `python -m lefiru` | Automation, batch analysis |
| GUI | `lefiru-analyzer` | Frameless PyQt6 application |

Orchestration and compliance logic live in
`src/lefiru/core/orchestrator.py`; the test catalog and tests, in
`src/lefiru/core/catalog.py`; and argument parsing, in `src/lefiru/cli/main.py`.
The concrete analyzers are in `src/lefiru/core/analyzers/`, split by family into
`excel/` and `python/`; the outputs in
`src/lefiru/reporting/` and the interface in `src/lefiru/ui/`.

## 2. Quick start

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[gui,dev]"

# GUI
lefiru-analyzer

# CLI: Excel in static mode
lefiru --path "file.xlsm" --analysis static

# CLI: Excel forcing COM (requires Excel + pywin32)
lefiru --path "file.xlsx" --analysis com --debug

# CLI: Python script / bytecode / executable
lefiru --path "script.py"
lefiru --path "app.exe" -o results

# Run only some tests
lefiru --path "workbook.xlsm" --tests vba,patterns,formulas
```

Extras: `gui` (PyQt6 + frameless), `windows` (pywin32), `dev`
(pytest, ruff, pre-commit).

### CLI options

| Option | Values / default | Notes |
|---|---|---|
| `--path` | path (required) | `.xlsx`, `.xlsm`, `.xlsb`, `.xltx`, `.xltm`, `.xlam`, `.py`, `.pyc`, `.exe` |
| `--analysis` | `static` \| `com` \| `both` (default `both`) | Excel only; `both` tries COM and falls back to static |
| `--output`, `-o` | `output_root()` | Root output directory (see section 6) |
| `--tests`, `-t` | comma-separated list | Default: `ALL` (all tests compatible with the extension) |
| `--debug`, `-d` | flag | Writes the detailed log file and shows DEBUG messages (no log file otherwise) |

### Exit codes

| Code | Status |
|---|---|
| `0` | `COMPLIANT` |
| `1` | `VULNERABLE` |
| `2` | `COMPLIANT_WITH_OBSERVATIONS` |
| `99` | Fatal error |

Other status values: `NOT_APPLICABLE`, `NOT_EXECUTED`, `ERROR`, `REQUIRES_REVIEW`
and `PROTECTED_WITH_PASSWORD`.

## 3. Structure

```
lefiru-analyzer/
├── .github/workflows/ci.yml
├── docs/                        index.md, architecture.md, tests.md
├── src/lefiru/
│   ├── __init__.py              __version__
│   ├── __main__.py              python -m lefiru
│   ├── paths.py                 resources and output folder
│   ├── cli/
│   │   └── main.py              argparse, analysis run and exit codes
│   ├── core/
│   │   ├── catalog.py           TESTS_AVAILABLE, TESTS_BY_TEST, extension map
│   │   ├── orchestrator.py      AnalysisOrchestrator: analyzes, consolidates and calculates status
│   │   ├── analysis_support.py  logging, hashes, critical sheets, anonymization
│   │   └── analyzers/
│   │       ├── excel/                   Excel analyzers
│   │       │   ├── excel_static.py        Excel without Excel (openpyxl / pyxlsb)
│   │       │   ├── excel_com.py           Excel via COM (any bitness)
│   │       │   ├── com_runtime.py         Excel detection, bitness and CLSCTX flags
│   │       │   ├── excel_formulas.py      formula integrity (formulas)
│   │       │   ├── excel_password.py      opening-encryption detection
│   │       │   ├── vba_patterns.py        insecure VBA patterns (insecure_patterns)
│   │       │   ├── bypass.py              authorized bypass + backups
│   │       │   ├── evidence_capture.py    off-screen evidence images (Excel + VBE + source)
│   │       │   ├── password_check.py      inference / dictionary
│   │       │   └── openpyxl_compat.py     .xlam extension for openpyxl
│   │       └── python/                  Python analyzers
│   │           ├── python_ast.py          AST analysis (dynamic_execution..traceability tests)
│   │           ├── python_evidence.py     PNG captures of the line of each finding
│   │           ├── python_bytecode.py     recovery from .pyc
│   │           └── python_executable.py   PyInstaller / cx_Freeze / py2exe
│   ├── reporting/
│   │   ├── report_document.py   JSON: one section per method
│   │   ├── report_writer.py     writes the JSON and coordinates the LaTeX/PDF report
│   │   ├── report_docx.py       LaTeX/PDF report
│   │   └── assets/              optional report logo
│   ├── data/passwords/          bundled dictionaries
│   └── ui/
│       ├── app.py               startup (entry point `lefiru-analyzer`)
│       ├── window.py            FramelessWindow
│       ├── shell.py             ApplicationShell: sidebar + page stack
│       ├── theme.py             dark theme styles
│       ├── widgets/             nav_sidebar, window_titlebar, brand_mark
│       ├── pages/               overview, analysis, reports, product_info,
│       │                        analysis_queue
│       └── resources/icon.png
├── tests/                       conftest.py, fixtures/, golden/
│   └── test_fixture_generator.py   regression with the generated fixtures
├── tools/generate_fixtures.py   fixture generator (Excel + Python)
├── pyproject.toml
├── AGENTS.md
└── README.md, LICENSE, CHANGELOG.md, CONTRIBUTING.md, SECURITY.md
```

## 4. Execution flow

1. `cli/main.py` resolves the path, validates the extension and creates the output structure.
2. `.py`, `.pyc`, `.exe` → `PythonCodeInspector` (Python pipeline).
3. Excel → pipeline according to `--analysis`:
   - `com`: `create_analyzer_com()` validates that Excel is registered and returns
     `LiveExcelInspector` (local activation with the correct bitness).
   - `static`: `StaticWorkbookInspector` (`openpyxl` / `pyxlsb`).
   - `both`: tries COM and, if it fails or there is no engine, continues with static.
4. Tests run respecting `order` and `dependencies` (for example, `patterns`
   depends on `vba`).
5. Findings are consolidated per test and the global status is calculated.
6. `report_writer` writes JSON and `"<name>_report.tex"` plus `"<name>_report.pdf"`.
7. The exit code is returned (0/1/2) or 99 on fatal error.

The GUI reuses the same orchestrator from `QThread` workers in
`ui/pages/analysis.py` (a single page for Excel and Python files).

## 5. Tests and test catalog

### Excel

| Test | Label | Tests | Depends on |
|---|---|---|---|
| `protections` | Workbook and sheet protections | structure_protection, critical_sheets_protection | — |
| `vba` | VBA project analysis | vba | — |
| `patterns` | Insecure patterns in code | insecure_patterns | `vba` |
| `connections` | External connections | external_connections | — |
| `formulas` | Critical formula analysis | formulas | — |
| `password` | Opening password | opening_bypass, password_opening | — |

- **opening_bypass** is reserved exclusively for the *structural opening bypass*
  (`XML_REMOVE_WORKBOOK_PASSWORD`, `BINARY_REMOVE_XLSB_PASSWORD`,
  `EXTRACT_CONTENT_NO_PASSWORD`). Other password findings are reported separately
  (`password_opening`) and do not count as opening_bypass.
- `password` is **hidden in the GUI** (`UI_HIDDEN_TESTS = {"password"}`) and only
  makes sense for encrypted files.
- `formulas` uses `is_critical_sheet()` from `core/analysis_support.py` to decide which sheets
  to analyze (names like input/config/data/calculation/balance, accent-stripped and token-based).
- `connections` counts `external_links`, `data_connections` and
  `defined_names` with external references as external (external_connections).

### Python

| Test | Label | Test |
|---|---|---|
| `python_dynamic_execution` | Dynamic execution (eval/exec) | dynamic_execution |
| `python_dangerous_commands` | Dangerous commands (os/subprocess) | dangerous_commands |
| `python_deserialization` | Insecure deserialization | deserialization |
| `python_credentials` | Hardcoded credentials/secrets | credentials |
| `python_connections` | Hardcoded external connections | connections |
| `python_traceability` | Traceability/logging | traceability |
| `python_analysis` | Alias of all of the above | dynamic_execution, dangerous_commands, deserialization, credentials, connections, traceability |

- traceability is **COMPLIANT** only if the `no_logging` finding does not exist.
- `without_tests` is the base status when there are no applicable tests.
- Findings are mapped with `PYTHON_CATEGORY_TO_TEST`.

## 6. Output structure

`prepare_output_directories()` creates, for each analyzed file:

```
<output>/
├── excel/<stem>/      (or python/<stem>/ for .py, .pyc and .exe)
│   ├── logs/          lefiru_analysis.log (CLI: only with --debug)
│   ├── reports/       <stem>_report.json, <stem>_report.tex, <stem>_report.pdf
│   │   └── evidence/  screenshots and artifacts (COM mode, bypass, etc.);
│   │                  VBA source exports go in evidence/vba/
│   └── backups/       copies made before tests that modify the file
```

The root folder is resolved in `lefiru.paths.output_root()`: `LEFIRU_OUTPUT` →
`results/` next to the executable (frozen application) → `results/` at the
project root (source code). It does not depend on the working directory and must
not be created with `Path(__file__).parents[N]`.

When an analysis starts (CLI or GUI), `lefiru.paths.ensure_output_root()` is
called; it resolves that root and creates it if it does not exist, so the results
folder appears even before any report is written. CLI and GUI use the same
subfolder names (`excel/`, `python/`).

### JSON construction

The report JSON is assembled **only** in
`reporting/report_document.py` (`ReportDocument`). Each section is a
`_section_<key>()` method and the `SECTIONS` tuple fixes the order and keys. To
add a new section:

1. create `_section_<key>()` that returns its content (or `None` to omit it
   when not applicable), and
2. add `<key>` to `SECTIONS`.

`AnalysisReportWriter` only chooses the file name, registers the
artifacts and writes what `ReportDocument.build()` returns; it does not rewrite
the JSON or complete it afterward. The orchestrator provides raw data
(`analysis`, `compliance`, `metadata`, etc.) and does not define the report shape.

## 7. Sensitive behaviors

### Protection bypass and editing tests

- `bypass.py` **modifies** the file to test whether protections are
  bypassable, creates a backup in `backups/` and restores it when finished.
- Never delete or overwrite `backups/` during a run.

### Evidence capture (never steals focus)

- `evidence_capture.py` produces every Excel evidence image. The workbook stays
  hidden: `Range.CopyPicture(Format=xlPicture)` + `Chart.Export` renders the
  range with no window at all. Do not set `Visible = True`, do not maximize and
  do not call `SetForegroundWindow`; `PrintWindow` + `PW_RENDERFULLCONTENT` is
  only the fallback when the range export comes back blank.
- `xlBitmap` pastes nothing under late binding and `Visible = False` yields a
  blank PNG instead of an error. Every capture is validated with Pillow
  (`image_has_content`) before it is registered, so a blank image is never
  reported as evidence.
- The helper workbook used for the export must have its window hidden
  (`helper.Windows(1).Visible = False`); otherwise `Workbooks.Add` cascades a
  visible window on the desktop.
- Build addresses with `Cells(rows, cols).Address`, never
  `Range("A1").Resize(rows, cols).Address`: with late COM binding the latter
  resolves to a single cell (the bottom-right corner).
- VBA: the VBE has no render API, so `capture_vbe()` parks the VBE window
  off-screen and captures it with `PrintWindow`. It needs `AccessVBOM`
  ("Trust access to the VBA project object model"); when that is disabled the
  source is rendered with Pillow instead (`render_code_png`), whose header
  states that it is a rendering and not a screenshot.
- `excel_static._create_code_screenshot()` delegates to the same renderer.

### Opening password test

- `password_check.py` looks for the opening password by inference from metadata
  and by local dictionary. It does not include embedded default password lists.
- Intrusive test: only on your own files or with authorization.
- The CLI has no option to provide a known opening password: the password test
  only uses inference from metadata and the local dictionary. Any credential
  handled internally must never be logged or persisted in reports (use
  `anonymize_credential()`).

### Python binary analysis

- It follows local imports; supports PyInstaller, cx_Freeze, py2exe, companion folders and
  binary fallback.
- Deliberate limits: 50 MB per file, 300 extracted members and 800 companion
  folders. Respect them.
- `decompyle3` does not support Python ≥ 3.9: decompilation failures must degrade to
  bytecode/binary analysis, never abort the analysis.

## 8. Code conventions

- **Language:** files and modules in English; domain functions, variables, logs and
  interface text in English (`finding`, `compliance`, `output_paths`, `test`).
- **Paths:** always `pathlib.Path`; resources with `lefiru.paths.resource()`.
  `os.path` is forbidden in new code, as are hardcoded absolute paths.
- **Layers:** `core/` does not import `PyQt6` or `lefiru.ui`. A test verifies this.
- **Logging:** `logging.getLogger(__name__)`; never `print` in analysis modules.
  Sanitize with `sanitize_string()` and anonymize secrets.
- **Resilience:** `try/except` per test/file so a failure does not take down the batch;
  log the error and continue, never silence it without a trace.
- **Findings:** dictionaries with `test`, `status`, `severity`, `description`,
  `evidence`, `method`. Stable identifiers: reports depend on them.
- **Optional dependencies:** COM/pywin32 and Excel may be missing; every COM path must
  degrade to static analysis.
- **GUI:** PyQt6; long tasks in `QThread` with progress signals. Do not block the UI
  thread. The intro animation lives in `ui/splash.py` and the UI uses native Qt
  widgets only (no Qt WebEngine).

## 9. Tests and fixtures

`tests/` contains the suite (pytest) and small canonical fixtures:

```powershell
pytest -q
python tools/generate_fixtures.py                     # tests/fixtures/generated/
python tools/generate_fixtures.py --skip-com          # without Excel
python tools/generate_fixtures.py --output-dir <path>
```

- Tests marked `com` require Excel + `pywin32` and do not run in CI.
- `tests/golden/` stores reference JSON to detect engine regressions.
- `tools/generate_fixtures.py` uses `create_excel_application()` (the same CLSCTX
  activation as the analyzer), so it works with 32- or 64-bit Excel and ignores
  the WPS registration. Only encrypted files and real VBA need Excel;
  `--skip-com` omits them.
- Real VBA requires enabling "Trust access to the VBA project object model" in the
  Excel Trust Center. Without it the VBE cannot even be opened, so VBA evidence
  falls back to `evidence_capture.render_code_png()` (no Excel, no window).
- Generated Python scripts are named `fixture_python_*.py` so pytest does not
  collect them.
- `tests/test_fixture_generator.py` uses the generator as a regression for the
  structure_protection, critical_sheets_protection, external_connections,
  formulas and dynamic_execution..connections tests.
- Do not version `results/`, `tests/fixtures/generated/`, `__pycache__/`, `.venv/`.

## 10. Known warnings

- The report is written as LaTeX and compiled to PDF. A LaTeX engine (`xelatex`,
  `lualatex`, `pdflatex` or `latexmk`) must be installed and available in `PATH` (or in
  the usual MiKTeX/TeX Live folders). Install it once with
  `winget install MiKTeX.MiKTeX` (recommended) or with the official TeX Live
  installer from <https://tug.org/texlive/windows.html>.
  MiKTeX is invoked with `-enable-installer` so missing packages are downloaded on the
  first run instead of opening a GUI prompt; that first compilation can take a couple
  of minutes. If no engine is found, the `.tex` source is kept, the PDF is generated
  with the `reportlab` fallback and the analysis continues without aborting.
- `decompyle3` is abandoned and does not install on Python ≥ 3.9; the extra does not force it.
- `com` mode depends on Excel being installed and on there being no dialogs or locked
  files; in CI use `static`.
- **COM and bitness.** Python and Office do not need to share bitness. All Excel
  COM goes through `com_runtime.create_excel_application()`, which uses
  `CoCreateInstance` with `CLSCTX_LOCAL_SERVER` and, if the bitness does not match,
  `CLSCTX_ACTIVATE_32_BIT_SERVER` / `..._64_BIT_SERVER`. Never use
  `win32com.client.Dispatch("Excel.Application")` directly:
  - `Dispatch` tries `GetActiveObject` and may attach to an open Excel;
  - it uses `CLSCTX_SERVER`, which tries to load the .NET `InprocServer32` and fails with
    `0x800700C1`.
  Detection (`com_runtime.plan_com`) ignores servers that are not `EXCEL.EXE`
  (WPS registers `et.exe /Automation` and also breaks activation).
- If no Excel is registered, `--analysis com` exits with code 99 and a message that
  indicates what is missing, and `--analysis both` continues with static analysis.
- **`openpyxl` and `.xlam`.** openpyxl validates the extension before reading the ZIP and does
  not include `.xlam` in its list. `core/analyzers/excel/openpyxl_compat.py` adds it when
  importing the `analyzers.excel` subpackage; if openpyxl is upgraded, verify that
  `.xlam` can still be read (covered by the `test_addin.xlam` fixture).
- A suffix outside `EXCEL_EXTENSIONS` / `PYTHON_EXTENSIONS` fails immediately
  (`ValueError` in `AnalysisOrchestrator`, exit code 99 in the CLI). Do not invent reports for
  formats without an analyzer, such as `.xls` (the `EXCEL_LEGACY` family, still pending).
- `ui/app.py` sets the titlebar to the `"mac"` style; this is intentional.
- **Qt WebEngine is no longer used.** The dashboard and the About page use the
  native `BrandMarkWidget`, which avoids the native crash that PyQt6 6.11
  produced when instantiating a `QWebEngineView`.
- The root-level `modulos/` and `ui/` no longer exist: any path or import that
  mentions them is wrong.

## 11. Quick file map

| You need to… | Go to |
|---|---|
| Add a test or check | `core/catalog.py` (`TESTS_AVAILABLE`, `TESTS_BY_TEST`) |
| Generate test fixtures | `tools/generate_fixtures.py` |
| Run the fixture regression | `tests/test_fixture_generator.py` |
| Change CLI arguments or exit codes | `cli/main.py` |
| Change how Excel is analyzed without Excel | `core/analyzers/excel/excel_static.py` |
| Add or map an Excel suffix | `core/catalog.py` (`EXCEL_*`, `TESTS_BY_EXTENSION`) |
| Change how Excel is analyzed with COM | `core/analyzers/excel/excel_com.py` |
| Adjust COM activation or 32/64-bit Excel detection | `core/analyzers/excel/com_runtime.py` |
| Add VBA patterns | `core/analyzers/excel/vba_patterns.py` |
| Change formula rules | `core/analyzers/excel/excel_formulas.py` |
| Change bypass/backups | `core/analyzers/excel/bypass.py` |
| Change how evidence images are captured | `core/analyzers/excel/evidence_capture.py` |
| Change the password test | `core/analyzers/excel/password_check.py` |
| Change Python rules | `core/analyzers/python/python_ast.py` |
| Change the capture of a Python finding's line | `core/analyzers/python/python_evidence.py` |
| Change `.exe`/`.pyc` extraction | `core/analyzers/python/python_executable.py`, `python/python_bytecode.py` |
| Change the report JSON | `reporting/report_document.py` (`ReportDocument`, `SECTIONS`) |
| Add a JSON section | `reporting/report_document.py`: create `_section_<key>()` and add `<key>` to `SECTIONS` |
| Change report or artifact names/paths | `reporting/report_writer.py` |
| Change the LaTeX/PDF report | `reporting/report_docx.py` |
| Change paths or resources | `paths.py` |
| Change the startup animation | `ui/splash.py` |
| Change the dashboard / About brand animation | `ui/widgets/brand_mark.py` |
| Change navigation or theme | `ui/shell.py`, `ui/theme.py`, `ui/widgets/nav_sidebar.py` |
| Change the analysis worker | `ui/pages/analysis.py` |
| Add a dependency | `pyproject.toml` (`dependencies` or extras) |

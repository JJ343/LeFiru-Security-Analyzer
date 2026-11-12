# LeFiru Security Analyzer

Security analysis tool for **Excel workbooks** (`.xlsx`, `.xlsm`, `.xlsb`,
`.xltx`, `.xltm`, `.xlam`) and **Python code** (`.py`, `.pyc`, `.exe`), aimed at
integrity, traceability and segregation-of-duties testing in controlled
environments.

It generates findings per test, calculates the compliance status and produces
JSON + a LaTeX/PDF report with the evidence.

> **Authorized use.** The project includes intrusive tests (opening password
> test, attempt to bypass protections) that **temporarily modify** the analyzed
> files. Use it only on your own files or with the owner's written authorization.

## Requirements

- Windows 10/11
- Python 3.11 or higher
- A LaTeX engine to build the PDF report: **MiKTeX** (recommended) or **TeX Live**.
  MiKTeX also downloads the packages used by the report the first time it runs.
  If no engine is found, the `.tex` source is still written and the PDF is generated
  with the built-in `reportlab` fallback, so the analysis never fails.
- Microsoft Excel + `pywin32` **only** for `com` mode (`static` mode does not need them).
  Excel can be 32- or 64-bit: if it does not match the Python bitness, an
  interpreter with Excel's bitness is required (see below).

### LaTeX engine (PDF)

The report is written in LaTeX and compiled to PDF. Install one engine once:

```powershell
# Option 1 (recommended on Windows)
winget install MiKTeX.MiKTeX

# Option 2: TeX Live (official installer)
# https://tug.org/texlive/windows.html
```

Close and reopen the terminal after installing so the engine is available in
`PATH`; the analyzer also detects the usual MiKTeX/TeX Live installation folders.
`xelatex`, `lualatex`, `pdflatex` and `latexmk` are supported.

## Installation

```powershell
# CLI only
pip install -e .

# CLI + desktop interface
pip install -e ".[gui]"

# COM mode (real Excel automation)
pip install -e ".[windows]"
```

## Usage

```powershell
# Desktop interface
lefiru-analyzer

# Excel in static mode (without Excel installed)
lefiru --path "workbook.xlsm" --analysis static

# Excel via COM
lefiru --path "workbook.xlsx" --analysis com --debug

# Python script, bytecode or executable
lefiru --path "script.py"
lefiru --path "app.exe" -o results

# Only some tests
lefiru --path "workbook.xlsm" --tests vba,patterns,formulas
```

### COM with 32- or 64-bit Excel

It works with any bitness combination, without installing another Python:

| Python | Excel | Activation |
|---|---|---|
| 64-bit | 64-bit | local server |
| 32-bit | 32-bit | local server |
| 64-bit | 32-bit | local server + `CLSCTX_ACTIVATE_32_BIT_SERVER` |
| 32-bit | 64-bit | local server + `CLSCTX_ACTIVATE_64_BIT_SERVER` |

The application detects the registered Excel (ignoring impostors such as WPS's
`et.exe`) and chooses the flags. It always uses **out-of-process** activation,
which avoids the .NET `InprocServer32` and the `0x800700C1` error.

If no Excel is registered, `--analysis com` exits with code 99 and explains what is
missing; `--analysis both` continues with static analysis.


## Outputs

For each analyzed file, `<output>/<stem>/` is created with:

```
logs/             lefiru_analysis.log
reports/          <stem>_report.json, <stem>_report.tex and <stem>_report.pdf
reports/evidence/ screenshots and supporting artifacts (VBA exports in evidence/vba/)
backups/          copy made before tests that modify the file
```

## Project structure

```
src/lefiru/
├── cli/        command-line interface
├── core/       analysis engine (does not import PyQt6)
├── reporting/  JSON and LaTeX/PDF report
├── data/       bundled dictionaries
└── ui/         PyQt6 desktop application
```

## License

[Apache-2.0](LICENSE).

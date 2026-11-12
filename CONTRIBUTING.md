T# Contributing

Thank you for your interest. This document describes the minimum workflow for a
change to be accepted.

## Environment

```powershell
git clone https://github.com/JJ343/LeFiru-Security-Analyzer
cd lefiru-analyzer
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[gui,dev]"
```

## Before opening a pull request

```powershell
ruff check src tests
pytest -q
```

And if the change touches the engine, run the CLI against a fixture and review the JSON:

```powershell
lefiru --path tests/fixtures/<file>.xlsm --analysis static -o out_check
```

## Rules

- **Do not mix** structural refactors with behavior changes: separate PRs.
- Test identifiers (`structure_protection`, `dynamic_execution`, …) and report JSON
  keys are **public API**: they are not renamed without a migration note.
- `lefiru.core` cannot import `PyQt6` or anything from `lefiru.ui`. A test verifies this.
- Log and interface messages are in English; file and module names are in English.
- Never include credentials, personal paths or client brands in the code.

## Style

- `ruff` with the configuration from `pyproject.toml`.
- Types in new signatures (`from __future__ import annotations`).
- `logging.getLogger(__name__)`; no `print` in analysis modules.
- Per-test/file error handling: a failure must not take down the whole batch.

"""Concrete analyzers by format and risk family.

The folder is split into two subpackages, one per input family:

- :mod:`lefiru.core.analyzers.excel` — Excel (.xlsx / .xlsm / .xlsb):
  static and COM analysis, formulas, VBA, opening password and bypass.
- :mod:`lefiru.core.analyzers.python` — Python (.py / .pyc / .exe):
  AST analysis, bytecode recovery and executable extraction.

Imports must target the concrete module (for example
``from lefiru.core.analyzers.excel.excel_static import StaticWorkbookInspector``).
"""

import logging
import re
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import openpyxl
from openpyxl.formula.translate import Translator
from openpyxl.utils import get_column_letter

from lefiru.core.catalog import EXCEL_OOXML
from lefiru.core.analysis_support import is_critical_sheet


class FormulaIntegrityInspector:
    """Analyzes Excel formulas to detect traceability and integrity risks."""

    # Limits per finding type (None = no limit)
    LIMIT_BY_TYPE: Dict[str, Optional[int]] = {
        "error_formula":         100,   # critical, but 100 already evidences the pattern
        "inconsistency_formula": 50,   # observation: 50 is more than enough
        "external_reference":    None,  # unique critical per cell — no limit
        "reference_dynamics":   100,   # medium
        "vba_source_cell":      None,  # critical credential — no limit
        "credential_in_cell":    50,   # credential in cell: 50 proves the pattern
    }
    # Legacy limit used only by _scan_credential_cell_values
    MAX_CREDENTIAL_SCANS = 50
    # Maximum number of formula cells inspected per sheet (avoids loading huge sheets)
    MAX_FORMULA_CELLS_PER_SHEET = 500
    ERROR_VALUES = {"#REF!", "#DIV/0!", "#NAME?", "#N/A", "#VALUE!", "#NUM!", "#NULL!"}
    TRACEABILITY_FUNCTIONS = {"INDIRECT", "INDIRECTO", "OFFSET", "DESREF"}
    FUNCTION_PATTERN = re.compile(r"([A-ZÁÉÍÓÚ\.]+)\s*\(", re.IGNORECASE)

    # ── Detection of hardcoded credentials in cells ───────────────────────────
    # Keywords that suggest a VBA variable stores a credential
    CREDENTIAL_VAR_KEYWORDS = frozenset({
        "password", "passwd", "pwd", "pass", "clave", "contrasena", "contra",
        "token", "secret", "apikey", "api_key", "authkey", "auth",
        "correo", "email", "mail", "usuario", "user", "username", "login",
        "credential", "credencial",
    })
    PASSWORD_VAR_PATTERNS = (
        re.compile(r"pass(?:word|wd|w|wrd|sw|code)?", re.IGNORECASE),
        re.compile(r"p(?:ass)?wd", re.IGNORECASE),
        re.compile(r"pswd", re.IGNORECASE),
        re.compile(r"contr(?:a|as|ase|asen|asena)?", re.IGNORECASE),
        re.compile(r"clav(?:e)?", re.IGNORECASE),
        re.compile(r"secret(?:o)?", re.IGNORECASE),
    )
    PASSWORD_TOKEN_KEYWORDS = frozenset({
        "password", "passwd", "pwd", "pw", "pswd", "pass", "passw",
        "passcode", "clave", "contra", "contras", "contrasena", "secret",
        "secreto",
    })
    PASSWORD_CONTEXT_HINTS = frozenset({
        "mail", "email", "correo", "user", "usuario", "login", "auth",
        "sap", "db", "sql", "ftp", "app", "admin", "adm", "api",
        "service", "svc", "portal", "web",
    })
    PASSWORD_COMPACT_RE = re.compile(
        r"^(?:pw|pwd|pswd|pass|passw|passwd|password|contra|contras(?:ena)?|clave|secret)"
        r"[a-z0-9]{1,24}$|^[a-z0-9]{1,24}"
        r"(?:pw|pwd|pswd|pass|passw|passwd|password|contra|contras(?:ena)?|clave|secret)$",
        re.IGNORECASE,
    )
    PASSWORD_CONTEXT_RE = re.compile(
        r"(?:clave|password|passwd|pwd|contrasen|codigo\s+de\s+acceso|control\s+de\s+acceso|"
        r"opencurrentdatabase|inputbox|login|autent|authenticate|mensaje\s*=|msgbox)",
        re.IGNORECASE,
    )
    # Pattern: variable = Sheets("Sheet").Range("Cell")  [with or without .Value at the end]
    VBA_CELL_READ_RE = re.compile(
        r'(?P<var>\w+)\s*=\s*(?:ThisWorkbook\.)?(?:Worksheets|Sheets)\s*\(\s*'
        r'["\'](?P<sheet>[^"\']+)["\']\s*\)\s*\.\s*Range\s*\(\s*'
        r'["\'](?P<cell>[^"\']+)["\']\s*\)(?:\.Value)?',
        re.IGNORECASE,
    )
    # A cell value looks like a password if: 6-100 chars, no spaces,
    # at least one letter AND at least one digit or special character
    CREDENTIAL_VALUE_RE = re.compile(
        r'^(?=.*[A-Za-z])(?=.*[\d!@#$%^&*()\-_=+\[\]{};:,.<>?/\\|`~])'
        r'[A-Za-z0-9!@#$%^&*()\-_=+\[\]{};:,.<>?/\\|`~]{6,100}$'
    )
    # Sheet names that suggest sensitive content
    SENSITIVE_SHEET_RE = re.compile(
        r'(?:password|contrase|clave|secret|config|credencial|auth|login|token)',
        re.IGNORECASE,
    )
    URL_OR_URI_RE = re.compile(
        r"(?i)^(?:[a-z][a-z0-9+\-.]*://|www\.)|(?:https?|ftps?|sftp|smb)://",
    )
    FILE_PATH_RE = re.compile(
        r"(?i)^(?:[A-Z]:[\\/]|\\\\[^\\/]+[\\/][^\\/]+)|/[^\s]+",
    )
    EXCEL_ERROR_LITERAL_RE = re.compile(
        r"(?i)^#(?:REF!|DIV/0!|NAME\?|N/A|VALUE!|NUM!|NULL!|SPILL!|CALC!|GETTING_DATA)$"
    )

    def __init__(self, file_path: Path):
        self.file_path = Path(file_path)
        self.logger = logging.getLogger(__name__)
        # Formula normalization cache — avoids re-creating Translator for the
        # same (formula, origin), which happens in workbooks with identical sheets.
        self._norm_cache: Dict[Tuple[str, str], str] = {}

    @staticmethod
    def _friendly_com_error(exc: Exception) -> str:
        """Normalizes raw COM errors so opaque messages like '<unknown>.Name' are not exposed."""
        raw = str(exc)
        lowered = raw.lower()
        if "<unknown>.name" in lowered:
            return "COM error resolving sheet/range name during formula analysis"
        if "-214" in raw or "com" in lowered:
            return f"COM error during formula analysis: {raw}"
        return raw

    @staticmethod
    def _safe_sheet_name(sheet: Any, fallback_idx: int) -> str:
        try:
            return str(getattr(sheet, "Name"))
        except Exception:
            return f"Sheet_{fallback_idx}"

    def analyze(self) -> Dict[str, Any]:
        suffix = self.file_path.suffix.lower()
        if suffix not in EXCEL_OOXML:
            return {
                "status": "NOT_APPLICABLE",
                "method": "no_supported",
                "detail": f"Formula analysis is not supported for {suffix} files",
                "findings": [],
                "total_formulas": 0,
                "summary": self._empty_summary(),
            }

        formula_wb = None
        values_wb = None
        try:
            # read_only=True enables streaming mode: it does not load the whole
            # workbook into memory and is significantly faster on large files.
            formula_wb = openpyxl.load_workbook(
                self.file_path,
                read_only=True,
                data_only=False,
                keep_links=True,
            )
            values_wb = openpyxl.load_workbook(
                self.file_path,
                read_only=True,
                data_only=True,
                keep_links=True,
            )
            sheet_sources = []
            for sheet_name in formula_wb.sheetnames:
                formula_ws = formula_wb[sheet_name]
                # formulas: formula analysis is restricted to critical sheets
                # (input/output/config/parametros/datos/resultado/calculo/process/control).
                # Non-critical sheets are skipped to focus the analysis on what matters
                # and improve performance on large files.
                if not is_critical_sheet(sheet_name):
                    sheet_sources.append({
                        "sheet": sheet_name,
                        "sheet_status": formula_ws.sheet_state,
                        "cells": [],
                        "skipped_by_no_critical": True,
                    })
                    continue

                values_ws = values_wb[sheet_name]
                cells = []
                collected = 0

                # Iterate both sheets in parallel to avoid random access
                # (not available in read_only mode).
                for f_row, v_row in zip(formula_ws.iter_rows(), values_ws.iter_rows()):
                    if collected >= self.MAX_FORMULA_CELLS_PER_SHEET:
                        break
                    for f_cell, v_cell in zip(f_row, v_row):
                        if collected >= self.MAX_FORMULA_CELLS_PER_SHEET:
                            break
                        if not self._is_formula_cell(f_cell):
                            continue
                        cells.append(
                            {
                                "cell": f_cell.coordinate,
                                "formula": str(f_cell.value),
                                "value_cache": v_cell.value,
                                "column": f_cell.column,
                                "row": f_cell.row,
                            }
                        )
                        collected += 1

                sheet_sources.append(
                    {
                        "sheet": sheet_name,
                        "sheet_status": formula_ws.sheet_state,
                        "cells": cells,
                    }
                )

            return self._analyze_sheet_sources(sheet_sources, method="openpyxl")
        except Exception as exc:
            self.logger.error("Error analyzing formulas: %s", exc)
            return {
                "status": "ERROR",
                "method": "openpyxl",
                "detail": str(exc),
                "findings": [],
                "total_formulas": 0,
                "summary": self._empty_summary(),
            }
        finally:
            if formula_wb is not None:
                formula_wb.close()
            if values_wb is not None:
                values_wb.close()

    def analyze_com_workbook(self, workbook: Any) -> Dict[str, Any]:
        """Analyzes formulas through a workbook opened by COM Automation."""
        try:
            sheet_sources = []
            truncated = False

            for idx, sheet in enumerate(workbook.Worksheets, start=1):
                cells = []
                sheet_name = self._safe_sheet_name(sheet, idx)
                sheet_state = self._sheet_state_from_com(sheet)

                # formulas: only analyze formulas on critical sheets.
                if not is_critical_sheet(sheet_name):
                    sheet_sources.append({
                        "sheet": sheet_name,
                        "sheet_status": sheet_state,
                        "cells": [],
                        "skipped_by_no_critical": True,
                    })
                    continue

                try:
                    used_range = sheet.UsedRange
                    row_count = int(getattr(used_range.Rows, "Count", 0) or 0)
                    col_count = int(getattr(used_range.Columns, "Count", 0) or 0)
                    if row_count == 0 or col_count == 0:
                        sheet_sources.append(
                            {
                                "sheet": sheet_name,
                                "sheet_status": sheet_state,
                                "cells": [],
                            }
                        )
                        continue

                    max_rows = min(row_count, 500)
                    max_cols = min(col_count, 200)
                    truncated = truncated or row_count > max_rows or col_count > max_cols
                    # Collect at most the highest limit defined per type (100)
                    max_cells_per_sheet = max(
                        (v for v in self.LIMIT_BY_TYPE.values() if v is not None), default=500
                    )

                    for row_index in range(1, max_rows + 1):
                        if len(cells) >= max_cells_per_sheet:
                            break
                        for col_index in range(1, max_cols + 1):
                            if len(cells) >= max_cells_per_sheet:
                                break
                            try:
                                excel_cell = used_range.Cells(row_index, col_index)
                                if not bool(getattr(excel_cell, "HasFormula", False)):
                                    continue

                                cells.append(
                                    {
                                        "cell": f"{get_column_letter(col_index)}{row_index}",
                                        "formula": str(excel_cell.Formula),
                                        "value_cache": excel_cell.Value,
                                        "column": col_index,
                                        "row": row_index,
                                    }
                                )
                            except Exception as cell_exc:
                                self.logger.debug(
                                    "Could not read cell via COM in %s (%s%s): %s",
                                    sheet_name,
                                    get_column_letter(col_index),
                                    row_index,
                                    self._friendly_com_error(cell_exc),
                                )
                                continue
                except Exception as exc:
                    self.logger.warning(
                        "Could not inspect formulas via COM on sheet %s: %s",
                        sheet_name,
                        self._friendly_com_error(exc),
                    )

                sheet_sources.append(
                    {
                        "sheet": sheet_name,
                        "sheet_status": sheet_state,
                        "cells": cells,
                    }
                )

            result = self._analyze_sheet_sources(sheet_sources, method="com_automation")
            if truncated:
                result["limitation"] = (
                    "COM formula analysis was limited to the first 500 rows and 200 columns of the UsedRange per sheet"
                )
            return result
        except Exception as exc:
            friendly_error = self._friendly_com_error(exc)
            self.logger.error("Error analyzing formulas via COM: %s", friendly_error)
            return {
                "status": "ERROR",
                "method": "com_automation",
                "detail": friendly_error,
                "findings": [],
                "total_formulas": 0,
                "summary": self._empty_summary(),
            }

    def _analyze_sheet_sources(self, sheet_sources: List[Dict[str, Any]], method: str) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        formulas_by_sheet: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        sheet_details = []

        for sheet_data in sheet_sources:
            formula_cells = 0
            # Per-type counter to apply individual limits
            type_counts: Dict[str, int] = defaultdict(int)
            sheet_name = sheet_data["sheet"]
            sheet_state = sheet_data.get("sheet_status", "visible")

            for cell_data in sheet_data.get("cells", []):
                formula_cells += 1
                formula = cell_data["formula"]
                functions = self._extract_functions(formula)

                # Skip normalization once we already have enough cells to
                # detect inconsistencies (3× the limit is more than enough).
                inconsistency_cap = self.LIMIT_BY_TYPE.get("inconsistency_formula")
                need_normalization = (
                    inconsistency_cap is None
                    or len(formulas_by_sheet[sheet_name]) < inconsistency_cap * 3
                )
                normalized = (
                    self._normalize_formula(formula, cell_data["cell"])
                    if need_normalization
                    else formula
                )

                normalized_cell = {
                    "cell": cell_data["cell"],
                    "formula": formula,
                    "formula_normalized": normalized,
                    "value_cache": cell_data.get("value_cache"),
                    "functions": functions,
                    "column": cell_data["column"],
                    "row": cell_data["row"],
                    "hidden": sheet_state != "visible",
                }
                formulas_by_sheet[sheet_name].append(normalized_cell)

                # Check whether all bounded types are saturated.
                # If so, only external references (unbounded) are worth looking for.
                all_bounded_saturated = all(
                    type_counts[type] >= limit
                    for type, limit in self.LIMIT_BY_TYPE.items()
                    if limit is not None
                )
                if all_bounded_saturated:
                    # Fast path: only external_reference (unbounded) via a cheap check
                    if self._has_external_reference(formula):
                        findings.append(self._build_finding(
                            "external_reference", "critical", sheet_name,
                            cell_data["cell"], formula,
                            "The formula depends on a workbook or resource external to the evaluated file.",
                        ))
                else:
                    cell_findings = self._collect_formula_findings(sheet_name, normalized_cell)
                    accepted: List[Dict[str, Any]] = []
                    for finding in cell_findings:
                        type = finding["type"]
                        limit = self.LIMIT_BY_TYPE.get(type)
                        if limit is None or type_counts[type] < limit:
                            accepted.append(finding)
                            type_counts[type] += 1
                    findings.extend(accepted)

            sheet_details.append(
                {
                    "sheet": sheet_name,
                    "sheet_status": sheet_state,
                    "total_formulas": formula_cells,
                    "skipped_by_no_critical": bool(sheet_data.get("skipped_by_no_critical")),
                }
            )

        findings.extend(self._detect_inconsistencies(formulas_by_sheet))
        findings = self._deduplicate_findings(findings)
        findings = self._compress_findings(findings)
        summary = self._summarize(findings)
        total_critical = summary.get("critical", 0)
        total_medium = summary.get("medium", 0)
        total_low = summary.get("low", 0)
        total_errors_formula = summary["by_type"].get("error_formula", 0)
        total_credentials = (
            summary["by_type"].get("vba_source_cell", 0)
            + summary["by_type"].get("credential_in_cell", 0)
        )

        if not any(detail["total_formulas"] for detail in sheet_details):
            status = "NOT_APPLICABLE"
            detail = "The file contains no evaluable formulas"
        elif total_credentials > 0 and total_errors_formula > 0:
            status = "VULNERABLE"
            detail = (
                f"{total_errors_formula} formula(s) with calculation errors were detected "
                f"and {total_credentials} hardcoded credential finding(s)"
            )
        elif total_credentials > 0:
            status = "VULNERABLE"
            detail = f"{total_credentials} hardcoded credential finding(s) were detected"
        elif total_errors_formula > 0:
            status = "COMPLIANT_WITH_OBSERVATIONS"
            detail = f"{total_errors_formula} formula(s) with calculation errors were detected"
        elif total_critical > 0:
            status = "VULNERABLE"
            detail = "Critical findings were detected in formulas"
        elif (total_medium + total_low) > 0:
            status = "COMPLIANT_WITH_OBSERVATIONS"
            detail = "No formulas with calculation errors were detected, but there are observations that should be reviewed"
        else:
            status = "COMPLIANT"
            detail = "No formulas with calculation errors were detected"

        return {
            "status": status,
            "method": method,
            "detail": detail,
            "findings": findings,
            "total_formulas": sum(detail["total_formulas"] for detail in sheet_details),
            "sheets": sheet_details,
            "summary": summary,
        }

    # ── Detection of hardcoded credentials in cells ───────────────────────────

    def analyze_vba_credential_links(self, vba_modules: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detects cells that store hardcoded credentials referenced from VBA.

        Analyzes the VBA code looking for assignments such as:
        ``variable = Sheets("Sheet").Range("Cell")``
        where the variable name suggests a credential (password, token, email, etc.)
        and then reads the actual value of that cell from the workbook.

        Only credentials explicitly referenced by VBA code are reported.
        No speculative scanning of cell values is performed.
        """
        findings: List[Dict[str, Any]] = []

        # VBA references → cells with credentials
        vba_refs = self._extract_vba_cell_refs(vba_modules)
        if vba_refs:
            cell_values = self._read_referenced_cells(
                {(r["sheet"], r["cell"]) for r in vba_refs}
            )
            for ref in vba_refs:
                key = (ref["sheet"].lower(), ref["cell"].upper())
                current_value = cell_values.get(key)
                desc = (
                    f"VBA module '{ref['module']}' (line {ref['line']}) "
                    f"reads the cell into the variable '{ref['var']}', "
                    f"whose name suggests it stores a credential."
                )
                if current_value is not None and str(current_value).strip():
                    desc += f" Cell value: {current_value}"
                findings.append(
                    self._build_finding(
                        "vba_source_cell",
                        "critical",
                        ref["sheet"],
                        ref["cell"],
                        f"VBA: {ref['var']} = Sheets(\"{ref['sheet']}\").Range(\"{ref['cell']}\")",
                        desc,
                        vba_module=ref["module"],
                        line_vba=ref["line"],
                        variable_vba=ref["var"],
                    )
                )

        findings = self._deduplicate_findings(findings)
        findings = self._compress_findings(findings)
        findings = self._deduplicate_findings(findings)
        summary = self._summarize(findings)

        if not findings:
            return {
                "status": "COMPLIANT",
                "method": "vba_credential_scan",
                "detail": "No hardcoded credentials were detected in cells",
                "findings": [],
                "total_formulas": 0,
                "summary": summary,
            }

        return {
            "status": "VULNERABLE",
            "method": "vba_credential_scan",
            "detail": f"{len(findings)} credential finding(s) in cells were detected",
            "findings": findings,
            "total_formulas": 0,
            "summary": summary,
        }

    def _extract_vba_cell_refs(self, vba_modules: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extracts Sheets("X").Range("Y") references assigned to credential-named variables."""
        refs: List[Dict[str, Any]] = []
        for module_name, module_data in vba_modules.items():
            code = module_data.get("code") or ""
            lines = code.splitlines()
            for lineno, line in enumerate(lines, start=1):
                for match in self.VBA_CELL_READ_RE.finditer(line):
                    var = match.group("var")
                    context_window = self._build_vba_context_window(lines, lineno - 1, var)
                    if self._is_credential_var(var, context_window):
                        refs.append({
                            "module": module_name,
                            "line": lineno,
                            "var": var,
                            "sheet": match.group("sheet"),
                            "cell": match.group("cell"),
                        })
        return refs

    def _is_credential_var(self, var_name: str, context: str = "") -> bool:
        """Returns True if the variable name suggests it stores a credential."""
        normalized = self._normalize_var_name(var_name)
        tokens = self._tokenize_var_name(var_name)

        if any(keyword in normalized for keyword in self.CREDENTIAL_VAR_KEYWORDS):
            return True

        if any(token in self.PASSWORD_TOKEN_KEYWORDS for token in tokens):
            return True

        if any(token.startswith(("pass", "passw", "contra", "contras", "clav", "secret")) for token in tokens):
            return True

        if self.PASSWORD_COMPACT_RE.search(normalized):
            return True

        # Compact cases with a short prefix/suffix, e.g. pwCorreo, correoPwd, pswdSap.
        if any(hint in normalized for hint in self.PASSWORD_CONTEXT_HINTS):
            if re.search(r"(?:^|[a-z0-9])(pw|pwd|pswd)(?:[a-z0-9]|$)", normalized, re.IGNORECASE):
                return True

        # Variables that are too short/ambiguous, such as 'cont', are only accepted
        # if the nearby context shows authentication/key semantics.
        if self._looks_like_secret_context(context, normalized):
            return True

        return any(pattern.search(normalized) for pattern in self.PASSWORD_VAR_PATTERNS)

    def _build_vba_context_window(self, lines: List[str], line_index: int, var_name: str) -> str:
        """Returns a VBA context window around an assignment line."""
        start = max(0, line_index - 3)
        end = min(len(lines), line_index + 4)
        window = "\n".join(lines[start:end])
        return f"{window}\nVAR={var_name}"

    def _looks_like_secret_context(self, context: str, normalized_var_name: str) -> bool:
        """Evaluates whether the nearby context suggests password/key usage."""
        if not context:
            return False

        normalized_context = self._normalize_var_name(context)
        if not self.PASSWORD_CONTEXT_RE.search(context):
            return False

        # Very short aliases allowed only with strong authentication context.
        short_aliases = {"cont", "cont1", "cont2", "cta", "cta1", "cta2", "codacc", "access_code"}
        if normalized_var_name in short_aliases:
            return True

        # Also accept short names that take part in comparisons or typical login usage.
        if len(normalized_var_name) <= 5 and normalized_var_name in normalized_context:
            auth_shapes = (
                f"mensaje{normalized_var_name}",
                f"{normalized_var_name}mensaje",
                f"false{normalized_var_name}",
                f"{normalized_var_name}show",
                f"{normalized_var_name}inputbox",
            )
            if any(shape in normalized_context for shape in auth_shapes):
                return True

        return False

    def _normalize_var_name(self, var_name: str) -> str:
        """Normalizes variable names to improve abbreviation matching."""
        ascii_name = unicodedata.normalize("NFKD", var_name)
        ascii_name = "".join(ch for ch in ascii_name if not unicodedata.combining(ch))
        return re.sub(r"[^a-z0-9]", "", ascii_name.lower())

    def _tokenize_var_name(self, var_name: str) -> List[str]:
        """Tokenizes camelCase, snake_case and mixed names to improve matching."""
        ascii_name = unicodedata.normalize("NFKD", var_name)
        ascii_name = "".join(ch for ch in ascii_name if not unicodedata.combining(ch))
        split_name = re.sub(r"([a-z])([A-Z])", r"\1 \2", ascii_name)
        split_name = re.sub(r"([A-Za-z])([0-9])", r"\1 \2", split_name)
        split_name = re.sub(r"([0-9])([A-Za-z])", r"\1 \2", split_name)
        split_name = re.sub(r"[^A-Za-z0-9]", " ", split_name)
        return [token.lower() for token in split_name.split() if token]

    def _read_referenced_cells(
        self, cell_refs: Set[Tuple[str, str]]
    ) -> Dict[Tuple[str, str], Any]:
        """Opens the workbook and returns the values of the referenced cells."""
        if not cell_refs or self.file_path.suffix.lower() not in EXCEL_OOXML:
            return {}
        values: Dict[Tuple[str, str], Any] = {}
        try:
            wb = openpyxl.load_workbook(self.file_path, read_only=True, data_only=True)
            sheets_lower = {s.lower(): s for s in wb.sheetnames}
            for sheet_name, cell_addr in cell_refs:
                current_name = sheets_lower.get(sheet_name.lower())
                if current_name is None:
                    continue
                try:
                    values[(sheet_name.lower(), cell_addr.upper())] = wb[current_name][cell_addr].value
                except Exception:
                    pass
            wb.close()
        except Exception as exc:
            self.logger.warning("Could not read cells referenced by VBA: %s", exc)
        return values

    def _scan_credential_cell_values(
        self,
        exclude_refs: Optional[Set[Tuple[str, str]]] = None,
    ) -> List[Dict[str, Any]]:
        """Scans cells on hidden or sensitively named sheets for password-like values (limited to 200)."""
        findings: List[Dict[str, Any]] = []
        excluded = exclude_refs or set()
        if self.file_path.suffix.lower() not in EXCEL_OOXML:
            return findings
        try:
            wb = openpyxl.load_workbook(self.file_path, read_only=True, data_only=True)
            for sheet_name in wb.sheetnames:
                if len(findings) >= self.MAX_CREDENTIAL_SCANS:
                    break
                ws = wb[sheet_name]
                is_hidden = ws.sheet_state != "visible"
                is_sensitive_name = bool(self.SENSITIVE_SHEET_RE.search(sheet_name))
                if not is_hidden and not is_sensitive_name:
                    continue
                for row in ws.iter_rows():
                    if len(findings) >= self.MAX_CREDENTIAL_SCANS:
                        break
                    for cell in row:
                        if not isinstance(cell.value, str):
                            continue
                        normalized_ref = (sheet_name.lower(), cell.coordinate.upper())
                        if normalized_ref in excluded:
                            continue

                        raw_value = cell.value.strip()
                        if not raw_value:
                            continue

                        if self._should_skip_credential_candidate(raw_value):
                            continue

                        if self.CREDENTIAL_VALUE_RE.match(raw_value):
                            findings.append(
                                self._build_finding(
                                    "credential_in_cell",
                                    "critical",
                                    sheet_name,
                                    cell.coordinate,
                                    raw_value,
                                    f"The cell contains a value that looks like a hardcoded credential: {raw_value}",
                                )
                            )
                            if len(findings) >= self.MAX_CREDENTIAL_SCANS:
                                break
            wb.close()
        except Exception as exc:
            self.logger.warning("Could not scan cells for credentials: %s", exc)
        return findings

    def _should_skip_credential_candidate(self, value: str) -> bool:
        """Discards literals that are usually credential false positives."""
        text = value.strip()
        lowered = text.lower()

        if lowered in {error.lower() for error in self.ERROR_VALUES}:
            return True

        if self.EXCEL_ERROR_LITERAL_RE.match(text):
            return True

        if self.URL_OR_URI_RE.search(text):
            return True

        if self.FILE_PATH_RE.search(text):
            return True

        # Typical non-secret values or common placeholders.
        if lowered in {"none", "null", "n/a", "na", "true", "false", "error"}:
            return True

        return False

    def _collect_formula_findings(self, sheet_name: str, cell_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        formula = cell_data["formula"]
        functions = cell_data["functions"]
        cell = cell_data["cell"]
        cached_value = cell_data.get("value_cache")

        if self._has_external_reference(formula):
            findings.append(
                self._build_finding(
                    "external_reference",
                    "critical",
                    sheet_name,
                    cell,
                    formula,
                    "The formula depends on a workbook or resource external to the evaluated file.",
                )
            )

        if self._has_traceability_function(functions):
            findings.append(
                self._build_finding(
                    "reference_dynamics",
                    "medium",
                    sheet_name,
                    cell,
                    formula,
                    "The formula uses dynamic references that hinder the traceability of the calculation.",
                )
            )

        if cached_value in self.ERROR_VALUES:
            findings.append(
                self._build_finding(
                    "error_formula",
                    "critical",
                    sheet_name,
                    cell,
                    formula,
                    f"The formula presents a calculated error: {cached_value}.",
                )
            )

        return findings

    def _sheet_state_from_com(self, sheet: Any) -> str:
        visible = getattr(sheet, "Visible", -1)
        if visible == 0:
            return "hidden"
        if visible == 2:
            return "veryHidden"
        return "visible"

    def _detect_inconsistencies(self, formulas_by_sheet: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        limit = self.LIMIT_BY_TYPE.get("inconsistency_formula")

        for sheet_name, cells in formulas_by_sheet.items():
            if limit is not None and len(findings) >= limit:
                break

            cells_by_column: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
            for cell in cells:
                cells_by_column[cell["column"]].append(cell)

            for column_cells in cells_by_column.values():
                if limit is not None and len(findings) >= limit:
                    break

                sorted_cells = sorted(column_cells, key=lambda item: item["row"])
                segment: List[Dict[str, Any]] = []

                for current in sorted_cells:
                    if not segment or current["row"] == segment[-1]["row"] + 1:
                        segment.append(current)
                    else:
                        findings.extend(self._analyze_segment(sheet_name, segment))
                        if limit is not None and len(findings) >= limit:
                            break
                        segment = [current]

                if limit is None or len(findings) < limit:
                    findings.extend(self._analyze_segment(sheet_name, segment))

        if limit is not None:
            findings = findings[:limit]
        return findings

    def _analyze_segment(self, sheet_name: str, segment: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if len(segment) < 3:
            return []

        counter = Counter(cell["formula_normalized"] for cell in segment)
        if len(counter) <= 1:
            return []

        dominant_formula, dominant_count = counter.most_common(1)[0]
        if dominant_count < 2:
            return []

        findings = []
        for cell in segment:
            if cell["formula_normalized"] == dominant_formula:
                continue
            findings.append(
                self._build_finding(
                    "inconsistency_formula",
                    "medium",
                    sheet_name,
                    cell["cell"],
                    cell["formula"],
                    "Review recommended: the formula in this cell deviates from the most common formula in nearby cells of the same range. This may be a valid exception, but it may also be a copy error or a modification worth reviewing.",
                )
            )
        return findings

    def _is_formula_cell(self, cell: Any) -> bool:
        if cell.data_type == "f":
            return True
        return isinstance(cell.value, str) and cell.value.startswith("=")

    def _normalize_formula(self, formula: str, origin: str) -> str:
        key = (formula, origin)
        if key not in self._norm_cache:
            try:
                self._norm_cache[key] = Translator(formula, origin=origin).translate_formula(dest="ZZ1000")
            except Exception:
                self._norm_cache[key] = formula
        return self._norm_cache[key]

    def _extract_functions(self, formula: str) -> List[str]:
        return [match.upper() for match in self.FUNCTION_PATTERN.findall(formula)]

    def _has_external_reference(self, formula: str) -> bool:
        lowered = formula.lower()
        return "[" in formula or "http://" in lowered or "https://" in lowered

    def _has_traceability_function(self, functions: List[str]) -> bool:
        return any(function in self.TRACEABILITY_FUNCTIONS for function in functions)

    def _build_finding(
        self,
        finding_type: str,
        severity: str,
        sheet_name: str,
        cell: str,
        formula: str,
        description: str,
        **extra: Any,
    ) -> Dict[str, Any]:
        finding = {
            "type": finding_type,
            "severity": severity,
            "sheet": sheet_name,
            "cell": cell,
            "formula": formula,
            "description": description,
        }
        if extra:
            finding.update(extra)
        return finding

    def _compress_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Collapses consecutive findings of the same type/sheet/description in the same
        column into a single finding with a cell range (e.g. C2:C81).

        Only findings whose cell is a simple reference (no ":") are compressed.
        Findings with cells already expressed as a range (generated by VBA cross-ref)
        are preserved.
        """
        from collections import defaultdict

        # Regex to parse a simple coordinate, e.g. "C2", "AB100"
        _COORD_RE = re.compile(r'^([A-Z]+)(\d+)$', re.IGNORECASE)

        def _col_to_int(col_str: str) -> int:
            """Converts column letter(s) to a 1-based index."""
            result = 0
            for ch in col_str.upper():
                result = result * 26 + (ord(ch) - ord('A') + 1)
            return result

        simple: List[Dict[str, Any]] = []
        passthrough: List[Dict[str, Any]] = []

        for f in findings:
            cell = f.get("cell", "")
            if ":" not in cell:
                simple.append(f)
            else:
                passthrough.append(f)

        if not simple:
            return passthrough

        # Group by (sheet, type, description)
        groups: Dict[tuple, List] = defaultdict(list)
        for f in simple:
            key = (f.get("sheet", ""), f.get("type", ""), f.get("description", ""))
            groups[key].append(f)

        compressed: List[Dict[str, Any]] = []

        for (_sheet, _type, _desc), group in groups.items():
            if len(group) == 1:
                compressed.append(group[0])
                continue

            # Parse coordinates with the regex
            parsed: List[tuple] = []  # (col_idx, row, finding)
            unparsed: List[Dict[str, Any]] = []
            for f in group:
                m = _COORD_RE.match(f.get("cell", ""))
                if m:
                    col_idx = _col_to_int(m.group(1))
                    row = int(m.group(2))
                    parsed.append((col_idx, row, f))
                else:
                    unparsed.append(f)

            compressed.extend(unparsed)

            if not parsed:
                continue

            # Per column, detect consecutive row segments
            by_col: Dict[int, list] = defaultdict(list)
            for col_idx, row, f in parsed:
                by_col[col_idx].append((row, f))

            for col_idx, rows_data in sorted(by_col.items()):
                rows_sorted = sorted(rows_data, key=lambda x: x[0])

                # Build segments of contiguous rows
                segments: List[List] = []
                seg = [rows_sorted[0]]
                for i in range(1, len(rows_sorted)):
                    if rows_sorted[i][0] == seg[-1][0] + 1:
                        seg.append(rows_sorted[i])
                    else:
                        segments.append(seg)
                        seg = [rows_sorted[i]]
                segments.append(seg)

                col_letter = get_column_letter(col_idx)

                for seg in segments:
                    if len(seg) == 1:
                        compressed.append(seg[0][1])
                    else:
                        first_row = seg[0][0]
                        last_row = seg[-1][0]
                        count = len(seg)
                        cell_range = f"{col_letter}{first_row}:{col_letter}{last_row}"

                        # Representative formula: the most frequent one in the segment
                        formulas = [s[1].get("formula", "") for s in seg]
                        dominant_formula = Counter(formulas).most_common(1)[0][0]

                        representative = dict(seg[0][1])
                        representative["cell"] = cell_range
                        representative["formula"] = dominant_formula
                        representative["description"] = (
                            f"{_desc} ({count} cells: {cell_range})"
                            if count > 1 and cell_range not in _desc
                            else _desc
                        )
                        representative["_grouped"] = count
                        compressed.append(representative)

        return compressed + passthrough

    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        unique = []
        seen = set()
        for finding in findings:
            key = (
                finding["type"],
                finding["sheet"],
                finding["cell"],
                finding.get("formula", ""),
                finding["description"],
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        return unique

    def _summarize(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        summary = self._empty_summary()
        by_type = Counter(finding["type"] for finding in findings)
        for finding in findings:
            severity = finding["severity"]
            if severity == "critical":
                summary["critical"] += 1
            elif severity == "medium":
                summary["medium"] += 1
            else:
                summary["low"] += 1
        summary["by_type"] = dict(by_type)
        return summary

    def _empty_summary(self) -> Dict[str, Any]:
        return {"critical": 0, "medium": 0, "low": 0, "by_type": {}}

"""Security test analysis orchestrator.

``AnalysisOrchestrator`` coordinates the Excel and Python analyzers, consolidates
findings per test and calculates the compliance status.

The test catalog lives in :mod:`lefiru.core.catalog` and the command-line
interface in :mod:`lefiru.cli.main`.
"""

import logging
import os
import threading
from datetime import datetime
from pathlib import Path

from lefiru.core.analyzers.excel.com_runtime import (
    ComNotAvailableError,
    create_analyzer_com,
)
from lefiru.core.analyzers.excel.excel_formulas import FormulaIntegrityInspector
from lefiru.core.analyzers.excel.excel_static import StaticWorkbookInspector
from lefiru.core.analyzers.excel.password_check import PasswordChecker
from lefiru.core.analyzers.excel.vba_patterns import UnsafePatternScanner
from lefiru.core.analyzers.python.python_ast import PythonCodeInspector
from lefiru.core.catalog import (
    TESTS_BY_TEST,
    EXCEL_EXTENSIONS,
    RULE_TO_CATEGORY_PY,
    TESTS_AVAILABLE,
    TESTS_BY_EXTENSION,
    PYTHON_CATEGORY_TO_TEST,
    PYTHON_EXTENSIONS,
    PYTHON_TEST_TO_CATEGORIES,
)
from lefiru.core.analysis_support import calculate_file_hash, tests_by_key
from lefiru.paths import output_root


class AnalysisOrchestrator:
    """Main class for the security analysis of Excel and Python files"""
    
    def __init__(
        self,
        file_path: str,
        mode: str,
        tests: list[str] | None = None,
        output_dir: str | None = None,
        password: str = None,
        brute_force_confirmation_cb=None,
        test_status_cb=None,
    ):
        self.file_path = Path(file_path)
        self.original_file_path = self.file_path
        self.mode = mode
        self.output_dir = Path(output_dir) if output_dir else output_root()
        self.password = password
        self.brute_force_confirmation_cb = brute_force_confirmation_cb
        self.test_status_cb = test_status_cb
        self.stop_brute_force_event = threading.Event()
        self.logger = logging.getLogger(__name__)
        self.executed_tests = []
        self.opening_resolution = None
        
        
        # Validate input
        suffix = self.file_path.suffix.lower()
        formats_supported = EXCEL_EXTENSIONS | PYTHON_EXTENSIONS
        if suffix not in formats_supported:
            raise ValueError(
                f"Unsupported extension: '{suffix or 'no extension'}'. "
                f"Accepted formats: {', '.join(sorted(formats_supported))}"
            )

        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
       
        
        self.logger.info(f"Initializing analysis of: {self.file_path.name}")
        self.logger.info(f"Mode: {self.mode}")
        if self.password:
            self.logger.info("Opening password provided")
        
        if not tests or "ALL" in tests:
            tests_default = sorted(
                TESTS_BY_EXTENSION.get(self.file_path.suffix.lower(), set()),
                key=lambda p: TESTS_AVAILABLE[p]["order"],
            )
            # Defensive fallback for unmapped extensions.
            self.tests = tests_default or list(TESTS_AVAILABLE.keys())
        else:
                # validate
                invalid_tests = set(tests) - set(TESTS_AVAILABLE.keys())
                if invalid_tests:
                    raise ValueError(f"Invalid tests: {invalid_tests}")
                self.tests = tests

    @staticmethod
    def _is_unlocked_excel_copy(path_str: str | None) -> bool:
        if not path_str:
            return False
        path = Path(path_str)
        if path.suffix.lower() not in EXCEL_EXTENSIONS:
            return False

        try:
            from lefiru.core.analyzers.excel.excel_password import OpenPasswordDetector

            pwd_info = OpenPasswordDetector(path).detect_password_protection()
            return not (pwd_info.get("has_password") and pwd_info.get("encrypted"))
        except Exception:
            return False

    def _apply_bypass_test(self, target: dict, pwd_info: dict, bypass_results: dict) -> None:
        """opening_bypass is reserved exclusively for structural opening bypass."""
        if not (pwd_info.get("has_password") and pwd_info.get("encrypted")):
            return

        compliance = target.setdefault(
            "compliance",
            {
                "general_status": "COMPLIANT",
                "tests": {},
                "critical_findings": [],
                "medium_findings": [],
                "low_findings": [],
                "recommendations": [],
            },
        )

        tests = tests_by_key(compliance.get("tests", {}))
        tests.pop("opening_bypass", None)
        compliance["tests"] = tests
        for key in ("critical_findings", "medium_findings", "low_findings"):
            compliance[key] = [
                finding for finding in compliance.get(key, [])
                if finding.get("test") != "opening_bypass"
            ]

        opening = (bypass_results or {}).get("opening_password", {})
        method = opening.get("effective_method")
        structural_methods = {
            "XML_REMOVE_WORKBOOK_PASSWORD",
            "BINARY_REMOVE_XLSB_PASSWORD",
            "EXTRACT_CONTENT_NO_PASSWORD",
        }
        evaluation_error = (bypass_results or {}).get("status") == "ERROR"
        structural_bypass = bool(opening.get("successful_bypass")) and method in structural_methods

        if evaluation_error:
            control = {
                "id": "opening_bypass",
                "name": "Resistance to opening bypass",
                "status": "NOT_APPLICABLE",
                "detail": f"Opening bypass could not be evaluated: {bypass_results.get('message', 'no detail')}"
            }
        elif structural_bypass:
            control = {
                "id": "opening_bypass",
                "name": "Resistance to opening bypass",
                "status": "VULNERABLE",
                "detail": f"The opening protection was bypassed using {method}"
            }
            compliance["critical_findings"].append({
                "test": "opening_bypass",
                "description": opening.get(
                    "message",
                    f"The opening protection was compromised using {method}"
                )
            })
            compliance["recommendations"].append(
                "Strengthen the opening control so it resists structural bypass and extraction without a password"
            )
        else:
            detail = "No effective structural bypass of the opening protection was identified"
            if method == "KNOWN_PASSWORD_ACCESS":
                detail = (
                    "No effective structural bypass was identified; access was obtained using a known password"
                )
            control = {
                "id": "opening_bypass",
                "name": "Resistance to opening bypass",
                "status": "COMPLIANT",
                "detail": detail
            }

        compliance["tests"]["opening_bypass"] = {
            "name": control["name"],
            "status": control["status"],
            "detail": control["detail"],
        }

        states = [item["status"] for item in compliance["tests"].values()]
        if "VULNERABLE" in states:
            compliance["general_status"] = "VULNERABLE"
        elif all(e in ["COMPLIANT", "NOT_APPLICABLE"] for e in states):
            compliance["general_status"] = "COMPLIANT"
        else:
            compliance["general_status"] = "COMPLIANT_WITH_OBSERVATIONS"

    def _consolidate_results(self, analysis_by_mode: dict) -> dict:
        """
        Consolidates results from multiple analysis modes (STATIC / COM),
        removing duplicates and keeping traceability of the origin.
        """

        # =========================================================
        # Definitions
        # =========================================================
        CRITICAL_CATEGORIES = {
            "credentials",
            "secrets",
            "connections",
            "sql_injection",
        }

        consolidated_findings = {}
        summary = {
            "critical": 0,
            "warnings": 0,
            "only_com": 0,
            "only_static": 0,
        }


        # Collect findings from each mode
        for mode, results_mode in analysis_by_mode.items():
            patterns = results_mode.get("insecure_patterns", {})
            module_findings = patterns.get("findings_by_module", {})

            for module, module_data in module_findings.items():
                for category, findings in module_data.get("categories", {}).items():
                    for h in findings:

                        key = (
                            module,
                            category,
                            h.get("description"),
                            h.get("line")
                        )

                        if key not in consolidated_findings:
                            consolidated_findings[key] = {
                                "module": module,
                                "category": category,
                                "description": h.get("description"),
                                "line": h.get("line"),
                                "context": h.get("context"),
                                "value_anonymized": h.get("value_anonymized"),
                                "modes": set(),
                            }

                        consolidated_findings[key]["modes"].add(mode)

        # =========================================================
        # Post-processing and counts
        # =========================================================
        for h in consolidated_findings.values():
            is_critical = h["category"] in CRITICAL_CATEGORIES

            if is_critical:
                summary["critical"] += 1
            else:
                summary["warnings"] += 1

            if h["modes"] == {"com"}:
                summary["only_com"] += 1
            elif h["modes"] == {"static"}:
                summary["only_static"] += 1

            # Normalize for serialization (JSON / DOCX)
            h["modes"] = sorted(h["modes"])

       
        # Final consolidated result
        return {
            "findings": list(consolidated_findings.values()),
            "summary": summary
        }
    
    def _run_python_analysis(self) -> dict:
        """
        Dedicated flow for Python files (.py / .pyc / .exe).

        It skips the entire Excel pipeline (COM, bypass, opening password) and
        runs PythonCodeInspector exclusively. It returns a structure
        compatible with AnalysisReportWriter.
        """
        self.logger.info("=" * 80)
        self.logger.info("STARTING PYTHON ANALYSIS")
        self.logger.info("=" * 80)

        metadata = self._get_file_info()
        hash_initial = metadata["hash"]
        self.logger.info(f"Initial SHA-256 hash: {hash_initial}")
        self.logger.info(f"Size: {metadata['size_bytes']} bytes")
        python_tests = self._resolve_tests_python_selected()
        extension = self.file_path.suffix.lower()
        self.logger.info(f"File extension: {extension}")
        self.logger.info(f"Selected Python tests: {python_tests if python_tests else 'none'}")

        # Run analyzer
        if python_tests:
            try:
                analyzer = PythonCodeInspector(
                    self.file_path,
                    output_root=self.output_dir,
                )
                analysis_raw = analyzer.analyze()
                analysis = self._filter_analysis_python_by_tests(analysis_raw, python_tests)
            except Exception as exc:  # noqa: BLE001
                self.logger.error("Error running PythonCodeInspector: %s", exc, exc_info=True)
                analysis = {
                    "status": "ERROR",
                    "error": "Python analysis could not be completed",
                    "findings": [],
                    "summary": {"critical": 0, "medium": 0, "low": 0, "by_category": {}},
                    "metadata": {},
                }
        else:
            analysis = {
                "status": "NOT_APPLICABLE",
                "detail": "No Python tests were selected to run",
                "findings": [],
                "summary": {"critical": 0, "medium": 0, "low": 0, "by_category": {}},
                "metadata": {},
            }

        # High-level log for the handling of Python executables.
        if self.file_path.suffix.lower() == ".exe":
            method_exe = analysis.get("metadata", {}).get("exe_analysis_method")
            if method_exe == "internal_extraction":
                extra = analysis.get("metadata", {}).get("internal_extraction", {})
                self.logger.info(
                    "EXE: internal extraction analysis (analyzed files: %s)",
                    extra.get("analyzed_files", "N/A"),
                )
            elif method_exe == "scan_binary_fallback":
                self.logger.info(
                    "EXE: no useful extraction was achieved; binary scan fallback was applied"
                )
            else:
                self.logger.info("EXE: analysis method not determined")

        self._log_python_analysis_details(analysis, python_tests)

        self.executed_tests = list(python_tests)

        # Build compliance from findings
        compliance = self._build_python_compliance(analysis, python_tests)

        # Group findings by test to make the JSON easier to read
        findings_by_test = self._build_findings_by_test_python(
            analysis, python_tests, compliance
        )

        # Build the structured analysis object: header + tests as direct
        # keys, the same as analysis.static in Excel files.
        analysis_structured = {
            # Analysis header
            "application_type": analysis.get("application_type"),
            "file_type": analysis.get("file_type"),
            "file":      str(self.file_path),
            "status":       analysis.get("status"),
            "detail":      analysis.get("detail", ""),
            "summary":      analysis.get("summary", {}),
            "metadata":     analysis.get("metadata", {}),
            # Individual tests as named keys (structure parallel to analysis.static in Excel)
            **findings_by_test,
        }

        hash_final = calculate_file_hash(self.file_path)
        integrity = {
            "status": "VALID" if hash_final == hash_initial else "INVALID",
            "hash_initial": hash_initial,
            "hash_final": hash_final,
            "message": (
                "The file was not modified during the analysis"
                if hash_final == hash_initial
                else "The file was modified during the analysis"
            ),
            "moment": "FINAL",
        }
        metadata["integrity"] = integrity

        # The JSON publishes tests as named sections, not as a list.
        compliance["tests"] = tests_by_key(compliance.get("tests", []))

        consolidated = {
            "timestamp": datetime.now().isoformat(),
            # analysis.python contains the header + named tests (same as Excel)
            "analysis": {"python": analysis_structured},
            "compliance": compliance,
            "metadata": metadata,
            "analysis_mode": "PYTHON",
        }

        self.logger.info("=" * 80)
        self.logger.info(f"PYTHON ANALYSIS COMPLETED: {compliance['general_status']}")
        self.logger.info("=" * 80)

        return consolidated

    def _build_findings_by_test_python(
        self,
        analysis: dict,
        python_tests: list[str],
        compliance: dict,
    ) -> dict:
        """
        Groups Python Analyzer findings by test name.

        Output structure per test::

            {
                "python_credentials": {
                    "label": "Hardcoded credentials/secrets",
                    "test": "credentials",
                    "status": "VULNERABLE",
                    "total_findings": 2,
                    "findings": [
                        {"type": ..., "severity": ..., "origin": ..., "line": ..., "description": ...}
                    ]
                },
                ...
            }
        """
        # Status index per test (comes from the compliance already built)
        status_by_test = {
            c["id"]: c["status"]
            for c in compliance.get("tests", [])
        }

        result: dict = {}

        for test in python_tests:
            meta = TESTS_AVAILABLE.get(test, {})
            categories = PYTHON_TEST_TO_CATEGORIES.get(test, set())
            if not categories:
                continue

            # Associated test (first category with a mapping)
            test_key = None
            test_name = None
            for cat in categories:
                if cat in PYTHON_CATEGORY_TO_TEST:
                    test_key, test_name = PYTHON_CATEGORY_TO_TEST[cat]
                    break

            status = status_by_test.get(test_key, "NOT_EXECUTED") if test_key else "NOT_EXECUTED"

            test_findings = [
                dict(h)
                for h in analysis.get("findings", [])
                if self._category_python_para_finding(h) in categories
            ]

            result[test] = {
                "label": meta.get("label", test),
                "test": test_key,
                "test_name": test_name,
                "status": status,
                "total_findings": len(test_findings),
                "findings": test_findings,
            }

            # Optional callback for the UI: on-screen visual progress only.
            if callable(self.test_status_cb):
                try:
                    self.test_status_cb(
                        test,
                        {
                            "label": meta.get("label", test),
                            "status": status,
                            "total_findings": len(test_findings),
                            "test": test_key,
                            "test_name": test_name,
                        },
                    )
                except Exception:
                    # Do not interrupt the analysis if the UI fails to render the status.
                    pass

        return result

    def _resolve_tests_python_selected(self) -> list[str]:
        """Resolves the selected Python tests, expanding aggregate aliases."""
        applicable = set(TESTS_BY_EXTENSION.get(self.file_path.suffix.lower(), set()))
        selected = [p for p in self.tests if p in applicable or p == "python_analysis"]

        if "python_analysis" in selected:
            selected = list(applicable)

        # Stable order according to the global configuration.
        return sorted(
            set(selected),
            key=lambda p: TESTS_AVAILABLE[p]["order"],
        )

    @staticmethod
    def _categories_enabled_python(python_tests: list[str]) -> set[str]:
        categories = set()
        for test in python_tests:
            categories.update(PYTHON_TEST_TO_CATEGORIES.get(test, set()))
        return categories

    @staticmethod
    def _category_python_para_finding(finding: dict) -> str:
        """Maps a finding to a Python test category (dynamic_execution..traceability)."""
        category = str(finding.get("category", "")).strip().lower()
        if category in PYTHON_CATEGORY_TO_TEST:
            return category

        if finding.get("type") != "rule_analysis":
            return category

        # Business rule: every analysis rule in the "quality" category
        # is consolidated into traceability.
        if category == "quality":
            return "traceability"

        name = str(finding.get("rule_name", "")).strip().lower()
        category_by_name = RULE_TO_CATEGORY_PY.get(name)
        if category_by_name:
            return category_by_name

        description = str(finding.get("description", "")).strip().lower()
        evidence = str(finding.get("evidence", "")).strip().lower()
        content = " ".join((name, description, evidence, category))

        if any(token in content for token in (
            "exec",
            "eval",
            "dynamic",
            "execution",
            "loop",
            "control flow",
        )):
            return "dynamic_execution"

        if any(token in content for token in (
            "command",
            "os command",
            "subprocess",
            "mail command",
        )):
            return "dangerous_commands"

        if any(token in content for token in (
            "deserialization",
            "deserialize",
            "pickle",
            "yaml.load",
            "marshal",
        )):
            return "deserialization"

        if any(token in content for token in (
            "credential",
            "credential",
            "password",
            "secret",
            "token",
            "cryptographic key",
            "salt",
        )):
            return "credentials"

        if any(token in content for token in (
            "connection",
            "http",
            "https",
            "cookie",
            "cors",
            "session",
            "ssrf",
            "url",
            "transport",
        )):
            return "connections"

        # Do not force analysis rules without an explicit traceability mapping.
        # They are kept out of the Python tests to avoid noise.
        return category

    def _filter_analysis_python_by_tests(self, analysis: dict, python_tests: list[str]) -> dict:
        """Filters Python findings by the selected tests and recalculates summary/status."""
        if analysis.get("status") == "ERROR":
            return analysis

        enabled_categories = self._categories_enabled_python(python_tests)
        findings_filtered = []
        for h in analysis.get("findings", []):
            category_mapped = self._category_python_para_finding(h)
            if category_mapped not in enabled_categories:
                continue
            h_normalized = dict(h)
            if h_normalized.get("category") != category_mapped:
                h_normalized["category_original"] = h_normalized.get("category")
                h_normalized["category"] = category_mapped
            findings_filtered.append(h_normalized)

        summary = {
            "critical": 0,
            "medium": 0,
            "low": 0,
            "by_category": {},
        }
        for h in findings_filtered:
            sev = h.get("severity", "low")
            if sev == "critical":
                summary["critical"] += 1
            elif sev == "medium":
                summary["medium"] += 1
            else:
                summary["low"] += 1
            cat = h.get("category", "others")
            summary["by_category"][cat] = summary["by_category"].get(cat, 0) + 1

        status = "COMPLIANT"
        detail = "No findings were detected in the selected Python tests"
        if summary["critical"] > 0:
            status = "VULNERABLE"
            detail = (
                f"Detected {summary['critical']} critical finding(s) "
                f"and {summary['medium']} medium finding(s)"
            )
        elif summary["medium"] > 0 or summary["low"] > 0:
            status = "REQUIRES_REVIEW"
            detail = (
                f"Detected {summary['medium']} medium finding(s) "
                f"and {summary['low']} low finding(s)"
            )

        return {
            **analysis,
            "findings": findings_filtered,
            "summary": summary,
            "status": status,
            "detail": detail,
        }

    def _log_python_analysis_details(self, analysis: dict, python_tests: list[str] | None = None) -> None:
        """Logs the details of the Python analysis grouped by test."""
        self.logger.info("\n" + "=" * 80)
        self.logger.info("PYTHON ANALYSIS DETAILS")
        self.logger.info("=" * 80)

        status = analysis.get("status", "UNDETERMINED")
        detail = analysis.get("detail", "")
        summary = analysis.get("summary", {})
        findings = analysis.get("findings", [])
        metadata = analysis.get("metadata", {})

        self.logger.info(f"Status: {status}")
        if detail:
            self.logger.info(f"Detail: {detail}")

        self.logger.info(
            "Severity summary -> critical: %s | medium: %s | low: %s",
            summary.get("critical", 0),
            summary.get("medium", 0),
            summary.get("low", 0),
        )

        by_category = summary.get("by_category", {})
        if by_category:
            self.logger.info("Findings by category:")
            for category, quantity in sorted(by_category.items(), key=lambda x: x[0]):
                self.logger.info(f"  - {category}: {quantity}")

        modules = metadata.get("source_modules", [])
        if modules:
            self.logger.info(f"Analyzed modules (source): {len(modules)}")
            for module in modules:
                self.logger.info(f"  • {module}")

        local_imports = metadata.get("imports_locales", [])
        if local_imports:
            self.logger.info(f"Local imports followed: {len(local_imports)}")
            for module in local_imports:
                self.logger.info(f"  • {module}")

        if not findings:
            self.logger.info("Status: COMPLIANT")
            self.logger.info("Detail: No security findings were detected in the Python analysis.")
            self.logger.info("=" * 80 + "\n")
            return

        severity_order = {"critical": 0, "medium": 1, "low": 2}
        tests_log = [
            (
                "dynamic_execution",
                "Dynamic execution",
                {"dynamic_execution"},
                "No uses of eval/exec or dynamic code execution were detected.",
            ),
            (
                "dangerous_commands",
                "Dangerous commands",
                {"dangerous_commands"},
                "No unsafe operating system or subprocess invocations were detected.",
            ),
            (
                "deserialization",
                "Insecure deserialization",
                {"deserialization"},
                "No insecure deserialization patterns were detected.",
            ),
            (
                "credentials",
                "Credentials / secrets",
                {"credentials"},
                "No hardcoded credentials or secrets were detected.",
            ),
            (
                "connections",
                "External connections",
                {"connections"},
                "No hardcoded external connections were detected.",
            ),
            (
                "traceability",
                "Traceability / logging",
                {"traceability"},
                "No traceability gaps were detected; logging is present.",
            ),
        ]

        if python_tests is not None:
            enabled_categories = self._categories_enabled_python(python_tests)
            tests_log = [
                item for item in tests_log
                if item[2] & enabled_categories
            ]

        remaining_findings = list(findings)
        total_printed = 0

        for control_id, test_name, categories, detail_without_findings in tests_log:
            test_findings = [
                h for h in findings
                if h.get("category") in categories
            ]

            for h in test_findings:
                if h in remaining_findings:
                    remaining_findings.remove(h)

            self.logger.info("\n" + "=" * 60)
            self.logger.info(f"PYTHON TEST: {test_name} ({control_id})")
            self.logger.info("=" * 60)

            if not test_findings:
                self.logger.info("  Status: COMPLIANT")
                self.logger.info("  Detail: %s", detail_without_findings)
                continue

            ordered_findings = sorted(
                test_findings,
                key=lambda h: (
                    severity_order.get(h.get("severity", "low"), 3),
                    str(h.get("origin", "")),
                    int(h.get("line", 0) or 0),
                ),
            )

            critical = sum(1 for h in ordered_findings if h.get("severity") == "critical")
            medium = sum(1 for h in ordered_findings if h.get("severity") == "medium")
            low = sum(1 for h in ordered_findings if h.get("severity") == "low")
            self.logger.info(
                "  Findings: %s (critical=%s, medium=%s, low=%s)",
                len(ordered_findings),
                critical,
                medium,
                low,
            )

            for h in ordered_findings:
                total_printed += 1
                severity = (h.get("severity") or "low").upper()
                type = h.get("type", "unknown")
                category = h.get("category", "others")
                origin = h.get("origin", self.file_path.name)
                line = h.get("line", 0) or 0
                description = h.get("description", "No description")

                self.logger.info(
                    "  [%03d] [%s] %s | category=%s | file=%s | line=%s",
                    total_printed,
                    severity,
                    type,
                    category,
                    origin,
                    line,
                )
                self.logger.info("        description: %s", description)

                if h.get("value") is not None:
                    self.logger.info("        value: %s", h.get("value"))
                if h.get("variable") is not None:
                    self.logger.info("        variable: %s", h.get("variable"))
                if h.get("offset") is not None:
                    self.logger.info("        binary_offset: %s", h.get("offset"))

        if remaining_findings:
            self.logger.info("\n" + "=" * 60)
            self.logger.info("PYTHON TEST: Other unmapped findings")
            self.logger.info("=" * 60)

            ordered_findings = sorted(
                remaining_findings,
                key=lambda h: (
                    severity_order.get(h.get("severity", "low"), 3),
                    str(h.get("category", "")),
                    str(h.get("origin", "")),
                    int(h.get("line", 0) or 0),
                ),
            )

            for h in ordered_findings:
                total_printed += 1
                severity = (h.get("severity") or "low").upper()
                type = h.get("type", "unknown")
                category = h.get("category", "others")
                origin = h.get("origin", self.file_path.name)
                line = h.get("line", 0) or 0
                description = h.get("description", "No description")

                self.logger.info(
                    "  [%03d] [%s] %s | category=%s | file=%s | line=%s",
                    total_printed,
                    severity,
                    type,
                    category,
                    origin,
                    line,
                )
                self.logger.info("        description: %s", description)

        self.logger.info("=" * 80 + "\n")

    def _build_python_compliance(self, analysis: dict, python_tests: list[str]) -> dict:
        """Builds the compliance block for PythonCodeInspector results."""
        compliance = {
            "general_status": "COMPLIANT",
            "tests": [],
            "critical_findings": [],
            "medium_findings": [],
            "low_findings": [],
            "recommendations": [],
        }

        if not python_tests:
            compliance["general_status"] = "NOT_APPLICABLE"
            compliance["tests"].append({
                "id": "without_tests",
                "name": "Python analysis",
                "status": "NOT_APPLICABLE",
                "detail": "No Python tests were selected to run",
            })
            return compliance

        if analysis.get("status") == "ERROR":
            compliance["general_status"] = "ERROR"
            compliance["tests"].append({
                "id": "without_tests",
                "name": "Python analysis",
                "status": "ERROR",
                "detail": f"The file could not be analyzed: {analysis.get('error', 'no detail')}",
            })
            return compliance

        # Group findings by category
        findings_by_category: dict[str, list] = {}
        for h in analysis.get("findings", []):
            cat = h.get("category", "others")
            findings_by_category.setdefault(cat, []).append(h)

            sev = h.get("severity", "low")
            input = {
                "test": None,  # assigned below
                "description": h.get("description", ""),
                "origin": h.get("origin"),
                "line": h.get("line"),
                "type": h.get("type"),
                "value": h.get("value"),
            }
            if sev == "critical":
                compliance["critical_findings"].append(input)
            elif sev == "medium":
                compliance["medium_findings"].append(input)
            else:
                compliance["low_findings"].append(input)

        enabled_categories = self._categories_enabled_python(python_tests)

        # Create tests only for categories included in the selected tests.
        for category, (test_key, test_name) in PYTHON_CATEGORY_TO_TEST.items():
            if category not in enabled_categories:
                continue
            findings_cat = findings_by_category.get(category, [])

            # Special case: traceability (logging) — COMPLIANT only if there is NO 'no_logging' finding
            if category == "traceability":
                logging_failure = any(h.get("type") == "no_logging" for h in findings_cat)
                critical = sum(1 for h in findings_cat if h.get("severity") == "critical")
                if logging_failure:
                    status = "VULNERABLE"
                    detail = "The script does not configure logging"
                elif critical:
                    status = "VULNERABLE"
                    detail = (
                        f"Detected {critical} critical finding(s) "
                        f"in category '{category}'"
                    )
                elif findings_cat:
                    status = "COMPLIANT_WITH_OBSERVATIONS"
                    detail = f"Detected {len(findings_cat)} non-critical finding(s)"
                else:
                    status = "COMPLIANT"
                    detail = "The script implements traceability through logging"
            else:
                critical = sum(1 for h in findings_cat if h.get("severity") == "critical")
                medium = sum(1 for h in findings_cat if h.get("severity") == "medium")
                if category == "connections" and (critical or medium):
                    status = "VULNERABLE"
                    detail = (
                        "Findings of medium or critical severity were detected "
                        f"in category '{category}'"
                    )
                elif critical:
                    status = "VULNERABLE"
                    detail = f"Detected {critical} critical finding(s) in category '{category}'"
                elif findings_cat:
                    status = "COMPLIANT_WITH_OBSERVATIONS"
                    detail = f"Detected {len(findings_cat)} non-critical finding(s)"
                else:
                    status = "COMPLIANT"
                    detail = "No findings in this category"

            compliance["tests"].append({
                "id": test_key,
                "name": test_name,
                "status": status,
                "detail": detail,
            })

            # Tag findings with the corresponding test
            for h in findings_cat:
                for bucket in ("critical_findings", "medium_findings", "low_findings"):
                    for item in compliance[bucket]:
                        if item["test"] is None and item.get("description") == h.get("description") \
                                and item.get("line") == h.get("line"):
                            item["test"] = test_key

        # General status
        states = [c["status"] for c in compliance["tests"]]
        if "VULNERABLE" in states:
            compliance["general_status"] = "VULNERABLE"
        elif "COMPLIANT_WITH_OBSERVATIONS" in states:
            compliance["general_status"] = "COMPLIANT_WITH_OBSERVATIONS"
        else:
            compliance["general_status"] = "COMPLIANT"

        # Recommendations
        if compliance["critical_findings"]:
            compliance["recommendations"].append(
                "CRITICAL: Remove hardcoded credentials/secrets and eliminate dynamic execution"
                " (eval/exec) or insecure deserialization (pickle.load, yaml.load without SafeLoader)."
            )
        if any(c["id"] == "traceability" and c["status"] == "VULNERABLE" for c in compliance["tests"]):
            compliance["recommendations"].append(
                "Configure the logging module to ensure traceability of the file."
            )
        if compliance["medium_findings"]:
            compliance["recommendations"].append(
                "Review uses of subprocess/shell, UNC paths and hardcoded URLs."
            )

        return compliance

    def run_full_analysis(self) -> dict:

        # Early branch for Python files (.py / .pyc / .exe)
        if self.file_path.suffix.lower() in PYTHON_EXTENSIONS:
            return self._run_python_analysis()

        metadata_global = self._get_file_info()
        # Hash calculation
        file_info = self._get_file_info()
        self.logger.info(f"Initial SHA-256 hash: {file_info['hash']}")
        self.logger.info(f"Size: {file_info['size_bytes']} bytes")
        hash_initial = file_info["hash"]
        
        hash_initial = calculate_file_hash(self.file_path)

        self.logger.info("=" * 80)
        self.logger.info("STARTING ANALYSIS")
        self.logger.info("=" * 80)

        checker = AnalysisOrchestrator(
            file_path=str(self.file_path),
            mode=self.mode,
            tests=self.tests,
            output_dir=str(self.output_dir),
            password=self.password,
            brute_force_confirmation_cb=self.brute_force_confirmation_cb,
            test_status_cb=self.test_status_cb,
        )
        checker.stop_brute_force_event = self.stop_brute_force_event

        result = checker.run_analysis(run_bypass=False)

        if checker.password and not self.password:
            self.password = checker.password

        # Global metadata is injected at the end: do not duplicate the one from the result
        result.pop("metadata", None)



        
        hash_final = calculate_file_hash(self.file_path)
        self.logger.info("")
        self.logger.info("="*80)
        self.logger.info("FINAL FILE INTEGRITY VERIFICATION")
        self.logger.info("="*80)
        self.logger.info(f"Initial hash: {hash_initial}")
        self.logger.info(f"Final hash : {hash_final}")
        
        consolidated = self._consolidate_result(result)
        
        integrity = {
            "status": "VALID" if hash_final == hash_initial else "INVALID",
            "hash_initial": hash_initial,
            "hash_final": hash_final,
            "message": (
                "The file was not modified during the analysis"
                if hash_final == hash_initial
                else "The file was modified during the analysis"
            ),
            "moment": "BEFORE_BYPASS"
        }
            
            
        metadata_global["integrity"] = integrity
        consolidated["metadata"] = metadata_global

        self.logger.warning("=" * 80)
        self.logger.warning("RUNNING GLOBAL BYPASS (ONLY ONCE)")
        self.logger.warning("=" * 80)

        try:
            bypass_results = self.run_bypass_analysis()
        except Exception as e:
            self.logger.error("Bypass analysis failed: %s", e, exc_info=True)
            bypass_results = {
                "status": "ERROR",
                "message": "Bypass analysis could not be completed"
            }

                
       
        
        
        
        
        consolidated["bypass_tests"] = bypass_results
        consolidated["bypass_executed"] = True
        consolidated["bypass_mode"] = "GLOBAL"
        self._apply_bypass_test(
            consolidated,
            result.get("opening_protection", {}),
            bypass_results,
        )
        
       

        
        consolidated["analysis_mode"] = self.mode
        consolidated["timestamp"] = datetime.now().isoformat()


        return consolidated


    

    def _consolidate_result(self, result: dict) -> dict:
        """Normalizes the analysis result into a flat structure.

        It deduplicates findings and recommendations inside ``compliance`` and
        converts the internal list of tests into named sections
        (``tests`` as a ``key -> {name, status, detail}`` map).
        The derived fields published at the root of the JSON
        (``tests``, ``general_status``, ``recommendations``) are built by
        :class:`lefiru.reporting.report_document.ReportDocument`.
        """

        def _deduplicate_findings(findings):
            seen = set()
            result = []

            for h in findings:
                key = (h.get("test"), h.get("description"))
                if key not in seen:
                    seen.add(key)
                    result.append(h)

            return result
        
        def _deduplicate_list(list):
            result = []
            seen = set()
            for item in list:
                if item not in seen:
                    seen.add(item)
                    result.append(item)
            return result

        compliance = result.get("compliance", {}) or {}

        general_status = compliance.get("general_status", "COMPLIANT")
        tests = tests_by_key(compliance.get("tests", []))

        critical_findings = _deduplicate_findings(compliance.get("critical_findings", []))
        medium_findings = _deduplicate_findings(compliance.get("medium_findings", []))
        low_findings = _deduplicate_findings(compliance.get("low_findings", []))
        recommendations = _deduplicate_list(compliance.get("recommendations", []))

        if general_status == "VULNERABLE":
            recommendations.append("CRITICAL: There are vulnerable tests")

        consolidated = dict(result)
        consolidated["compliance"] = {
            "general_status": general_status,
            "tests": tests,
            "critical_findings": critical_findings,
            "medium_findings": medium_findings,
            "low_findings": low_findings,
            "recommendations": recommendations
        }

        return consolidated




    def run_analysis(self, run_bypass: bool = True) -> dict:
        
        """
            Runs the NORMAL security analysis.
            
            IMPORTANT:
            - Runs the Bypass test at the end.
            - Modifies the file
            """
        
        MODES_ANALYSIS = ["static", "com"]
        self.logger.info("=" * 80)
        self.logger.info("STARTING SECURITY ANALYSIS")
        self.logger.info("=" * 80)
        
        # Basic file information
        file_info = self._get_file_info()
        self.logger.info(f"Size: {file_info['size_bytes']} bytes")
        # TEST FILTER

        extension = self.file_path.suffix.lower()

        self.applicable_tests = TESTS_BY_EXTENSION.get(extension, set())

        self.logger.info(
            f"File type detected: {extension} "
            f"(Applicable tests: {sorted(self.applicable_tests)})"
        )

        # Filter the requested tests by the applicable ones
        self.tests = [
            p for p in self.tests
            if p in self.applicable_tests
        ]
        
        # OPENING PASSWORD DETECTION
        from lefiru.core.analyzers.excel.excel_password import OpenPasswordDetector
        pwd_detector = OpenPasswordDetector(self.file_path)
        pwd_info = pwd_detector.detect_password_protection()

        # Exclude the 'password' test from the applicable ones if the file is not encrypted.
        # This prevents it from appearing as an executed step (NOT_APPLICABLE) in files without a password.
        if not (pwd_info.get("has_password") and pwd_info.get("encrypted")):
            self.applicable_tests = self.applicable_tests - {"password"}
            self.tests = [p for p in self.tests if p != "password"]

        review_password = "password" in self.tests

        if pwd_info["has_password"] and pwd_info["encrypted"]:
            self.logger.warning("=" * 80)
            self.logger.warning("FILE PROTECTED WITH AN OPENING PASSWORD DETECTED")
            self.logger.warning("=" * 80)
            self.logger.warning(f"Type: {pwd_info['protection_type']}")
            self.logger.warning(f"Message: {pwd_info['message']}")

            if review_password and not self.password:
                self.logger.info("\n" + "=" * 80)
                self.logger.info("RESOLVING OPENING ACCESS")
                self.logger.info("=" * 80)
                self.logger.info("Opening: attempting a structural bypass before trying passwords...")

                try:
                    from lefiru.core.analyzers.excel.password_check import PasswordChecker
                    from lefiru.core.analyzers.excel.bypass import BypassTester
                    tester = BypassTester(self.file_path, self.output_dir, password=None)
                    pre_bypass_result = tester.test_workbook_password_bypass()
                    self.opening_resolution = {"bypass": pre_bypass_result}

                    if (
                        pre_bypass_result.get("successful_bypass")
                        and self._is_unlocked_excel_copy(pre_bypass_result.get("unlocked_file"))
                    ):
                        unlocked_path = Path(pre_bypass_result["unlocked_file"])
                        self.file_path = unlocked_path
                        self.logger.warning(
                            "Opening resolved by structural bypass: %s",
                            unlocked_path.name,
                        )
                    else:
                        self.logger.info("Opening: structural bypass did not yield a usable copy; starting password brute force...")

                        execute_brute_force = True
                        if self.brute_force_confirmation_cb is not None:
                            execute_brute_force = self.brute_force_confirmation_cb(self.file_path)

                        if not execute_brute_force:
                            self.logger.info("Opening: password brute force skipped by user decision.")
                            brute_force_result = {
                                "type": "opening_cracking",
                                "password_found": None,
                                "attempts": 0,
                                "risk_level": "NOT_APPLICABLE",
                                "detail": "Brute force skipped by user decision"
                            }
                        else:
                            self.stop_brute_force_event.clear()
                            password_checker = PasswordChecker(self.file_path, stop_event=self.stop_brute_force_event)
                            brute_force_result = password_checker.brute_force_opening_password()
                        self.opening_resolution["password"] = brute_force_result

                        if brute_force_result["password_found"]:
                            self.password = brute_force_result["password_found"]
                            pwd_info["password_found"] = self.password
                            self.logger.warning(
                                "Opening resolved with the found password — '%s'",
                                self.password,
                            )
                            self.logger.warning(
                                "OPENING PASSWORD FOUND: '%s'",
                                self.password,
                            )
                        else:
                            self.logger.info(f"Opening: {brute_force_result['detail']}")
                            self.logger.error("")
                            self.logger.error("The file cannot be analyzed without a password or an effective structural bypass.")
                            self.logger.error("   Options:")
                            self.logger.error("   1. Analyze an unprotected copy of the file")
                            self.logger.error("   2. Review the opening bypass result")
                            self.logger.error("")

                            return {
                                "metadata": file_info,
                                "analysis_mode": self.mode,
                                "timestamp": datetime.now().isoformat(),
                                "opening_protection": pwd_info,
                                "password_check": {self.mode: {"opening": brute_force_result}},
                                "opening_resolution": self.opening_resolution,
                                "analysis_blocked": True,
                                "compliance": {
                                    "general_status": "PROTECTED_WITH_PASSWORD",
                                    "tests": {},
                                    "critical_findings": [],
                                    "medium_findings": [],
                                    "low_findings": [],
                                    "recommendations": [
                                        "EXCELLENT: The file has opening password protection",
                                        "This is robust protection that prevents unauthorized access",
                                        "• For the analysis, use an unprotected copy or attempt an authorized bypass"
                                    ]
                                }
                            }
                except Exception as e:
                    self.logger.warning(f"Opening: initial access could not be resolved: {e}")
                    self.logger.error("")
                    self.logger.error("The file cannot be analyzed without a password.")
                    self.logger.error("   Options:")
                    self.logger.error("   1. Analyze an unprotected copy of the file")
                    self.logger.error("")

                    return {
                        "metadata": file_info,
                        "analysis_mode": self.mode,
                        "timestamp": datetime.now().isoformat(),
                        "opening_protection": pwd_info,
                        "analysis_blocked": True,
                        "compliance": {
                            "general_status": "PROTECTED_WITH_PASSWORD",
                            "tests": {
                                "password_opening": {
                                    "name": "Opening password protection",
                                    "status": "COMPLIANT",
                                    "detail": "File protected with opening encryption (robust protection)"
                                }
                            },
                            "critical_findings": [],
                            "medium_findings": [],
                            "low_findings": [],
                            "recommendations": [
                                "EXCELLENT: The file has opening password protection",
                                "This is robust protection that prevents unauthorized access",
                                "• For the analysis, use an unprotected copy or attempt an authorized bypass"
                            ]
                        }
                    }
            elif not review_password and not self.password:
                self.logger.info(
                    "Opening password detected, but the password test is disabled; the opening test will not run."
                )
                return {
                    "metadata": file_info,
                    "analysis_mode": self.mode,
                    "timestamp": datetime.now().isoformat(),
                    "opening_protection": pwd_info,
                    "analysis_blocked": True,
                    "compliance": {
                        "general_status": "PROTECTED_WITH_PASSWORD",
                        "tests": {},
                        "critical_findings": [],
                        "medium_findings": [],
                        "low_findings": [],
                        "recommendations": [
                            "The file is encrypted with an opening password and cannot be analyzed without providing a password"
                        ]
                    }
                }
            else:
                self.logger.info("Password provided, attempting to open...")
        
        
        # Results structure
        
        results = {
                "timestamp": datetime.now().isoformat(),
                "opening_protection": pwd_info,
                "analysis": {},
            }

        # COM pre-flight: if only COM was requested and there is no compatible
        # engine, it is a fatal error. Without this check, consolidation would
        # evaluate the tests with empty data and report a misleading status.
        if self.mode == "com" and self.file_path.suffix.lower() not in PYTHON_EXTENSIONS:
            from lefiru.core.analyzers.excel.com_runtime import plan_com

            plan = plan_com()
            if not plan.available:
                raise ComNotAvailableError(plan.reason)
            self.logger.info("Plan COM: %s", plan.reason)

        # Execution by mode
        
        for mode in MODES_ANALYSIS:
            # 1. Skip validations at the start of the loop
            if self.mode == "static" and mode == "com":
                self.logger.info("COM mode skipped (STATIC-only run)")
                continue

            if self.mode == "com" and mode == "static":
                self.logger.info("STATIC mode skipped (COM-only run)")
                continue

            self.logger.info("-" * 60)
            self.logger.info(f"Running analysis in {mode.upper()} mode")

            analyzer = None
            try:
                # 2. Analyzer initialization
                if mode == "static":
                    analyzer = StaticWorkbookInspector(
                        self.file_path,
                        output_root=self.output_dir
                    )
                else:
                    analyzer = create_analyzer_com(
                        self.file_path,
                        output_root=self.output_dir,
                        password=self.password,
                    )

                # 3. Test execution
                mode_results = {}
                self._run_tests_selected(analyzer, mode_results, mode)
                results["analysis"][mode] = mode_results

                if hasattr(analyzer, "get_evidence"):
                    mode_results["evidence"] = analyzer.get_evidence()

            except Exception as e:
                
                if mode == "com" and str(e) == "COM_NOT_EVALUABLE_PROTECTION":

                        results["analysis"][mode] = {
                            "mode_status": "NOT_EVALUABLE",
                            "reason": "FILE_PROTECTED_FOR_COM"
                        }
                elif isinstance(e, ComNotAvailableError):
                        # Expected environment condition (no Excel registered or
                        # no pywin32): reported without a traceback and the mode
                        # continues as not evaluable.
                        self.logger.warning(f"COM mode not available: {e}")

                        results["analysis"][mode] = {
                            "mode_status": "NOT_EVALUABLE",
                            "reason": "COM_NO_AVAILABLE",
                            "detail": str(e),
                        }
                else:
                        self.logger.error(
                            f"Error in {mode} mode: {e}",
                            exc_info=True # ONLY for real errors
                        )

                        results["analysis"][mode] = {
                            "mode_status": "ERROR",
                            "reason": f"ERROR_{mode.upper()}",
                            "error": f"{mode.upper()} analysis could not be completed"
                        }


            finally:
                # 4. Safe resource cleanup
                if analyzer and hasattr(analyzer, "close"):
                    analyzer.close()


        # Consolidation
        
        self.logger.info("=" * 80)
        self.logger.info("CONSOLIDATING RESULTS")
        self.logger.info("=" * 80)

        results["consolidated"] = self._consolidate_results(results["analysis"])
        results["analysis_mode"] = ", ".join(results["analysis"].keys()).upper()
        
        # Consolidate evidence at the root level
        results["evidence"] = {}

        for mode, data in results["analysis"].items():
            if "evidence" in data:
                results["evidence"][f"mode_{mode}"] = data["evidence"]

        
        
        
        # ============================
        # COMPLIANCE NORMALIZATION
        # ============================

        # Detect whether COM was evaluable
        com_ok = (
            results.get("analysis", {})
                .get("com", {})
                .get("mode_status") != "NOT_EVALUABLE"
        )

        protections_static = (
            results.get("analysis", {})
                .get("static", {})
                .get("protections", {})
                .get("static", {})
        )

        protections_com = (
            results.get("analysis", {})
                .get("com", {})
                .get("protections", {})
                .get("com", {})
        )

        # Policy: use COM only if it was evaluable, otherwise use STATIC
        if com_ok and protections_com:
            results["protections"] = protections_com
            results["protections"]["source"] = "COM"
        else:
            results["protections"] = protections_static
            results["protections"]["source"] = "STATIC"
                
        # Evaluate compliance
        self.logger.info("\n" + "=" * 80)
        self.logger.info("EVALUATING POLICY COMPLIANCE")
        self.logger.info("=" * 80)
        compliance = self._evaluate_compliance(results)
        
        results["compliance"] = compliance
        
       
       
        
        
        
        all_p = set(self.executed_tests) == set(self.tests)
        general_status = results["compliance"]["general_status"]
        


        # Final analysis bypass. 
        if run_bypass:
            self.logger.warning("=" * 80)
            self.logger.warning("RUNNING BYPASS ")
            self.logger.warning("This bypass runs as part of the standard flow")
            self.logger.warning("=" * 80)

            try:
                bypass_results = self.run_bypass_analysis()
                results["bypass_tests"] = bypass_results
                results["bypass_executed"] = True
                results["bypass_mode"] = "MANDATORY"
                self._apply_bypass_test(
                    results,
                    results.get("opening_protection", {}),
                    bypass_results,
                )
            except Exception as bypass_error:
                self.logger.error(
                    f"ERROR DURING AUTOMATIC BYPASS: {bypass_error}",
                    exc_info=True
                )
                results["bypass_tests"] = {
                    "status": "ERROR",
                    "message": str(bypass_error)
                }
                results["bypass_executed"] = True
                results["bypass_mode"] = "MANDATORY_ERROR"
            self._apply_bypass_test(
                results,
                results.get("opening_protection", {}),
                results.get("bypass_tests", {}),
            )
                
        
        
        vba_modules = []

        vba_detected = results.get("_vba_modules_detected", {})
        for mode, modules in vba_detected.items():
            vba_modules.extend(modules)

        # Remove duplicates and sort
        vba_modules = sorted(set(vba_modules))

        # Ensure metadata
        results.setdefault("metadata", self._get_file_info())

        results["metadata"]["exported_vba"] = {
            "modules": vba_modules
        }

        # The public result exposes tests as named sections.
        results["compliance"]["tests"] = tests_by_key(
            results.get("compliance", {}).get("tests", [])
        )

        return results
    
    def _get_file_info(self) -> dict:
        """Gets basic file information"""
        stats = self.file_path.stat()
        file_hash = calculate_file_hash(self.file_path)
        
        return {
            "name": self.file_path.name,
            "path_complete": str(self.file_path.absolute()),
            "type": self.file_path.suffix.lower(),
            "size_bytes": stats.st_size,
            "size_mb": round(stats.st_size / (1024 * 1024), 2),
            "modification_date": datetime.fromtimestamp(stats.st_mtime).isoformat(),
            "hash": file_hash
        }
    
    def _evaluate_compliance(self, results: dict) -> dict:
        self.logger.info("[COMPLIANCE START] Starting compliance evaluation")
        self.logger.info(f"[COMPLIANCE] Callback assigned? {self.test_status_cb is not None}")
        self.logger.info(f"[COMPLIANCE] Is it callable? {callable(self.test_status_cb)}")
        """
        Evaluates compliance according to the decision matrix:
        - COMPLIANT: All tests effective
        - VULNERABLE: At least one failed test
        - NOT_APPLICABLE: Tests not required for this file type
        """
        compliance = {
            "general_status": "EVALUATING",
            "tests": [],
            "critical_findings": [],
            "medium_findings": [],
            "low_findings": [],
            "recommendations": []
        }
        
        def _emit_test(test: dict):
            """Emits a real-time callback for an evaluated test"""
            self.logger.debug(f"[CALLBACK] Emitting test: {test['id']} - Status: {test['status']}")
            self.logger.debug(f"[CALLBACK] Is it callable? {callable(self.test_status_cb)}")
            if callable(self.test_status_cb):
                try:
                    findings_test = len([h for h in (compliance.get("critical_findings", []) + compliance.get("medium_findings", []) + compliance.get("low_findings", [])) if h.get("test") == test["id"]])
                    self.logger.debug(f"[CALLBACK] Findings for {test['id']}: {findings_test}")
                    self.test_status_cb(
                        test["id"],
                        {
                            "label": test["name"],
                            "status": test["status"],
                            "total_findings": findings_test,
                            "test": test["id"],
                            "test_name": test["name"],
                        },
                    )
                    self.logger.debug(f"[CALLBACK] Callback emitted for {test['id']}")
                except Exception as e:
                    self.logger.error(f"[CALLBACK] ERROR emitting callback: {e}", exc_info=True)
        
        selected_tests = getattr(self, "executed_tests", [])
        tests_scope = set()

        for test in selected_tests:
            tests_scope.update(TESTS_BY_TEST.get(test, []))

        self.logger.info("COMPLIANCE SCOPE:")
        for test in selected_tests:
            label = TESTS_AVAILABLE[test]["label"]
            self.logger.info(f"  - {label}")

        metadata = results.get("metadata")

        if not metadata:
            # Safe fallback: global file metadata
            metadata = self._get_file_info()

        file_type = metadata["type"]
        

        pwd_info = results.get("opening_protection", {})
        
        # If the analysis was blocked by a password, return only this control
        if results.get("analysis_blocked"):
            control_opening = next(
                (control for control in compliance["tests"] if control["id"] == "opening_bypass"),
                None
            )
            compliance["general_status"] = (
                control_opening["status"] if control_opening else "COMPLIANT"
            )
            return compliance
        
        # Test 1: Workbook structure protection
        if "structure_protection" in tests_scope:
            protections = results.get("protections", {})
            if protections.get("protected_workbook"):
                control = {
                    "id": "structure_protection",
                    "name": "Workbook structure protection",
                    "status": "COMPLIANT",
                    "detail": "Workbook correctly protected"
                }
                compliance["tests"].append(control)
                _emit_test(control)
            else:
                control = {
                    "id": "structure_protection",
                    "name": "Workbook structure protection",
                    "status": "VULNERABLE",
                    "detail": "Workbook without structure protection"
                }
                compliance["tests"].append(control)
                compliance["critical_findings"].append({
                    "test": "structure_protection",
                    "description": "The workbook has no structure protection"
                })
                _emit_test(control)
        
        # Test 2: Critical sheet protection
        # Test 2: Critical sheet protection
        if "critical_sheets_protection" in tests_scope:
            protections = results.get("protections", {})
            critical_sheets = protections.get("critical_sheets_without_protection", [])

            if critical_sheets:
                control = {
                    "id": "critical_sheets_protection",
                    "name": "Critical sheet protection",
                    "status": "VULNERABLE",
                    "detail": f"{len(critical_sheets)} unprotected sheet(s)"
                }
                compliance["tests"].append(control)
                compliance["critical_findings"].append({
                    "test": "critical_sheets_protection",
                    "description": f"Unprotected critical sheets: {', '.join(critical_sheets)}"
                })
                _emit_test(control)
            else:
                control = {
                    "id": "critical_sheets_protection",
                    "name": "Critical sheet protection",
                    "status": "COMPLIANT",
                    "detail": "All critical sheets are protected"
                }
                compliance["tests"].append(control)
                _emit_test(control)
                
        # Test 3: VBA protection (if applicable)
        if "vba" in tests_scope:
            
            metadata = results.get("metadata")

            if not metadata:
                # Safe fallback: global file metadata
                metadata = self._get_file_info()
            file_type = metadata.get("type")
            
            # Prefer COM, fall back to STATIC
            pre = results.get("analysis", {}).get("com") or {}
            if not pre or 'status' in pre:
                self.logger.debug("STATIC analysis selected for VBA")
                vba = (results.get("analysis",{})
                   .get("static",{})
                   .get("vba", {})
                   .get("static",{})
                   )
            else:
                self.logger.debug("COM analysis selected for VBA")
                vba = (results.get("analysis",{})
                   .get("com",{})
                   .get("vba", {})
                   .get("com",{})
                   )
            self.logger.debug("VBA FOUND:")
            self.logger.debug(vba)
            has_macros = bool(
                vba.get("has_macros")
                or vba.get("has_vba")
                or vba.get("modules")
            )

            if has_macros:
                if vba.get("protected_project"):
                    control = {
                        "id": "vba",
                        "name": "VBA code protection",
                        "status": "COMPLIANT",
                        "detail": "VBA project protected with a password"
                    }
                    compliance["tests"].append(control)
                    _emit_test(control)
                elif vba.get("accessible_code"):
                    control = {
                        "id": "vba",
                        "name": "VBA code protection",
                        "status": "VULNERABLE",
                        "detail": "Accessible VBA code"
                    }
                    compliance["tests"].append(control)
                    compliance["critical_findings"].append({
                        "test": "vba",
                        "description": "The VBA code can be viewed"
                    })
                    _emit_test(control)
                else:
                    control = {
                        "id": "vba",
                        "name": "VBA code protection",
                        "status": "COMPLIANT",
                        "detail": "VBA code protected"
                    }
                    compliance["tests"].append(control)
                    _emit_test(control)
            else:
                control = {
                    "id": "vba",
                    "name": "VBA code protection",
                    "status": "NOT_APPLICABLE",
                    "detail": "File without macros"
                }
                compliance["tests"].append(control)
                _emit_test(control)
        
        # Test 4: Absence of secrets in code
        if "insecure_patterns" in tests_scope:
            pre = results.get("analysis", {}).get("com") or {}
            if not pre or 'status' in pre:
                self.logger.debug("STATIC analysis selected")
                vba = (
                results.get("analysis", {})
                    .get("static", {})
                    .get("vba", {})
                    .get("static", {})
                )
                patterns = (
                results.get("analysis", {})
                        .get("static", {})
                        .get("insecure_patterns", {})
                        .get("static", {})
                )
            else:
                self.logger.debug("COM analysis selected")
                vba = (
                     results.get("analysis", {})
                    .get("com", {})
                    .get("vba", {})
                    .get("com", {})
                )
                patterns = (
                         results.get("analysis", {})
                        .get("com", {})
                        .get("insecure_patterns", {})
                        .get("com", {})
                )

            self.logger.debug("PATTERNS FOUND")
            self.logger.debug(patterns)

            if patterns.get("status") != "NOT_APPLICABLE":
                found_secrets = patterns.get("found_secrets", 0)

                # Map categories that are NOT secrets and count occurrences
                summary_others_categories = {}

                categories_accounting = {
                    "sql_injection": "SQL injection",
                    "connections": "external connection",
                    "dangerous_commands": "dangerous command",
                    "evasion": "evasion"
                }

                findings_by_category = patterns.get("findings_by_category", {})

                for key, label in categories_accounting.items():
                    quantity = len(findings_by_category.get(key, []))
                    if quantity > 0:
                        summary_others_categories[label] = quantity

                if found_secrets > 0:
                    control = {
                        "id": "insecure_patterns",
                        "name": "Absence of secrets in code",
                        "status": "VULNERABLE",
                        "detail": f"{found_secrets} secret(s) or credential(s) detected in the code"
                    }
                    compliance["tests"].append(control)
                    compliance["critical_findings"].append({
                        "test": "insecure_patterns",
                        "description": "Embedded secrets or credentials were detected in the code"
                    })
                    _emit_test(control)

                else:
                    detail = "No secrets or credentials were detected in the code"

                    if summary_others_categories:
                        detail += ". Other insecure patterns were identified: "

                        parts = []
                        for label, quantity in summary_others_categories.items():
                            parts.append(f"{quantity} {label}{'' if quantity == 1 else 's'}")

                        detail += ", ".join(parts)
                        

                    control = {
                        "id": "insecure_patterns",
                        "name": "Absence of secrets in code",
                        "status": "COMPLIANT",
                        "detail": detail
                    }
                    compliance["tests"].append(control)
                    _emit_test(control)

            else:
                if vba.get("has_vba") is False:
                    control = {
                        "id": "insecure_patterns",
                        "name": "Absence of secrets in code",
                        "status": "NOT_APPLICABLE",
                        "detail": "File without VBA"
                    }
                    compliance["tests"].append(control)
                    _emit_test(control)
                else:
                    control = {
                        "id": "insecure_patterns",
                        "name": "Absence of secrets in code",
                        "status": "COMPLIANT",
                        "detail": "VBA code not accessible for analysis"
                    }
                    compliance["tests"].append(control)
                    _emit_test(control)

        
        # Test 5: Secure external connections
        if "external_connections" in tests_scope:
            pre = results.get("analysis", {}).get("com") or {}
            if not pre or 'status' in pre:
                self.logger.debug("STATIC analysis selected")
                external = (results.get("analysis",{})
                            .get("static")
                            .get("external_connections", {})
                            .get("static"))
            else:
                
                self.logger.debug("COM analysis selected")
                external = (results.get("analysis",{})
                            .get("com")
                            .get("external_connections", {})
                            .get("com"))
            
            # Guard: validate that external is not None
            if external is None:
                external = {}
            
            links = external.get("external_links", [])
            connections = external.get("data_connections", [])
            names = external.get("defined_names", [])

            if links or connections or names:
                control = {
                    "id": "external_connections",
                    "name": "External connection management",
                    "status": "VULNERABLE",
                    "detail": (
                        f"{len(links)} link(s), {len(connections)} connection(s), "
                        f"{len(names)} external name(s) detected"
                    ),
                }
                compliance["tests"].append(control)
                compliance["medium_findings"].append({
                    "test": "external_connections",
                    "description": "There are external connections that must be reviewed"
                })
                _emit_test(control)
            else:
                control = {
                    "id": "external_connections",
                    "name": "External connection management",
                    "status": "COMPLIANT",
                    "detail": "No external connections were detected"
                }
                compliance["tests"].append(control)
                _emit_test(control)
        
        if "formulas" in tests_scope:
            formulas = self._get_formula_results(results)
            formulas_status = formulas.get("status")
            formulas_summary = formulas.get("summary", {})
            critical = formulas_summary.get("critical", 0)
            medium = formulas_summary.get("medium", 0)
            low = formulas_summary.get("low", 0)
            by_type = formulas_summary.get("by_type", {})
            credentials_critical = (
                by_type.get("vba_source_cell", 0)
                + by_type.get("credential_in_cell", 0)
            )

            if formulas_status == "NOT_APPLICABLE":
                control = {
                    "id": "formulas",
                    "name": "Integrity and traceability of critical formulas",
                    "status": "COMPLIANT",
                    "detail": formulas.get("detail", "The file contains no evaluable formulas")
                }
                compliance["tests"].append(control)
                _emit_test(control)
            elif formulas_status == "ERROR":
                control = {
                    "id": "formulas",
                    "name": "Integrity and traceability of critical formulas",
                    "status": "VULNERABLE",
                    "detail": f"Formulas could not be evaluated: {formulas.get('detail', 'no detail')}"
                }
                compliance["tests"].append(control)
                compliance["critical_findings"].append({
                    "test": "formulas",
                    "description": "The formula evaluation could not be completed"
                })
                _emit_test(control)
            elif credentials_critical > 0:
                control = {
                    "id": "formulas",
                    "name": "Integrity and traceability of critical formulas",
                    "status": "VULNERABLE",
                    "detail": formulas.get(
                        "detail",
                        "Hardcoded credentials were detected in cells referenced by formulas/VBA"
                    )
                }
                compliance["tests"].append(control)
                for finding in formulas.get("findings", []):
                    if finding.get("type") in {"vba_source_cell", "credential_in_cell"}:
                        compliance["critical_findings"].append({
                            "test": "formulas",
                            "description": (
                                f"{finding.get('sheet')}!{finding.get('cell')}: "
                                f"{finding.get('description')}"
                            )
                        })
                _emit_test(control)
            elif critical > 0:
                
                if formulas_status == "COMPLIANT_WITH_OBSERVATIONS":
                    
                    control = {
                    "id": "formulas",
                    "name": "Integrity and traceability of critical formulas",
                    "status": "COMPLIANT_WITH_OBSERVATIONS",
                    "detail": formulas.get("detail", "Critical findings were detected in formulas")
                    }
                    compliance["tests"].append(control)
                    for finding in formulas.get("findings", []):
                        if finding.get("severity") == "critical":
                            compliance["critical_findings"].append({
                                "test": "formulas",
                                "description": (
                                    f"{finding.get('sheet')}!{finding.get('cell')}: "
                                    f"{finding.get('description')}"
                                )
                            })
                    _emit_test(control)
                else:
                    control = {
                        "id": "formulas",
                        "name": "Integrity and traceability of critical formulas",
                        "status": "VULNERABLE",
                        "detail": formulas.get("detail", "Critical findings were detected in formulas")
                    }
                    compliance["tests"].append(control)
                    for finding in formulas.get("findings", []):
                        if finding.get("severity") == "critical":
                            compliance["critical_findings"].append({
                                "test": "formulas",
                                "description": (
                                    f"{finding.get('sheet')}!{finding.get('cell')}: "
                                    f"{finding.get('description')}"
                                )
                            })
                    _emit_test(control)
            elif (medium + low) > 0 or formulas_status == "COMPLIANT_WITH_OBSERVATIONS":
                control = {
                    "id": "formulas",
                    "name": "Integrity and traceability of critical formulas",
                    "status": "COMPLIANT_WITH_OBSERVATIONS",
                    "detail": formulas.get(
                        "detail",
                        "No critical findings were detected, but there are formula observations"
                    )
                }
                compliance["tests"].append(control)
                _emit_test(control)
            else:
                control = {
                    "id": "formulas",
                    "name": "Integrity and traceability of critical formulas",
                    "status": "COMPLIANT",
                    "detail": formulas.get("detail", "No critical findings were detected in formulas")
                }
                compliance["tests"].append(control)
                _emit_test(control)

            for finding in formulas.get("findings", []):
                if finding.get("severity") == "medium":
                    compliance["medium_findings"].append({
                        "test": "formulas",
                        "description": (
                            f"{finding.get('sheet')}!{finding.get('cell')}: "
                            f"{finding.get('description')}"
                        )
                    })
                elif finding.get("severity") == "low":
                    compliance["low_findings"].append({
                        "test": "formulas",
                        "description": (
                            f"{finding.get('sheet')}!{finding.get('cell')}: "
                            f"{finding.get('description')}"
                        )
                    })

        # Determine general status
        states = [c["status"] for c in compliance["tests"]]
        if "VULNERABLE" in states:
            compliance["general_status"] = "VULNERABLE"
        elif all(e in ["COMPLIANT", "NOT_APPLICABLE"] for e in states):
            compliance["general_status"] = "COMPLIANT"
        else:
            compliance["general_status"] = "COMPLIANT_WITH_OBSERVATIONS"
        
        # General recommendation by criticality
        if compliance["critical_findings"]:
            compliance["recommendations"].append(
                "CRITICAL: Remediate critical findings immediately before releasing to production"
            )
        # Generate recommendations
        
        if "structure_protection" in tests_scope:
            protections = results.get("protections", {})
            if not protections.get("protected_workbook"):
                compliance["recommendations"].append(
                    "Protect workbook structure (Review > Protect Workbook)"
                )

        
        if "critical_sheets_protection" in tests_scope:
            protections = results.get("protections", {})
            critical_sheets = protections.get("critical_sheets_without_protection", [])

            if critical_sheets:
                compliance["recommendations"].append(
                    f"Protect critical sheets: {', '.join(critical_sheets)}"
                )

        
        if "vba" in tests_scope:
            metadata = results.get("metadata")

            if not metadata:
                # Safe fallback: global file metadata
                metadata = self._get_file_info()
            file_type = metadata.get("type")

            pre = results.get("analysis", {}).get("com") or {}
            if not pre or 'status' in pre:
                vba = (
                    results.get("analysis", {})
                    .get("static", {})
                    .get("vba", {})
                    .get("static", {})
                )
            else:
                vba = (
                    results.get("analysis", {})
                    .get("com", {})
                    .get("vba", {})
                    .get("com", {})
                )
            has_macros = bool(
                vba.get("has_macros")
                or vba.get("has_vba")
                or vba.get("modules")
            )

            if has_macros and not vba.get("protected_project"):
                compliance["recommendations"].append(
                    "Protect the VBA project with a password (VBA Editor > Tools > Properties)"
                )

                
        if "insecure_patterns" in tests_scope:
            patterns = results.get("insecure_patterns", {})
            if patterns.get("found_secrets", 0) > 0:
                compliance["recommendations"].append(
                    "Remove hardcoded credentials/secrets from the VBA code"
                )
                
                
                
        if "external_connections" in tests_scope:
            external = results.get("external_connections", {})
            if (
                external.get("external_links")
                or external.get("data_connections")
                or external.get("defined_names")
            ):
                compliance["recommendations"].append(
                    "Review and document the external connections and credentials used"
                )
                
                        
        if "formulas" in tests_scope:
            formulas = self._get_formula_results(results)
            if formulas.get("status") == "VULNERABLE":
                compliance["recommendations"].append(
                    "Review formulas with external references, pattern inconsistencies and calculated errors in critical cells"
                )
            elif formulas.get("summary", {}).get("medium", 0) > 0:
                compliance["recommendations"].append(
                    "Reduce the use of dynamic references and formulas that hide errors to improve calculation traceability"
                )



        
        # Detailed summary of findings
        self.logger.info("\n" + "="*80)
        self.logger.info("ANALYSIS SUMMARY")
        self.logger.info("="*80)
        self.logger.info(f"General Status: {compliance['general_status']}")
        self.logger.info(f"Tests evaluated: {len(compliance['tests'])}")
        self.logger.info(f"Critical Findings: {len(compliance['critical_findings'])}")
        
        if compliance['critical_findings']:
            self.logger.error("\nCRITICAL FINDINGS DETECTED:")
            for finding in compliance['critical_findings']:
                self.logger.error(f"  • [{finding['test']}] {finding['description']}")
        
        if compliance['recommendations']:
            self.logger.info("\nRECOMMENDATIONS:")
            for i, rec in enumerate(compliance['recommendations'], 1):
                self.logger.info(f"  {i}. {rec}")
        
        self.logger.info("="*80 + "\n")
        
        return compliance
    
    def _eval_protections(self, analyzer, results, mode):
        self.logger.info("[*] Evaluating protections")
        results.setdefault("protections", {})
        data = analyzer.check_workbook_protection()
        
        results["protections"][mode] = data
        
        if data.get("protected_workbook"):
            results["protections"]["status"] = "COMPLIANT"
        else:
            results["protections"]["status"]= "VULNERABLE"
        

    def _eval_vba(self, analyzer, results, mode):
        self.logger.info("[*] Analyzing VBA"  )
        results.setdefault("vba", {})
        
        data = analyzer.check_vba_protection()
        results["vba"][mode] = data
        
        
        modules = []

        if data and isinstance(data.get("modules"), dict):
            for module_name in data["modules"].keys():
                modules.append(module_name)

        results.setdefault("_vba_modules_detected", {})
        results["_vba_modules_detected"][mode] = modules

        
        # CASE 1: File WITHOUT macros -> NOT APPLICABLE
        # Compatibility: some analyzers report `has_vba` instead of
        # `has_macros`. We also use the presence of modules as a fallback.
        has_macros = bool(
            (data or {}).get("has_macros")
            or (data or {}).get("has_vba")
            or (data or {}).get("modules")
        )
        if not data or not has_macros:
            results["vba"]["status"] = "NOT_APPLICABLE"
            return

        #CASE 2: Protected VBA project
        if data.get("protected_project"):
            results["vba"]["status"] = "COMPLIANT"
        else:
            #CASE 3: Unprotected VBA project
            results["vba"]["status"] = "VULNERABLE"

            

    def _eval_patterns(self, analyzer, results, mode):
        self.logger.info("[*] Analyzing insecure patterns")
        
        results.setdefault("patterns", {})

        results.setdefault("insecure_patterns", {})

        vba_by_mode = results.get("vba", {}).get(mode, {})
        

        
        if not vba_by_mode.get("accessible_code"):
            results["insecure_patterns"][mode] = {
                "status": "NOT_APPLICABLE",
                "reason": "Code not accessible"
            }
            results["patterns"]["status"] = "NOT_APPLICABLE"
            return


        
        detector = UnsafePatternScanner(vba_by_mode.get("modules", {}))
        scan = detector.scan_patterns()
        results["insecure_patterns"][mode] = scan

        secrets = scan.get("found_secrets", 0)

        
        if secrets > 0:
                results["patterns"]["status"] = "VULNERABLE"
        else:
            results["patterns"]["status"] = "COMPLIANT"



    def _eval_connections(self, analyzer, results,mode):
        self.logger.info("[*] Analyzing external connections")
        
        results.setdefault("connections", {})
        results.setdefault("external_connections", {})
        
        data =analyzer.check_external_connections()
        results["external_connections"][mode] = data
        
        
        if (
            data.get("external_links")
            or data.get("data_connections")
            or data.get("defined_names")
        ):
                results["connections"]["status"] = "VULNERABLE"
        else:
            results["connections"]["status"] = "COMPLIANT"



    def _eval_formulas(self, analyzer, results, mode):
        self.logger.info("[*] Analyzing critical formulas")
        results.setdefault("formulas", {})
        results.setdefault("formula_analysis", {})

        if mode == "com" and hasattr(analyzer, "check_formula_integrity"):
            formula_analysis = analyzer.check_formula_integrity()
        else:
            formula_analysis = FormulaIntegrityInspector(self.file_path).analyze()

        # ── Cross-reference: cells that VBA reads as credentials ──────────
        # If the VBA analysis already ran for this mode, we combine its modules
        # with the formula analysis to detect hardcoded passwords in cells.
        vba_data = results.get("vba", {}).get(mode, {})
        if isinstance(vba_data.get("modules"), dict) and vba_data["modules"]:
            fa_cred = FormulaIntegrityInspector(self.file_path)
            vba_cred = fa_cred.analyze_vba_credential_links(vba_data["modules"])
            if vba_cred.get("findings"):
                formula_analysis.setdefault("findings", []).extend(vba_cred["findings"])
                # Recompute summary and status with the merged findings
                formula_analysis["summary"] = fa_cred._summarize(formula_analysis["findings"])
                summary = formula_analysis["summary"]
                critical = summary.get("critical", 0)
                medium = summary.get("medium", 0)
                low = summary.get("low", 0)
                by_type = summary.get("by_type", {})
                credentials = (
                    by_type.get("vba_source_cell", 0)
                    + by_type.get("credential_in_cell", 0)
                )

                if credentials > 0:
                    formula_analysis["status"] = "VULNERABLE"
                    formula_analysis["detail"] = (
                        f"Detected {credentials} hardcoded credential finding(s)"
                    )
                elif critical > 0:
                    formula_analysis["status"] = "VULNERABLE"
                    formula_analysis["detail"] = (
                        f"Detected {critical} critical finding(s) in formulas / cells"
                    )
                elif (medium + low) > 0:
                    formula_analysis["status"] = "COMPLIANT_WITH_OBSERVATIONS"
                    formula_analysis["detail"] = (
                        "No critical findings were detected, but there are observations worth reviewing"
                    )
                else:
                    formula_analysis["status"] = "COMPLIANT"
                    formula_analysis["detail"] = "No findings were detected in formulas"
                self.logger.info(
                    f"  + {len(vba_cred['findings'])} credential finding(s) in cells (VBA cross-ref)"
                )

        results["formula_analysis"][mode] = formula_analysis
        results["formulas"][mode] = {
            "status": formula_analysis.get("status", "UNDETERMINED"),
            "detail": formula_analysis.get("detail", "")
        }
        results["formulas"]["status"] = formula_analysis.get("status", "UNDETERMINED")

    def _eval_password(self, analyzer, results, mode):
        self.logger.info("[*] Checking the opening password")
        results.setdefault("password", {})
        results.setdefault("password_check", {})

        # Skip the entire test if the file has no opening encryption
        pwd_info = results.get("opening_protection", {})
        if not (pwd_info.get("has_password") and pwd_info.get("encrypted")):
            results["password"]["status"] = "NOT_APPLICABLE"
            self.logger.info("Opening: the file has no opening encryption; test skipped.")
            return

        password_checker = PasswordChecker(self.file_path)
        results["password_check"][mode] = {}

        # ──── Opening password test ────
        self.logger.info("\n" + "="*80)
        self.logger.info("CHECKING THE OPENING PASSWORD")
        self.logger.info("="*80)
        
        if self.password:
            opening_pwd_check = password_checker.check_opening_password(self.password)
            results["password_check"][mode].setdefault("opening", {})
            results["password_check"][mode]["opening"] = opening_pwd_check
            
            if opening_pwd_check["password_in_dictionary"]:
                self.logger.error(f"{opening_pwd_check['detail']}")
            else:
                self.logger.info(f"{opening_pwd_check['detail']}")
        else:
            # Attempt an automatic dictionary attack
            self.logger.info("Opening: attempting an automatic dictionary attack...")
            brute_force_result = password_checker.brute_force_opening_password()
            results["password_check"][mode].setdefault("opening", {})
            results["password_check"][mode]["opening"] = brute_force_result
            
            if brute_force_result["password_found"]:
                self.logger.error(f"{brute_force_result['detail']}")
            else:
                self.logger.info(f"{brute_force_result['detail']}")

        # ──── Determine final status for the opening password only ────
        opening_data = results["password_check"][mode].get("opening", {})

        weak_password = False
        if self.password:
            weak_password = opening_data.get("password_in_dictionary", False)
        else:
            weak_password = bool(opening_data.get("password_found"))

        if opening_data.get("detail") == "File is not encrypted":
            results["password"]["status"] = "NOT_APPLICABLE"
        elif weak_password:
            results["password"]["status"] = "VULNERABLE"
        else:
            results["password"]["status"] = "COMPLIANT"


            
    def _run_tests_selected(self, analyzer, results, mode):
        """
        Runs the selected tests respecting:
        - the order defined in TESTS_AVAILABLE
        - declared dependencies
        """

        executed = set()

        # sort tests according to configuration
        tests_ordered = sorted(
            self.tests,
            key=lambda p: TESTS_AVAILABLE[p]["order"]
        )

        for test in tests_ordered:
            label = TESTS_AVAILABLE[test]["label"]
            
            
            
            if test not in self.applicable_tests:
                results[test] = {
                    "status": "NOT_APPLICABLE",
                    "reason": f"Not applicable to {self.file_path.suffix.lower()} files"
                }

                self.logger.info(
                    f"TEST NOT APPLICABLE: {label} "
                    f"(file {self.file_path.suffix.lower()})"
                )

                continue

           
            dependencies = TESTS_AVAILABLE[test].get("dependencies", [])
            missing = [d for d in dependencies if d not in executed]

            
            if missing:
                results[test] = {
                    "status": "SKIPPED",
                    "reason": f"Unmet dependencies: {missing}"
                }

                self.logger.warning(
                    f"TEST SKIPPED: {label} "
                    f"(requires {missing})"
                )

                continue


                

            self.logger.info("")
            self.logger.info("=" * 60)
            self.logger.info(f"STARTING TEST: {label}")
            self.logger.info("=" * 60)

            # Notify the start in real time per mode (STATIC/COM)
            if callable(self.test_status_cb):
                try:
                    self.test_status_cb(test, {
                        "label": label,
                        "status": "IN_PROGRESS",
                        "total_findings": 0,
                        "mode": mode,
                        "test": "",
                        "test_name": "",
                    })
                except Exception:
                    pass

            method = getattr(self, f"_eval_{test}")
            method(analyzer, results,mode)
            
            
            status = results.get(test, {}).get("status", "UNDETERMINED")

            self.logger.info(f"TEST FINISHED: {label}")
            self.logger.info(f"  Status: {status}")
            self.logger.info("-" * 60)

            # Emit the test result in real time per mode (STATIC/COM)
            if callable(self.test_status_cb):
                try:
                    if test == "protections":
                        # Two separate callbacks: workbook structure + critical sheets
                        prot = results.get("protections", {}).get(mode, {})
                        sheets = len(prot.get("critical_sheets_without_protection", []))
                        wb_prot = prot.get("protected_workbook", True)
                        self.test_status_cb(test, {
                            "label": "Workbook structure",
                            "status": "COMPLIANT" if wb_prot else "VULNERABLE",
                            "total_findings": 0 if wb_prot else 1,
                            "detail": "Protected" if wb_prot else "No structure protection",
                            "mode": mode,
                            "test": "",
                            "test_name": "",
                        })
                        self.test_status_cb(test, {
                            "label": "Critical sheets",
                            "status": "COMPLIANT" if sheets == 0 else "VULNERABLE",
                            "total_findings": sheets,
                            "detail": "All protected" if sheets == 0 else f"{sheets} unprotected sheet(s)",
                            "mode": mode,
                            "test": "",
                            "test_name": "",
                        })
                    else:
                        # Remaining tests: a single callback with detail
                        detail_ui = ""
                        total_findings_ui = 0
                        if test == "vba":
                            vba = results.get("vba", {}).get(mode, {})
                            if status == "NOT_APPLICABLE":
                                detail_ui = "No macros"
                            elif vba.get("protected_project"):
                                detail_ui = "VBA protected with a password"
                            else:
                                detail_ui = "VBA without protection"
                                total_findings_ui = 1
                        elif test == "patterns":
                            patt = results.get("insecure_patterns", {}).get(mode, {})
                            secrets = patt.get("found_secrets", 0)
                            if secrets > 0:
                                detail_ui = f"{secrets} secret(s) detected"
                                total_findings_ui = secrets
                            elif status == "NOT_APPLICABLE":
                                detail_ui = "VBA not accessible"
                            else:
                                detail_ui = "No secrets in code"
                        elif test == "connections":
                            conn = results.get("external_connections", {}).get(mode, {})
                            links = len(conn.get("external_links", []))
                            connections = len(conn.get("data_connections", []))
                            total = links + connections
                            if total > 0:
                                detail_ui = f"{links} link(s), {connections} connection(s)"
                                total_findings_ui = total
                            else:
                                detail_ui = "No external connections"
                        elif test == "formulas":
                            form = results.get("formula_analysis", {}).get(mode, {})
                            summary = form.get("summary", {})
                            critical = summary.get("critical", 0)
                            medium = summary.get("medium", 0)
                            if critical > 0:
                                detail_ui = f"{critical} critical finding(s)"
                                total_findings_ui = critical
                            elif medium > 0:
                                detail_ui = f"{medium} observation(s)"
                                total_findings_ui = medium
                            elif status == "ERROR":
                                detail_ui = "Could not be analyzed"
                            else:
                                detail_ui = "No findings in formulas"
                        self.test_status_cb(test, {
                            "label": label,
                            "status": status,
                            "total_findings": total_findings_ui,
                            "detail": detail_ui,
                            "mode": mode,
                            "test": "",
                            "test_name": "",
                        })
                except Exception:
                    pass

            executed.add(test)
            if test not in self.executed_tests:
                self.executed_tests.append(test)

    def _get_formula_results(self, results: dict) -> dict:
        static_formulas = (
            results.get("analysis", {})
            .get("static", {})
            .get("formula_analysis", {})
            .get("static", {})
        )
        com_formulas = (
            results.get("analysis", {})
            .get("com", {})
            .get("formula_analysis", {})
            .get("com", {})
        )

        if static_formulas and static_formulas.get("status") not in {"NOT_APPLICABLE", "ERROR"}:
            return static_formulas

        if com_formulas:
            return com_formulas

        return static_formulas


    

    
    def precheck_vba_access(self) -> dict:
        """
        Quick pre-check to validate VBA access before the full analysis.
        It does NOT run tests.
        """
        if self.mode != "com":
            return {"enabled": True}

        analyzer = create_analyzer_com(
            self.file_path,
            output_root=self.output_dir,
            password=self.password,
        )

        try:
            status = analyzer.is_vba_trust_enabled()
            return status
        finally:
            analyzer.close()

    def run_bypass_analysis(self) -> dict:
        """
        Runs authorized bypass tests.

         WARNING:
        - Modifies the file
        - Breaks integrity
        """
        from lefiru.core.analyzers.excel.bypass import BypassTester

        self.logger.warning("=" * 80)
        self.logger.warning("Initializing BYPASS")
        self.logger.warning("=" * 80)

        tester = BypassTester(self.file_path, self.output_dir, password=self.password)

        results = {}

        backup = tester.create_backup()
        results["backup_original"] = str(backup)

        results["opening_password"] = tester.test_workbook_password_bypass()

        if results["opening_password"].get("successful_bypass"):
            unlocked_file = results["opening_password"].get("unlocked_file")
            if unlocked_file:
                tester.file_path = Path(unlocked_file)
                self.logger.info(
                    "Continuing sheet and VBA bypass on the unlocked copy: %s",
                    tester.file_path.name
                )

        marks_already_captured = results["opening_password"].get("successful_bypass", False)
        results["sheets"] = tester.test_sheet_protection_bypass(write_marks=not marks_already_captured)
        results["vba"] = tester.test_vba_protection_bypass()

        if (
            results["opening_password"].get("successful_bypass")
            or results["sheets"].get("successful_bypass")
            or results["vba"].get("successful")
        ):
            results["status"] = "SUCCESSFUL_BYPASS"
            results["file_modified"] = str(tester.file_modified)
            self.logger.warning("FILE MODIFIED BY BYPASS")
        else:
            tester.restore_backup()
            results["status"] = "WITHOUT_CHANGES"
            self.logger.info("Bypass could not be performed; file restored")

        results.setdefault("evidence", {}).update(tester.get_evidence())

        return results


#Made by juajojim -2026

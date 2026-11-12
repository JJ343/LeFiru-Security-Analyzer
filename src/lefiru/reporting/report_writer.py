"""
JSON and LaTeX/PDF report generator.

The JSON structure is defined by :class:`ReportDocument`; this module only
decides the file name, resolves the artifacts and writes the result.
"""

import json
import logging
import traceback
from pathlib import Path
from typing import Dict, Any

from lefiru.reporting.report_document import ReportDocument
from lefiru.reporting.report_docx import ReportComposer


class AnalysisReportWriter:
    """Security analysis report generator"""

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.reports_dir = self.output_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)

    def _build_artifacts(self, json_file: Path) -> Dict[str, str]:
        """Paths of the generated artifacts that accompany the report."""
        artifacts = {"json": str(json_file)}

        # Detect active log file (if any)
        for handler in logging.getLogger().handlers:
            if hasattr(handler, "baseFilename"):
                artifacts["log"] = handler.baseFilename
                break

        return artifacts

    def generate_reports(self, results: Dict[str, Any]) -> tuple:
        """
        Generates the JSON report and the LaTeX/PDF report

        Args:
            results: Analysis results

        Returns:
            Tuple (json_path, report_path)
        """
        # Extract metadata from the result
        metadata = results.get("metadata", {}) or {}

        file_name = metadata.get("name", "report")
        base_name = Path(file_name).stem

        # Generate JSON (ReportDocument is the only one that builds the document)
        json_file = self.reports_dir / f"{base_name}_report.json"
        document = ReportDocument(
            results,
            artifacts=self._build_artifacts(json_file),
        ).build()
        self._generate_json(document, json_file)

        # Generate LaTeX/PDF report
        report_file = None
        try:
            composer = ReportComposer()
            report_file = composer.generate(json_file)
            self.logger.info(f"Report generated from JSON: {json_file.name}")
        except Exception as e:
            error_details = traceback.format_exc()
            self.logger.error(f"Error generating report:\n{error_details}")
            self.logger.warning(f"The report could not be generated: {e}")

        return str(json_file), str(report_file) if report_file else None
    
    def _generate_json(self, document: Dict[str, Any], file_path: Path):
        """Writes the complete JSON document."""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(document, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"JSON report generated: {file_path.name}")
            
        except Exception as e:
            self.logger.error(f"Error generating JSON: {str(e)}")
            raise
    
    def _get_policy_mapping(self) -> Dict[str, Dict[str, str]]:
        """Gets the mapping of tests to policies"""
        # This information should come from policy_map.yml
        # For now, hardcoded as a fallback
        return {
            'structure_protection': {
                'policy': 'Access and Source Code - Structure protection',
                'reference': 'IT-001'
            },
            'critical_sheets_protection': {
                'policy': 'Access and Source Code - Critical sheet protection',
                'reference': 'IT-002'
            },
            'vba': {
                'policy': 'Access and Source Code - VBA code protection',
                'reference': 'IT-003'
            },
            'insecure_patterns': {
                'policy': 'Password custody - Absence of secrets',
                'reference': 'IT-004'
            },
            'external_connections': {
                'policy': 'Input/Output - External connection management',
                'reference': 'IT-005'
            },
            'formulas': {
                'policy': 'Calculation integrity - Critical formula traceability (analysis limited to critical sheets; credentials in all sheets)',
                'reference': 'IT-007'
            }
        }
    
    def generate_evidence_screenshot(self, results: Dict[str, Any], sheet_name: str = None):
        """
        Placeholder to generate evidence screenshots
        It would require pyautogui or similar for screen captures
        """
        # TODO: Implement screen capture if required
        pass


def test_report_generator():
    """Test function"""
    # Test data with the flat report structure
    test_results = {
        "metadata": {
            "name": "test_file.xlsm",
            "path_complete": "C:/test/test_file.xlsm",
            "type": ".xlsm",
            "size_bytes": 1024000,
            "size_mb": 1.0,
            "modification_date": "2025-11-27T10:00:00",
            "hash": "abc123def456",
        },
        "analysis_mode": "static",
        "timestamp": "2025-11-27T10:00:00",
        "protections": {
            "protected_workbook": True,
            "total_sheets": 3,
            "protected_sheets": 2,
            "critical_sheets_without_protection": [],
        },
        "vba": {
            "has_vba": True,
            "protected_project": True,
            "accessible_code": False,
        },
        "insecure_patterns": {
            "status": "NOT_APPLICABLE",
            "reason": "VBA code not accessible",
        },
        "external_connections": {
            "external_links": [],
            "data_connections": [],
            "defined_names": [],
        },
        "compliance": {
            "general_status": "COMPLIANT",
            "tests": {
                "structure_protection": {
                    "name": "Structure protection",
                    "status": "COMPLIANT",
                    "detail": "OK",
                }
            },
            "critical_findings": [],
            "medium_findings": [],
            "recommendations": [],
        },
        "consolidated": {
            "summary": {
                "critical": 0,
                "warnings": 0,
                "only_com": 0,
                "only_static": 0,
            },
            "findings": [],
        },
        "evidence": {},
        "general_status": "COMPLIANT",
        "tests": {},
        "recommendations": [],
    }

    gen = AnalysisReportWriter("test_output")
    json_file, report_file = gen.generate_reports(test_results)
    print(f"JSON: {json_file}")
    print(f"Report: {report_file}")


if __name__ == "__main__":
    test_report_generator()

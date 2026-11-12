"""
JSON document of the analysis report.

This module concentrates the construction of the JSON delivered as the analysis
result in a single class. ``AnalysisReportWriter`` does not build or rewrite
the document: it takes the raw result from the orchestrator, passes it to
:class:`ReportDocument` and writes what ``build()`` returns.

Each report section is a ``_section_<key>`` method with no arguments that
returns the content of that key (or ``None`` to omit it). The order of
``SECTIONS`` defines the order of the keys in the JSON.

To add a new section:

1. add the key to ``SECTIONS`` (at the desired position), and
2. create the ``_section_<key>`` method that returns its content.

The orchestrator, the writer and the LaTeX/PDF report do not need to be touched.
"""

from __future__ import annotations

import logging
from typing import Any

from lefiru.core.analysis_support import tests_by_key


class ReportDocument:
    """Assembles the report JSON from the analysis result.

    Parameters
    ----------
    result:
        Raw structure returned by ``AnalysisOrchestrator``.
    artifacts:
        Paths of generated artifacts (JSON, log, etc.). They are registered in
        ``metadata.artifacts``; if empty, the key is not added.
    """

    #: JSON sections, in order. The builder method of each one is
    #: called ``_section_<key>``.
    SECTIONS: tuple[str, ...] = (
        "metadata",
        "timestamp",
        "analysis_mode",
        "opening_protection",
        "analysis_blocked",
        "analysis",
        "protections",
        "consolidated",
        "evidence",
        "compliance",
        "tests",
        "general_status",
        "recommendations",
        "bypass_tests",
        "bypass_executed",
        "bypass_mode",
    )

    def __init__(self, result: dict[str, Any] | None, artifacts: dict[str, str] | None = None):
        self.result: dict[str, Any] = dict(result or {})
        self.artifacts: dict[str, str] = dict(artifacts or {})
        self.logger = logging.getLogger(__name__)

    def build(self) -> dict[str, Any]:
        """Returns the complete JSON document, section by section."""
        document: dict[str, Any] = {}

        for key in self.SECTIONS:
            constructor = getattr(self, f"_section_{key}", None)
            if not callable(constructor):
                raise AttributeError(
                    f"Missing _section_{key}() method for section '{key}'"
                )

            value = constructor()
            if value is not None:
                document[key] = value

        self.logger.debug(
            "JSON document built with %d sections: %s",
            len(document),
            ", ".join(document),
        )
        return document

    # ------------------------------------------------------------------
    # Sections
    # ------------------------------------------------------------------
    def _section_metadata(self) -> dict[str, Any] | None:
        metadata = dict(self.result.get("metadata") or {})

        if self.artifacts:
            metadata["artifacts"] = dict(self.artifacts)

        return metadata or None

    def _section_timestamp(self) -> str | None:
        return self.result.get("timestamp")

    def _section_analysis_mode(self) -> str | None:
        return self.result.get("analysis_mode")

    def _section_opening_protection(self) -> dict[str, Any] | None:
        return self.result.get("opening_protection")

    def _section_analysis_blocked(self) -> bool | None:
        return self.result.get("analysis_blocked")

    def _section_analysis(self) -> dict[str, Any] | None:
        return self.result.get("analysis")

    def _section_protections(self) -> dict[str, Any] | None:
        return self.result.get("protections")

    def _section_consolidated(self) -> dict[str, Any] | None:
        return self.result.get("consolidated")

    def _section_evidence(self) -> dict[str, Any] | None:
        return self.result.get("evidence")

    def _section_compliance(self) -> dict[str, Any] | None:
        compliance = dict(self.result.get("compliance") or {})
        if "tests" in compliance:
            compliance["tests"] = tests_by_key(compliance["tests"])
        return compliance or None

    def _section_tests(self) -> dict[str, Any] | None:
        tests = tests_by_key(self._field_compliance("tests"))
        return tests or None

    def _section_general_status(self) -> str | None:
        return self._field_compliance("general_status")

    def _section_recommendations(self) -> list[str] | None:
        return self._field_compliance("recommendations")

    def _section_bypass_tests(self) -> dict[str, Any] | None:
        return self.result.get("bypass_tests")

    def _section_bypass_executed(self) -> bool | None:
        return self.result.get("bypass_executed")

    def _section_bypass_mode(self) -> str | None:
        return self.result.get("bypass_mode")

    # ------------------------------------------------------------------
    # Internal utilities
    # ------------------------------------------------------------------
    def _field_compliance(self, key: str) -> Any:
        """Reads a field from ``compliance`` with a fallback at the root.

        The orchestrator exposes ``tests``, ``general_status`` and
        ``recommendations`` inside ``compliance``; the root is kept
        as a fallback for old or partial results.
        """
        compliance = self.result.get("compliance")

        if isinstance(compliance, dict) and key in compliance:
            return compliance[key]

        return self.result.get(key)

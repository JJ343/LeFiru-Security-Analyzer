#!/usr/bin/env python3
from pathlib import Path
import json
import argparse
import sys
import traceback
import logging
import re
import shutil
import subprocess
from typing import Any

from lefiru.core.analysis_support import tests_as_list
from lefiru.core.catalog import test_name
from lefiru.paths import resource
logger = logging.getLogger(__name__)


# ── Minimal LaTeX document API ───────────────────────────────────────────────
# The report content is built with the same calls that were previously used
# for the DOCX report (add_paragraph / add_run / bold / add_picture). These
# small classes collect that content and render it to a LaTeX document, which
# is then compiled to PDF with a local LaTeX engine.

PT_TO_CM = 0.03514598


class _Length(float):
    """Length in centimetres, mimicking docx.shared lengths."""

    @property
    def cm(self) -> float:
        return float(self)


def Pt(value: float) -> _Length:
    return _Length(value * PT_TO_CM)


def Cm(value: float) -> _Length:
    return _Length(value)


class WD_PARAGRAPH_ALIGNMENT:
    LEFT = "left"
    CENTER = "center"
    RIGHT = "right"
    JUSTIFY = "justify"


class _Font:
    def __init__(self):
        self.name = "Latin Modern Roman"
        self.size = Cm(0.39)  # ~11 pt


class _Style:
    def __init__(self):
        self.font = _Font()


class _ParagraphFormat:
    def __init__(self):
        self.left_indent = 0.0
        self.first_line_indent = 0.0


class _Run:
    def __init__(self, text: str = ""):
        self.text = str(text) if text is not None else ""
        self.bold = False
        self.italic = False
        self.font = _Font()
        self.pictures: list[tuple[Path, float | None]] = []

    def add_picture(self, path, width=None):
        self.pictures.append((Path(path), width))
        return self


class _Paragraph:
    def __init__(self, text: str | None = None, style: str | None = None):
        self.runs: list[_Run] = []
        self.alignment = None
        self.style = style
        self.paragraph_format = _ParagraphFormat()
        if text:
            self.add_run(text)

    def add_run(self, text: str = "") -> _Run:
        run = _Run(text)
        self.runs.append(run)
        return run


class _Element:
    def clear(self):
        return None


class _Header:
    def __init__(self):
        self.is_linked_to_previous = False
        self._element = _Element()
        self.paragraphs: list[_Paragraph] = []

    def add_paragraph(self, text: str | None = None, style: str | None = None):
        paragraph = _Paragraph(text, style)
        self.paragraphs.append(paragraph)
        return paragraph


class _Section:
    def __init__(self):
        self.header = _Header()
        # Page geometry in centimetres (A4, 2.5 cm margins).
        self.page_width = Cm(21.0)
        self.left_margin = Cm(2.5)
        self.right_margin = Cm(2.5)


class _Styles(dict):
    def __missing__(self, key):
        value = _Style()
        self[key] = value
        return value


_ESCAPE_MAP = {
    "&": r"\&",
    "%": r"\%",
    "$": r"\$",
    "#": r"\#",
    "_": r"\_",
    "{": r"\{",
    "}": r"\}",
    "~": r"\textasciitilde{}",
    "^": r"\textasciicircum{}",
}

_UNICODE_MAP = {
    "•": r"\textbullet{}",
    "·": r"\textperiodcentered{}",
    "–": "--",
    "—": "---",
    "…": r"\ldots{}",
    "→": r"$\rightarrow$",
    "←": r"$\leftarrow$",
    "≥": r"$\geq$",
    "≤": r"$\leq$",
    "“": "``",
    "”": "''",
    "‘": "`",
    "’": "'",
    "\u00a0": "~",
}


def _latex_escape(text: Any) -> str:
    """Escape plain text for LaTeX and translate the common Unicode symbols."""
    value = "" if text is None else str(text)
    placeholder = "\x00"
    value = value.replace("\\", placeholder)
    for char, replacement in _ESCAPE_MAP.items():
        value = value.replace(char, replacement)
    value = value.replace(placeholder, r"\textbackslash{}")
    for char, replacement in _UNICODE_MAP.items():
        value = value.replace(char, replacement)
    # Keep Latin-1 text (Spanish accents included); replace the rest so
    # pdflatex cannot abort on a character it does not know.
    value = "".join(ch if ord(ch) < 256 or ch in "\n\t" else "?" for ch in value)
    return value


LATEX_INSTALL_HINT = (
    "Install a LaTeX engine to build the PDF from the LaTeX source. "
    "On Windows the recommended option is MiKTeX "
    "(winget install MiKTeX.MiKTeX); TeX Live is also supported. "
    "Restart the terminal afterwards so the engine is found in PATH. "
    "Without it the report is still written, using the built-in PDF renderer."
)


def _find_latex_engine() -> str | None:
    """Return an available LaTeX engine, looking in PATH and common folders."""
    for name in ("xelatex", "lualatex", "pdflatex", "latexmk"):
        found = shutil.which(name)
        if found:
            return found

    candidates = [
        r"C:\Program Files\MiKTeX\miktex\bin\x64\pdflatex.exe",
        r"C:\Program Files\MiKTeX\miktex\bin\pdflatex.exe",
        r"C:\texlive\2024\bin\windows\pdflatex.exe",
        r"C:\texlive\2025\bin\windows\pdflatex.exe",
        r"C:\texlive\2023\bin\windows\pdflatex.exe",
    ]
    local = Path.home() / "AppData" / "Local" / "Programs"
    candidates.extend(str(p) for p in local.glob("MiKTeX/miktex/bin/*/pdflatex.exe"))
    for candidate in candidates:
        if Path(candidate).is_file():
            return candidate
    return None


def _is_miktex(engine: str) -> bool:
    return "miktex" in engine.lower()


def _compile_latex(tex_path: Path, engine: str | None) -> Path | None:
    """Compile the .tex file to PDF, returning the PDF path or ``None``."""
    if not engine:
        logger.warning(
            "No LaTeX engine found (xelatex/lualatex/pdflatex/latexmk). "
            "The LaTeX source was written to %s.\n%s",
            tex_path,
            LATEX_INSTALL_HINT,
        )
        return None

    is_latexmk = "latexmk" in Path(engine).name.lower()
    if is_latexmk:
        command = [
            engine,
            "-pdf",
            "-interaction=nonstopmode",
            "-halt-on-error",
            tex_path.name,
        ]
    else:
        command = [
            engine,
            "-interaction=nonstopmode",
            "-halt-on-error",
            "-output-directory",
            str(tex_path.parent),
            tex_path.name,
        ]
        # MiKTeX installs missing packages on first use. Without this flag it
        # opens a GUI prompt and the headless compilation hangs until timeout.
        if _is_miktex(engine):
            command.insert(1, "-enable-installer")

    pdf_path = tex_path.with_suffix(".pdf")
    process = None
    try:
        for _ in range(2):
            process = subprocess.run(
                command,
                cwd=str(tex_path.parent),
                capture_output=True,
                text=True,
                timeout=300,
            )
        for suffix in (".aux", ".out", ".toc", ".fls", ".fdb_latexmk"):
            auxiliary = tex_path.with_suffix(suffix)
            if auxiliary.exists():
                auxiliary.unlink()

        if pdf_path.is_file():
            # Keep the folder clean; the .log is only useful on failures.
            log_path = tex_path.with_suffix(".log")
            if log_path.exists():
                log_path.unlink()
            return pdf_path

        log_tail = ""
        log_path = tex_path.with_suffix(".log")
        if log_path.is_file():
            try:
                log_tail = "\n".join(log_path.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()[-25:])
            except OSError:
                pass
        logger.error(
            "LaTeX compilation failed (exit code %s).\n%s",
            process.returncode if process else "unknown",
            log_tail or (process.stdout if process else "") or "",
        )
    except Exception as exc:  # noqa: BLE001 - a report must not break the analysis
        logger.error("LaTeX compilation failed for %s: %s", tex_path, exc)

    return None


class Document:
    """Collects report paragraphs and writes LaTeX/PDF."""

    def __init__(self):
        self.blocks: list[_Paragraph] = []
        self.styles = _Styles()
        self.sections = [_Section()]
        self._body_font = self.styles["Normal"].font
        self._assets_dir: Path | None = None
        self._asset_counter = 0
        self._tex_path: Path | None = None

    def add_paragraph(self, text: str | None = None, style: str | None = None):
        paragraph = _Paragraph(text, style)
        self.blocks.append(paragraph)
        return paragraph

    # ── rendering ───────────────────────────────────────────────────────────
    def _image(self, path: Path, width: float | None) -> str:
        assert self._assets_dir is not None
        source = Path(path)
        if not source.is_file():
            logger.warning("Image not found for the report: %s", source)
            return ""
        self._asset_counter += 1
        name = f"img_{self._asset_counter:03d}{source.suffix.lower() or '.png'}"
        destination = self._assets_dir / name
        try:
            shutil.copy2(source, destination)
        except OSError as exc:
            logger.warning("Could not copy report image %s: %s", source, exc)
            return ""
        width_option = f"width={float(width):.2f}cm" if width else r"width=\linewidth"
        return rf"\includegraphics[{width_option}]{{{self._assets_dir.name}/{name}}}"

    def _render_runs(self, runs: list[_Run]) -> str:
        parts: list[str] = []
        for run in runs:
            if run.text:
                text = _latex_escape(run.text).replace("\n", "\\\\\n")
                size = float(getattr(run.font, "size", 0) or 0)
                if size and abs(size - float(self._body_font.size)) > 0.05:
                    points = size / PT_TO_CM
                    text = (
                        rf"{{\fontsize{{{points:.1f}}}{{{points * 1.2:.1f}}}"
                        rf"\selectfont {text}}}"
                    )
                if run.italic:
                    text = rf"\textit{{{text}}}"
                if run.bold:
                    text = rf"\textbf{{{text}}}"
                parts.append(text)
            for path, width in run.pictures:
                rendered = self._image(path, float(width) if width else None)
                if rendered:
                    parts.append(rendered)
        return "".join(parts)

    def _render_paragraph(self, paragraph: _Paragraph) -> str:
        raw_text = "".join(run.text for run in paragraph.runs).strip()
        if raw_text and set(raw_text) == {"_"} and len(raw_text) >= 5:
            return "\\par\\noindent\\rule{\\linewidth}{0.4pt}\\par\n\n"

        body = self._render_runs(paragraph.runs)
        if not body.strip():
            return "\\vspace{0.35em}\n"

        left = float(getattr(paragraph.paragraph_format, "left_indent", 0) or 0)
        if left > 0:
            body = rf"\hspace*{{{left:.2f}cm}}{body}"

        if paragraph.alignment == WD_PARAGRAPH_ALIGNMENT.CENTER:
            return "\\begin{center}\n" + body + "\n\\end{center}\n\n"
        if paragraph.alignment == WD_PARAGRAPH_ALIGNMENT.RIGHT:
            return "\\begin{flushright}\n" + body + "\n\\end{flushright}\n\n"
        return body + "\n\n"

    def _render_header(self) -> str:
        header = self.sections[0].header
        parts = [self._render_runs(p.runs) for p in header.paragraphs]
        return "".join(part for part in parts if part.strip())

    def _reportlab_markup(self, runs: list[_Run]) -> str:
        """Build the inline markup used by reportlab Paragraph objects."""
        from xml.sax.saxutils import escape

        parts: list[str] = []
        for run in runs:
            if not run.text:
                continue
            text = escape(str(run.text)).replace("\n", "<br/>")
            size = float(getattr(run.font, "size", 0) or 0)
            if size and abs(size - float(self._body_font.size)) > 0.05:
                points = size / PT_TO_CM
                text = f'<font size="{points:.1f}">{text}</font>'
            if run.italic:
                text = f"<i>{text}</i>"
            if run.bold:
                text = f"<b>{text}</b>"
            parts.append(text)
        return "".join(parts)

    def _reportlab_images(self, runs: list[_Run]):
        """Return reportlab Image flowables for the pictures in the runs."""
        from PIL import Image as PILImage
        from reportlab.lib.units import cm
        from reportlab.platypus import Image

        flowables = []
        for run in runs:
            for path, width in run.pictures:
                source = Path(path)
                if not source.is_file():
                    continue
                try:
                    with PILImage.open(source) as image:
                        pixel_width, pixel_height = image.size
                    width_cm = float(width) if width else 15.5
                    height_cm = width_cm * pixel_height / max(pixel_width, 1)
                    # Do not let a single evidence image overflow the page.
                    if height_cm > 22:
                        scale = 22 / height_cm
                        width_cm *= scale
                        height_cm *= scale
                    flowables.append(
                        Image(str(source), width=width_cm * cm, height=height_cm * cm)
                    )
                except Exception as exc:  # noqa: BLE001 - an image must not break the report
                    logger.warning("Could not add image %s to the PDF: %s", source, exc)
        return flowables

    def _write_pdf(self, pdf_path: Path) -> Path | None:
        """Fallback PDF renderer used when no LaTeX engine is installed."""
        try:
            from reportlab.lib.enums import TA_CENTER, TA_LEFT
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.platypus import (
                HRFlowable,
                Paragraph,
                SimpleDocTemplate,
                Spacer,
            )
            from reportlab.lib.utils import ImageReader
        except ImportError:
            logger.warning(
                "reportlab is not installed; the .tex source was written but "
                "no PDF could be produced."
            )
            return None

        base_style = ParagraphStyle(
            "ReportBody",
            fontName="Helvetica",
            fontSize=10.5,
            leading=14,
            spaceAfter=5,
            alignment=TA_LEFT,
        )
        center_style = ParagraphStyle(
            "ReportCenter",
            parent=base_style,
            alignment=TA_CENTER,
            spaceAfter=8,
        )

        header = self.sections[0].header
        header_images = self._reportlab_images(
            [run for paragraph in header.paragraphs for run in paragraph.runs]
        )

        def draw_page(canvas, doc):
            canvas.setFont("Helvetica", 8)
            canvas.drawCentredString(A4[0] / 2, 1.2 * cm, str(canvas.getPageNumber()))
            for flowable in header_images:
                try:
                    image_reader = ImageReader(flowable.filename)
                    pixel_width, pixel_height = image_reader.getSize()
                    width = 6 * cm
                    height = width * pixel_height / max(pixel_width, 1)
                    canvas.drawImage(
                        flowable.filename,
                        2.5 * cm,
                        A4[1] - 2.5 * cm,
                        width=width,
                        height=height,
                        preserveAspectRatio=True,
                        mask="auto",
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.debug("Could not draw the report logo: %s", exc)

        story = []
        for paragraph in self.blocks:
            raw_text = "".join(run.text for run in paragraph.runs).strip()
            if raw_text and set(raw_text) == {"_"} and len(raw_text) >= 5:
                story.append(Spacer(1, 4))
                story.append(HRFlowable(width="100%", thickness=0.5, color="#888888"))
                story.append(Spacer(1, 4))
                continue

            markup = self._reportlab_markup(paragraph.runs)
            style = center_style if paragraph.alignment == WD_PARAGRAPH_ALIGNMENT.CENTER else base_style
            left = float(getattr(paragraph.paragraph_format, "left_indent", 0) or 0)
            if left and style is base_style:
                style = ParagraphStyle(
                    f"ReportBody{left:.2f}",
                    parent=base_style,
                    leftIndent=left * cm,
                )
            if markup.strip():
                story.append(Paragraph(markup, style))
            images = self._reportlab_images(paragraph.runs)
            if images:
                story.extend(images)
                story.append(Spacer(1, 6))

        document = SimpleDocTemplate(
            str(pdf_path),
            pagesize=A4,
            leftMargin=2.5 * cm,
            rightMargin=2.5 * cm,
            topMargin=2.8 * cm,
            bottomMargin=2.2 * cm,
            title=pdf_path.stem,
            author="LeFiru Security Analyzer",
        )
        document.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
        return pdf_path

    def _preamble(self, engine: str | None) -> str:
        engine_name = Path(engine).name.lower() if engine else ""
        unicode_engine = "xelatex" in engine_name or "lualatex" in engine_name

        lines = [
            r"\documentclass[11pt,a4paper]{article}",
            r"\usepackage[margin=2.5cm]{geometry}",
            r"\usepackage{graphicx}",
            r"\usepackage{xcolor}",
            r"\usepackage{parskip}",
            r"\usepackage[hidelinks]{hyperref}",
        ]
        if unicode_engine:
            lines.append(r"\usepackage{fontspec}")
        else:
            lines.extend([
                r"\usepackage[utf8]{inputenc}",
                r"\usepackage[T1]{fontenc}",
                r"\usepackage{lmodern}",
                r"\usepackage{textcomp}",
            ])

        header = self._render_header()
        if header:
            lines.extend([
                r"\usepackage{fancyhdr}",
                r"\pagestyle{fancy}",
                r"\fancyhf{}",
                rf"\lhead{{{header}}}",
                r"\renewcommand{\headrulewidth}{0pt}",
                r"\fancyfoot[C]{\thepage}",
            ])
        else:
            lines.append(r"\pagestyle{plain}")

        lines.extend([
            r"\setlength{\parindent}{0pt}",
            r"\setlength{\parskip}{0.35em}",
            r"\begin{document}",
            "",
        ])
        return "\n".join(lines)

    def save(self, output_path) -> Path:
        output = Path(output_path)
        stem = output.with_suffix("")
        tex_path = stem.with_suffix(".tex")
        self._tex_path = tex_path
        tex_path.parent.mkdir(parents=True, exist_ok=True)
        self._assets_dir = tex_path.parent / f"{stem.name}_assets"
        self._assets_dir.mkdir(parents=True, exist_ok=True)

        engine = _find_latex_engine()
        parts = [self._preamble(engine)]
        parts.extend(self._render_paragraph(paragraph) for paragraph in self.blocks)
        parts.append("\n\\end{document}\n")
        tex_path.write_text("".join(parts), encoding="utf-8")
        logger.info("LaTeX report written to %s", tex_path)

        if engine:
            compiled = _compile_latex(tex_path, engine)
            if compiled:
                return compiled
            logger.warning(
                "The LaTeX compilation did not produce a PDF. "
                "Generating it with the built-in renderer instead."
            )
        else:
            logger.warning(
                "Generating the PDF with the built-in renderer instead."
            )
        pdf_path = self._write_pdf(tex_path.with_suffix(".pdf"))
        return pdf_path or tex_path


class ReportComposer:
    """
    Security report generator from the results JSON.

    The content is rendered to LaTeX and compiled to PDF.
    """
    
    RISKS_BY_TEST = {
        "structure_protection": [
            "Deleting critical sheets (Control, Parameters)",
            "Adding sheets with malicious logic",
            "Hiding sheets to evade reviews",
            "Renaming sheets, breaking VBA references"
        ],
        "critical_sheets_protection": [
            "Direct modification of critical information without control",
            "Alteration of financial or control results",
            "Loss of integrity of the underlying information",
            "Fraud or results-manipulation risks",
            "Breakdown of segregation of duties"
        ],
        "vba": [
            "Intentional or accidental modification of the process logic",
            "Insertion of malicious code",
            "Loss of traceability over changes to the logic",
            "Inability to guarantee the integrity and reliability of the file"
        ],
        "insecure_patterns": [
            "Exposure of credentials or sensitive information embedded in the VBA code",
            "Unauthorized access to integrated systems, databases or services",
            "Misuse of hardcoded secrets by users with access to the file or the VBA project",
            "Compromise of confidentiality and increased operational and fraud risk"
        ],
        "external_connections": [
            "Dependence on undocumented external sources",
            "Alteration of results due to changes in the source",
            "Misuse of embedded credentials",
            "Failures when running the file in other environments"
        ],
        "formulas": [
            "Errors or manipulation in critical calculations of the file",
            "Dependence on uncontrolled external references",
            "Loss of traceability of the logic implemented in formulas"
        ]
    }
    
    RECOMMENDATIONS_BY_TEST = {
            "structure_protection": {
                "title": "Protect the workbook structure",
                "description": (
                    "It is recommended to enable workbook structure protection in Excel, "
                    "so that changes to the file layout are restricted "
                    "to authorized users and uncontrolled alterations are prevented."
                ),
                "actions": [
                    "Excel → Review → Protect Workbook",
                    "Enable the Structure option",
                    "Set a password in accordance with the internal security policy",
                ],
            },

            "critical_sheets_protection": {
                "title": "Protect the critical sheets of the file",
                "description": (
                    "It is recommended to protect all critical sheets of the file, in order "
                    "to prevent unauthorized modification of key information used in "
                    "the calculations, reports or controls of the process, and to strengthen "
                    "the segregation of duties by limiting who can edit those sheets or cells."
                ),
                "actions": [
                    "Identify the sheets considered critical for the process",
                    "Excel → Review → Protect Sheet",
                    "Restrict editing of critical cells",
                    "Review the editing permissions configured on the workbook and sheets",
                    "Ensure that only authorized personnel can modify the file logic",
                    "Set a password aligned with the internal policy",
                    "Periodically validate editing permissions through control tests",
                ],
            },

            "vba": {
                "title": "Protect the VBA project with a password",
                "description": (
                    "Set a protection password for the VBA project so that "
                    "unauthorized users cannot "
                    "view or modify the source code of the file."
                ),
                "actions": [
                    "Open the VBA Editor (ALT + F11)",
                    "VBA Editor → Tools → VBAProject Properties",
                    "Protection tab → enable Lock project for viewing",
                    "Set a strong password in accordance with the internal policy",
                ],
            },

            "insecure_patterns": {
                "title": "Remove secrets and credentials from the VBA code",
                "description": (
                    "It is recommended to remove any secret, credential or sensitive information "
                    "embedded directly in the VBA code, in order to reduce the risk of "
                    "exposing confidential information or allowing unauthorized access."
                ),
                "actions": [
                    "Review the VBA code for embedded credentials, tokens or keys",
                    "Remove hardcoded sensitive values",
                    "Use secure authentication mechanisms or external configuration",
                    "Restrict access to the VBA code by protecting the project",
                ],
            },

            "external_connections": {
                "title": "Review and document the external connections and credentials used",
                "description": (
                    "Perform a formal review of all external connections in "
                    "the Excel file and properly document their purpose, origin and owners, "
                    "reducing risks of external dependency and information exposure."
                ),
                "actions": [
                    "Identify all external connections and links to external sources",
                    "Validate the operational need for each connection",
                    "Document for each connection: data source, type and owners",
                    "Verify that no credentials are exposed in plain text",
                    "Remove connections that are not necessary",
                    "Evaluate the use of centralized, controlled data sources",
                ],
            },

            "formulas": {
                "title": "Strengthen the traceability and integrity of critical formulas",
                "description": (
                    "It is recommended to review the formulas that support critical calculations in the file, "
                    "removing uncontrolled external references, pattern inconsistencies and "
                    "mechanisms that hinder calculation traceability. "
                    "Scope: the automated formula analysis focuses exclusively on the "
                    "sheets considered critical. A sheet is classified as critical when its "
                    "name (case-, accent- and separator-insensitive) contains words "
                    "associated with inputs/outputs, configuration, parameters, data, calculations, "
                    "results, processes, controls, validations, reconciliations, reports, "
                    "indicators, master sheets or balance. Non-critical sheets are "
                    "excluded from the formula analysis to focus the review on the calculations "
                    "that support process decisions and to optimize performance. However, "
                    "the search for hardcoded credentials continues to apply to all "
                    "sheets in the file."
                ),
                "actions": [
                    "Identify formulas with external or dynamic references in critical sheets",
                    "Standardize ranges with inconsistent formula patterns",
                    "Correct cells with calculation errors before releasing the file",
                    "Document justified exceptions for formulas that conceal errors",
                    "If a relevant sheet was not analyzed, rename it with a critical identifier "
                    "(input, output, calculo, etc.) so it is included in future analyses",
                ],
            },
        }

    RECOMMENDATIONS_PY_BY_TEST = {
        "dynamic_execution": {
            "title": "Remove unsafe dynamic execution",
            "description": (
                "Avoid the direct use of eval, exec or compile with untrusted data to "
                "reduce the risk of arbitrary code execution."
            ),
            "actions": [
                "Replace eval/exec with explicit, validated logic",
                "Apply allowlists for permitted expressions",
                "Validate and sanitize all input before processing it",
            ],
        },
        "dangerous_commands": {
            "title": "Control system command invocations",
            "description": (
                "Restrict the execution of operating system commands and avoid building "
                "commands dynamically from external input."
            ),
            "actions": [
                "Use subprocess with argument lists and shell=False",
                "Remove os.system where a safe alternative exists",
                "Log sensitive commands that are executed",
            ],
        },
        "deserialization": {
            "title": "Secure data deserialization",
            "description": (
                "Avoid insecure deserialization of objects or structures from "
                "untrusted sources."
            ),
            "actions": [
                "Avoid pickle/marshal with external data",
                "Use safe loaders such as yaml.safe_load",
                "Validate the schema and origin of the data before deserializing",
            ],
        },
        "credentials": {
            "title": "Remove hardcoded credentials and IPs",
            "description": (
                "Remove from the code any secrets, tokens, passwords and IPs defined in plain text "
                "to prevent the exposure of sensitive information."
            ),
            "actions": [
                "Move secrets to environment variables or the corporate vault",
                "Rotate compromised credentials detected during the analysis",
                "Implement CI validations to block new hardcoding",
            ],
        },
        "connections": {
            "title": "Externalize connection configuration",
            "description": (
                "Centralize paths, URLs and connection strings outside the code to improve "
                "security, maintenance and per-environment deployment."
            ),
            "actions": [
                "Use per-environment configuration files",
                "Avoid absolute paths and endpoints embedded in the code",
                "Document the origin, purpose and owner of each connection",
            ],
        },
        "traceability": {
            "title": "Strengthen traceability and code quality",
            "description": (
                "Ensure that scripts log key events and follow good quality practices "
                "to facilitate operational support."
            ),
            "actions": [
                "Implement structured logging in the main flow",
                "Log errors and critical events with sufficient context",
                "Fix quality and maintainability rules reported by the analysis",
            ],
        },
    }

    RISKS_PY_BY_TEST = {
        "dynamic_execution": [
            "Arbitrary code execution due to unsafe use of eval/exec/compile",
            "Compromise of script integrity due to unvalidated inputs",
        ],
        "dangerous_commands": [
            "Operating system command injection",
            "Escalation of impact due to uncontrolled command execution",
        ],
        "deserialization": [
            "Execution of malicious payloads during deserialization",
            "Compromise of integrity and availability due to untrusted data",
        ],
        "credentials": [
            "Exposure of secrets, tokens or credentials in the source code",
            "Unauthorized access due to the use of hardcoded sensitive information",
        ],
        "connections": [
            "Dependence on hardcoded, ungoverned endpoints/paths",
            "Operational risk due to unmanaged environment changes",
        ],
        "traceability": [
            "Loss of traceability due to missing or weak logging",
            "Difficulty in the forensic analysis of incidents",
        ],
    }


    # RESULTS PARSER
    
    def parse_results(self, json_path: Path) -> dict:
        
        def get_vba_exported(data) -> list:
            
            """
            Returns the real paths of exported VBA modules,
            deduplicated by logical module.
            Always returns a list.
            If COM mode does not expose modules (e.g. file protected from COM),
            the static analysis evidence is used as a fallback.
            """

            modules_com = (
                data
                .get("analysis", {})
                .get("com", {})
                .get("evidence", {})
                .get("com_mode", {})
                .get("exported_vba", {})
                .get("modules", []))
            
            paths = list(modules_com) if modules_com else []

            # Fallback: use static analysis evidence when COM did not expose modules
            if not paths:
                modules_static = (
                    data
                    .get("analysis", {})
                    .get("static", {})
                    .get("vba", {})
                    .get("static", {})
                    .get("modules", {})
                ) or {}
                for data in modules_static.values():
                    file = data.get("file_exported") if isinstance(data, dict) else None
                    if file:
                        paths.append(file)

            deduplicated = {}

            for path in paths:
                # Get the filename without extension
                name = Path(path).stem

                # Remove the trailing timestamp (_YYYYMMDD_HHMMSS)
                name = re.sub(r"_\d{8}_\d{6}$", "", name)

                # The VBA module is the last segment
                module = name.split("_")[-1]

                # Store only one path per module
                if module not in deduplicated:
                    deduplicated[module] = path

            return list(deduplicated.values())

        def get_screenshots(data) -> tuple:
            
            """
            Returns the real screenshot paths,
            deduplicated by logical module.
            Returns a tuple (captures, empty_dict for compatibility).
            If COM produced no screenshots, the images generated by the static analysis are used.
            """

            screenshots_com = (
                data
                .get("analysis", {})
                .get("com", {})
                .get("evidence", {})
                .get("com_mode", {})
                .get("screenshots", []))

            screenshots = list(screenshots_com) if screenshots_com else []

            # Fallback: VBA code images generated by the static analysis
            if not screenshots:
                modules_static = (
                    data
                    .get("analysis", {})
                    .get("static", {})
                    .get("vba", {})
                    .get("static", {})
                    .get("modules", {})
                ) or {}
                for data in modules_static.values():
                    image = data.get("image_exported") if isinstance(data, dict) else None
                    if image:
                        screenshots.append(image)

            # Return a tuple with the captures first and an empty value second for compatibility
            return screenshots, []

        def get_sheets_no_protected(data):
            """
            Returns the UNPROTECTED sheets with:
            - name
            - criticality
            - modification evidence
            """

            # Sheet details
            sheet_details = (
                data
                .get("analysis", {})
                .get("com", {})
                .get("protections", {})
                .get("com", {})
                .get("sheet_details", [])
            )

            #  Modification tests
            modification_tests = (
                data
                .get("analysis", {})
                .get("com", {})
                .get("protections", {})
                .get("com", {})
                .get("modification_tests", {})
            )

            result = []

            # Process unprotected sheets
            for sheet in sheet_details:
                if sheet.get("protected") is False:
                    name = sheet.get("name")
                    critical = sheet.get("critical", False)
                    visible= sheet.get("visible")

                    evidence = modification_tests.get(name, {}).get("evidence") if modification_tests else None

                    result.append({
                        "name": name,
                        "critical": critical,
                        "evidence": evidence,
                        "visible": visible
                    })

            return result
        
        data = json.loads(json_path.read_text(encoding="utf-8"))

        # Defensive guards for metadata
        metadata = data.get("metadata", {})
        result_data = data

        is_python_flow = data.get("analysis_mode") == "PYTHON" or bool(
            result_data.get("analysis", {}).get("python")
        )

        if not metadata:
            metadata = result_data.get("metadata", {})

        compliance = result_data.get("compliance", {})
        # Read from analysis.python (new structure) with fallback to the legacy key
        python_analysis = (
            result_data.get("analysis", {}).get("python")
            or data.get("python_analysis", {})
        )
        
        context = {
            "data_raw":data,
            "path": metadata.get("path_complete", "N/A"),
            "size_bytes": metadata.get("size_bytes", 0),
            "size_mb": metadata.get("size_mb", 0),
            "file": metadata.get("name", "file.xlsx"),
            "modification_date" : metadata.get("modification_date", "N/A"),
            "type" : metadata.get("type", ".xlsx"),
            "hash": metadata.get("hash", "N/A"),
            "log": metadata.get("artifacts", {}).get("log", "N/A"),
            "json": metadata.get("artifacts", {}).get("json", "N/A"),
            "opening_protections": result_data.get("opening_protection", {}),
            "protections_ctr1": result_data.get("analysis", {}).get("com", {}).get("protections", {}).get("com", {}),
            "ctr_exec": result_data.get("analysis", {}),
            "ctr_des": {},  # Compatibility: empty since there is no developer
            "bypass_tests": data.get("bypass_tests", {}),
            "general_status": compliance.get("general_status", "UNDETERMINED"),
            "tests": tests_as_list(
                compliance.get("tests") or result_data.get("tests", {})
            ),
            "critical_findings": compliance.get("critical_findings", []),
            "medium_findings": compliance.get("medium_findings", []),
            "low_findings": compliance.get("low_findings", []),
            "recommendations": compliance.get("recommendations", []),
            "date": result_data.get("timestamp", data.get("timestamp", "2026-01-01"))[:10],
            "python_analysis": python_analysis,
            "is_python_flow": is_python_flow,
        }
        
        context["analysis_mode"] = self.determine_mode_analysis(data)
        context["exported_vba"] = get_vba_exported(data) or []
        context["screenshots"] = get_screenshots(data)[0] or []
        context["unprotected_sheets"] = get_sheets_no_protected(data) or []
        context["tests_selected"] = {
            test["key"] for test in context.get("tests", [])
        }
        
        # ctr2 warning
        sheets_no_critical = [
            h["name"]
            for h in context.get("unprotected_sheets", [])
            if not h.get("critical", False)
        ]

        if sheets_no_critical:
            for test in context.get("tests", []):
                if test.get("key") == "critical_sheets_protection" and test.get("status") == "COMPLIANT":
                    
                    detail_base = test.get("detail", "")
                    clarification = (
                        "\n\nThe test evaluates exclusively the protection of critical sheets. "
                        "No critical sheets without protection were identified, therefore the test is compliant; "
                        "however, non-critical sheets without protection were identified. "
                        "It is recommended to also protect non-critical sheets to strengthen the control environment."
                    )

                    # Avoid duplicating the clarification if the Word document is regenerated
            
                    if clarification not in detail_base:
                        test["detail"] = detail_base + clarification
                    

        return context
        
    @staticmethod
    def _test_status(context, test_key: str) -> str:
        """Return the status of a test from the consolidated results."""
        for test in context.get("tests", []):
            if test.get("key") == test_key:
                return str(test.get("status", ""))
        return ""

    def _add_test_recommendation(
        self,
        doc,
        context,
        test_key: str,
        mapping=None,
        status: str | None = None,
    ):
        """Add the recommendation of a single test inside its own section."""
        data = (mapping or self.RECOMMENDATIONS_BY_TEST).get(test_key)
        if not data and test_key.startswith("python_"):
            data = (mapping or self.RECOMMENDATIONS_BY_TEST).get(test_key[7:])
        if not data:
            return

        if status is None:
            status = self._test_status(context, test_key)

        if status not in {
            "VULNERABLE",
            "WARNING",
            "COMPLIANT_WITH_OBSERVATIONS",
            "REQUIRES_REVIEW",
        }:
            return

        p = doc.add_paragraph()
        p.add_run("Recommendation: ").bold = True
        p.add_run(data["title"])

        p = doc.add_paragraph()
        p.add_run("Description:\n").bold = True
        p.add_run(data["description"])

        p = doc.add_paragraph()
        p.add_run("Suggested action:\n").bold = True
        for action in data["actions"]:
            self.add_bullet_item(doc, action, indent=2.5)

        doc.add_paragraph("_" * 80)

    def add_recommendations_prioritized(self, doc, tests):
        """
        Generates the Prioritized Recommendations section based on unsatisfactory tests.
        """

        # Filter vulnerable tests or tests with observations
        target_tests = [
            t for t in tests
            if t.get("status") in ("VULNERABLE", "WARNING")
        ]

        if not target_tests:
            return

        # Section title
        p = doc.add_paragraph()
        p.add_run("Prioritized Recommendations").bold = True

        counter = 1

        for t in target_tests:
            test_key = t.get("key")

            data = self.RECOMMENDATIONS_BY_TEST.get(test_key)
            if not data:
                continue  # No formal recommendation defined

            # Recommendation title
            p = doc.add_paragraph()
            p.add_run(
                f"RECOMMENDATION {counter} ({t.get('name', test_key)}): {data['title']}"
            ).bold = True

            # Description
            p = doc.add_paragraph()
            p.add_run("Description:\n").bold = True
            p.add_run(data["description"])

            # Suggested actions
            p = doc.add_paragraph()
            p.add_run("Suggested action:\n").bold = True

            for action in data["actions"]:
                self.add_bullet_item(doc, action, indent=2.5)

            # Visual separator
            doc.add_paragraph("_" * 80)

            counter += 1

    def add_risks_by_test(self, doc, tests):
        """
        Generates the risks-by-test section for unsatisfactory tests.
        """
        target_tests = [
            t for t in tests
            if t.get("status") in ("VULNERABLE", "WARNING", "COMPLIANT_WITH_OBSERVATIONS", "REQUIRES_REVIEW")
        ]

        if not target_tests:
            return

        p = doc.add_paragraph()
        p.add_run("RISKS BY TEST").bold = True

        for t in target_tests:
            test_key = t.get("key", "N/A")
            risks = self.RISKS_PY_BY_TEST.get(test_key, [])
            if not risks:
                continue

            p = doc.add_paragraph()
            p.add_run(f"{t.get('name', test_key)}:").bold = True
            for risk in risks:
                self.add_bullet_item(doc, risk, indent=2.5)

    def add_recommendations_prioritized_python(self, doc, tests):
        """
        Generates prioritized recommendations for unsatisfactory Python tests.
        """
        target_tests = [
            t for t in tests
            if t.get("status") in ("VULNERABLE", "WARNING", "COMPLIANT_WITH_OBSERVATIONS", "REQUIRES_REVIEW")
        ]

        if not target_tests:
            return

        p = doc.add_paragraph()
        p.add_run("PRIORITIZED RECOMMENDATIONS").bold = True

        counter = 1
        for t in target_tests:
            test_key = t.get("key")
            data = self.RECOMMENDATIONS_PY_BY_TEST.get(test_key)
            if not data:
                continue

            p = doc.add_paragraph()
            p.add_run(
                f"RECOMMENDATION {counter} ({t.get('name', test_key)}): {data['title']}"
            ).bold = True

            p = doc.add_paragraph()
            p.add_run("Description:\n").bold = True
            p.add_run(data["description"])

            p = doc.add_paragraph()
            p.add_run("Suggested action:\n").bold = True
            for action in data["actions"]:
                self.add_bullet_item(doc, action, indent=2.5)

            doc.add_paragraph("_" * 80)
            counter += 1

    def _add_header_with_logo(self, doc: Document, logo_path: Path):
        """
        Adds a header with the institutional logo.
        """
        section = doc.sections[0]
        header = section.header

        # Clear previous header content
        header.is_linked_to_previous = False
        header._element.clear()

        paragraph = header.add_paragraph()
        paragraph.alignment = WD_PARAGRAPH_ALIGNMENT.LEFT

        run = paragraph.add_run()

        # Adjust the size to the real logo
        run.add_picture(
            str(logo_path),
            width=Cm(6.0)  # recommended for header
        )
    
    def add_numbered_item(self, doc, text, style_name="List Number"):
        p = doc.add_paragraph(style=style_name)
        p.paragraph_format.left_indent = Cm(1.25)
        run = p.add_run(self._sanitize_xml_text(text))
        run.bold = True

    def add_bullet_item(self,doc, text , indent : float = 2):
        p = doc.add_paragraph(f"• {self._sanitize_xml_text(text)}")
        p.paragraph_format.left_indent = Cm(indent)
        p.paragraph_format.first_line_indent = Cm(-0.5)
      
    def add_sub_bullet_item(self, doc, text, indent: float = 3.75):
        """
        Sub-bullet of type 'o' with greater indentation.
        """
        p = doc.add_paragraph(f"o {self._sanitize_xml_text(text)}")
        p.paragraph_format.left_indent = Cm(indent)
        p.paragraph_format.first_line_indent = Cm(-0.5)

    def add_evidence_image(self, doc, image_path, max_width_cm: float = 15.5) -> None:
        """Inserts an evidence screenshot fitted to the usable page width.

        If the path does not exist or the file is not a valid image, a warning
        is logged and the report continues.
        """
        if not image_path:
            return

        path = Path(str(image_path))
        if not path.is_file():
            logger.warning("Visual evidence not found: %s", path)
            return

        # The same screenshot may be referenced from several sections of the
        # report; insert it only once.
        seen = getattr(self, "_inserted_evidence", None)
        if seen is None:
            seen = self._inserted_evidence = set()
        resolved = path.resolve()
        if resolved in seen:
            return

        section = doc.sections[0]
        available = section.page_width - section.left_margin - section.right_margin
        width = min(Cm(max_width_cm), available)

        try:
            paragraph = doc.add_paragraph()
            paragraph.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER
            paragraph.add_run().add_picture(str(path), width=width)
            seen.add(resolved)
        except Exception as exc:  # noqa: BLE001 - an image must not break the DOCX
            logger.warning(
                "Could not insert visual evidence %s: %s", path, exc
            )

    def add_evidence_images(self, doc, evidence, max_width_cm: float = 15.5) -> None:
        """Inserts every existing image found in an evidence value.

        Evidence may be a single path, a list/tuple of paths or a descriptive
        string such as "Protection verified"; only real image files are added.
        """
        if not evidence:
            return

        if isinstance(evidence, (list, tuple, set)):
            candidates = list(evidence)
        else:
            candidates = [evidence]

        for candidate in candidates:
            if not candidate or not isinstance(candidate, (str, Path)):
                continue
            path = Path(str(candidate))
            if path.is_file():
                self.add_evidence_image(doc, path, max_width_cm)

    # Control characters not allowed in XML 1.0 (except tab, LF and CR).
    _INVALID_XML_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

    @classmethod
    def _sanitize_xml_text(cls, text) -> str:
        """Removes NULL bytes and control characters that are invalid in XML.

        Strings extracted from binaries (metadata) may contain control
        characters that break document generation; they are replaced with the
        Unicode replacement character to preserve the rest of the content.
        """
        if text is None:
            return ""
        return cls._INVALID_XML_CHARS_RE.sub("\ufffd", str(text))

    @staticmethod
    def _is_unsatisfactory_python(status: str) -> bool:
        status_norm = str(status or "").upper()
        return status_norm in {"VULNERABLE", "WARNING"}

    @staticmethod
    def _has_multiple_modules(context: dict) -> bool:
        """Indicates whether the analyzed Python file spans several files/modules.

        They are considered "several" when the analysis reported more than one
        source module (metadata) or when the findings come from more than one
        distinct ``origin`` (e.g. executables with multiple embedded modules).
        """
        python_section = (
            context.get("data_raw", {})
            .get("analysis", {})
            .get("python", {})
        )
        if not isinstance(python_section, dict):
            return False

        metadata = python_section.get("metadata", {})
        if isinstance(metadata, dict):
            total = metadata.get("total_modules_source")
            if not total:
                total = len(metadata.get("source_modules", []) or [])
            if (total or 0) > 1:
                return True

        origins = set()
        for value in python_section.values():
            if not isinstance(value, dict):
                continue
            for finding in value.get("findings", []) or []:
                origin = finding.get("origin")
                if origin:
                    origins.add(str(origin))
                    if len(origins) > 1:
                        return True
        return False

    @staticmethod
    def _label_source_evidence(source: str | None) -> str:
        """Translates the evidence source of a Python finding into a readable label.

        Only applies to extractable artifacts (.pyc/.exe). It highlights when the
        finding comes from recovered code, since its reconstruction may be
        approximate.
        """
        map = {
            "code_recovered": (
                "Recovered code (approximate reconstruction of the executable/bytecode)"
            ),
            "metadata_binary": "Binary metadata of the executable",
        }
        return map.get(str(source or "").strip().lower(), "")
    # ── external_connections helpers ────────────────────────────────────────────────────

    _TYPE_LABEL_CONNECTION = {
        "FormulaExternalRef": "Formula with external ref.",
        "DataConnection":     "Data connection",
        "QueryTable":         "Query table",
        "ExternalLink":       "External link",
        "DefinedName":        "Defined Name",
    }
    
    _TYPE_LOCATION_MANUAL = {
        "ExternalLink": "Data → Workbook Links",
        "DataConnection": "Data → Queries & Connections",
        "QueryTable": "Data → Queries & Connections / Table with external source",
        "DefinedName": "Formulas → Name Manager (Ctrl + F3)",
        "FormulaExternalRef": "Search formulas (Ctrl + F) using '['",
    }


    def _render_connections_external(self, doc, ctr5_exec: dict, vulnerable_result: str = "VULNERABLE") -> None:
        """
        Renders all external connections from external_connections as structured bullets.

        Each finding shows: Type, Detail, Sheet and Cell/Reference.
        If the location is not available it is explicitly marked as "Not determined".
        """

        # ── 1. Unify all items into a homogeneous list ───────────────
        items: list[dict] = []

        for raw in ctr5_exec.get("external_links", []):
            item = raw if isinstance(raw, dict) else {"type": "ExternalLink", "origin": str(raw)}
            if "type" not in item:
                item["type"] = "ExternalLink"
            items.append(item)

        for raw in ctr5_exec.get("data_connections", []):
            item = raw if isinstance(raw, dict) else {"type": "DataConnection", "name": str(raw)}
            if "type" not in item:
                item["type"] = "DataConnection"
            items.append(item)

        for raw in ctr5_exec.get("defined_names", []):
            item = raw if isinstance(raw, dict) else {"type": "DefinedName", "name": str(raw)}
            if "type" not in item:
                item["type"] = "DefinedName"
            items.append(item)

        # ── 2. Case with no findings ────────────────────────────────────────────
        if not items:
            p = doc.add_paragraph()
            p.add_run("Result: ").bold = True
            p.add_run("COMPLIANT")
            self.add_bullet_item(doc, "No external connections were detected in the Excel file.")
            return

        # ── 3. Result header ───────────────────────────────────────
        p = doc.add_paragraph()
        p.add_run("Result: ").bold = True
        p.add_run(vulnerable_result)

        p = doc.add_paragraph()
        p.add_run(
            f"{len(items)} external connection(s) / link(s) detected. "
        )

        types_with_location = {
        "QueryTable",
        "DefinedName",
        "FormulaExternalRef"
        }

        types_present = set()
        # ── 4. Bullets per finding ──────────────────────────────────────────
        for idx, item in enumerate(items, 1):
            type_raw   = item.get("type", "")
            type_label = self._TYPE_LABEL_CONNECTION.get(type_raw, type_raw or "Connection")
            
            # Finding description / name
            name = (
                item.get("name")
                or item.get("origin")
                or item.get("reference")
                or item.get("definition")
            )
            type = item.get("type")
            formula     = item.get("formula", "")
            conn_str    = item.get("connection_string", "")
            description = item.get("description", "")
            
            parts = [x for x in [name, description, conn_str, formula] if x and str(x) not in ("None", "")]
            detail = " | ".join(str(p)[:120] for p in parts) or "–"
            
            
            types_present.add(type)
            
            # Sheet and cell / reference
            sheet = item.get("sheet") or "Not determined"

            cell_or_ref = (
                item.get("cell")
                or item.get("code_line")
                or item.get("reference")
            )
            cell_label = str(cell_or_ref)[:120] if cell_or_ref else "Not determined"

            
            self.add_bullet_item(doc, f"Finding {idx}: {type_label}")
            if  name :
                self.add_sub_bullet_item(doc, f"name: {name}")
                
            else:
                self.add_sub_bullet_item(doc, f"Detail: {detail[:200]}")
                   
            if type in types_with_location:
                if sheet:
                    self.add_sub_bullet_item(doc, f"Sheet: {sheet}")
                else:
                    self.add_sub_bullet_item(doc, "Sheet: Not determined")

                if cell_or_ref:
                    self.add_sub_bullet_item(doc, f"Cell/Reference: {cell_label}")
                else:
                    self.add_sub_bullet_item(doc, "Cell/Reference: Not determined")

        if types_present:
            doc.add_paragraph()
            p = doc.add_paragraph()
            p.add_run("Where to validate manually: ").bold = True

            for t in sorted(types_present):
                location = self._TYPE_LOCATION_MANUAL.get(t)
                label = self._TYPE_LABEL_CONNECTION.get(t, t)

                if location:
                    self.add_bullet_item(doc, f"{label}: {location}")
        doc.add_paragraph("")   # space after the findings block

    # ── End external_connections helpers ─────────────────────────────────────────────────

    def determine_mode_analysis(self, data: dict) -> str:
        """
        Determines the analysis mode actually executed
        from the JSON evidence.
        """
        if data.get("analysis_mode") == "PYTHON" or bool(
            data.get("analysis", {}).get("python")
        ):
            return "PYTHON"

        modes = set()

        analysis = data.get("analysis", {})

        if "static" in analysis:
            modes.add("STATIC")

        if "com" in analysis:
            modes.add("COM")

        if len(modes) == 2:
            return "STATIC and COM"
        elif len(modes) == 1:
            return list(modes)[0]
        else:
            return "UNDETERMINED"

    # ── Deep Fallback Methods for COM Failure ────────────────────────────
    
    def _build_fallback_protection_structure(self, context: dict) -> dict:
        """
        Builds fallback data for structure_protection when COM fails.
        Uses compliance information to determine the protection status.
        """
        tests = context.get("tests", [])
        test_structure_protection = next((c for c in tests if c.get("key") == "structure_protection"), {})
        
        return {
            "protected_workbook": test_structure_protection.get("status") == "COMPLIANT",
            "protect_structure": test_structure_protection.get("status") == "COMPLIANT",
            "protect_windows": False,
            "detail": test_structure_protection.get("detail", "Not available"),
            "status": test_structure_protection.get("status", "VULNERABLE"),
            "source": "FALLBACK_JSON",
            "method": "Compliance analysis from the consolidated result"
        }

    def _build_fallback_protection_sheets_critical(self, context: dict) -> dict:
        """
        Builds fallback data for critical_sheets_protection when COM fails.
        Extracts information about unprotected critical sheets from compliance.
        """
        tests = context.get("tests", [])
        test_critical_sheet_protection = next((c for c in tests if c.get("key") == "critical_sheets_protection"), {})
        critical_findings = context.get("critical_findings", [])
        
        # Look for unprotected sheets in the findings
        unprotected_sheets = []
        for finding in critical_findings:
            if test_critical_sheet_protection.get("key") in finding.get("test", ""):
                desc = finding.get("description", "")
                # Match the pattern "Unprotected critical sheets: X, Y, Z"
                if "unprotected critical sheets" in desc.lower():
                    import re
                    match = re.search(r":\s*(.+?)(?:\n|$)", desc)
                    if match:
                        names = [n.strip() for n in match.group(1).split(",")]
                        for name in names:
                            unprotected_sheets.append({
                                "name": name,
                                "protected": False,
                                "critical": True,
                                "visible": "VISIBLE",
                                "evidence": "Detected in compliance analysis"
                            })
        
        total_sheets = 0
        protected_sheets = 0
        try:
            # Try to extract numbers from the detail
            detail = test_critical_sheet_protection.get("detail", "")
            import re
            match = re.search(r"(\d+)\s+unprotected\s+sheet", detail)
            if match:
                sheets_without_prot = int(match.group(1))
                # Estimation: assume between 5-25 total sheets
                total_sheets = max(sheets_without_prot + 3, 8)
                protected_sheets = total_sheets - sheets_without_prot
        except:
            total_sheets = len(unprotected_sheets) + 3 if unprotected_sheets else 3
            protected_sheets = max(0, total_sheets - len(unprotected_sheets))
        
        return {
            "total_sheets": total_sheets if total_sheets > 0 else 3,
            "protected_sheets": protected_sheets if protected_sheets >= 0 else 0,
            "critical_sheets_without_protection": [h["name"] for h in unprotected_sheets],
            "sheet_details": unprotected_sheets,
            "modification_tests": {h["name"]: {"accessible": True} for h in unprotected_sheets},
            "source": "FALLBACK_JSON",
            "method": "Findings analysis from compliance"
        }

    def _build_fallback_vba(self, context: dict) -> dict:
        """
        Builds fallback data for vba when COM fails.
        Uses information about whether VBA exists and its protection status.
        """
        tests = context.get("tests", [])
        test_vba = next((c for c in tests if c.get("key") == "vba"), {})
        
        # Determine whether there is VBA
        has_vba = "VBA" in test_vba.get("detail", "") or test_vba.get("status") != "NOT_APPLICABLE"
        
        return {
            "has_vba": has_vba,
            "protected_project": test_vba.get("status") == "COMPLIANT",
            "modules": [],
            "detail": test_vba.get("detail", "Not available"),
            "status": test_vba.get("status", "NOT_APPLICABLE"),
            "source": "FALLBACK_JSON",
            "method": "Static analysis from compliance"
        }

    def _build_fallback_patterns_insecure(self, context: dict) -> dict:
        """
        Builds fallback data for insecure_patterns when COM fails.
        Uses information about secrets detected in the findings.
        """
        tests = context.get("tests", [])
        test_patterns_insecure = next((c for c in tests if c.get("key") == "insecure_patterns"), {})
        critical_findings = context.get("critical_findings", [])
        medium_findings = context.get("medium_findings", [])
        
        found_secrets = []
        for finding in critical_findings + medium_findings:
            if test_patterns_insecure.get("key") in finding.get("test", ""):
                found_secrets.append({
                    "type": "secret_detected",
                    "detail": finding.get("description", ""),
                    "severity": "critical" if finding in critical_findings else "medium"
                })
        
        return {
            "has_secrets": len(found_secrets) > 0,
            "secrets": found_secrets,
            "detail": test_patterns_insecure.get("detail", "Not available"),
            "status": test_patterns_insecure.get("status", "COMPLIANT"),
            "source": "FALLBACK_JSON",
            "method": "Consolidated findings analysis"
        }

    def _render_fallback_com_unavailable(self, doc, test_key: str, context: dict) -> bool:
        """
        Renders a fallback block when COM is not available.
        Returns True if a fallback was rendered, False if valid COM data exists.
        """
        ctr_exec = context.get("ctr_exec", {})
        
        # Check whether there really is no COM data
        has_com_data = ctr_exec.get("com") and "mode_status" not in ctr_exec.get("com", {})
        
        if has_com_data:
            return False  # There is COM data, do not use the fallback
        
        # Render the fallback warning
        p = doc.add_paragraph()
        p.add_run("Analysis Note: ").bold = True
        p.add_run(
            "COM mode is not available. Consolidated results based on a previous "
            "analysis are presented. It is recommended to run COM analysis when possible."
        )
        
        return True

    # ── End Fallback Methods ─────────────────────────────────────────────────

    @staticmethod
    def _is_python_context(context: dict) -> bool:
        type = str(context.get("type", "")).lower()
        mode = str(context.get("analysis_mode", "")).upper()
        return mode == "PYTHON" or type in {".py", ".pyc", ".exe"} or bool(context.get("python_analysis"))

    def _add_report_header(
        self, doc, file_name: str, date: str
    ) -> None:
        """Adds the report title block as plain text, without metadata tables."""
        p = doc.add_paragraph()
        run = p.add_run("SECURITY REPORT")
        run.bold = True
        run.font.size = Pt(16)
        p.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER

        p = doc.add_paragraph()
        run = p.add_run(f"File: {file_name}")
        run.italic = True
        p.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER

        p = doc.add_paragraph()
        run = p.add_run(f"Date: {date}")
        run.font.size = Pt(9)
        p.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER

        doc.add_paragraph("")

    def generate_docx_python(self, context: dict, output_path: Path):
        self._inserted_evidence = set()
        
        def  Findings_by_test(context:dict, ctr: str, title: str, description: str, domain: str):
            """_summary_

            Args:
                context (dict): data, used above, i.e. the entire JSON passed in the variable.
                ctr (_type_): name of the test in the JSON
                title (_type_): Title of the finding.
                description (_type_): Description of what the finding does
                domain (_type_): Policy guideline
            """
            #Test title
            doc.add_paragraph().add_run(title).bold = True
            #Context
            doc.add_paragraph().add_run("Context").bold = True
            doc.add_paragraph(description)
            #Policy domain
            doc.add_paragraph().add_run("Applicable policy guideline:").bold = True
            doc.add_paragraph(domain)
            #Test status
            
                        
            status_ctrl = context.get("data_raw", {}) \
                .get("analysis", {}) \
                .get("python", {}) \
                .get(ctr, {}) \
                .get("status", "N/A")
                
            if status_ctrl == "COMPLIANT":
                
                p = doc.add_paragraph()
                p.add_run("Result: ").bold = True
                p.add_run("COMPLIANT")

                doc.add_paragraph("No relevant findings were detected in this test.")
            elif status_ctrl in {"VULNERABLE", "COMPLIANT_WITH_OBSERVATIONS"}:
                p = doc.add_paragraph()
                p.add_run("Result: ").bold = True
                if status_ctrl == "VULNERABLE":
                    p.add_run("VULNERABLE")
                else:   
                    p.add_run("COMPLIANT_WITH_OBSERVATIONS")
                
                total_findings = context.get("data_raw", {}) \
                        .get("analysis", {}) \
                        .get("python", {}) \
                        .get(ctr, {}) \
                        .get("total_findings", "N/A")
                        
                doc.add_paragraph(f"{total_findings} findings were detected")

                    
                
                findings = context.get("data_raw", {}) \
                        .get("analysis", {}) \
                        .get("python", {}) \
                        .get(ctr, {}) \
                        .get("findings", [])

                # Note when any finding comes from code recovered from
                # an executable/bytecode (approximate reconstruction of the binary).
                if any(h.get("source_evidence") == "code_recovered" for h in findings):
                    note = doc.add_paragraph()
                    note.add_run(
                        "Note: some findings in this test were discovered in "
                        "code recovered from the executable/bytecode. That code is an "
                        "approximate reconstruction and may contain inaccuracies or "
                        "references unrelated to the original file."
                    ).italic = True

                # Only indicate the source file/module when the file contains
                # several analyzed files or modules (e.g. executables with
                # multiple embedded modules); with a single module it is redundant.
                multiple_modules = self._has_multiple_modules(context)

                for items in findings:
                    evidence = items.get("evidence", "N/A")
                    severity = items.get("severity", "N/A")
                    line = items.get("line", "N/A")
                    value = items.get("value", "N/A")
                    source_file = items.get("origin")
                    origin_evidence = self._label_source_evidence(
                        items.get("source_evidence")
                    )
                    if evidence != "N/A":
                        self.add_bullet_item(
                            doc,
                            f"Context: {evidence} | Severity: {severity} | Line: {line}"

                        )
                        if multiple_modules and source_file:
                            self.add_sub_bullet_item(
                                doc,
                                f"Source file/module: {source_file}"
                            )
                        if value != "N/A":
                            self.add_sub_bullet_item(
                                doc,
                                f"Value: {value}"
                            )
                        if origin_evidence:
                            self.add_sub_bullet_item(
                                doc,
                                f"Evidence origin: {origin_evidence}"
                            )
                    else:
                        description= items.get("description", "N/A")
                        self.add_bullet_item(
                            doc, f"Context: {description}")
                        self.add_sub_bullet_item(doc, f"Severity: {severity} | Line: {line}")
                        if multiple_modules and source_file:
                            self.add_sub_bullet_item(
                                doc,
                                f"Source file/module: {source_file}"
                            )
                        if value != "N/A":
                            self.add_sub_bullet_item(
                                doc,
                                f"Value: {value}"
                            )
                        if origin_evidence:
                            self.add_sub_bullet_item(
                                doc,
                                f"Evidence origin: {origin_evidence}"
                            )

                    # Screenshot of the exact Python code line, if it exists.
                    self.add_evidence_image(doc, items.get("evidence_image"))

            self._add_test_recommendation(
                doc,
                context,
                ctr,
                mapping=self.RECOMMENDATIONS_PY_BY_TEST,
                status=status_ctrl,
            )


        doc = Document()
        logo_path = resource("reporting/assets/logo.png")
        if logo_path.exists():
            self._add_header_with_logo(doc, logo_path)

        style = doc.styles["Normal"]
        font = style.font
        font.name = "Aptos (Cuerpo)"
        font.size = Pt(11)

        file_name = Path(context.get("file", "script.py")).stem
        self._add_report_header(doc, file_name, context.get("date", "N/A"))

        p = doc.add_paragraph()
        p.add_run("PYTHON SECURITY ANALYSIS").bold = True
        doc.add_paragraph("_" * 85)

        # Brief explanation of the tool
        doc.add_paragraph().add_run("ABOUT THE TOOL").bold = True
        doc.add_paragraph(
            "LeFiru Security Analyzer is an internal tool that automates the security review "
            "of Python files (.py, .pyc and .exe). It analyzes source code, bytecode and packaged "
            "executables looking for dynamic execution, dangerous commands, "
            "insecure deserialization, hardcoded credentials, external connections "
            "and traceability gaps, and produces this report together with a JSON "
            "result file."
        )
        doc.add_paragraph("_" * 85)
        doc.add_paragraph().add_run("RESOURCES CONSULTED").bold = True
        self.add_numbered_item(doc,
                               "Analyzed Application:", 
                               style_name="List Number 2")
        self.add_bullet_item(doc, f"File name: {context.get('file', 'N/A')}")
        self.add_bullet_item(doc, f"Size: {context.get('size_mb', 0)} MB ({context.get('size_bytes', 0)} bytes)")
        self.add_bullet_item(doc, f"SHA-256 hash: {context.get('hash', 'N/A')}")
        self.add_bullet_item(doc, f"Last modified date: {context.get('modification_date', 'N/A')}")
        file_type = context.get("type", "N/A")
        if file_type == ".py":
            self.add_bullet_item(doc, f"Format: .py (Python code)")
        elif file_type == ".pyc":
            self.add_bullet_item(doc, f"Format: .pyc (Python bytecode)")
        elif file_type == ".exe":
            self.add_bullet_item(doc, f"Format: .exe (executable packaged with Python)")
        else:
            self.add_bullet_item(doc, f"Format: {file_type}")
        doc.add_paragraph("_" * 85)
        self.add_numbered_item(doc,
            "Analysis Support Tool:", 
            style_name="List Number 2")
        doc.add_paragraph("LeFiru Security Analyzer: "
        "Internal tool developed to automate security analysis of Python files"
        ", enabling the detection of insecure patterns, compliance validation and generation of technical evidence.")
        self.add_bullet_item(doc, "Version: v1.0.1")
        self.add_bullet_item(doc, "Analysis mode: STATIC (Python code analysis)")
        
        
        timestamp_raw = context.get("data_raw", {}) \
                            .get("timestamp")

        self.add_sub_bullet_item(doc,f"Timestamp: {timestamp_raw}")
        doc.add_paragraph("_" * 85)
        self.add_numbered_item(doc,
            "Automatically Generated Evidence", 
            style_name="List Number 2")
        
        self.add_bullet_item(doc, f"Full JSON Report: {context.get('json', 'N/A')}")
        self.add_bullet_item(doc, f"Detailed log: {context.get('log', 'N/A')}")
        doc.add_paragraph("_" * 85)
        doc.add_paragraph().add_run("ANALYSIS PERFORMED").bold = True
        doc.add_paragraph().add_run("Context").bold = True
        doc.add_paragraph("The analysis was carried out using the LeFiru Security Analyzer tool"
                          ", through a static analysis of the Python code, consisting of inspecting the"
                          "structure of the script, development patterns, use of external resources and compliance with good"
                          "security practices.")
        #Dynamic execution
        Findings_by_test(context,
                             "python_dynamic_execution", 
                             "Dynamic Execution Analysis",
                                "This test looks for dangerous functions in the code such as eval and exec;"
                                "these can enable unauthorized modification that allows the execution of malicious code" ,
                                "Development or change guideline and Segregation of Duties."
                            )
 
        #Dangerous commands        
        Findings_by_test(context,
                             "python_dangerous_commands", 
                             "Dangerous Commands Analysis",
                             "This test seeks to identify the use of functions or modules that allow"
                             "the execution of operating system commands, such as os.system or subprocess." 
                             "The use of these commands without adequate validation may allow an attacker to execute" 
                             "malicious code, compromise system security or alter its operation.",
                             "Development or change guideline and Segregation of Duties.")
        #Insecure deserialization    
        Findings_by_test(context,
                             "python_deserialization", 
                             "Insecure Deserialization",
                             "This test seeks to identify the use of deserialization mechanisms "
                             "for untrusted data (such as pickle, json, yaml or others) without adequate validation. "
                             "Insecure deserialization may allow an attacker to manipulate the input data "
                             "to execute malicious code, alter the program logic or compromise the integrity of the system.",
                             "Development or change guideline and Segregation of Duties")


        #Hardcoded credentials
        Findings_by_test(context,
                             "python_credentials", 
                             "Hardcoded Credentials Analysis",
                             "This test seeks to identify credentials embedded directly in the source code, "
                             "such as users, passwords, tokens or API keys. Storing this sensitive information in the code "
                             "represents a security risk, since it may be exposed through repositories, logs or unauthorized access, "
                             "facilitating the compromise of systems and services.",
                             "Development or change guideline and Access")

        #Hardcoded external connections
        Findings_by_test(context,
                             "python_connections", 
                             "Hardcoded External Connections Analysis",
                             "This test identifies paths and URLs defined directly in the source code. "
                             "Hardcoding these values reduces the flexibility of the system and makes it harder to maintain, since any change "
                             "requires modifications to the code. In addition, it may expose information about the internal structure of the application or its "
                             "external dependencies.",
                             "Documentation and Development or Change Guideline")

        #Traceability, logging and quality
        Findings_by_test(context,
                             "python_traceability", 
                             "Code Traceability and Quality Analysis",
                             "This test evaluates the presence of traceability and logging mechanisms within the code, "
                             "as well as compliance with good quality practices. The absence or deficiency of logs hinders "
                             "error detection, system monitoring and incident analysis.",
                             "Documentation Guideline")
        
        tests = context.get("tests", [])

        total_tests = len(tests)
        unsatisfactory = sum(
            1 for t in tests if self._is_unsatisfactory_python(t.get("status", ""))
        )
        satisfactory = max(0, total_tests - unsatisfactory)

        p = doc.add_paragraph()
        p.add_run("OVERALL RESULT").bold = True
        self.add_bullet_item(doc, f"Total Tests Evaluated: {total_tests}", indent=2.5)
        self.add_bullet_item(doc, f"Unsatisfactory Tests: {unsatisfactory}", indent=2.5)
        self.add_bullet_item(doc, f"Satisfactory Tests: {satisfactory}", indent=2.5)

        self.add_risks_by_test(
            doc,
            context.get("tests", []),
        )

        doc.add_paragraph("_" * 85)
        return doc.save(output_path)
    
    def summary_code_vba(self, code, max_lines=10, max_signatures=5):
        """
        Returns a structured summary of the VBA code:
        - signatures: first 'max_signatures' Sub / Function declarations
        - code lines: first 'max_lines' non-empty lines
        """

        if not code:
            return {
                "total_lines": 0,
                "signatures": [],
                "code_lines": [],
                "truncated": False
            }

        lines = [l.strip() for l in code.splitlines() if l.strip()]
        total_lines = len(lines)
        
        signatures = []
        body = []

        for line in lines:
            lower = line.lower()
            if lower.startswith(("sub ", "function ")):
                signatures.append(line)
            else:
                body.append(line)

        return {
            "total_lines": total_lines,
            "signatures": signatures[:max_signatures],          #  ONLY 5 signatures
            "code_lines": body[:max_lines],   #  10 lines of code
            "truncated": len(body) > max_lines
        }

    def add_findings_detailed(self, doc, findings, title):
        """
        Generates a Detailed Findings section in the Word document.
        Formulas findings are grouped into a compact table to prevent a high
        number of cells with errors from producing an excessively long document.
        """

        if not findings:
            return

        # Separate formulas findings from the rest
        h_others = []
        seen = set()
        for finding in findings:
            test_key = finding.get("test")
            description = finding.get("description", "No description")

            if test_key == "formulas":
                continue

            key = (test_key, description)
            if key in seen:
                continue

            seen.add(key)
            h_others.append(finding)

        if not h_others:
            return

        # Section title
        p = doc.add_paragraph()
        run = p.add_run(title)
        run.bold = True

        contador = 1
        tests_con_risk_rendering = getattr(self, "_tests_con_risk_rendering", set())

        # ── Findings from other tests (original format) ──────────────────────
        for h in h_others:
            test_key = h.get("test", "N/A")
            description = h.get("description", "No description")

            p = doc.add_paragraph()
            p.add_run(f"FINDING {contador} ({test_name(test_key)}): {description}").bold = True

            risks = self.RISKS_BY_TEST.get(test_key, [])
            if risks and test_key not in tests_con_risk_rendering:
                p = doc.add_paragraph()
                p.add_run("Risk:").bold = True
                for r in risks:
                    self.add_bullet_item(doc, r, indent=2.5)
                tests_con_risk_rendering.add(test_key)

            contador += 1

        self._tests_con_risk_rendering = tests_con_risk_rendering

   
    
    def filter_screenshot_protections(self, paths: list) -> list:
        """
        Returns only the screenshots related to 'protections',
        regardless of their position in the list.
        """
       
        for r in paths:
                if "protections" in Path(r).stem.lower():
                    return r
        return None

    # GENERADOR LATEX/PDF
    def generate_docx(self, context: dict, output_path: Path):
        self._inserted_evidence = set()
        if self._is_python_context(context):
            return self.generate_docx_python(context, output_path)

        doc = Document()
        self._tests_con_risk_rendering = set()
        
        logo_path = resource("reporting/assets/logo.png")
        if logo_path.exists():
            self._add_header_with_logo(doc, logo_path)

        # BASE STYLE        
        style = doc.styles["Normal"]
        font = style.font
        font.name = "Aptos (Cuerpo)"
        font.size = Pt(11)
        
       
        # REPORT – FILE_NAME – DATE

        file_name = Path(context["file"]).stem

        self._add_report_header(doc, file_name, context["date"])

        # REPORT SECTION TITLE
        p = doc.add_paragraph()
        run = p.add_run("EXCEL SECURITY ANALYSIS")
        run.bold = True

        doc.add_paragraph("_" * 85)
        # Brief explanation of the tool
        doc.add_paragraph().add_run("ABOUT THE TOOL").bold = True

        doc.add_paragraph(
            "LeFiru Security Analyzer is an internal tool that automates the security review "
            "of Excel files (.xlsx, .xlsm, .xlsb, .xltx, .xltm and .xlam). It inspects workbook and sheet "
            "protections, VBA code, external connections, critical formulas and "
            "opening encryption, generates technical evidence and produces this "
            "report together with a JSON result file."
        )
        doc.add_paragraph("_" * 85)
        #Resources consulted.
        doc.add_paragraph().add_run("RESOURCES CONSULTED").bold = True
        
                
        self.add_numbered_item(
            doc,
            "Analyzed Application:",
            style_name="List Number 2"
            
        )
        
        self.add_bullet_item(
            doc,
            f"File name: {context['file']}"
          
        )
        
        
        self.add_bullet_item(
            doc,
            f"Size: {context.get('size_mb', 'N/A')} MB ({context.get('size_bytes', 'N/A')} bytes)"
            
        )
        
        
        self.add_bullet_item(
            doc,
            f"SHA-256 hash: {context.get('hash', 'N/A')}"
            
        )
        
        
        self.add_bullet_item(
            doc,
            f"Modification Date: {context.get('modification_date', 'N/A')}"
            
        )
        
        type = context.get('type', '').upper()
        if type == ".XLSX" :
            self.add_bullet_item(
                doc,
                f"Format: {context.get('type', '').upper()} (Excel Open XML)"
                
            )
        elif type == ".XLSM":
            self.add_bullet_item(
                    doc,
                    f"Format: {context.get('type', '').upper()}  (Excel Macro-Enabled)"
                    
                )
        elif type == ".XLSB":
            self.add_bullet_item(
                    doc,
                    f"Format: {context.get('type', '').upper()}  (Excel Binary Workbook)"
                    
                )
        elif type == "PY":
            self.add_bullet_item(
                    doc,
                    f"Format: {context.get('type', '').upper()}  (Python Script)"
                    
            )
            
        elif type == "PYC":
            self.add_bullet_item(
                    doc,
                    f"Format: {context.get('type', '').upper()}  (compiled Python bytecode file)"
                    
            )
        elif type == "EXE":
            self.add_bullet_item(
                    doc,
                    f"Format: {context.get('type', '').upper()}  (Executable File)"
                    
            )
            
        self.add_numbered_item(
            doc,
            "Analysis Support Tool:",
            style_name="List Number 2"
            
        )
        
        doc.add_paragraph(
            "LeFiru Security Analyzer: Internal tool developed "
            "to automate security analysis, review of protections, VBA code extraction, "
            "compliance validation, generation of photographic evidence and authorized "
            "bypass tests."
        )
        
        self.add_bullet_item(
            doc,
            "Version: v 1.0.1",
            indent=2.5
            
        )
        
        analysis_mode =context['analysis_mode']
        if analysis_mode == "STATIC and COM":
            
            self.add_bullet_item(
                doc,
                "Analysis mode: COM Automation (analysis with an interactive Excel instance installed) "
                "and STATIC (static analysis of the file without running Excel)",
                indent=2.5
            )
        elif analysis_mode == "STATIC":
            self.add_bullet_item(
                doc,
                "Analysis mode: STATIC (static analysis of the file without running Excel)",
                indent=2.5
            )
        else:
            self.add_bullet_item(
                doc,
                "Analysis mode: COM Automation (analysis with an interactive Excel instance installed)",
                indent=2.5
            )
            
        
        timestamp_evaluation = context.get("data_raw", {}).get("timestamp", "N/A")
        self.add_sub_bullet_item(
            doc,
            f"Timestamp: {timestamp_evaluation}"
        )
        
        self.add_numbered_item(
            doc,
            "Automatically Generated Evidence",
            style_name="List Number 2"
            
        )
        
        self.add_bullet_item(
            doc,
            f"Full JSON Report: {context.get('json','')}"
            
        )
        
        self.add_bullet_item(
            doc,
            f"Exported VBA code:"
            
        )
        
        if context["exported_vba"]:
            
            for item in context["exported_vba"]:
                self.add_sub_bullet_item(
                    doc,
                    f"{item}",
                    indent=2.3
                )
        else:
             self.add_sub_bullet_item(
                    doc,
                    "Not applicable",
                    indent=2.3
                )
            
        screenshots = context["screenshots"]
        tests_sel = context.get("tests_selected", set())
        
        if screenshots:
            self.add_bullet_item(
            doc,
            f"Screenshots ({len(context['screenshots'])})"
            )
            for item in context['screenshots']:
                self.add_sub_bullet_item(
                    doc,
                    f"{item}",
                    indent=2.3
                )
                self.add_evidence_image(doc, item)
        else:
            self.add_bullet_item(
            doc,
            f"Screenshots (0)"
            )
            self.add_sub_bullet_item(
                    doc,
                    f"Not applicable",
                    indent=2.3
            )
        
        self.add_bullet_item(
            doc,
            f"Detailed log {context['log']}"
            )

        doc.add_paragraph("_" * 85)

        #ANALYSIS PERFORMED
        
        doc.add_paragraph().add_run("ANALYSIS PERFORMED").bold = True
       
        doc.add_paragraph().add_run("Context").bold = True
        
        doc.add_paragraph(
            "The analysis was carried out using the LeFiru Security Analyzer tool, "
            "which runs a series of automated tests to "
            "assess the security posture of the application through COM Automation (direct interaction with Excel) "
            "and through a static analysis, which consists of the direct inspection of the internal structure " 
            "of the file and its components (for example, sheets, protections, links and metadata) without "
            "executing the content or the macros, in order to identify insecure configurations, " 
            "potential exposures and missing security controls from a structural standpoint.")
        
        opening_protection = context["opening_protections"]
    
        if not opening_protection.get('has_password') and  not opening_protection.get('encrypted'):
            flag= False
            doc.add_paragraph(
                "The file does not present opening encryption, which allowed "
                "a complete technical analysis of the protections of the "
                "workbook structure, sheet protections and the VBA project."
            )
        else:
            flag = True
            doc.add_paragraph(  
                "The file has opening encryption, which limited "
                "the direct technical analysis of certain internal protections, "
                "due to the access controls applied."
            )
             

        
        #CONTENT
        doc.add_paragraph().add_run("CONTENT").bold = True
        #OPENING ENCRYPTION
        p = doc.add_paragraph()
        run = p.add_run("Opening Encryption Verification")
        run.bold = True
        
        if flag == False:
            p = doc.add_paragraph()
            p.add_run("Result: ").bold = True
            p.add_run("No opening encryption detected" )
            
            e = doc.add_paragraph()
            e.add_run("Technical evidence: ").bold = True
            e.add_run("File with a standard ZIP structure accessible without a password")
            
            es = doc.add_paragraph()
            es.add_run("Status ").bold = True
            es.add_run("ACCESSIBLE FILE for full analysis")
        else:
            
            p = doc.add_paragraph()
            p.add_run("Result: ").bold = True
            p.add_run("Opening encryption detected")

            e = doc.add_paragraph()
            e.add_run("Technical evidence: ").bold = True
            e.add_run("File protected with a password; its content cannot be accessed")

            es = doc.add_paragraph()
            es.add_run("Status ").bold = True
            es.add_run("NON-ACCESSIBLE FILE for full analysis")
            
        # Initialize ctr_eje for all tests that need it
        ctr_exec = context.get("ctr_exec", {})
        
        #WORKBOOK STRUCTURE (structure_protection)
        p = doc.add_paragraph()
        run = p.add_run("Workbook Structure Protection")
        run.bold = True

        if "structure_protection" not in tests_sel:
            p = doc.add_paragraph()
            p.add_run("Result: ").bold = True
            p.add_run("Not applicable: test skipped for this analysis.")
        else:
            # Deep fallback strategy for COM
            ctr1 = ctr_exec.get("com", {}).get("protections", {}).get("com", {})
            com_error = ctr1.get("error") if ctr1 else None
            
            # If COM has an error or is empty, try static
            if not ctr1 or com_error:
                ctr1 = ctr_exec.get("static", {}).get("protections", {}).get("static", {})
            
            # If static is also empty, or both fail, use the deep fallback
            if not ctr1 or ctr1.get("error"):
                if self._render_fallback_com_unavailable(doc, "structure_protection", context):
                    ctr1 = self._build_fallback_protection_structure(context)
            
            # Final fallback if everything fails
            if not ctr1:
                ctr1 = context.get("protections", {})
            
            protected_workbook = ctr1.get("protected_workbook", False)
            protect_structure = ctr1.get("protect_structure", False)
            protect_windows = ctr1.get("protect_windows", False)

            if not protected_workbook:
                self.add_bullet_item(doc, "Result: VULNERABLE")
            else:
                self.add_bullet_item(doc, "Result: COMPLIANT")

            if not protect_structure:
                self.add_bullet_item(
                    doc,
                    "Critical finding: The workbook does not have structure protection enabled"
                )
                self.add_bullet_item(
                    doc,
                    "Impact: It allows any user to add, delete, rename or hide sheets without restrictions"
                )
                p = doc.add_paragraph()
                run = p.add_run("Evidence generated:")
                run.bold = True
                
                if ctr1.get("source") != "FALLBACK_JSON":
                    p = doc.add_paragraph()
                    run = p.add_run("Screenshot:")
                    run.bold = True
                    img_protections = self.filter_screenshot_protections(screenshots) or "N/A"
                    self.add_bullet_item(doc, f"Evidence: {img_protections}")
                    self.add_evidence_images(doc, img_protections)
                
                self.add_bullet_item(
                    doc,
                    "Analysis: workbook protected: "
                    f"{'Yes' if protected_workbook else 'No'}, "
                    "structure protected: "
                    f"{'Yes' if protect_structure else 'No'}, "
                    "windows protected: "
                    f"{'Yes' if protect_windows else 'No'}"
                )
            else:
                self.add_bullet_item(doc, "Finding: The workbook has protections enabled")

        self._add_test_recommendation(doc, context, "structure_protection")

        #WORKBOOK STRUCTURE (critical sheet protection)
        p = doc.add_paragraph()
        run = p.add_run("Sheet Protection")
        run.bold = True

        if "critical_sheets_protection" not in tests_sel:
            p = doc.add_paragraph()
            p.add_run("Result: ").bold = True
            p.add_run("Not applicable: test skipped for this analysis.")
        else:
            if ctr_exec and ctr_exec.get("com") and "mode_status" not in ctr_exec.get("com", {}):
                com_data = ctr_exec.get("com", {})
                prot_data = com_data.get("protections", {}).get("com", {})
                
                # Check whether COM reports an error
                if prot_data.get("error"):
                    # COM failed, use the deep fallback
                    if self._render_fallback_com_unavailable(doc, "critical_sheets_protection", context):
                        prot_data = self._build_fallback_protection_sheets_critical(context)
                
                total_sheets = prot_data.get("total_sheets", 0)
                protected_sheets = prot_data.get("protected_sheets", 0)

                p = doc.add_paragraph()
                run = p.add_run("Total sheets analyzed:")
                run.bold = True
                p.add_run(f"{total_sheets} sheets")

                p = doc.add_paragraph()
                run = p.add_run("Protected sheets:")
                run.bold = True
                p.add_run(f"{protected_sheets}/{total_sheets} ({round((protected_sheets/total_sheets)*100) if total_sheets else 0}%)")

                if total_sheets == protected_sheets:
                    p = doc.add_paragraph()
                    p.add_run("Result: ").bold = True
                    p.add_run("COMPLIANT")
                    doc.add_paragraph("All sheets are protected")
                else:
                    p = doc.add_paragraph()
                    p.add_run("Result: ").bold = True
                    p.add_run("VULNERABLE")

                    p = doc.add_paragraph()
                    run = p.add_run("Sheet detail of the file:")
                    run.bold = True

                    p = doc.add_paragraph()
                    run = p.add_run(f"Sheets WITHOUT Protection ({total_sheets - protected_sheets}):")
                    run.bold = True

                    unprotected_sheets = prot_data.get("sheet_details", context.get("unprotected_sheets", []))
                    tests = prot_data.get("modification_tests",[])
                   
                    if unprotected_sheets:
                        for item in unprotected_sheets:
                            # Get test data for this specific sheet
                            item2 = tests.get(item.get("name"), {}) if isinstance(tests, dict) else {}
                            
                            if item.get("critical"):
                                p = doc.add_paragraph()
                                p.add_run(f"{item.get('name')} (CRITICAL SHEET): ").bold = True
                                p.add_run("Unprotected, modifiable without restriction.")
                            else:
                                p = doc.add_paragraph()
                                p.add_run(f"{item.get('name')}").bold = True
                                p.add_run(" Unprotected, modifiable without restriction.")
                       
                            self.add_sub_bullet_item(
                                doc, f"Evidence: {item2.get('evidence',[])}")
                            self.add_evidence_images(doc, item2.get("evidence"))
                            
                            if "error" not in item2:
                                write_cell = item2.get("cell_test") or "A1"
                                if item2.get("mark_type") == "text":
                                    write_note = (
                                        "Write test: successful, fallback text written "
                                        f"in cell {write_cell}"
                                    )
                                else:
                                    write_note = (
                                        "Write test: successful, evidence image inserted "
                                        f"at cell {write_cell}"
                                    )
                                self.add_sub_bullet_item(doc, write_note)
                            else:
                                self.add_sub_bullet_item(
                                        doc, "Write test: Unable to write to the sheet")
                            visibility= item.get("visible")
                            if visibility == "VISIBLE":
                                self.add_sub_bullet_item(
                                    doc, "Visibility: Visible sheet"
                                )
                            elif visibility == "HIDDEN":
                                self.add_sub_bullet_item(
                                    doc, "Visibility: Hidden sheet"
                                )
                            elif visibility == "VERY_HIDDEN":
                                
                                self.add_sub_bullet_item(
                                    doc, "Visibility: Sheet only visible from VBA"
                                )
                            else:
                                 self.add_sub_bullet_item(
                                    doc, "Visibility: undetermined"
                                )
                            
                        p = doc.add_paragraph()
                        p.add_run("CRITICAL FINDING: ").bold = True
                        p.add_run(
                            f"{total_sheets - protected_sheets} sheet(s) of the file are "
                            "completely unprotected and can be modified without restriction."
                        )
            else:
                # Use the deep fallback when COM is not available
                if self._render_fallback_com_unavailable(doc, "critical_sheets_protection", context):
                    prot_data = self._build_fallback_protection_sheets_critical(context)
                else:
                    # Fallback to static
                    prot_data = (
                        ctr_exec.get("static", {})
                        .get("protections", {}).get("static", {})
                    )
                
                # If static has no data either, use the global context
                if not prot_data:
                    prot_data = context.get("protections", {})
                
                total_sheets = prot_data.get("total_sheets", 0)
                protected_sheets = prot_data.get("protected_sheets", 0)

                p = doc.add_paragraph()
                run = p.add_run("Total sheets analyzed:")
                run.bold = True
                p.add_run(f"{total_sheets} sheets")

                p = doc.add_paragraph()
                run = p.add_run("Protected sheets:")
                run.bold = True
                p.add_run(f"{protected_sheets}/{total_sheets} ({round((protected_sheets/total_sheets)*100) if total_sheets else 0}%)")

                p = doc.add_paragraph()
                p.add_run("Result: ").bold = True
                p.add_run("COMPLIANT" if total_sheets == protected_sheets else "VULNERABLE")

        self._add_test_recommendation(doc, context, "critical_sheets_protection")

        #VBA Project Protection (vba)
        p = doc.add_paragraph()
        run = p.add_run("VBA Project Protection\n\n")
        run.bold = True

        # Initialize ctr3_ej for all blocks
        ctr3_exec = {}

        if "vba" not in tests_sel:
            p = doc.add_paragraph()
            p.add_run("Result: ").bold = True
            p.add_run("Not applicable: test skipped for this analysis.")
        elif ctr_exec.get("com") and "mode_status" not in ctr_exec.get("com",{}):
            
            ctr3_exec = ctr_exec.get("com", {}).get("vba", {}).get("com", {})
            
            # Check whether COM reports an error
            if ctr3_exec.get("status") == "VBA_ACCESS_DISABLED" or ctr3_exec.get("error"):
                if self._render_fallback_com_unavailable(doc, "vba", context):
                    ctr3_exec = self._build_fallback_vba(context)
            
            if ctr3_exec.get("has_vba"):
                p = doc.add_paragraph()
                if ctr3_exec.get("accessible_code"):
                    p.add_run("Status: ").bold = True
                    p.add_run(f"VBA project is NOT protected.\n\n")  
                    p = doc.add_paragraph()
                    p.add_run("Total VBA modules: ").bold = True
                    p.add_run(f"{ctr3_exec.get('total_modules', 0)}\n\n") 
                    p = doc.add_paragraph()
                    p.add_run("Technical evidence of the modules with code:\n\n").bold = True 
                    
                    modules = ctr3_exec.get("modules", {})
                    
                    modules_con_code = [n for n, d in modules.items() if isinstance(d, dict) and d.get("lines", 0) > 0]
                    
                    for name, data in modules.items():
                       
                        if data.get("lines", 0) > 0:

                            doc.add_paragraph().add_run(f"MODULE: {name}").bold = True

                            summary = self.summary_code_vba(data.get("code"))
                            
                            p = doc.add_paragraph()
                            p.add_run("Number of lines: ").bold = True
                            p.add_run(f"{data.get('lines', 0)}")

                            if summary["signatures"]:
                                p = doc.add_paragraph()
                                p.add_run("Functions detected:").bold = True

                                for f in summary["signatures"]:
                                    self.add_bullet_item(doc, f)

                            if summary["code_lines"]:
                                p = doc.add_paragraph()
                                p.add_run("First lines of code:").bold = True

                                for l in summary["code_lines"]:
                                    doc.add_paragraph(l)

                            if summary["truncated"]:
                                doc.add_paragraph("...")
                    
                    if not modules_con_code:
                        p = doc.add_paragraph()
                        p.add_run("Note: ").bold = True
                        p.add_run(
                            f"{len(modules)} VBA module(s) were detected in the project, "
                            "but all of them have 0 lines of code (empty modules or DocumentModule type without implemented logic)."
                        )
                        self.add_bullet_item(doc, f"Modules detected: {', '.join(modules.keys())}")


                    
                else:
                    p = doc.add_paragraph()
                    p.add_run("Status: ").bold = True
                    p.add_run(f"VBA project is protected.")  
                    
                    p = doc.add_paragraph()
                    p.add_run("Result: ").bold = True
                    p.add_run(f"COMPLIANT")  
            else:
                p = doc.add_paragraph()
                p.add_run("Status: ").bold = True
                p.add_run(f"The file has no VBA")  
                
                p = doc.add_paragraph()
                p.add_run("Result: ").bold = True
                p.add_run(f"COMPLIANT")  
        else:
            # Use the deep fallback or static when COM is not available
            if self._render_fallback_com_unavailable(doc, "vba", context):
                ctr3_exec = self._build_fallback_vba(context)
            else:
                ctr3_exec = ctr_exec.get("static", {}).get("vba", {}).get("static", {})
            
            if ctr3_exec.get("has_vba") is None:
                p = doc.add_paragraph()
                p.add_run("Status: ").bold = True
                p.add_run("VBA code not accessible\n\n")
                p = doc.add_paragraph()
                p.add_run("Note: ").bold = True
                p.add_run(f"Detailed analysis of the VBA project requires COM mode")
                p = doc.add_paragraph()
                p.add_run("Result: ").bold = True
                p.add_run(f"COMPLIANT")
            elif not ctr3_exec.get("has_vba"):
                p = doc.add_paragraph()
                p.add_run("Status: ").bold = True
                p.add_run(f"The file has no VBA")  
                p = doc.add_paragraph()
                p.add_run("Result: ").bold = True
                p.add_run(f"COMPLIANT")
            else:
                # has_vba == True (with or without protection). Show static evidence.
                protected_project = ctr3_exec.get("protected_project")
                modules = ctr3_exec.get("modules", {}) or {}

                p = doc.add_paragraph()
                p.add_run("Status: ").bold = True
                if protected_project:
                    p.add_run("VBA project is protected (code extracted through static analysis).\n\n")
                else:
                    p.add_run("VBA project is NOT protected.\n\n")

                p = doc.add_paragraph()
                p.add_run("Total VBA modules: ").bold = True
                p.add_run(f"{len(modules)}\n\n")

                if modules:
                    p = doc.add_paragraph()
                    p.add_run("Technical evidence of the modules with code:\n\n").bold = True

                    for name, data in modules.items():
                        if not isinstance(data, dict):
                            continue
                        if data.get("lines", 0) <= 0:
                            continue

                        doc.add_paragraph().add_run(f"MODULE: {name}").bold = True

                        summary = self.summary_code_vba(data.get("code"))

                        p = doc.add_paragraph()
                        p.add_run("Number of lines: ").bold = True
                        p.add_run(f"{data.get('lines', 0)}")

                        if summary["signatures"]:
                            p = doc.add_paragraph()
                            p.add_run("Functions detected:").bold = True
                            for f in summary["signatures"]:
                                self.add_bullet_item(doc, f)

                        if summary["code_lines"]:
                            p = doc.add_paragraph()
                            p.add_run("First lines of code:").bold = True
                            for l in summary["code_lines"]:
                                doc.add_paragraph(l)

                        if summary["truncated"]:
                            doc.add_paragraph("...")

                p = doc.add_paragraph()
                p.add_run("Result: ").bold = True
                p.add_run("COMPLIANT" if protected_project else "VULNERABLE")
    
        self._add_test_recommendation(doc, context, "vba")

        #Absence of secrets in code (insecure_patterns).
        p = doc.add_paragraph()
        run = p.add_run("Absence of secrets in code\n\n")
        run.bold = True

        # Initialize ctr4_ej for all blocks
        ctr4_exec = {}

        if "insecure_patterns" not in tests_sel:
            p = doc.add_paragraph()
            p.add_run("Result: ").bold = True
            p.add_run("Not applicable: test skipped for this analysis.")
        elif ctr_exec.get("com") and "mode_status" not in ctr_exec.get("com",{}):
            ctr4_exec = ctr_exec.get("com", {}).get("insecure_patterns", {}).get("com", {})
            
            # Check whether COM reports an error
            if ctr4_exec.get("status") == "VBA_ACCESS_DISABLED" or ctr4_exec.get("error"):
                if self._render_fallback_com_unavailable(doc, "insecure_patterns", context):
                    ctr4_exec = self._build_fallback_patterns_insecure(context)
            
            if 'status' in ctr4_exec:
                p = doc.add_paragraph()
                p.add_run("Status: ").bold =True
                p.add_run(f"{ctr4_exec.get('status', 0)}")  
                p = doc.add_paragraph()
                p.add_run("Reason: ").bold =True
                p.add_run(f"{ctr4_exec.get('reason', 0)}")  
                p = doc.add_paragraph()
                p.add_run("Result: ").bold =True
                p.add_run(f"COMPLIANT")  
            else:
                summary= ctr4_exec.get("summary")
                if summary:
                    self.add_bullet_item(doc,
                                         f"{summary}")
                else:
                    findings= ctr4_exec.get('findings_by_module') or {}
                    p = doc.add_paragraph()
                    p.add_run("Modules analyzed: ").bold =True
                    p.add_run(f"{ctr4_exec.get('modules_analyzed', 0)}")
                
                    if findings:
                        for module_name, data in findings.items():

                            p = doc.add_paragraph()
                            p.add_run(f"Module name: {module_name}").bold =True
                            self.add_bullet_item(
                                doc,
                                f"Lines of code: {data.get('code_lines', 0)}"
                            )

                            categories = data.get("categories", {})

                            for category, findings in categories.items():
                                if not findings:
                                    continue  #skip empty categories

                                p = doc.add_paragraph()
                                p.add_run("Category: ").bold =True
                                p.add_run(f"{category.upper()}")
                                for h in findings:
                                    self.add_bullet_item(
                                        doc,
                                        f"Line {h.get('line')}"
                                    )
                                    self.add_bullet_item(
                                        doc,
                                        f"{h.get('description')}"
                                    )
                                    self.add_bullet_item(
                                        doc,
                                        f"Context: {h.get('context')}"
                                    )
        else:
            # Use the deep fallback or static when COM is not available
            if self._render_fallback_com_unavailable(doc, "insecure_patterns", context):
                ctr4_exec = self._build_fallback_patterns_insecure(context)
            else:
                ctr4_exec = ctr_exec.get("static", {}).get("insecure_patterns", {}).get("static", {})
            
            ctr3_static = ctr_exec.get("static", {}).get("vba", {}).get("static", {})
            if ctr4_exec.get("status"):
                p = doc.add_paragraph()
                p.add_run("Status: ").bold = True
                if ctr4_exec.get("status") == "NOT_APPLICABLE" and ctr3_static.get("has_vba") is False:
                    p.add_run("NOT_APPLICABLE")
                    p = doc.add_paragraph()
                    p.add_run("Reason: ").bold = True
                    p.add_run("The file has no VBA")
                    p = doc.add_paragraph()
                    p.add_run("Result: ").bold = True
                    p.add_run("NOT_APPLICABLE")
                else:
                    p.add_run("COMPLIANT")
                    p = doc.add_paragraph()
                    p.add_run("Reason: ").bold = True
                    p.add_run("VBA code not accessible for analysis")
                    p = doc.add_paragraph()
                    p.add_run("Result: ").bold = True
                    p.add_run("COMPLIANT")
            else:
                p = doc.add_paragraph()
                p.add_run("Result: ").bold = True
                p.add_run("NOT APPLICABLE - Static analysis available without a complete analysis") 
      
        self._add_test_recommendation(doc, context, "insecure_patterns")

        #External Connection Tests (external_connections)
        p = doc.add_paragraph()
        run = p.add_run("External Connection Tests\n")
        run.bold = True

        # Initialize ctr5_ej
        ctr5_exec = {}

        if "external_connections" not in tests_sel:
            p = doc.add_paragraph()
            p.add_run("Result: ").bold = True
            p.add_run("Not applicable: test skipped for this analysis.")
        elif ctr_exec.get("com") and "mode_status" not in ctr_exec.get("com",{}):
            ctr5_exec = (
                    ctr_exec
                    .get("com", {})
                    .get("external_connections", {})
                    .get("com", {})
                )
            self._render_connections_external(doc, ctr5_exec, vulnerable_result="VULNERABLE")

        else:
            # Use static data when COM is not available
            ctr5_exec = (
                    ctr_exec
                    .get("static", {})
                    .get("external_connections", {})
                    .get("static", {})
                )
            self._render_connections_external(doc, ctr5_exec, vulnerable_result="OBSERVATION")

        self._add_test_recommendation(doc, context, "external_connections")

        # ── formulas: Critical Formula Analysis ──────────────────────────────
        p = doc.add_paragraph()
        run = p.add_run("Critical Formula Analysis\n")
        run.bold = True


        if "formulas" not in tests_sel:
            p = doc.add_paragraph()
            p.add_run("Result: ").bold = True
            p.add_run("Not applicable: test skipped for this analysis.")
        else:
            # Get formula data from the analysis
            ctr7_data = {}
            com_formulas = ctr_exec.get("com", {}).get("formula_analysis", {}).get("com", {})
            static_formulas = ctr_exec.get("static", {}).get("formula_analysis", {}).get("static", {})

            com_ok = bool(com_formulas) and com_formulas.get("status") not in {"ERROR", "NOT_APPLICABLE"}
            static_ok = bool(static_formulas) and static_formulas.get("status") not in {"ERROR", "NOT_APPLICABLE"}

            if com_ok:
                ctr7_data = com_formulas
            elif static_ok:
                ctr7_data = static_formulas
            else:
                # If both come back as ERROR/NOT_APPLICABLE, prioritize the one with more context.
                ctr7_data = com_formulas or static_formulas or {}


            if ctr7_data.get("limitation"):
                p = doc.add_paragraph()
                p.add_run("Technical detail of the applied limitation: ").bold = True
                p.add_run(str(ctr7_data.get("limitation")))

            total_formulas_7 = ctr7_data.get("total_formulas", 0)
            p = doc.add_paragraph()
            p.add_run("Total formulas evaluated: ").bold = True
            p.add_run(str(total_formulas_7))

            # Collect all formulas findings with their severity
            all_007 = (
                [(h, "Critical") for h in context.get("critical_findings", []) if h.get("test") == "formulas"] +
                [(h, "Medium")   for h in context.get("medium_findings", [])   if h.get("test") == "formulas"] +
                [(h, "Low")    for h in context.get("low_findings", [])    if h.get("test") == "formulas"]
            )

            # Collect credential-type findings directly from the formula analysis
            _TYPES_CREDENTIAL = {"vba_source_cell", "credential_in_cell"}
            cred_findings = []

            # Look in formula_analysis.com.findings[] and formula_analysis.static.findings[]
            analysis_form_sources = [
                ctr_exec.get("com", {}).get("formula_analysis", {}).get("com", {}),
                ctr_exec.get("static", {}).get("formula_analysis", {}).get("static", {}),
            ]
            for analysis_form in analysis_form_sources:
                if not analysis_form:
                    continue
                for h in analysis_form.get("findings", []):
                    if h.get("type") in _TYPES_CREDENTIAL:
                        cred_findings.append(h)

            # Consolidate matches by sheet/cell to avoid duplicating findings
            # when the same cell appears as "read by VBA" and also as
            # "credential in cell". Merge fields so the final finding holds
            # all available information (vba_module, line_vba, etc.)
            credential_by_cell = {}
            priority_type = {"vba_source_cell": 2, "credential_in_cell": 1}
            for h in cred_findings:
                key = (h.get("sheet", ""), h.get("cell", ""))
                current = credential_by_cell.get(key)
                if current is None:
                    credential_by_cell[key] = dict(h)  # copy to allow merging
                    continue
                
                # Prioritize by type
                current_prio = priority_type.get(current.get("type", ""), 0)
                h_prio = priority_type.get(h.get("type", ""), 0)
                
                if h_prio > current_prio:
                    # h is the higher type: keep h as the base but merge fields from current
                    merged = dict(h)
                    for field in ["vba_module", "line_vba", "variable_vba"]:
                        if field not in merged and field in current:
                            merged[field] = current[field]
                    credential_by_cell[key] = merged
                else:
                    # current is higher or equal: keep current but add fields from h
                    for field in ["vba_module", "line_vba", "variable_vba"]:
                        if field not in current and field in h:
                            current[field] = h[field]
            cred_findings = list(credential_by_cell.values())

            status_7 = ctr7_data.get("status", "UNDETERMINED")
            p = doc.add_paragraph()
            p.add_run("Result: ").bold = True
            if not all_007 and not cred_findings:
                p.add_run("COMPLIANT – No findings were detected in formulas.")
            else:
                total_findings = len(all_007) + len(cred_findings)
                p.add_run(f"{status_7.replace('_', ' ')} – {total_findings} finding(s) detected")

                # Formulas findings bullets (excluding credentials for now)
                _TYPE_LABEL = {
                    "external_reference":    "External reference",
                    "inconsistency_formula": "Formula inconsistency",
                    "reference_dynamics":    "Dynamic reference",
                    "concealment_errors":   "Error concealment",
                    "formula_volatile":        "Volatile formula",
                    "error_formula":          "Formula error",
                    "vba_source_cell":       "Credential read by VBA",
                    "credential_in_cell":    "Credential in cell",
                }


                for h_item, sev_label in all_007:
                    type = h_item.get("type", "")
                    if type in _TYPES_CREDENTIAL:
                        continue  # Skip credentials here, they are processed below
                    desc_raw = h_item.get("description", "")

                    # Extract sheet/cell: prefer direct fields, otherwise parse the description
                    sheet_str  = h_item.get("sheet", "")
                    cell_str = h_item.get("cell", "")
                    desc_text = desc_raw
                    if not sheet_str and "!" in desc_raw and ": " in desc_raw:
                        ref_part, desc_text = desc_raw.split(": ", 1)
                        sheet_str, cell_str = ref_part.split("!", 1) if "!" in ref_part else (ref_part, "")

                    type_label  = _TYPE_LABEL.get(type, type or "Finding")
                    grouped    = h_item.get("_grouped", 1)
                    grouped_sfx = f" ({grouped} cells)" if grouped and grouped > 1 else ""

                    # Main bullet
                    bullet_txt = f"[{sev_label}] {type_label} | Sheet: {sheet_str} | Cell: {cell_str}{grouped_sfx}"
                    self.add_bullet_item(doc, bullet_txt, indent=2.5)

                    # Sub-bullet with description
                    if desc_text:
                        self.add_sub_bullet_item(doc, desc_text)

                # Process credential findings from the formula analysis
                for h_cred in cred_findings:
                    type = h_cred.get("type", "")
                    type_label = _TYPE_LABEL.get(type, type)
                    sheet = h_cred.get("sheet", "")
                    cell = h_cred.get("cell", "")
                    desc = h_cred.get("description", "")
                    vba_module = h_cred.get("vba_module")
                    line_vba = h_cred.get("line_vba")
                    
                    # Main bullet: [Critical] Credential in cell | Sheet: correo1 | Cell: A2
                    bullet_txt = f"[Critical] {type_label} | Sheet: {sheet} | Cell: {cell}"
                    self.add_bullet_item(doc, bullet_txt, indent=2.5)
                    
                    # Sub-bullet with description
                    if desc:
                        self.add_sub_bullet_item(doc, desc)
                    
                    # Extract the anonymized value from the description
                    import re
                    val_m = re.search(r"hardcoded credential:\s*([^\"|\n]+)", desc, re.IGNORECASE)
                    if val_m:
                        self.add_sub_bullet_item(doc, f"Value (anonymized): {val_m.group(1).strip()}")

                    # Show the originating module/line when the finding comes from a VBA read
                    if not vba_module:
                        mod_m = re.search(r"VBA\s+module\s+'([^']+)'", desc, re.IGNORECASE)
                        if mod_m:
                            vba_module = mod_m.group(1)
                    if line_vba is None:
                        lin_m = re.search(r"line\s+(\d+)", desc, re.IGNORECASE)
                        if lin_m:
                            line_vba = lin_m.group(1)

                    if vba_module:
                        self.add_sub_bullet_item(doc, f"Source module: {vba_module}")
                    if line_vba is not None and str(line_vba).strip() != "":
                        self.add_sub_bullet_item(doc, f"Source line: {line_vba}")
                    
                    self.add_sub_bullet_item(doc, f"Credential type: {type_label}")

        self._add_test_recommendation(doc, context, "formulas")

        #Protection bypass tests (ROBUSTNESS TEST)

        p = doc.add_paragraph()
        run = p.add_run("Protection bypass tests\n")
        run.bold = True


        
        bypass = context.get("bypass_tests", {})

        status = bypass.get("status")

        # Determine whether the only "success" was access with a known password (not a structural bypass)
        _METHODS_STRUCTURAL = {
            "XML_REMOVE_WORKBOOK_PASSWORD",
            "BINARY_REMOVE_XLSB_PASSWORD",
            "EXTRACT_CONTENT_NO_PASSWORD",
            "AGGRESSIVE_PROTECTION_STRIP",
            "TRIVIAL_PASSWORD_DECRYPT",
        }
        _pwd_bypass = bypass.get("opening_password", {})
        _sheets_bypass = bypass.get("sheets", {})
        _vba_bypass = bypass.get("vba", {})
        _method_pwd = _pwd_bypass.get("effective_method", "")
        _only_password_known = (
            status == "SUCCESSFUL_BYPASS"
            and _method_pwd == "KNOWN_PASSWORD_ACCESS"
            and not _sheets_bypass.get("successful_bypass")
            and not _vba_bypass.get("successful")
        )
        _bypass_structural = (
            status == "SUCCESSFUL_BYPASS"
            and (
                _method_pwd in _METHODS_STRUCTURAL
                or _sheets_bypass.get("successful_bypass")
                or _vba_bypass.get("successful")
            )
        )

        # CASE 1-A: Password found by dictionary, without a structural bypass
        if _only_password_known:
            bypass_status = "VULNERABLE"
            password_found = context.get("opening_protections", {}).get("password_found", "")

            p = doc.add_paragraph()
            p.add_run("Result: ").bold = True
            p.add_run("VULNERABLE")

            bypass_detail = (
                "The opening password was identified through a dictionary attack. "
                "A weak password that appears in commonly used dictionaries compromises the security of the file."
            )

            if password_found:
                self.add_bullet_item(
                    doc,
                    f"The opening password was found through a dictionary attack: '{password_found}'"
                )
                self.add_sub_bullet_item(
                    doc,
                    "A password that can be identified through a dictionary is considered weak."
                )
                self.add_sub_bullet_item(
                    doc,
                    "It is recommended to replace the password with a stronger one that does not appear in common dictionaries."
                )

        # CASE 1-B: SUCCESSFUL STRUCTURAL BYPASS
        elif _bypass_structural:
            bypass_status = "VULNERABLE"
            p = doc.add_paragraph()
            p.add_run("Result: ").bold = True
            p.add_run("VULNERABLE")

            bypass_detail = (
                "One or more protection mechanisms were bypassed "
                "during the authorized bypass tests."
            )

            file_mod = bypass.get("file_modified")
            if file_mod:
                self.add_bullet_item(
                    doc,
                    f"The file was modified during the bypass test: {file_mod}"
                )

            # Opening password bypass
            pwd = _pwd_bypass
            if pwd.get("successful_bypass") and _method_pwd in _METHODS_STRUCTURAL:
                self.add_bullet_item(
                    doc,
                    "Successful bypass of the opening password."
                )
                self.add_sub_bullet_item(
                    doc,
                    f"Effective method: {pwd.get('effective_method')}"
                )
                self.add_sub_bullet_item(
                    doc,
                    f"Unlocked file: {pwd.get('unlocked_file')}"
                )

            # Sheet bypass
            sheets = _sheets_bypass
            if sheets.get("successful_bypass"):
                self.add_bullet_item(
                    doc,
                    "Successful bypass of sheet protections."
                )
                self.add_sub_bullet_item(
                    doc,
                    f"Effective method: {sheets.get('effective_method')}"
                )
                self.add_sub_bullet_item(
                    doc,
                    f"Unprotected sheets: {', '.join(sheets.get('unprotected_sheets', []))}"
                )

            # VBA bypass
            vba = _vba_bypass
            if vba.get("successful"):
                self.add_bullet_item(
                    doc,
                    "Successful bypass of the VBA code protection."
                )
                self.add_sub_bullet_item(
                    doc,
                    f"Modified markers: {', '.join(vba.get('markers_modified', []))}"
                )

            # Evidence
            evidence = bypass.get("evidence", {}).get("bypass", {})
            screenshots = evidence.get("screenshots", [])

            if screenshots:
                p = doc.add_paragraph()
                p.add_run("Graphical evidence of the bypass:").bold = True

                for sc in screenshots:
                    self.add_bullet_item(doc, sc)
                    self.add_evidence_image(doc, sc)

        # CASE 2: NO CHANGES
        elif status == "WITHOUT_CHANGES":

            p = doc.add_paragraph()
            p.add_run("Result: ").bold = True
            p.add_run("COMPLIANT")

            bypass_status = "COMPLIANT"
            bypass_detail = (
                "It was not possible to bypass the protection mechanisms evaluated "
                "through the bypass tests."
            )

            self.add_bullet_item(
                doc,
                "It was not possible to bypass the protections through the bypass techniques evaluated."
            )

        # CASE 3: BYPASS NOT EXECUTED / ERROR
      
        else:
            p = doc.add_paragraph()
            p.add_run("Result: ").bold = True
            p.add_run("UNDETERMINED")
            
            bypass_status = "UNDETERMINED"
            bypass_detail = (
                "The bypass tests did not produce a conclusive result "
                "due to technical limitations."
            )


            self.add_bullet_item(
                doc,
                "It was not possible to run the bypass tests or no conclusive result was obtained."
            )

        #Total tests
        
        tests = context["tests"]

        opening_protection = context.get("opening_protections", {})
        file_con_password = bool(
            opening_protection.get("has_password") and opening_protection.get("encrypted")
        )

        total_tests = len(tests)

        satisfactory = 0
        unsatisfactory = 0

        for c in tests:
            status = c.get("status")

            if status == "COMPLIANT":
                satisfactory += 1
            elif status in ("VULNERABLE", "WARNING"):
                unsatisfactory += 1

        if file_con_password and unsatisfactory == 0:
            satisfactory = 1
            total_tests += 1
            tests = tests + [{
                "key": "password_opening",
                "name": "Opening password",
                "status": "COMPLIANT",
                "detail": "The file has an active opening password"
            }]
                
        if context.get("critical_findings"):
            self.add_findings_detailed(
                doc,
                context.get("critical_findings", []),
                "DETAILED CRITICAL FINDINGS"
            )

        if context.get("medium_findings"):
            self.add_findings_detailed(
                doc,
                context.get("medium_findings", []),
                "DETAILED MEDIUM FINDINGS"
            )

        if context.get("low_findings"):
            self.add_findings_detailed(
                doc,
                context.get("low_findings", []),
                "DETAILED LOW FINDINGS"
            )
        #Recommendations are now shown inside each test section


        doc.add_paragraph("_" * 85)


        # SAVE
        
        return doc.save(output_path)

    
    # ORCHESTRATOR
    
    def generate(self, json_path: Path, code: str ="CODE") -> Path:
        try:
            logger.debug(f"Starting report generation from JSON: {json_path}")
            context = self.parse_results(json_path)
            logger.debug(f"Context parsed successfully. Main keys: {list(context.keys())}")
            
            file_name = Path(context["file"]).stem
            output_dir = json_path.parent
            output_dir.mkdir(parents=True, exist_ok=True)
            context["code"] = code
            
            output_pdf = output_dir / f"{file_name}_report.pdf"
            logger.debug(f"Generating LaTeX/PDF report at: {output_pdf}")
            report_path = self.generate_docx(context, output_pdf)
            logger.debug("LaTeX/PDF report generated successfully")

            return report_path or output_pdf
        except Exception as e:
            error_msg = f"Error generating report from {json_path}:\n{traceback.format_exc()}"
            logger.error(error_msg)
            raise



# CLI
def main():
    parser = argparse.ArgumentParser(
        description="LaTeX/PDF Report Generator from a results JSON"
    )

    parser.add_argument(
        "json",
        help="Path to the results JSON file"
    )
    
    parser.add_argument(
    "--code",
    help="Deprecated: the report code is no longer shown in the report",
    default="CODE"
    )


    args = parser.parse_args()
    json_path = Path(args.json)

    if not json_path.exists():
        print(f"ERROR: JSON file not found: {json_path}")
        sys.exit(1)

    print("Generating LaTeX/PDF report…")
    print(f"  • JSON: {json_path}")

    generator = ReportComposer()


    code = args.code
    report_path = generator.generate(json_path, code=code)


    print("\nReport generated successfully:")
    print(f"  • REPORT → {report_path}")
    print("\nFolder:")
    print(f"  {json_path.parent}")


if __name__ == "__main__":
    main()

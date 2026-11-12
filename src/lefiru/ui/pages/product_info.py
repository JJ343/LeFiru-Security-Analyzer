"""About page: project overview, documentation sections and links."""

from __future__ import annotations

import html

from PyQt6.QtCore import QSize, Qt, QUrl, pyqtSignal
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QStackedWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from lefiru import __version__
from lefiru.ui.widgets.brand_mark import BrandMarkWidget
from lefiru.ui.widgets.icons import make_github_icon, make_icon

# Replace with the public repository URL once it is published.
GITHUB_URL = "https://github.com/"

_ACCENT = "#43e6c8"
_TEXT = "#b7d2ce"
_MUTED = "#7fa19d"
_RULE = "#1c2d34"

_RISK_COLORS = {
    "LOW": "#3ee08f",
    "MEDIUM": "#f2c94c",
    "HIGH": "#ff8a73",
    "CRITICAL": "#ff5c5c",
}


def _heading(text: str, *, top: int = 18) -> str:
    return (
        f'<p style="color:{_ACCENT}; font-size:11px; font-weight:700; '
        f'margin-top:{top}px; margin-bottom:6px;">{html.escape(text)}</p>'
    )


def _paragraph(text: str) -> str:
    return f'<p style="margin:4px 0; line-height:150%;">{text}</p>'


def _mono(text: str) -> str:
    return (
        f'<span style="font-family:Consolas; font-weight:700; '
        f'color:{_ACCENT};">{html.escape(text)}</span>'
    )


def _risk(level: str) -> str:
    color = _RISK_COLORS.get(level, _MUTED)
    return (
        f'<span style="font-size:10px; font-weight:700; color:{color};">'
        f"{level}</span>"
    )


def _table(
    headers: tuple[str, ...],
    rows: tuple[tuple[str, ...], ...],
    widths: tuple[str, ...],
) -> str:
    """Small rich-text table; QTextBrowser has no CSS grid."""
    head = "".join(
        f'<td width="{width}" style="font-size:10px; font-weight:700; '
        f'color:{_MUTED}; padding:0 10px 6px 0; '
        f'border-bottom:1px solid {_RULE};">{html.escape(header)}</td>'
        for header, width in zip(headers, widths)
    )
    body = []
    for row in rows:
        cells = "".join(
            f'<td style="padding:8px 10px 8px 0; vertical-align:top; '
            f'border-bottom:1px solid {_RULE};">{cell}</td>'
            for cell in row
        )
        body.append(f"<tr>{cells}</tr>")
    return (
        '<table width="100%" cellspacing="0" cellpadding="0">'
        f"<tr>{head}</tr>{''.join(body)}</table>"
    )


def _note(text: str) -> str:
    return (
        '<table width="100%" cellspacing="0" cellpadding="9" '
        'style="margin-top:16px;">'
        f'<tr><td bgcolor="#0f2b24" style="color:{_TEXT};">'
        f'<span style="color:{_ACCENT}; font-weight:700;">NOTE</span> '
        f"{text}</td></tr></table>"
    )


def _extensions_html() -> str:
    excel_rows = (
        (_mono(".XLSX"), "OOXML workbook without macros", _risk("LOW"), "Static · COM"),
        (_mono(".XLSM"), "OOXML workbook with VBA macros", _risk("HIGH"), "Static · COM"),
        (
            _mono(".XLSB"),
            "Binary workbook, may contain VBA",
            _risk("HIGH"),
            "Static (limited) · COM",
        ),
        (_mono(".XLTX"), "OOXML template without macros", _risk("LOW"), "Static · COM"),
        (_mono(".XLTM"), "OOXML template with VBA macros", _risk("HIGH"), "Static · COM"),
        (
            _mono(".XLAM"),
            "VBA add-in that usually exposes no sheets",
            _risk("HIGH"),
            "Static · COM",
        ),
    )
    python_rows = (
        (_mono(".PY"), "Readable source code", _risk("LOW"), "AST · evidence"),
        (_mono(".PYC"), "Compiled bytecode", _risk("MEDIUM"), "Recovery · heuristics"),
        (
            _mono(".EXE"),
            "Packaged Python: PyInstaller, cx_Freeze, py2exe, Nuitka",
            _risk("MEDIUM"),
            "Extraction · binary scan",
        ),
    )
    return (
        f'<div style="color:{_TEXT}; font-size:13px;">'
        + _paragraph(
            "LeFiru accepts nine formats. The extension decides the pipeline: "
            "Excel workbooks go through the Excel analyzers, Python assets "
            "through the code inspector."
        )
        + _heading("EXCEL WORKBOOKS", top=14)
        + _table(
            ("Format", "Description", "Risk", "Analyzers"),
            excel_rows,
            ("14%", "50%", "12%", "24%"),
        )
        + _heading("PYTHON FILES", top=22)
        + _table(
            ("Format", "Description", "Risk", "Analyzers"),
            python_rows,
            ("14%", "50%", "12%", "24%"),
        )
        + _heading("NOT ANALYZED YET", top=22)
        + _paragraph(
            f"{_mono('.XLS')}, {_mono('.XLT')} and {_mono('.XLA')} belong to the "
            "legacy binary family. There is no analyzer for them yet, so the run "
            "is rejected instead of producing an incomplete report. Any other "
            "extension fails the same way."
        )
        + _note(
            "Macros are never executed. VBA is read as data, and enabling it "
            "should be limited to .XLSM, .XLTM, .XLAM and .XLSB files with a "
            "justified need and formal controls."
        )
        + "</div>"
    )


def _excel_html() -> str:
    comparison = (
        (
            "Runs Microsoft Excel",
            "No — reads the package with openpyxl / pyxlsb",
            "Yes — local Excel via COM",
        ),
        ("Platform", "Windows, Linux, macOS", "Windows only"),
        ("Extra requirements", "None beyond Python", "Excel installed + pywin32"),
        (
            "Protection checks",
            "Structure and sheet flags, VBA protection signature",
            "Real write tests on every sheet",
        ),
        (
            "VBA access",
            "Extracts modules from vbaProject.bin when possible",
            "Exports modules as .bas and checks AccessVBOM",
        ),
        (
            "External connections",
            "Links, data connections, names and external formulas",
            "Same data, read from the live workbook",
        ),
        (
            "Visual evidence",
            "Rendered captures, no Excel window",
            "Screenshots of sheets, ranges and the VBE",
        ),
        ("Modifies the file", "Never", "Temporarily; restored from backups/"),
    )
    tests = (
        (
            "Protections",
            "Workbook structure and critical sheets that were left unprotected",
        ),
        (
            "VBA",
            "Project presence, protection and access to the object model",
        ),
        (
            "Insecure patterns",
            "Dangerous VBA patterns: shell, file I/O, obfuscation",
        ),
        (
            "Connections",
            "External links, data connections and external defined names",
        ),
        (
            "Formulas",
            "Critical-sheet formulas and the external references they carry",
        ),
        (
            "Opening password",
            "Structural bypass, metadata inference and local dictionary",
        ),
    )
    return (
        f'<div style="color:{_TEXT}; font-size:13px;">'
        + _paragraph(
            "Excel can be inspected in two ways. Static analysis never opens "
            "Excel; COM analysis drives a local Excel instance and reproduces "
            "what a user would see."
        )
        + _heading("STATIC VS COM", top=14)
        + _table(
            ("", "Static", "COM"),
            comparison,
            ("22%", "39%", "39%"),
        )
        + _heading("WHAT EACH TEST VALIDATES", top=22)
        + _table(("Test", "Scope"), tests, ("26%", "74%"))
        + _note(
            "The default mode <b>both</b> tries COM first and falls back to "
            "static analysis, so a machine without Excel (or a blocked "
            "workbook) never aborts the run."
        )
        + "</div>"
    )


def _python_html() -> str:
    checks = (
        (
            "Dynamic execution",
            "eval, exec, compile, __import__",
            _risk("CRITICAL"),
        ),
        (
            "Dangerous commands",
            "os.system, os.popen, subprocess.*",
            _risk("HIGH"),
        ),
        (
            "Deserialization",
            "pickle, yaml.load, marshal, shelve",
            _risk("CRITICAL"),
        ),
        (
            "Credentials",
            "Hardcoded passwords, tokens, API keys, high-entropy strings",
            _risk("HIGH"),
        ),
        (
            "Connections",
            "Hardcoded URLs, UNC paths, JDBC/ODBC, permissive CORS",
            _risk("MEDIUM"),
        ),
        (
            "Traceability",
            "Missing logging and error handling",
            _risk("LOW"),
        ),
    )
    return (
        f'<div style="color:{_TEXT}; font-size:13px;">'
        + _paragraph(
            "The Python pipeline reads source, bytecode and packaged "
            "executables, follows local imports and reports every finding "
            "with the line that caused it."
        )
        + _heading("SIX CHECKS", top=14)
        + _table(("Check", "What it looks for", "Severity"), checks, ("26%", "58%", "16%"))
        + _heading("WHAT IS INSPECTED", top=22)
        + _paragraph(
            f"{_mono('.py')} files are parsed as an AST and local imports are "
            f"followed. {_mono('.pyc')} files are recovered heuristically, and "
            f"{_mono('.exe')} files are unpacked (PyInstaller, cx_Freeze, "
            "py2exe, Nuitka), including companion folders, with a binary "
            "pattern scan as the last fallback."
        )
        + _paragraph(
            "Findings that come from source code get a PNG capture of the "
            "offending line. If "
            "decompilation is not possible on the running Python version, the "
            "analysis degrades to bytecode/binary inspection instead of "
            "aborting."
        )
        + _note(
            "Deliberate caps: 50 MB per binary scan, 300 extracted members "
            "and 800 companion files. A failure in one test never stops the "
            "batch; it is logged and the remaining checks continue."
        )
        + "</div>"
    )


SECTIONS = (
    ("Allowed extensions", "Nine supported formats and what is left out", _extensions_html),
    ("Excel analysis", "Static vs COM: what each mode can prove", _excel_html),
    ("Python analysis", "Six checks over source, bytecode and executables", _python_html),
)

MENU = [
    ("description", "Description", "Overview and version", "about"),
    ("extensions", "Allowed extensions", "Formats and risk", "reports"),
    ("excel", "Excel analysis", "Static vs COM", "analysis"),
    ("python", "Python analysis", "Scripts and binaries", "analysis"),
]


class AboutNavItem(QFrame):
    """Menu card with icon, title and subtitle."""

    activated = pyqtSignal(str)

    def __init__(self, key, title, subtitle, icon_name, parent=None):
        super().__init__(parent)
        self.key = key
        self._title = title
        self._subtitle = subtitle
        self._icon_name = icon_name

        self.setObjectName("about_nav_item")
        self.setProperty("active", False)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setAttribute(Qt.WidgetAttribute.WA_Hover, True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        row = QHBoxLayout(self)
        row.setContentsMargins(9, 7, 9, 7)
        row.setSpacing(10)

        self.badge = QLabel(self)
        self.badge.setObjectName("about_nav_icon")
        self.badge.setFixedSize(30, 30)
        self.badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.badge.setPixmap(make_icon(icon_name, "#8fb3b0", 17).pixmap(17, 17))
        row.addWidget(self.badge)

        text = QVBoxLayout()
        text.setSpacing(0)
        title_label = QLabel(title, self)
        title_label.setObjectName("about_nav_title")
        subtitle_label = QLabel(subtitle, self)
        subtitle_label.setObjectName("about_nav_subtitle")
        text.addWidget(title_label)
        text.addWidget(subtitle_label)
        row.addLayout(text, 1)

    def set_active(self, active: bool):
        active = bool(active)
        if self.property("active") == active:
            return
        self.setProperty("active", active)
        color = "#43e6c8" if active else "#8fb3b0"
        self.badge.setPixmap(
            make_icon(self._icon_name, color, 17).pixmap(17, 17)
        )
        style = self.style()
        style.unpolish(self)
        style.polish(self)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and self.rect().contains(
            event.position().toPoint()
        ):
            self.activated.emit(self.key)
        super().mouseReleaseEvent(event)


class ProductInfoPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("about_page")

        self._current = "description"
        self.nav_items: dict[str, AboutNavItem] = {}

        root = QVBoxLayout(self)
        root.setContentsMargins(32, 24, 32, 24)
        root.setSpacing(16)

        root.addLayout(self._build_header())

        columns = QHBoxLayout()
        columns.setSpacing(18)
        root.addLayout(columns, 1)
        columns.addWidget(self._build_menu())
        columns.addWidget(self._build_content(), 1)

        footer = QLabel("© Controlled use · Apache-2.0")
        footer.setObjectName("about_footer")
        root.addWidget(footer)

        self.show_content("description")

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def _build_header(self) -> QHBoxLayout:
        header = QHBoxLayout()
        header.setSpacing(10)
        heading = QVBoxLayout()
        heading.setSpacing(2)
        title = QLabel("About LeFiru")
        title.setObjectName("page_title")
        subtitle = QLabel("Security analysis for Excel workbooks and Python code")
        subtitle.setObjectName("page_subtitle")
        heading.addWidget(title)
        heading.addWidget(subtitle)
        header.addLayout(heading, 1)

        self.version_chip = QLabel(f"v{__version__}")
        self.version_chip.setObjectName("about_version")
        header.addWidget(self.version_chip, 0, Qt.AlignmentFlag.AlignVCenter)

        self.github_button = QPushButton()
        self.github_button.setObjectName("github_button")
        self.github_button.setIcon(make_github_icon("#05201c", 20))
        self.github_button.setIconSize(QSize(20, 20))
        self.github_button.setFixedSize(38, 38)
        self.github_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.github_button.setToolTip("Open the project page on GitHub")
        self.github_button.setAccessibleName("Open the project page on GitHub")
        self.github_button.clicked.connect(self._open_github)
        header.addWidget(self.github_button, 0, Qt.AlignmentFlag.AlignVCenter)
        return header

    def _build_menu(self) -> QWidget:
        card = QFrame()
        card.setObjectName("about_menu")
        card.setFixedWidth(258)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 14, 12, 14)
        layout.setSpacing(3)

        label = QLabel("CONTENTS")
        label.setObjectName("about_menu_label")
        layout.addWidget(label)
        layout.addSpacing(6)

        for key, title, subtitle, icon in MENU:
            item = AboutNavItem(key, title, subtitle, icon, card)
            item.activated.connect(self.show_content)
            self.nav_items[key] = item
            layout.addWidget(item)
        layout.addStretch()
        return card

    def _build_content(self) -> QWidget:
        card = QFrame()
        card.setObjectName("about_content_card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(10)

        self.section_title = QLabel("Description")
        self.section_title.setObjectName("about_section_title")
        self.section_hint = QLabel("What the tool does and which version you have")
        self.section_hint.setObjectName("about_section_hint")
        layout.addWidget(self.section_title)
        layout.addWidget(self.section_hint)

        self.stacked = QStackedWidget()
        self.stacked.setObjectName("about_stack")
        self.brand_mark = BrandMarkWidget()
        self.brand_mark.setFixedHeight(230)
        self.stacked.addWidget(self._build_description())
        self.stacked.addWidget(self._build_text_view())
        layout.addWidget(self.stacked, 1)
        return card

    def _build_description(self) -> QWidget:
        page = QWidget()
        page.setObjectName("description_page")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        layout.addWidget(self.brand_mark)

        name = QLabel("LeFiru Security Analyzer")
        name.setObjectName("about_hero_title")
        name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(name)

        tagline = QLabel(
            "Find security and traceability risks before they reach production."
        )
        tagline.setObjectName("about_hero_tagline")
        tagline.setWordWrap(True)
        tagline.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(tagline)
        layout.addSpacing(6)

        facts = QHBoxLayout()
        facts.setSpacing(8)
        facts.addStretch()
        for text in ("Excel · VBA", "Python · Bytecode", "JSON + PDF reports"):
            chip = QLabel(text)
            chip.setObjectName("about_fact")
            facts.addWidget(chip)
        facts.addStretch()
        layout.addLayout(facts)

        description = QLabel(
            "LeFiru inspects workbooks and Python assets, verifies their "
            "protections and code patterns, and produces traceable evidence "
            "with a compliance status in JSON and a LaTeX/PDF report."
        )
        description.setObjectName("about_description")
        description.setWordWrap(True)
        description.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(description)
        layout.addStretch()
        return page

    def _build_text_view(self) -> QTextBrowser:
        self.text_view = QTextBrowser()
        self.text_view.setObjectName("about_text")
        self.text_view.setOpenExternalLinks(True)
        self.text_view.setFrameShape(QFrame.Shape.NoFrame)
        return self.text_view

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------
    def show_content(self, key):
        if isinstance(key, int):
            key = MENU[key][0] if 0 <= key < len(MENU) else "description"

        self._current = key
        for name, item in self.nav_items.items():
            item.set_active(name == key)

        if key == "description":
            self.section_title.setText("Description")
            self.section_hint.setText(
                "What the tool does and which version you have"
            )
            self.stacked.setCurrentIndex(0)
            return

        index = next(
            (i for i, (name, *_rest) in enumerate(MENU) if name == key), 0
        )
        if index <= 0:
            self.show_content("description")
            return
        title, hint, build = SECTIONS[index - 1]
        self.section_title.setText(title)
        self.section_hint.setText(hint)
        self.text_view.setHtml(build())
        self.text_view.verticalScrollBar().setValue(0)
        self.stacked.setCurrentIndex(1)

    def back_menu(self):
        self.show_content("description")

    def set_dark_mode(self, dark: bool) -> None:
        """Keep the brand animation in sync with the application theme."""
        self.brand_mark.set_dark_mode(dark)

    def _open_github(self):
        QDesktopServices.openUrl(QUrl(GITHUB_URL))

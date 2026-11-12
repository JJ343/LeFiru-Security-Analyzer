"""Reports browser: find analyses by name and open their folders.

The page has two levels:

* output families (``results/excel``, ``results/python``), and
* the analyses inside the selected family.

Every row is a card with an icon, a title and a small status line. The search
box filters the current list by name and the header buttons refresh the view or
open the folder in the system file explorer.
"""

from __future__ import annotations

from functools import partial
from pathlib import Path

from PyQt6.QtCore import QSize, Qt, QUrl, pyqtSignal
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from lefiru.paths import ensure_output_root
from lefiru.ui.widgets.eliding import ElidingLabel
from lefiru.ui.widgets.icons import make_icon


class ReportRow(QFrame):
    """Clickable card with an icon badge, a name and a status subtitle."""

    activated = pyqtSignal(str)

    def __init__(
        self,
        key: str,
        title: str,
        subtitle: str,
        icon_name: str = "folder",
        accent: str = "#43e6c8",
        parent=None,
    ):
        super().__init__(parent)
        self.key = key
        self._title = title
        self._subtitle = subtitle

        self.setObjectName("report_row")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setAttribute(Qt.WidgetAttribute.WA_Hover, True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip(f"{title}\n{subtitle}")

        row = QHBoxLayout(self)
        row.setContentsMargins(12, 10, 12, 10)
        row.setSpacing(12)

        badge = QLabel(self)
        badge.setObjectName("report_icon")
        badge.setFixedSize(36, 36)
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setPixmap(make_icon(icon_name, accent, 18).pixmap(18, 18))
        row.addWidget(badge)

        text = QVBoxLayout()
        text.setSpacing(1)
        title_label = ElidingLabel(title, self)
        title_label.setObjectName("report_title")
        subtitle_label = ElidingLabel(subtitle, self)
        subtitle_label.setObjectName("report_subtitle")
        text.addWidget(title_label)
        text.addWidget(subtitle_label)
        row.addLayout(text, 1)

        chevron = QLabel(self)
        chevron.setFixedSize(18, 18)
        chevron.setPixmap(make_icon("chevron", "#4f726e", 16).pixmap(16, 16))
        row.addWidget(chevron)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and self.rect().contains(
            event.position().toPoint()
        ):
            self.activated.emit(self.key)
        super().mouseReleaseEvent(event)


class ReportsPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("reports_page")

        self.outputs = self._resolve_directory_outputs()
        self._entries: list[dict] = []
        self._rows: list[ReportRow] = []
        self._view = "outputs"
        self._current_output: Path | None = None

        root = QVBoxLayout(self)
        root.setContentsMargins(32, 24, 32, 24)
        root.setSpacing(16)

        # ── Header ────────────────────────────────────────────────────
        header = QHBoxLayout()
        header.setSpacing(10)
        heading = QVBoxLayout()
        heading.setSpacing(2)
        title = QLabel("Reports and evidence")
        title.setObjectName("page_title")
        subtitle = ElidingLabel("Search and open your saved analyses")
        subtitle.setObjectName("page_subtitle")
        heading.addWidget(title)
        heading.addWidget(subtitle)
        header.addLayout(heading, 1)

        self.back_btn = self._ghost_button("Back", "back")
        self.back_btn.clicked.connect(self.load_analysis)
        self.back_btn.setVisible(False)
        header.addWidget(self.back_btn)

        self.refresh_btn = QPushButton()
        self.refresh_btn.setObjectName("report_icon_button")
        self.refresh_btn.setIcon(make_icon("refresh", "#8fb3b0", 18))
        self.refresh_btn.setIconSize(QSize(18, 18))
        self.refresh_btn.setFixedSize(38, 38)
        self.refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.refresh_btn.setToolTip("Refresh the list")
        self.refresh_btn.clicked.connect(self._refresh_view)
        header.addWidget(self.refresh_btn)

        self.open_folder_btn = self._ghost_button("Open folder", "folder")
        self.open_folder_btn.setToolTip("Open the current folder in the file explorer")
        self.open_folder_btn.clicked.connect(self._open_current_folder)
        header.addWidget(self.open_folder_btn)
        root.addLayout(header)

        # ── Search ────────────────────────────────────────────────────
        search_row = QHBoxLayout()
        search_row.setSpacing(12)
        self.search = QLineEdit()
        self.search.setObjectName("report_search")
        self.search.setPlaceholderText("Search by name")
        self.search.setClearButtonEnabled(True)
        self.search.setFixedHeight(40)
        self.search.addAction(
            make_icon("search", "#6d918d", 17),
            QLineEdit.ActionPosition.LeadingPosition,
        )
        self.search.textChanged.connect(self._apply_filter)
        search_row.addWidget(self.search, 1)

        self.count_label = QLabel("")
        self.count_label.setObjectName("report_count")
        search_row.addWidget(self.count_label)
        root.addLayout(search_row)

        # ── List ──────────────────────────────────────────────────────
        self.scroll = QScrollArea()
        self.scroll.setObjectName("report_scroll")
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )

        self.list_widget = QWidget()
        self.list_widget.setObjectName("report_list")
        self.list_layout = QVBoxLayout(self.list_widget)
        self.list_layout.setContentsMargins(0, 2, 6, 2)
        self.list_layout.setSpacing(8)

        self.empty_label = QLabel("")
        self.empty_label.setObjectName("report_empty")
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_label.setWordWrap(True)
        self.empty_label.setVisible(False)
        self.list_layout.addWidget(self.empty_label)
        self.list_layout.addStretch()

        self.scroll.setWidget(self.list_widget)
        root.addWidget(self.scroll, 1)

        note = QLabel("Rows open the folder with the system's default application.")
        note.setObjectName("report_note")
        root.addWidget(note)

    # ------------------------------------------------------------------
    # Builders
    # ------------------------------------------------------------------
    def _ghost_button(self, text: str, icon_name: str) -> QPushButton:
        button = QPushButton(text)
        button.setObjectName("report_ghost")
        button.setIcon(make_icon(icon_name, "#8fb3b0", 17))
        button.setIconSize(QSize(17, 17))
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        return button

    def _resolve_directory_outputs(self) -> Path:
        """Get the output folder (`results/`, see lefiru.paths.output_root)."""
        return ensure_output_root()

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------
    def load_analysis(self):
        """Show the output families inside ``results/``."""
        if not self.outputs.exists():
            QMessageBox.warning(
                self,
                "Folder not found",
                "The reports folder does not exist yet.",
            )
            return

        self._view = "outputs"
        self._current_output = None
        self.back_btn.setVisible(False)
        self._reset_search("Search folders by name")

        folders = self._subfolders(self.outputs)
        entries = [
            {
                "name": folder.name,
                "subtitle": self._analysis_count(folder),
                "icon": "folder",
                "accent": "#43e6c8",
                "action": partial(self.show_analysis_of_output, folder),
            }
            for folder in folders
        ]
        self._render(
            entries,
            "No analysis folders yet.\nRun an analysis and its results will "
            "show up here.",
        )

    def show_analysis_of_output(self, output_folder: Path):
        """Show the analyses inside the chosen output family."""
        if not output_folder.exists() or not output_folder.is_dir():
            QMessageBox.warning(
                self,
                "Folder not available",
                f"The folder {output_folder.name} no longer exists.",
            )
            self.load_analysis()
            return

        self._view = "analysis"
        self._current_output = output_folder
        self.back_btn.setVisible(True)
        self._reset_search("Search analyses by name")

        folders = self._subfolders(output_folder)
        entries = [
            {
                "name": folder.name,
                "subtitle": self._report_status(folder),
                "icon": "reports",
                "accent": "#9a8cff",
                "action": partial(self.open_analysis, folder),
            }
            for folder in folders
        ]
        self._render(
            entries,
            f"{output_folder.name} has no analyses yet.",
        )

    # ------------------------------------------------------------------
    # Rendering and search
    # ------------------------------------------------------------------
    def _render(self, entries: list[dict], empty_text: str):
        self._entries = entries
        self._empty_text = empty_text
        self._apply_filter(self.search.text())

    def _apply_filter(self, text: str):
        query = (text or "").strip().lower()
        matched = [entry for entry in self._entries if query in entry["name"].lower()]

        self._clear_rows()
        for entry in matched:
            row = ReportRow(
                entry["name"],
                entry["name"],
                entry["subtitle"],
                entry["icon"],
                entry["accent"],
            )
            row.activated.connect(lambda _key, action=entry["action"]: action())
            self.list_layout.insertWidget(self.list_layout.count() - 1, row)
            self._rows.append(row)

        if query:
            self.count_label.setText(
                f"{len(matched)} of {len(self._entries)}"
                if self._entries
                else "0 results"
            )
        else:
            total = len(self._entries)
            self.count_label.setText(f"{total} item{'' if total == 1 else 's'}")

        if matched:
            self.empty_label.setVisible(False)
        else:
            self.empty_label.setText(
                f"No results for “{text.strip()}”." if query else self._empty_text
            )
            self.empty_label.setVisible(True)

    def _clear_rows(self):
        for row in self._rows:
            self.list_layout.removeWidget(row)
            row.hide()
            row.deleteLater()
        self._rows.clear()

    def _reset_search(self, placeholder: str):
        self.search.blockSignals(True)
        self.search.clear()
        self.search.blockSignals(False)
        self.search.setPlaceholderText(placeholder)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _subfolders(self, folder: Path) -> list[Path]:
        return sorted(
            [p for p in folder.iterdir() if p.is_dir()],
            key=lambda p: p.name.lower(),
        )

    def _analysis_count(self, folder: Path) -> str:
        count = len(self._subfolders(folder))
        if count == 0:
            return "No analyses yet"
        return f"{count} analys{'is' if count == 1 else 'es'}"

    def _report_status(self, folder: Path) -> str:
        reports = folder / "reports"
        if not reports.is_dir():
            return "No reports folder"
        has_json = any(reports.glob("*.json"))
        has_pdf = any(reports.glob("*.pdf"))
        parts = [
            name
            for name, present in (("JSON", has_json), ("PDF", has_pdf))
            if present
        ]
        if not parts:
            return "No report generated yet"
        return f"{' · '.join(parts)} available"

    def _refresh_view(self):
        if self._view == "analysis" and self._current_output is not None:
            self.show_analysis_of_output(self._current_output)
        else:
            self.load_analysis()

    def _open_current_folder(self):
        target = self._current_output or self.outputs
        if not target.exists():
            QMessageBox.warning(
                self,
                "Folder not available",
                "The output folder no longer exists.",
            )
            self._refresh_view()
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(target.resolve())))

    def open_analysis(self, folder: Path):
        if not folder.exists() or not folder.is_dir():
            QMessageBox.warning(
                self,
                "Folder not available",
                f"The folder {folder.name} no longer exists.",
            )
            self.load_analysis()
            return

        QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder.resolve())))

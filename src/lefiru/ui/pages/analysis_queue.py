"""Live analysis queue dialog.

Shows one card per file with its status, stage and progress. Cards update in
place while the analysis runs, and queued or running files can be skipped or
stopped from the card button or its context menu.
"""

from __future__ import annotations

from PyQt6.QtCore import QSize, Qt
from PyQt6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMenu,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from lefiru.ui.widgets.eliding import ElidingLabel
from lefiru.ui.widgets.icons import make_icon


STATUS_STYLES = {
    "EN_QUEUE": ("Queued", "queued", "#8fb3b0", "queue"),
    "ANALYZING": ("Running", "running", "#43e6c8", "analysis"),
    "SKIPPED": ("Skipped", "muted", "#c9a86a", "back"),
    "ERROR": ("Error", "error", "#ff8f8f", "about"),
}

COMPLIANCE_STYLES = {
    "COMPLIANT": ("Compliant", "ok"),
    "COMPLIANT_WITH_OBSERVATIONS": ("Observations", "warn"),
    "VULNERABLE": ("Vulnerable", "error"),
    "NOT_APPLICABLE": ("N/A", "muted"),
    "NOT_EXECUTED": ("Not executed", "muted"),
    "REQUIRES_REVIEW": ("Review", "warn"),
    "PROTECTED_WITH_PASSWORD": ("Protected", "warn"),
}


class QueueRow(QFrame):
    """Card for one file: icon, name, stage, status chip and progress."""

    def __init__(self, index: int, analysis_page, parent=None):
        super().__init__(parent)
        self.index = index
        self.analysis_page = analysis_page

        self.setObjectName("queue_row")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(8)

        top = QHBoxLayout()
        top.setSpacing(11)

        self.badge = QLabel(self)
        self.badge.setObjectName("queue_row_icon")
        self.badge.setFixedSize(34, 34)
        self.badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        top.addWidget(self.badge)

        text = QVBoxLayout()
        text.setSpacing(1)
        self.name = ElidingLabel("", self)
        self.name.setObjectName("queue_file_name")
        self.stage = ElidingLabel("", self)
        self.stage.setObjectName("queue_file_stage")
        text.addWidget(self.name)
        text.addWidget(self.stage)
        top.addLayout(text, 1)

        self.chip = QLabel(self)
        self.chip.setObjectName("queue_chip")
        self.chip.setProperty("state", "queued")
        top.addWidget(self.chip, 0, Qt.AlignmentFlag.AlignTop)

        self.action = QPushButton(self)
        self.action.setObjectName("queue_action")
        self.action.setCursor(Qt.CursorShape.PointingHandCursor)
        self.action.clicked.connect(self._run_action)
        top.addWidget(self.action, 0, Qt.AlignmentFlag.AlignTop)

        layout.addLayout(top)

        self.bar = QProgressBar(self)
        self.bar.setObjectName("queue_row_bar")
        self.bar.setRange(0, 100)
        self.bar.setValue(0)
        self.bar.setTextVisible(False)
        layout.addWidget(self.bar)

        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._context_menu)
        self._status = "EN_QUEUE"

    # ------------------------------------------------------------------
    def update_state(self, item: dict):
        status = item.get("status", "EN_QUEUE")
        self._status = status
        self.name.setText(item.get("name", ""))
        self.stage.setText(item.get("detail", ""))
        self.setToolTip(f"{item.get('name', '')}\n{item.get('detail', '')}")

        if status == "COMPLETED":
            text, state = COMPLIANCE_STYLES.get(
                item.get("compliance", ""), ("Done", "ok")
            )
            color = {"ok": "#7ef0d0", "warn": "#ffcf7d", "error": "#ff8f8f"}.get(
                state, "#8fb3b0"
            )
            icon_name = "reports"
        else:
            text, state, color, icon_name = STATUS_STYLES.get(
                status, ("Queued", "queued", "#8fb3b0", "queue")
            )

        percentage = int(item.get("progress", 0) or 0)
        if status == "ANALYZING":
            text = f"{percentage}%"
        self.chip.setText(text)
        self._set_chip_state(state)
        self.badge.setPixmap(make_icon(icon_name, color, 18).pixmap(18, 18))

        if status in ("COMPLETED", "SKIPPED", "ERROR"):
            self.bar.setValue(100)
            self.bar.setProperty("state", "done")
        else:
            self.bar.setValue(max(0, min(100, percentage)))
            self.bar.setProperty("state", "running" if status == "ANALYZING" else "idle")
        self._repolish(self.bar)

        if status == "EN_QUEUE":
            self.action.setText("Skip")
            self.action.setVisible(True)
        elif status == "ANALYZING":
            self.action.setText("Stop")
            self.action.setVisible(True)
        else:
            self.action.setVisible(False)

    def _set_chip_state(self, state: str):
        self.chip.setProperty("state", state)
        self._repolish(self.chip)

    @staticmethod
    def _repolish(widget):
        style = widget.style()
        style.unpolish(widget)
        style.polish(widget)

    # ------------------------------------------------------------------
    def _run_action(self):
        self.analysis_page.request_jump(self.index)

    def _context_menu(self, pos):
        menu = QMenu(self)
        if self._status == "ANALYZING":
            action = menu.addAction("Stop this analysis")
        else:
            action = menu.addAction("Skip this analysis")
        action.setEnabled(self._status in ("EN_QUEUE", "ANALYZING"))
        if menu.exec(self.mapToGlobal(pos)) == action:
            self.analysis_page.request_jump(self.index)


class AnalysisQueueDialog(QDialog):
    """Popup with the files being analyzed by the unified analysis page."""

    def __init__(self, analysis_page, parent=None):
        super().__init__(parent)
        self.analysis_page = analysis_page
        self._rows: dict[int, QueueRow] = {}

        self.setObjectName("analysis_queue")
        self.setWindowTitle("Analysis queue")
        self.setMinimumSize(640, 520)
        self.resize(680, 560)

        root = QVBoxLayout(self)
        root.setContentsMargins(22, 20, 22, 18)
        root.setSpacing(16)

        root.addLayout(self._build_header())

        # ── File cards ────────────────────────────────────────────────
        self.scroll = QScrollArea()
        self.scroll.setObjectName("queue_scroll")
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )

        self.list_widget = QWidget()
        self.list_widget.setObjectName("queue_list")
        self.rows_layout = QVBoxLayout(self.list_widget)
        self.rows_layout.setContentsMargins(0, 0, 6, 0)
        self.rows_layout.setSpacing(8)

        self.empty_label = QLabel(
            "No analyses in progress.\nStart a run from the Analyze page and "
            "every file will show up here."
        )
        self.empty_label.setObjectName("queue_empty")
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_label.setWordWrap(True)
        self.rows_layout.addWidget(self.empty_label)
        self.rows_layout.addStretch()

        self.scroll.setWidget(self.list_widget)
        root.addWidget(self.scroll, 1)

        # ── Overall progress ──────────────────────────────────────────
        progress_card = QFrame()
        progress_card.setObjectName("queue_progress_card")
        progress_layout = QVBoxLayout(progress_card)
        progress_layout.setContentsMargins(14, 12, 14, 12)
        progress_layout.setSpacing(8)

        progress_top = QHBoxLayout()
        progress_label = QLabel("Overall progress")
        progress_label.setObjectName("queue_progress_label")
        self.progress_text = QLabel("0 of 0 files")
        self.progress_text.setObjectName("queue_progress_text")
        progress_top.addWidget(progress_label)
        progress_top.addStretch()
        progress_top.addWidget(self.progress_text)
        progress_layout.addLayout(progress_top)

        self.global_bar = QProgressBar()
        self.global_bar.setObjectName("queue_bar")
        self.global_bar.setRange(0, 1)
        self.global_bar.setValue(0)
        self.global_bar.setTextVisible(False)
        progress_layout.addWidget(self.global_bar)
        root.addWidget(progress_card)

        # ── Footer ────────────────────────────────────────────────────
        footer = QHBoxLayout()
        footer.setSpacing(10)
        note = QLabel("Right-click a file to skip it or stop it.")
        note.setObjectName("queue_note")
        footer.addWidget(note)
        footer.addStretch()
        self.close_button = QPushButton("Close")
        self.close_button.setObjectName("queue_close")
        self.close_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.close_button.clicked.connect(self.close)
        footer.addWidget(self.close_button)
        root.addLayout(footer)

        self.analysis_page.queue_updated.connect(self.refresh)
        self.refresh()

    # ------------------------------------------------------------------
    # Header
    # ------------------------------------------------------------------
    def _build_header(self) -> QHBoxLayout:
        header = QHBoxLayout()
        header.setSpacing(12)

        icon = QLabel()
        icon.setObjectName("queue_header_icon")
        icon.setFixedSize(40, 40)
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon.setPixmap(make_icon("queue", "#43e6c8", 20).pixmap(20, 20))
        header.addWidget(icon)

        heading = QVBoxLayout()
        heading.setSpacing(1)
        title = QLabel("Analysis queue")
        title.setObjectName("queue_title")
        self.summary = ElidingLabel("No analyses in progress")
        self.summary.setObjectName("queue_subtitle")
        heading.addWidget(title)
        heading.addWidget(self.summary)
        header.addLayout(heading, 1)

        self.state_chip = QLabel("Idle")
        self.state_chip.setObjectName("queue_chip")
        self.state_chip.setProperty("state", "idle")
        header.addWidget(self.state_chip, 0, Qt.AlignmentFlag.AlignVCenter)

        self.button_refresh = QPushButton()
        self.button_refresh.setObjectName("queue_icon_button")
        self.button_refresh.setIcon(make_icon("refresh", "#8fb3b0", 18))
        self.button_refresh.setIconSize(QSize(18, 18))
        self.button_refresh.setFixedSize(36, 36)
        self.button_refresh.setCursor(Qt.CursorShape.PointingHandCursor)
        self.button_refresh.setToolTip("Refresh the queue")
        self.button_refresh.clicked.connect(self.refresh)
        header.addWidget(self.button_refresh, 0, Qt.AlignmentFlag.AlignVCenter)
        return header

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------
    def refresh(self):
        status = list(getattr(self.analysis_page, "status_queue", []))
        self._sync_rows(status)

        completed = sum(
            1
            for item in status
            if item.get("status") in ("COMPLETED", "ERROR", "SKIPPED")
        )
        total = len(status)
        self.global_bar.setMaximum(max(total, 1))
        self.global_bar.setValue(completed)
        self.progress_text.setText(f"{completed} of {total} files")

        if total:
            self.summary.setText(
                f"{self._current_file(status)} · {completed} of {total} finished"
            )
        else:
            self.summary.setText("No analyses in progress")

        self._update_state_chip(status)

    @staticmethod
    def _current_file(status: list[dict]) -> str:
        for item in status:
            if item.get("status") == "ANALYZING":
                return item.get("name", "")
        return "Queue ready"

    def _update_state_chip(self, status: list[dict]):
        if not status:
            text, state = "Idle", "idle"
        elif any(item.get("status") == "ANALYZING" for item in status):
            text, state = "Running", "running"
        elif all(
            item.get("status") in ("COMPLETED", "ERROR", "SKIPPED") for item in status
        ):
            text, state = "Finished", "ok"
        else:
            text, state = "Queued", "queued"
        self.state_chip.setText(text)
        self.state_chip.setProperty("state", state)
        QueueRow._repolish(self.state_chip)

    # ------------------------------------------------------------------
    # Rows
    # ------------------------------------------------------------------
    def _sync_rows(self, status: list[dict]):
        if len(status) != len(self._rows):
            self._rebuild_rows(status)
            return
        for index, item in enumerate(status):
            self._rows[index].update_state(item)

    def _rebuild_rows(self, status: list[dict]):
        for row in self._rows.values():
            self.rows_layout.removeWidget(row)
            row.hide()
            row.deleteLater()
        self._rows.clear()

        for index, item in enumerate(status):
            row = QueueRow(index, self.analysis_page, self.list_widget)
            row.update_state(item)
            self.rows_layout.insertWidget(self.rows_layout.count() - 1, row)
            self._rows[index] = row

        self.empty_label.setVisible(not status)

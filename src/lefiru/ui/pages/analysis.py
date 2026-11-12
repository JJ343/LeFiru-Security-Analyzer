"""Unified analysis page for Excel and Python files."""

from __future__ import annotations

from pathlib import Path
from threading import Event
import html
import logging

from PyQt6.QtCore import Qt, QTimer, QObject, QThread, pyqtSignal, pyqtSlot
from PyQt6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from lefiru.core.catalog import (
    EXCEL_EXTENSIONS,
    EXCEL_TESTS_AVAILABLE,
    PYTHON_EXTENSIONS,
    PYTHON_TESTS_AVAILABLE,
    TESTS_BY_EXTENSION,
    test_name,
)
from lefiru.core.orchestrator import AnalysisOrchestrator
from lefiru.core.analysis_support import prepare_output_directories, setup_logging
from lefiru.paths import ensure_output_root
from lefiru.reporting.report_writer import AnalysisReportWriter
from lefiru.ui.widgets.eliding import ElidingLabel


SUPPORTED_EXTENSIONS = EXCEL_EXTENSIONS | PYTHON_EXTENSIONS
UI_HIDDEN_TESTS = {"password"}

# Short, plain-language hints shown as tooltips so each check is self-explanatory.
TEST_DESCRIPTIONS = {
    "protections": "Verifies workbook structure and critical sheet protection.",
    "vba": "Inspects the VBA project and its macro code.",
    "patterns": "Looks for insecure patterns such as Shell or unqualified calls.",
    "connections": "Reviews external links, data connections and defined names.",
    "formulas": "Checks the integrity of formulas on critical sheets.",
    "python_dynamic_execution": "Detects eval, exec and other dynamic execution.",
    "python_dangerous_commands": "Detects risky os and subprocess usage.",
    "python_deserialization": "Detects unsafe pickle or marshal usage.",
    "python_credentials": "Finds hardcoded passwords, tokens and keys.",
    "python_connections": "Finds hardcoded hosts, URLs and endpoints.",
    "python_traceability": "Checks that security-relevant events are logged.",
}

# Compact labels for the UI; the full description stays in the tooltip.
TEST_SHORT_LABELS = {
    "protections": "Protections",
    "vba": "VBA project",
    "patterns": "Code patterns",
    "connections": "Connections",
    "formulas": "Formulas",
    "python_dynamic_execution": "Dynamic code",
    "python_dangerous_commands": "OS commands",
    "python_deserialization": "Deserialization",
    "python_credentials": "Credentials",
    "python_connections": "Connections",
    "python_traceability": "Traceability",
}

# Headings the worker prints in the activity log.
LOG_HEADINGS = {
    "COM ANALYSIS",
    "STATIC ANALYSIS",
    "GENERAL ANALYSIS",
    "FINAL TEST SUMMARY",
    "CRITICAL FINDINGS",
    "RECOMMENDATIONS",
    "OUTPUT FOLDER:",
    "REPORTS GENERATED:",
}


def _is_excel(path: Path) -> bool:
    return path.suffix.lower() in EXCEL_EXTENSIONS


def _is_python(path: Path) -> bool:
    return path.suffix.lower() in PYTHON_EXTENSIONS


def _kind(path: Path) -> str:
    return "Excel" if _is_excel(path) else "Python"


class AnalysisWorker(QObject):
    """Runs the analyzer over a list of Excel and/or Python files."""

    progress = pyqtSignal(str)
    finished = pyqtSignal()
    failed = pyqtSignal(str)

    vba_prompt_requested = pyqtSignal(object)
    brute_force_prompt_requested = pyqtSignal(object)
    brute_force_started = pyqtSignal()
    brute_force_finished = pyqtSignal()

    queue_initialized = pyqtSignal(list)
    file_started = pyqtSignal(int, str)
    file_progress = pyqtSignal(int, int, str)
    file_finished = pyqtSignal(int, dict)
    file_failed = pyqtSignal(int, str)

    def __init__(self, files: list[Path], selected_tests: list[str], logger_name: str):
        super().__init__()
        self.files = [Path(file) for file in files]
        self.selected_tests = list(selected_tests)
        self.logger = logging.getLogger(logger_name)
        self._checker = None
        self._index_current = -1
        self._skip: set[int] = set()
        self._cancel_index = -1
        self._events_test = 0
        self._events_estimates = 1
        self._mode_section_current = None
        self._summary_emitted = False

        self._vba_prompt_event = Event()
        self._continue_without_vba = False
        self._brute_force_prompt_event = Event()
        self._continue_brute_force = False

    # ------------------------------------------------------------------
    # Queue control
    # ------------------------------------------------------------------
    def request_jump(self, index: int):
        self._skip.add(index)

    def stop_file(self, index: int):
        if index == self._index_current and self._checker is not None:
            self._cancel_index = index
            if hasattr(self._checker, "stop_event"):
                self._checker.stop_event.set()
            if hasattr(self._checker, "stop_brute_force_event"):
                self._checker.stop_brute_force_event.set()

    # ------------------------------------------------------------------
    # Prompts (Excel only)
    # ------------------------------------------------------------------
    def set_vba_prompt_response(self, should_continue: bool):
        self._continue_without_vba = should_continue
        self._vba_prompt_event.set()

    def set_brute_force_prompt_response(self, should_continue: bool):
        self._continue_brute_force = should_continue
        self._brute_force_prompt_event.set()

    def stop_brute_force(self):
        if self._checker is not None:
            self._checker.stop_brute_force_event.set()

    def _request_confirmation_vba(self, file: Path, precheck: dict) -> bool:
        self._continue_without_vba = False
        self._vba_prompt_event.clear()
        self.vba_prompt_requested.emit({"file": str(file), "precheck": precheck})
        self._vba_prompt_event.wait()
        return self._continue_without_vba

    def _request_confirmation_brute_force(self, file: Path) -> bool:
        self._continue_brute_force = False
        self._brute_force_prompt_event.clear()
        self.brute_force_prompt_requested.emit({"file": str(file)})
        self._brute_force_prompt_event.wait()
        if self._continue_brute_force:
            self.brute_force_started.emit()
        return self._continue_brute_force

    # ------------------------------------------------------------------
    # Test status -> live output
    # ------------------------------------------------------------------
    def _on_test_status(self, test: str, payload: dict):
        status = str(payload.get("status", "UNDETERMINED"))
        label = str(payload.get("label", test))
        total = int(payload.get("total_findings", 0) or 0)
        test_key = str(payload.get("test", ""))
        test_display = str(payload.get("test_name", ""))
        detail = str(payload.get("detail", ""))
        mode = str(payload.get("mode", "")).strip().lower()

        if status != "IN_PROGRESS":
            self._events_test += 1

        if self._index_current >= 0:
            percentage = min(95, int(self._events_test / max(1, self._events_estimates) * 100))
            if status == "IN_PROGRESS" and percentage < 5:
                percentage = 5
            mode_txt = "COM" if mode == "com" else "STATIC" if mode == "static" else "GENERAL"
            if test_key and test_display:
                stage = f"{test_display}: {status}"
            else:
                stage = f"{mode_txt} · {label}..."
                if status != "IN_PROGRESS":
                    stage = f"{mode_txt} · {label}: {detail or status}"
            self.file_progress.emit(self._index_current, percentage, stage)

        if mode and not (test_key and test_display) and mode != self._mode_section_current:
            title_mode = "COM" if mode == "com" else "STATIC" if mode == "static" else mode.upper()
            self.progress.emit(f"\n{title_mode} ANALYSIS")
            self._mode_section_current = mode

        if status == "IN_PROGRESS":
            self.progress.emit(f"{label}...")
            return

        if test_key and test_display:
            if not self._summary_emitted:
                self.progress.emit("\nFINAL TEST SUMMARY")
                self._summary_emitted = True
            mark = "[OK]" if status == "COMPLIANT" else "[X]" if status == "VULNERABLE" else "[!]"
            extra = f"  ({total} finding(s))" if total else ""
            self.progress.emit(f"    {mark} {test_display}{extra}")
            return

        mark = "[OK]" if status in ("COMPLIANT", "NOT_APPLICABLE") else "[X]" if status in ("VULNERABLE", "ERROR") else "[!]"
        suffix = f" · {total} finding(s)" if total else ""
        self.progress.emit(f"  {mark} {label}: {detail or status}{suffix}")

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------
    def _tests_for(self, file: Path) -> list[str]:
        applicable = set(TESTS_BY_EXTENSION.get(file.suffix.lower(), set()))
        selected = [key for key in self.selected_tests if key in applicable]
        if _is_excel(file) and "password" in applicable:
            selected.append("password")
        return selected

    @pyqtSlot()
    def run(self):
        try:
            if not self.files:
                self.failed.emit("No files were selected")
                return

            self.progress.emit(f"Analyzing {len(self.files)} file(s)...\n")
            self.queue_initialized.emit(
                [{"name": file.name, "kind": _kind(file)} for file in self.files]
            )

            for index, file in enumerate(self.files):
                try:
                    if index in self._skip:
                        self.file_finished.emit(
                            index, {"skipped": True, "detail": "Skipped by the user"}
                        )
                        continue

                    self._index_current = index
                    self.file_started.emit(index, file.name)
                    self._events_test = 0
                    self._mode_section_current = None
                    self._summary_emitted = False

                    file_tests = self._tests_for(file)
                    if not file_tests:
                        self.progress.emit(
                            f"\n{file.name}: no applicable tests for this file type.\n"
                        )
                        self.file_finished.emit(
                            index,
                            {"skipped": True, "detail": "No applicable tests"},
                        )
                        continue

                    family = "excel" if _is_excel(file) else "python"
                    self._events_estimates = max(1, len(file_tests) * 4)
                    self.progress.emit("\n" + "-" * 78)
                    self.progress.emit(f"{_kind(file)} · {file.name}")
                    self.progress.emit("-" * 78 + "\n")

                    output_paths = prepare_output_directories(
                        base_output=str(ensure_output_root() / family),
                        excel_file=file,
                        mode="both" if family == "excel" else "python",
                    )
                    log_file = setup_logging(str(output_paths["root"]), logging.INFO)

                    checker = AnalysisOrchestrator(
                        file_path=str(file),
                        mode="both",
                        tests=file_tests,
                        output_dir=str(output_paths["root"]),
                        brute_force_confirmation_cb=(
                            self._request_confirmation_brute_force
                            if family == "excel"
                            else None
                        ),
                        test_status_cb=self._on_test_status,
                    )
                    self._checker = checker

                    if family == "excel" and "vba" in file_tests:
                        self.progress.emit("Checking VBA trust...\n")
                        precheck = checker.precheck_vba_access()
                        if not precheck.get("enabled", True):
                            self.logger.warning(
                                "VBA_ACCESS_DISABLED - Environment status: %s", precheck
                            )
                            if not self._request_confirmation_vba(file, precheck):
                                self.file_finished.emit(
                                    index,
                                    {
                                        "skipped": True,
                                        "detail": "Skipped by VBA configuration",
                                    },
                                )
                                continue
                            self.progress.emit(
                                "Continuing without VBA evaluation.\n"
                            )
                            file_tests.remove("vba")
                            checker.tests = file_tests

                    self.progress.emit("Running analysis...\n")
                    results = checker.run_full_analysis()
                    self.brute_force_finished.emit()

                    if self._cancel_index == index:
                        self._cancel_index = -1
                        self.file_finished.emit(
                            index, {"skipped": True, "detail": "Stopped by the user"}
                        )
                        continue

                    report_gen = AnalysisReportWriter(str(output_paths["root"]))
                    json_file, report_file = report_gen.generate_reports(results)

                    status = results.get("compliance", {}).get("general_status", "UNDETERMINED")
                    critical = len(
                        results.get("compliance", {}).get("critical_findings", []) or []
                    )
                    self.file_finished.emit(
                        index, {"status": status, "critical": critical}
                    )

                    self.progress.emit(f"\nOverall status: {status}\n")
                    findings = results.get("compliance", {}).get("critical_findings", [])
                    if findings:
                        self.progress.emit("CRITICAL FINDINGS")
                        for item in findings:
                            self.progress.emit(
                                f"  • [{test_name(item.get('test', ''))}] "
                                f"{item.get('description', '')}"
                            )
                    recommendations = results.get("compliance", {}).get("recommendations", [])
                    if recommendations:
                        self.progress.emit("\nRECOMMENDATIONS")
                        for item in recommendations:
                            self.progress.emit(f"  • {item}")

                    self.progress.emit("\nOutput folder:")
                    self.progress.emit(f"  {output_paths['root']}")
                    self.progress.emit("Reports generated:")
                    self.progress.emit(f"  JSON: {json_file}")
                    if report_file:
                        self.progress.emit(f"  Report: {report_file}")
                    if log_file:
                        self.progress.emit(f"  Log: {log_file}")
                    self.progress.emit("")

                except Exception as exc:  # noqa: BLE001
                    self.logger.exception("Error analyzing %s", file)
                    self.progress.emit(f"\nError while analyzing {file.name}: {exc}\n")
                    self.file_failed.emit(index, str(exc))

            self.finished.emit()

        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class AnalysisPage(QWidget):
    """Single page that analyzes Excel and Python files from one file picker."""

    queue_updated = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)

        self.files: list[Path] = []
        self.logger = logging.getLogger("ui.analysis")
        self.analysis_thread = None
        self.analysis_worker = None
        self.status_queue: list[dict] = []
        self._mode_brute_force = False

        self.setAcceptDrops(True)

        root = QVBoxLayout(self)
        root.setContentsMargins(32, 24, 32, 24)
        root.setSpacing(18)

        header = QHBoxLayout()
        heading = QVBoxLayout()
        heading.setSpacing(2)
        title = QLabel("Security Analysis")
        title.setObjectName("page_title")
        subtitle = QLabel("Analyze Excel workbooks and Python files in one place")
        subtitle.setObjectName("page_subtitle")
        heading.addWidget(title)
        heading.addWidget(subtitle)
        header.addLayout(heading)
        header.addStretch()
        root.addLayout(header)

        columns = QHBoxLayout()
        columns.setSpacing(18)
        root.addLayout(columns, 1)

        # ── Left: intake + tests ───────────────────────────────────────
        left_container = QWidget()
        left_container.setObjectName("analysis_left")
        left = QVBoxLayout(left_container)
        left.setContentsMargins(0, 0, 0, 0)
        left.setSpacing(14)

        left_scroll = QScrollArea()
        left_scroll.setObjectName("analysis_scroll")
        left_scroll.setWidgetResizable(True)
        left_scroll.setFrameShape(QFrame.Shape.NoFrame)
        left_scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        left_scroll.setWidget(left_container)
        self.left_scroll = left_scroll
        columns.addWidget(left_scroll, 5)

        drop_zone = QFrame()
        drop_zone.setObjectName("drop_zone")
        drop_layout = QVBoxLayout(drop_zone)
        drop_layout.setContentsMargins(24, 26, 24, 26)
        drop_layout.setSpacing(8)
        drop_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.drop_mark = QLabel("↑")
        self.drop_mark.setObjectName("drop_mark")
        self.drop_mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.drop_title = QLabel("Select one or more files")
        self.drop_title.setObjectName("drop_title")
        self.drop_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.drop_title.setWordWrap(True)
        self.drop_subtitle = QLabel(
            "Excel and Python · drag and drop or use the button below"
        )
        self.drop_subtitle.setObjectName("drop_subtitle")
        self.drop_subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.drop_subtitle.setWordWrap(True)

        self.select_button = QPushButton("Select files")
        self.select_button.setObjectName("primary_button")
        self.select_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.select_button.setMinimumHeight(44)
        self.select_button.clicked.connect(self._on_primary_clicked)

        drop_layout.addWidget(self.drop_mark)
        drop_layout.addWidget(self.drop_title)
        drop_layout.addWidget(self.drop_subtitle)
        drop_layout.addSpacing(6)
        drop_layout.addWidget(self.select_button, alignment=Qt.AlignmentFlag.AlignHCenter)
        left.addWidget(drop_zone)

        files_panel = QFrame()
        files_panel.setObjectName("panel")
        files_layout = QVBoxLayout(files_panel)
        files_layout.setContentsMargins(16, 14, 16, 14)
        files_layout.setSpacing(8)
        files_header = QHBoxLayout()
        files_label = QLabel("Selected files")
        files_label.setObjectName("section_title")
        self.clear_button = QPushButton("Clear")
        self.clear_button.setObjectName("ghost_button")
        self.clear_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.clear_button.clicked.connect(self._clear_files)
        self.clear_button.setVisible(False)
        files_header.addWidget(files_label)
        files_header.addStretch()
        files_header.addWidget(self.clear_button)
        files_layout.addLayout(files_header)

        self.file_list = QListWidget()
        self.file_list.setObjectName("file_list")
        self.file_list.setMinimumHeight(96)
        self.file_list.setMaximumHeight(140)
        files_layout.addWidget(self.file_list)
        left.addWidget(files_panel)

        tests_panel = QFrame()
        tests_panel.setObjectName("panel")
        tests_layout = QVBoxLayout(tests_panel)
        tests_layout.setContentsMargins(14, 14, 14, 15)
        tests_layout.setSpacing(12)

        tests_header = QHBoxLayout()
        tests_heading = QVBoxLayout()
        tests_heading.setSpacing(1)
        tests_label = QLabel("Tests")
        tests_label.setObjectName("section_title")
        self.tests_hint = QLabel("All checks enabled")
        self.tests_hint.setObjectName("section_hint")
        tests_heading.addWidget(tests_label)
        tests_heading.addWidget(self.tests_hint)
        tests_header.addLayout(tests_heading)
        tests_header.addStretch()
        self.all_tests = QCheckBox("Select all")
        self.all_tests.setObjectName("select_all")
        self.all_tests.setChecked(True)
        self.all_tests.setCursor(Qt.CursorShape.PointingHandCursor)
        self.all_tests.toggled.connect(self._toggle_all_tests)
        tests_header.addWidget(self.all_tests)
        tests_layout.addLayout(tests_header)

        tests_columns = QGridLayout()
        tests_columns.setHorizontalSpacing(14)
        tests_columns.setVerticalSpacing(12)
        self.checkboxes_tests: dict[str, QCheckBox] = {}
        self.excel_group = self._build_test_group(
            "Excel files",
            "Workbooks and add-ins",
            EXCEL_TESTS_AVAILABLE,
            "#43e6c8",
        )
        self.python_group = self._build_test_group(
            "Python files",
            "Scripts and executables",
            PYTHON_TESTS_AVAILABLE,
            "#9a8cff",
        )
        self.tests_columns = tests_columns
        self._tests_narrow = None
        self._layout_test_groups()
        tests_layout.addLayout(tests_columns)
        left.addWidget(tests_panel)
        left.addStretch()

        # ── Right: live activity ───────────────────────────────────────
        right = QVBoxLayout()
        right.setSpacing(12)
        columns.addLayout(right, 6)

        activity_panel = QFrame()
        activity_panel.setObjectName("panel")
        activity_layout = QVBoxLayout(activity_panel)
        activity_layout.setContentsMargins(18, 15, 18, 16)
        activity_layout.setSpacing(12)

        activity_header = QHBoxLayout()
        activity_heading = QVBoxLayout()
        activity_heading.setSpacing(1)
        activity_label = QLabel("Activity")
        activity_label.setObjectName("section_title")
        self.progress_label = QLabel("Ready when you are")
        self.progress_label.setObjectName("section_hint")
        activity_heading.addWidget(activity_label)
        activity_heading.addWidget(self.progress_label)
        activity_header.addLayout(activity_heading)
        activity_header.addStretch()
        self.activity_status = QLabel("Idle")
        self.activity_status.setObjectName("activity_status")
        self.activity_status.setProperty("state", "idle")
        activity_header.addWidget(
            self.activity_status, alignment=Qt.AlignmentFlag.AlignTop
        )
        activity_layout.addLayout(activity_header)

        # Current file: name, stage and its own progress bar
        current_card = QFrame()
        current_card.setObjectName("current_file_card")
        current_layout = QVBoxLayout(current_card)
        current_layout.setContentsMargins(14, 11, 14, 12)
        current_layout.setSpacing(4)
        self.current_file = ElidingLabel("No file running")
        self.current_file.setObjectName("current_file_name")
        self.current_stage = ElidingLabel("Select files to begin")
        self.current_stage.setObjectName("current_file_stage")
        current_layout.addWidget(self.current_file)
        current_layout.addWidget(self.current_stage)

        self.file_bar = QProgressBar()
        self.file_bar.setObjectName("file_bar")
        self.file_bar.setRange(0, 100)
        self.file_bar.setValue(0)
        self.file_bar.setTextVisible(False)
        current_layout.addWidget(self.file_bar)
        activity_layout.addWidget(current_card)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setObjectName("analysis_output")
        self.output.setPlaceholderText(
            "Nothing to show yet.\n\n"
            "Pick your files and press Analyze — every step, result and "
            "evidence path will appear here in real time."
        )
        activity_layout.addWidget(self.output, 1)

        self.global_progress = QProgressBar()
        self.global_progress.setObjectName("queue_bar")
        self.global_progress.setRange(0, 1)
        self.global_progress.setValue(0)
        self.global_progress.setTextVisible(True)
        activity_layout.addWidget(self.global_progress)
        right.addWidget(activity_panel, 1)

        self._refresh_file_list()
        self._refresh_action_state()
        self._update_tests_summary()

    # ------------------------------------------------------------------
    # Selection
    # ------------------------------------------------------------------
    def _file_filter(self) -> str:
        patterns = " ".join(f"*{ext}" for ext in sorted(SUPPORTED_EXTENSIONS))
        return f"Supported files ({patterns});;All files (*)"

    def _on_primary_clicked(self):
        if self.files:
            self.execute_analysis()
            return
        self._choose_files(start_after=True)

    def _choose_files(self, start_after: bool = False):
        selected, _ = QFileDialog.getOpenFileNames(
            self,
            "Select files to analyze",
            "",
            self._file_filter(),
        )
        if not selected:
            return
        self._add_files([Path(file) for file in selected])
        if start_after:
            self.execute_analysis()

    def _add_files(self, files: list[Path]):
        known = {str(path) for path in self.files}
        for file in files:
            if file.suffix.lower() not in SUPPORTED_EXTENSIONS:
                continue
            if str(file) not in known:
                self.files.append(file)
                known.add(str(file))
        self._refresh_file_list()
        self._refresh_action_state()

    def _clear_files(self):
        if self.analysis_thread is not None:
            return
        self.files.clear()
        self._refresh_file_list()
        self._refresh_action_state()

    def _refresh_file_list(self):
        self.file_list.clear()
        for file in self.files:
            prefix = "XLS" if _is_excel(file) else "PY"
            item = QListWidgetItem(f"[{prefix}]  {file.name}")
            item.setToolTip(str(file))
            self.file_list.addItem(item)
        self.clear_button.setVisible(bool(self.files) and self.analysis_thread is None)
        if not self.files:
            self.drop_title.setText("Select one or more files")
            self.drop_subtitle.setText(
                "Excel and Python · drag and drop or use the button below"
            )
        else:
            count = len(self.files)
            self.drop_title.setText(f"{count} file(s) ready to analyze")
            self.drop_subtitle.setText(
                "Excel and Python are processed together, one after another"
            )

    def _refresh_action_state(self):
        if self.analysis_thread is not None:
            return
        if self.files:
            self.select_button.setText(f"Analyze {len(self.files)} file(s)")
        else:
            self.select_button.setText("Select files")
        self.select_button.setEnabled(True)

    def _toggle_all_tests(self, checked: bool):
        for chk in self.checkboxes_tests.values():
            chk.setChecked(checked)
        self._update_tests_summary()

    def _build_test_group(self, title, hint, tests, accent) -> QFrame:
        """Build a friendly card with the checks of one file family."""
        group = QFrame()
        group.setObjectName("test_group_box")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(5, 10, 5, 11)
        layout.setSpacing(4)

        header = QHBoxLayout()
        header.setSpacing(7)
        dot = QLabel("●")
        dot.setObjectName("test_dot")
        dot.setStyleSheet(f"color: {accent};")
        name = QLabel(title)
        name.setObjectName("test_group_title")
        count = QLabel("0")
        count.setObjectName("test_group_count")
        header.addWidget(dot)
        header.addWidget(name)
        header.addStretch()
        header.addWidget(count)
        layout.addLayout(header)

        hint_label = ElidingLabel(hint)
        hint_label.setObjectName("test_group_hint")
        layout.addWidget(hint_label)
        layout.addSpacing(3)

        group_count = 0
        for key, info in sorted(tests.items(), key=lambda item: item[1]["order"]):
            if key in UI_HIDDEN_TESTS:
                continue
            chk = QCheckBox(TEST_SHORT_LABELS.get(key, info["label"]))
            chk.setToolTip(TEST_DESCRIPTIONS.get(key, info["label"]))
            chk.setCursor(Qt.CursorShape.PointingHandCursor)
            chk.setChecked(True)
            chk.toggled.connect(self._update_tests_summary)
            self.checkboxes_tests[key] = chk
            layout.addWidget(chk)
            group_count += 1
        count.setText(str(group_count))
        layout.addStretch()
        return group

    def _layout_test_groups(self):
        """Stack the two test groups when the left column cannot fit them."""
        if not hasattr(self, "excel_group"):
            return
        # Tests panel left/right padding plus its border.
        panel_margins = 28 + 2
        available = max(0, self.left_scroll.viewport().width() - panel_margins)
        needed = (
            self.excel_group.minimumSizeHint().width()
            + self.python_group.minimumSizeHint().width()
            + self.tests_columns.horizontalSpacing()
        )
        narrow = available < needed
        self.tests_hint.setVisible(not narrow)
        if narrow == self._tests_narrow:
            return
        self._tests_narrow = narrow
        self.tests_columns.removeWidget(self.excel_group)
        self.tests_columns.removeWidget(self.python_group)
        self.tests_columns.addWidget(self.excel_group, 0, 0)
        if narrow:
            self.tests_columns.addWidget(self.python_group, 1, 0)
        else:
            self.tests_columns.addWidget(self.python_group, 0, 1)
        self.tests_columns.setColumnStretch(0, 1)
        self.tests_columns.setColumnStretch(1, 0 if narrow else 1)
        self.tests_columns.invalidate()
        self.tests_columns.activate()
        self.left_scroll.widget().adjustSize()

    def _update_tests_summary(self, *_):
        total = len(self.checkboxes_tests)
        selected = len(self._selected_tests())
        if selected == total and total:
            self.tests_hint.setText(f"All {total} checks enabled")
        elif selected == 0:
            self.tests_hint.setText("No checks selected")
        else:
            self.tests_hint.setText(f"{selected} of {total} checks enabled")
        if self.all_tests.isChecked() != (selected == total):
            self.all_tests.blockSignals(True)
            self.all_tests.setChecked(selected == total)
            self.all_tests.blockSignals(False)

    # ------------------------------------------------------------------
    # Activity helpers
    # ------------------------------------------------------------------
    def _set_activity_state(self, state: str, text: str):
        self.activity_status.setText(text)
        self.activity_status.setProperty("state", state)
        style = self.activity_status.style()
        style.unpolish(self.activity_status)
        style.polish(self.activity_status)

    def _set_current_file(self, name: str, stage: str, progress: int | None = None):
        self.current_file.setText(name)
        self.current_stage.setText(stage)
        if progress is not None:
            self.file_bar.setValue(max(0, min(100, int(progress))))

    def _append_log(self, text: str):
        for line in str(text).splitlines() or [""]:
            self.output.append(self._format_log_line(line))

    def _format_log_line(self, line: str) -> str:
        raw = line.rstrip()
        stripped = raw.strip()
        if not stripped:
            return "<div style='height:7px'></div>"
        if len(stripped) >= 3 and set(stripped) <= {"-", "—", "─"}:
            return (
                "<div style='color:#1e3239; letter-spacing:2px;'>"
                + "─" * 44
                + "</div>"
            )

        indent = len(raw) - len(raw.lstrip(" "))
        escaped = html.escape(raw).lstrip()
        if indent:
            escaped = "&nbsp;" * indent + escaped

        upper = stripped.upper()
        if upper in LOG_HEADINGS or upper.endswith(" ANALYSIS"):
            return (
                "<div style='color:#43e6c8; font-weight:700; font-size:11px; "
                "letter-spacing:1px; margin-top:6px;'>"
                + html.escape(stripped)
                + "</div>"
            )
        if stripped.startswith(("Excel ·", "Python ·")):
            return (
                "<div style='color:#eaf9f6; font-weight:700; font-size:13px; "
                "margin-top:2px;'>"
                + html.escape(stripped)
                + "</div>"
            )

        if stripped.startswith("[OK]"):
            return f"<div style='color:#6ff2da;'>{escaped}</div>"
        if stripped.startswith("[X]"):
            return f"<div style='color:#ff8f8f;'>{escaped}</div>"
        if stripped.startswith("[!]"):
            return f"<div style='color:#ffcf7d;'>{escaped}</div>"
        if stripped.startswith(("Error", "ERROR")):
            return f"<div style='color:#ff8f8f;'>{escaped}</div>"
        if stripped.startswith(("JSON:", "Report:", "Log:")):
            return f"<div style='color:#7f9d99;'>{escaped}</div>"
        if len(stripped) > 2 and stripped[1:3] == ":\\":
            return f"<div style='color:#7f9d99;'>{escaped}</div>"
        if stripped.startswith("•"):
            return f"<div style='color:#c3e0db;'>{escaped}</div>"
        return f"<div style='color:#a9c7c2;'>{escaped}</div>"

    # ------------------------------------------------------------------
    # Drag and drop
    # ------------------------------------------------------------------
    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._layout_test_groups()
        # The scroll viewport reaches its final width after the layout pass,
        # so re-check once the geometry has settled.
        QTimer.singleShot(0, self._layout_test_groups)

    def showEvent(self, event):
        super().showEvent(event)
        QTimer.singleShot(0, self._layout_test_groups)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        files = []
        for url in event.mimeData().urls():
            if url.isLocalFile():
                files.append(Path(url.toLocalFile()))
        if files:
            self._add_files(files)
            event.acceptProposedAction()

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------
    def _selected_tests(self) -> list[str]:
        return [key for key, chk in self.checkboxes_tests.items() if chk.isChecked()]

    def execute_analysis(self):
        if self.analysis_thread is not None:
            return
        if not self.files:
            self._choose_files(start_after=True)
            return

        selected_tests = self._selected_tests()
        if not selected_tests:
            QMessageBox.warning(self, "No tests", "Select at least one test to run.")
            return

        self.status_queue = []
        self.progress_label.setText("Starting the analysis…")
        self._set_activity_state("running", "Running")
        self.output.clear()
        self._set_current_file("Preparing…", "Waiting for the first file", 0)
        self.global_progress.setRange(0, max(1, len(self.files)))
        self.global_progress.setValue(0)
        self._set_analysis_running(True)
        self._start_worker(list(self.files), selected_tests)

    def _start_worker(self, files: list[Path], selected_tests: list[str]):
        self.analysis_thread = QThread(self)
        self.analysis_worker = AnalysisWorker(files, selected_tests, self.logger.name)
        self.analysis_worker.moveToThread(self.analysis_thread)

        self.analysis_thread.started.connect(self.analysis_worker.run)
        self.analysis_worker.progress.connect(self._append_log)
        self.analysis_worker.queue_initialized.connect(self._on_queue_initialized)
        self.analysis_worker.file_started.connect(self._on_file_started)
        self.analysis_worker.file_progress.connect(self._on_file_progress)
        self.analysis_worker.file_finished.connect(self._on_file_finished)
        self.analysis_worker.file_failed.connect(self._on_file_failed)
        self.analysis_worker.vba_prompt_requested.connect(self._resolve_prompt_vba)
        self.analysis_worker.brute_force_prompt_requested.connect(
            self._resolve_prompt_brute_force
        )
        self.analysis_worker.brute_force_started.connect(self._on_brute_force_started)
        self.analysis_worker.brute_force_finished.connect(self._on_brute_force_finished)
        self.analysis_worker.finished.connect(self._on_analysis_finished)
        self.analysis_worker.finished.connect(self.analysis_thread.quit)
        self.analysis_worker.failed.connect(self._on_analysis_failed)
        self.analysis_worker.failed.connect(self.analysis_thread.quit)
        self.analysis_thread.finished.connect(self._cleanup_analysis_worker)
        self.analysis_thread.finished.connect(self.analysis_worker.deleteLater)
        self.analysis_thread.finished.connect(self.analysis_thread.deleteLater)

        self.analysis_thread.start()

    def _set_analysis_running(self, running: bool):
        self.select_button.setEnabled(not running)
        self.clear_button.setVisible(not running and bool(self.files))
        self.file_list.setEnabled(not running)
        for chk in self.checkboxes_tests.values():
            chk.setEnabled(not running)
        self.all_tests.setEnabled(not running)

        if running:
            self.select_button.setText("Analyzing...")
        else:
            self._mode_brute_force = False
            self.select_button.setStyleSheet("")
            self._refresh_action_state()
            self.progress_label.setText("Ready for a new run")

    def _on_analysis_finished(self):
        self._append_log("Analysis finished.")
        self._set_analysis_running(False)
        self._set_activity_state("done", "Finished")
        self.progress_label.setText(f"{len(self.files)} file(s) processed")
        self._set_current_file("Analysis complete", "All files processed", 100)
        self.global_progress.setValue(self.global_progress.maximum())

    def _on_analysis_failed(self, error: str):
        self._append_log(f"Error while analyzing: {error}")
        self._set_analysis_running(False)
        self._set_activity_state("error", "Error")
        self.progress_label.setText("The run could not finish")
        self._set_current_file("Analysis failed", "See the activity log", 0)

    def _cleanup_analysis_worker(self):
        self.analysis_worker = None
        self.analysis_thread = None
        self._refresh_file_list()
        self._refresh_action_state()

    # ------------------------------------------------------------------
    # Prompts
    # ------------------------------------------------------------------
    def _resolve_prompt_vba(self, _payload):
        should_continue = self.ask_continue_without_vba()
        if self.analysis_worker is not None:
            self.analysis_worker.set_vba_prompt_response(should_continue)

    def _resolve_prompt_brute_force(self, payload):
        file_name = Path(payload.get("file", "")).name
        should_continue = self.ask_brute_force(file_name)
        if self.analysis_worker is not None:
            self.analysis_worker.set_brute_force_prompt_response(should_continue)

    def ask_continue_without_vba(self) -> bool:
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setWindowTitle("VBA access not enabled")
        msg.setText(
            "Trust in access to the VBA project object model has not been enabled.\n\n"
            "Macro (VBA) analysis cannot be performed. Do you want to continue?"
        )
        btn_yes = msg.addButton("Yes", QMessageBox.ButtonRole.YesRole)
        btn_no = msg.addButton("No", QMessageBox.ButtonRole.NoRole)
        btn_help = msg.addButton("How to enable VBA", QMessageBox.ButtonRole.HelpRole)
        msg.setDefaultButton(btn_no)
        msg.exec()
        clicked = msg.clickedButton()
        if clicked == btn_help:
            self.show_instructions_vba()
            return self.ask_continue_without_vba()
        return clicked == btn_yes

    def show_instructions_vba(self):
        QMessageBox.information(
            self,
            "How to enable VBA access",
            (
                "To enable access to the VBA project object model:\n\n"
                "1. Open Microsoft Excel\n"
                "2. Go to File > Options\n"
                "3. Select Trust Center\n"
                "4. Click 'Trust Center Settings'\n"
                "5. Enter 'Macro Settings'\n"
                "6. Enable 'Trust access to the VBA project object model'\n"
                "7. Accept and close Excel completely\n"
                "8. Run the analysis again"
            ),
        )

    def ask_brute_force(self, file_name: str) -> bool:
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Icon.Question)
        msg.setWindowTitle("Opening password brute force")
        msg.setText(
            f"The file '{file_name}' is protected with an opening password and "
            "it was not possible to open it through structural bypass.\n\n"
            "Do you want to run a dictionary attack to try to find the password?\n\n"
            "Warning: this process may take several minutes."
        )
        btn_yes = msg.addButton("Yes, run brute force", QMessageBox.ButtonRole.YesRole)
        btn_no = msg.addButton("No, skip", QMessageBox.ButtonRole.NoRole)
        msg.setDefaultButton(btn_no)
        msg.exec()
        return msg.clickedButton() == btn_yes

    def _stop_brute_force(self):
        if self.analysis_worker is not None:
            self.analysis_worker.stop_brute_force()
        self.select_button.setEnabled(False)
        self.select_button.setText("Stopping...")
        self._append_log("Stop request sent. The brute force will stop shortly.")

    def _on_brute_force_started(self):
        self._mode_brute_force = True
        self.select_button.clicked.disconnect()
        self.select_button.clicked.connect(self._stop_brute_force)
        self.select_button.setStyleSheet(
            "background-color: #4e0707; color: white; font-weight: bold;"
        )
        self.select_button.setText("Stop brute force")
        self.select_button.setEnabled(True)
        self._append_log("Brute force started. Press the red button to stop it.")

    def _on_brute_force_finished(self):
        if self._mode_brute_force:
            self._mode_brute_force = False
            self.select_button.clicked.disconnect()
            self.select_button.clicked.connect(self._on_primary_clicked)
            self.select_button.setStyleSheet("")
            self.select_button.setText("Analyzing...")
            self.select_button.setEnabled(False)

    # ------------------------------------------------------------------
    # Queue
    # ------------------------------------------------------------------
    def request_jump(self, index):
        if not (0 <= index < len(self.status_queue)):
            return
        status = self.status_queue[index]["status"]
        if status == "EN_QUEUE":
            if self.analysis_worker is not None:
                self.analysis_worker.request_jump(index)
            self.status_queue[index].update(
                status="SKIPPED", progress=100, detail="Skipped by the user"
            )
            self.queue_updated.emit()
        elif status == "ANALYZING":
            if self.analysis_worker is not None:
                self.analysis_worker.stop_file(index)
                self.analysis_worker.stop_brute_force()
            self.status_queue[index].update(detail="Stopping...")
            self.queue_updated.emit()

    def _on_queue_initialized(self, names):
        self.status_queue = []
        for entry in names:
            if isinstance(entry, dict):
                name = entry.get("name", "")
                kind = entry.get("kind", "")
            else:
                name = str(entry)
                kind = ""
            self.status_queue.append(
                {
                    "name": name,
                    "kind": kind,
                    "status": "EN_QUEUE",
                    "progress": 0,
                    "detail": "In queue",
                }
            )
        self.queue_updated.emit()

    def _on_file_started(self, index, name):
        if 0 <= index < len(self.status_queue):
            self.status_queue[index].update(
                status="ANALYZING", progress=0, detail="Analyzing..."
            )
            self.queue_updated.emit()
        total = len(self.status_queue)
        position = f"File {index + 1} of {total}" if total else ""
        self.progress_label.setText(f"{position} · analyzing")
        self._set_current_file(name, "Starting…", 0)

    def _on_file_progress(self, index, percentage, stage):
        if 0 <= index < len(self.status_queue):
            self.status_queue[index].update(progress=percentage, detail=stage)
            self.queue_updated.emit()
            self._set_current_file(
                self.status_queue[index]["name"], stage, percentage
            )

    def _on_file_finished(self, index, info):
        if not (0 <= index < len(self.status_queue)):
            return
        if info.get("skipped"):
            self.status_queue[index].update(
                status="SKIPPED",
                progress=100,
                detail=info.get("detail", "Skipped"),
            )
            stage = info.get("detail", "Skipped")
        else:
            critical = int(info.get("critical", 0) or 0)
            detail = "Completed"
            if critical:
                detail += f" · {critical} critical"
            self.status_queue[index].update(
                status="COMPLETED",
                progress=100,
                detail=detail,
                compliance=info.get("status", ""),
            )
            stage = info.get("status", "Completed").replace("_", " ").title()
        self._set_current_file(self.status_queue[index]["name"], stage, 100)
        completed = sum(
            1
            for item in self.status_queue
            if item["status"] in ("COMPLETED", "ERROR", "SKIPPED")
        )
        self.global_progress.setValue(completed)
        self.queue_updated.emit()

    def _on_file_failed(self, index, _error):
        if 0 <= index < len(self.status_queue):
            self.status_queue[index].update(
                status="ERROR", progress=100, detail="Analysis error"
            )
            self._set_current_file(
                self.status_queue[index]["name"], "Analysis error", 100
            )
            self.queue_updated.emit()

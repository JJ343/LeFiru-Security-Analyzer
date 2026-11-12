"""
macOS-style title bar for the app's frameless window.

Traffic lights (minimize/maximize/close) on the right in Windows order,
icon + title in white, centered.

NOTE: this file is independent. Modifying it does NOT affect `main_window.py`.
"""

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import QPushButton, QLabel, QHBoxLayout, QWidget
from qframelesswindow import TitleBar

from lefiru.paths import resource

ICON_PATH = resource("ui/resources/icon.png")


# ---------------------------------------------------------------------------
# macOS-style bar (traffic lights on the right, centered title)
# ---------------------------------------------------------------------------
class WindowTitleBar(TitleBar):
    """Three circular buttons (red/yellow/green) on the left."""

    def __init__(self, parent):
        super().__init__(parent)
        self.setFixedHeight(36)
        # Without this, the bar (a QWidget subclass) does not paint its
        # stylesheet background and the frameless window background shows behind.
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)

        # Hide the default buttons (on the right)
        self.minBtn.hide()
        self.maxBtn.hide()
        self.closeBtn.hide()

        # Traffic lights
        self.closeDot = self._make_dot("#ff5f57", "#e0443e")
        self.minDot = self._make_dot("#febc2e", "#dea123")
        self.maxDot = self._make_dot("#28c840", "#1aab29")

        self.closeDot.clicked.connect(self.window().close)
        self.minDot.clicked.connect(self.window().showMinimized)
        self.maxDot.clicked.connect(self._toggle_max)

        lights = QWidget(self)
        lay = QHBoxLayout(lights)
        lay.setContentsMargins(8, 0, 12, 0)
        lay.setSpacing(8)
        # Windows order: minimize, maximize, close
        for dot in (self.minDot, self.maxDot, self.closeDot):
            lay.addWidget(dot)

        # Icon + title (in white), grouped and centered
        center = QWidget(self)
        center_lay = QHBoxLayout(center)
        center_lay.setContentsMargins(0, 0, 0, 0)
        center_lay.setSpacing(8)

        self.iconLabel = QLabel(center)
        if ICON_PATH.exists():
            self.iconLabel.setPixmap(
                QPixmap(str(ICON_PATH)).scaled(
                    18, 18,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )
            )
        self.iconLabel.setStyleSheet("background: transparent;")

        self.titleLabel = QLabel("LeFiru Security Analyzer", center)
        self.titleLabel.setStyleSheet(
            "color: #e8f5f3; font: 600 12px 'Segoe UI'; background: transparent;"
        )

        center_lay.addWidget(self.iconLabel)
        center_lay.addWidget(self.titleLabel)

        # Left spacer of the same width as the traffic lights, so the title is
        # centered with respect to the WHOLE width of the bar.
        spacer = QWidget(self)
        spacer.setFixedWidth(lights.sizeHint().width())

        # The base already brings a stretch before the buttons; we reuse it as
        # the right stretch and only add the left one, so they are symmetric.
        # Result: [spacer] [stretch] [icon+title] [base stretch] [lights]
        self.hBoxLayout.insertWidget(0, spacer, 0, Qt.AlignmentFlag.AlignLeft)
        self.hBoxLayout.insertStretch(1, 1)
        self.hBoxLayout.insertWidget(2, center, 0, Qt.AlignmentFlag.AlignCenter)
        self.hBoxLayout.addWidget(lights, 0, Qt.AlignmentFlag.AlignRight)

    def _make_dot(self, color: str, hover: str) -> QPushButton:
        btn = QPushButton(self)
        btn.setFixedSize(13, 13)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setStyleSheet(f"""
            QPushButton {{
                background: {color};
                border: none;
                border-radius: 6px;
            }}
            QPushButton:hover {{ background: {hover}; }}
        """)
        return btn

    def _toggle_max(self):
        win = self.window()
        if win.isMaximized():
            win.showNormal()
        else:
            win.showMaximized()

    def set_dark_mode(self, is_dark: bool):
        """Adjust the bar color according to the theme (dark/light)."""
        if is_dark:
            self.setStyleSheet(
                "WindowTitleBar { background: #070a0d;"
                " border-bottom: 1px solid #142028; }"
            )
            self.titleLabel.setStyleSheet(
                "color: #e8f5f3; font: 600 12px 'Segoe UI'; background: transparent;"
            )

        else:
            self.setStyleSheet(
                "WindowTitleBar { background: #e6efec;"
                " border-bottom: 1px solid #d5e4df; }"
            )
            self.titleLabel.setStyleSheet(
                "color: #102320; font: 600 12px 'Segoe UI'; background: transparent;"
            )


# ---------------------------------------------------------------------------
# Registry of available bars
# ---------------------------------------------------------------------------
TITLE_BARS = {
    "mac": WindowTitleBar,
}


def create_title_bar(name: str, parent):
    """
    Create an instance of the bar registered under that name.

    Args:
        name (str): key in `TITLE_BARS` (currently only "mac").
        parent: the parent frameless window.

    Returns:
        TitleBar: the requested bar (the Mac bar by default).
    """
    bar_cls = TITLE_BARS.get(name, WindowTitleBar)
    return bar_cls(parent)

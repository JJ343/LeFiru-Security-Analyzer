"""Top-level application window.

The window uses the native Windows chrome (title bar and system buttons) and
only hosts `ApplicationShell` inside it.
"""

from __future__ import annotations

from PyQt6.QtWidgets import QApplication, QVBoxLayout, QWidget

from lefiru.ui.shell import ApplicationShell


class ShellWindow(QWidget):
    """Native window that wraps `ApplicationShell`."""

    def __init__(self) -> None:
        super().__init__()

        self.setWindowTitle("LeFiru Security Analyzer")

        # Content: the application shell, reused as is
        self.content = ApplicationShell()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.content)

        self.setMinimumSize(1120, 720)
        self._resize_to_screen()
        self._center_on_screen()

    def _resize_to_screen(self) -> None:
        """Open with a large window adapted to the current screen."""
        screen = QApplication.screenAt(self.cursor().pos()) or QApplication.primaryScreen()
        if screen is None:
            self.resize(1440, 860)
            return
        available = screen.availableGeometry()
        width = min(1600, max(1180, int(available.width() * 0.90)))
        height = min(1000, max(760, int(available.height() * 0.90)))
        self.resize(width, height)

    def _center_on_screen(self) -> None:
        """Place the window at the center of the screen where the cursor is."""
        screen = QApplication.screenAt(self.cursor().pos()) or QApplication.primaryScreen()
        if screen is None:
            return
        geo = self.frameGeometry()
        geo.moveCenter(screen.availableGeometry().center())
        self.move(geo.topLeft())

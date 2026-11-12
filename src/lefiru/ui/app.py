"""Entry point of the desktop application."""

from __future__ import annotations

import sys

from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication

from lefiru.paths import resource
from lefiru.ui.splash import show_intro_then
from lefiru.ui.window import ShellWindow


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("LeFiru Security Analyzer")
    app.setWindowIcon(QIcon(str(resource("ui/resources/icon.png"))))

    show_intro_then(ShellWindow, app)

    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())

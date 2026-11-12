"""Shared labels used by several pages."""

from __future__ import annotations

from PyQt6.QtCore import QSize, Qt
from PyQt6.QtWidgets import QLabel, QSizePolicy


class ElidingLabel(QLabel):
    """Label that shortens its text with an ellipsis instead of widening the UI.

    The full text stays available in the widget tooltip.
    """

    def __init__(self, text: str = "", parent=None):
        super().__init__(parent)
        self._full_text = text
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.setText(text)

    def setText(self, text: str):
        self._full_text = text
        self.setToolTip(text)
        super().setText(text)
        self._refresh()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._refresh()

    def sizeHint(self) -> QSize:
        metrics = self.fontMetrics()
        width = metrics.horizontalAdvance(self._full_text or " ")
        return QSize(width, super().sizeHint().height())

    def minimumSizeHint(self) -> QSize:
        return QSize(0, super().minimumSizeHint().height())

    def _refresh(self):
        width = max(0, self.width() - 2)
        elided = self.fontMetrics().elidedText(
            self._full_text, Qt.TextElideMode.ElideMiddle, width
        )
        super().setText(elided)

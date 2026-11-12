"""Small vector icons drawn at runtime.

The sidebar needs a handful of monochrome glyphs. Drawing them with QPainter
keeps the look consistent at any DPI and avoids shipping a set of PNG assets.
"""

from __future__ import annotations

from PyQt6.QtCore import QByteArray, QPointF, QRectF, Qt
from PyQt6.QtGui import QColor, QIcon, QPainter, QPen, QPixmap
from PyQt6.QtSvg import QSvgRenderer


GITHUB_PATH = (
    "M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 "
    "0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 "
    "17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 "
    "1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 "
    "1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 "
    "3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 "
    "3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 "
    "0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"
)


def make_github_icon(color: str = "#8fb3b0", size: int = 20) -> QIcon:
    """Return the GitHub mark rendered from its official vector path."""
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">'
        f'<path fill="{color}" d="{GITHUB_PATH}"/></svg>'
    )
    renderer = QSvgRenderer(QByteArray(svg.encode("utf-8")))
    scale = 2
    pixmap = QPixmap(size * scale, size * scale)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    renderer.render(painter)
    painter.end()
    pixmap.setDevicePixelRatio(scale)
    return QIcon(pixmap)


def make_icon(name: str, color: str = "#8fb3b0", size: int = 20) -> QIcon:
    """Return a crisp outline icon drawn on a 24x24 grid.

    Args:
        name: One of ``dashboard``, ``analysis``, ``reports``, ``queue``,
            ``about`` or ``search``.
        color: Stroke color.
        size: Logical size in pixels.
    """
    scale = 2
    pixels = size * scale
    pixmap = QPixmap(pixels, pixels)
    pixmap.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    painter.scale(pixels / 24.0, pixels / 24.0)

    pen = QPen(QColor(color))
    pen.setWidthF(1.7)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)

    if name == "dashboard":
        for x, y in ((3.5, 3.5), (13.5, 3.5), (3.5, 13.5), (13.5, 13.5)):
            painter.drawRoundedRect(QRectF(x, y, 7, 7), 2, 2)
    elif name == "analysis":
        painter.drawRoundedRect(QRectF(4, 3, 16, 18), 3, 3)
        for y in (8, 12, 16):
            painter.drawLine(QPointF(8, y), QPointF(16, y))
    elif name == "reports":
        for x, top in ((4, 12), (10, 6), (16, 9)):
            painter.drawRoundedRect(QRectF(x, top, 4, 20 - top), 1.2, 1.2)
        painter.drawLine(QPointF(3, 20.5), QPointF(21, 20.5))
    elif name == "queue":
        for y in (6, 12, 18):
            painter.setBrush(QColor(color))
            painter.drawEllipse(QPointF(5.5, y), 1.4, 1.4)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawLine(QPointF(9.5, y), QPointF(20, y))
    elif name in {"about", "info"}:
        painter.drawEllipse(QPointF(12, 12), 8.2, 8.2)
        painter.setBrush(QColor(color))
        painter.drawEllipse(QPointF(12, 8.2), 1.1, 1.1)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawLine(QPointF(12, 11), QPointF(12, 16.5))
    elif name == "search":
        painter.drawEllipse(QPointF(10.5, 10.5), 6.2, 6.2)
        painter.drawLine(QPointF(15.2, 15.2), QPointF(20, 20))
    elif name == "folder":
        painter.drawRoundedRect(QRectF(3.5, 6.5, 17, 12.5), 2, 2)
        painter.drawLine(QPointF(3.5, 10.5), QPointF(20.5, 10.5))
    elif name in {"back", "chevron"}:
        painter.drawLine(QPointF(14.5, 5.5), QPointF(8.5, 12))
        painter.drawLine(QPointF(8.5, 12), QPointF(14.5, 18.5))
    elif name == "refresh":
        painter.drawArc(QRectF(4.5, 4.5, 15, 15), 40 * 16, 280 * 16)
        painter.drawLine(QPointF(18.6, 6.0), QPointF(18.6, 10.2))
        painter.drawLine(QPointF(18.6, 6.0), QPointF(14.4, 6.0))
    elif name in {"open", "external"}:
        painter.drawRoundedRect(QRectF(4, 9, 11, 11), 2, 2)
        painter.drawLine(QPointF(12.5, 4.5), QPointF(19.5, 4.5))
        painter.drawLine(QPointF(19.5, 4.5), QPointF(19.5, 11.5))
        painter.drawLine(QPointF(19.5, 4.5), QPointF(12.0, 12.0))
    else:
        painter.drawEllipse(QPointF(12, 12), 8, 8)

    painter.end()
    pixmap.setDevicePixelRatio(scale)
    return QIcon(pixmap)

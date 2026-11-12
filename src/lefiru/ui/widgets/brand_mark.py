"""Native, lightweight LeFiru brand animation.

The widget paints a living backdrop behind the wordmark: a breathing glow,
a drifting particle field with links, a slow scan band and an orbital halo,
plus a specular sweep across the letters. Everything is drawn with
``QPainter``, so the widget needs no Qt WebEngine and no image assets.

Used by the dashboard hero and the About page.
"""

from __future__ import annotations

import math
import random

from PyQt6.QtCore import QPointF, QRectF, Qt, QTimer
from PyQt6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QRadialGradient,
)
from PyQt6.QtWidgets import QSizePolicy, QWidget

_TAU = math.tau


class BrandMarkWidget(QWidget):
    """Animated LeFiru wordmark with a live backdrop."""

    TICK_MS = 40
    PARTICLE_COUNT = 34
    SCAN_PERIOD = 10.0
    SWEEP_CYCLE = 7.0
    SWEEP_TRAVEL = 6.2

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumHeight(210)
        self.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )
        self._dark = True
        self._clock = 0.0

        # Stable pseudo-random field: rebuilding it every frame would make the
        # particles jitter and cost CPU for nothing.
        rng = random.Random(1103)
        self._particles: tuple[tuple[float, ...], ...] = tuple(
            (
                rng.random(),  # horizontal position (fraction)
                rng.random(),  # vertical position (fraction)
                rng.uniform(0.012, 0.045),  # rising speed (fraction per second)
                rng.uniform(0.7, 2.0),  # dot radius (px)
                rng.uniform(0.0, _TAU),  # phase offset
                rng.uniform(3.0, 9.0),  # horizontal drift (px)
                rng.uniform(0.6, 1.8),  # twinkle speed
            )
            for _ in range(self.PARTICLE_COUNT)
        )

        self._timer = QTimer(self)
        self._timer.setInterval(self.TICK_MS)
        self._timer.timeout.connect(self._tick)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def set_dark_mode(self, dark: bool) -> None:
        self._dark = dark
        self.update()

    def showEvent(self, event) -> None:  # noqa: N802 - Qt naming
        self._timer.start()
        super().showEvent(event)

    def hideEvent(self, event) -> None:  # noqa: N802 - Qt naming
        self._timer.stop()
        super().hideEvent(event)

    def _tick(self) -> None:
        # No wrap-around: modding the clock would make every cycle-driven
        # animation jump once the counter reset.
        self._clock += self.TICK_MS / 1000.0
        self.update()

    # ------------------------------------------------------------------
    # Painting
    # ------------------------------------------------------------------
    def paintEvent(self, event) -> None:  # noqa: N802 - Qt naming
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing, True)

        rect = QRectF(self.rect())
        if rect.width() < 4 or rect.height() < 4:
            painter.end()
            return

        accent = QColor("#43e6c8") if self._dark else QColor("#129b8b")
        text_light = QColor("#f2fcff") if self._dark else QColor("#0c2724")
        text_muted = QColor(150, 190, 188) if self._dark else QColor(72, 106, 102)
        intensity = 1.0 if self._dark else 0.72

        path, font = self._wordmark_path(rect)
        bounds = path.boundingRect()

        self._paint_backdrop(painter, rect, accent, bounds, intensity)
        self._paint_wordmark(painter, path, accent, text_light, intensity)
        self._paint_sweep(painter, rect, path, intensity)
        self._paint_subtitle(painter, rect, bounds, font, text_muted)

        painter.end()

    def _wordmark_path(self, rect: QRectF) -> tuple[QPainterPath, QFont]:
        font = QFont("Segoe UI")
        font.setWeight(QFont.Weight.DemiBold)
        font.setPixelSize(max(28, int(min(rect.height() * 0.32, rect.width() * 0.145))))
        font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 1.2)

        path = QPainterPath()
        path.addText(0.0, 0.0, font, "LeFiru")
        target = QPointF(rect.center().x(), rect.center().y() - rect.height() * 0.05)
        path.translate(target - path.boundingRect().center())
        return path, font

    # -- backdrop ------------------------------------------------------
    def _paint_backdrop(
        self,
        painter: QPainter,
        rect: QRectF,
        accent: QColor,
        bounds: QRectF,
        intensity: float,
    ) -> None:
        t = self._clock
        red, green, blue = accent.red(), accent.green(), accent.blue()
        center = bounds.center()

        painter.setPen(Qt.PenStyle.NoPen)

        # Breathing bloom: one wide halo plus two smaller drifting ones.
        blooms = (
            (0.00, -0.02, 0.62, 26, 0.55),
            (-0.24, 0.06, 0.40, 13, 0.33),
            (0.26, -0.05, 0.36, 11, 0.41),
        )
        for index, (du, dv, scale, alpha, speed) in enumerate(blooms):
            drift_x = rect.width() * du + math.sin(t * speed + index * 1.7) * rect.height() * 0.03
            drift_y = rect.height() * dv + math.cos(t * speed * 0.8 + index) * rect.height() * 0.04
            radius = max(
                rect.height() * scale * (1.0 + 0.06 * math.sin(t * speed * 1.4 + index)),
                1.0,
            )
            gradient = QRadialGradient(center + QPointF(drift_x, drift_y), radius)
            gradient.setColorAt(0.0, QColor(red, green, blue, int(alpha * intensity)))
            gradient.setColorAt(0.55, QColor(red, green, blue, int(alpha * 0.35 * intensity)))
            gradient.setColorAt(1.0, QColor(red, green, blue, 0))
            painter.setBrush(QBrush(gradient))
            painter.drawEllipse(center + QPointF(drift_x, drift_y), radius, radius)

        # Particle field with proximity links.
        points: list[tuple[float, float, float, int]] = []
        for x0, y0, speed, radius, phase, drift, twinkle in self._particles:
            x = rect.left() + rect.width() * x0 + math.sin(t * 0.35 + phase) * drift
            travel = (y0 - speed * t) % 1.0
            y = rect.top() + rect.height() * travel
            alpha = 30 + 45 * (0.5 + 0.5 * math.sin(t * twinkle + phase))
            points.append((x, y, radius, int(alpha * intensity)))

        for i, (xi, yi, _, _) in enumerate(points):
            for xj, yj, _, _ in points[i + 1 :]:
                dx, dy = xj - xi, yj - yi
                distance_sq = dx * dx + dy * dy
                if distance_sq < 4900.0:  # 70 px
                    fade = 1.0 - math.sqrt(distance_sq) / 70.0
                    painter.setPen(QPen(QColor(red, green, blue, int(26 * fade * intensity)), 1.0))
                    painter.drawLine(QPointF(xi, yi), QPointF(xj, yj))

        painter.setPen(Qt.PenStyle.NoPen)
        for x, y, radius, alpha in points:
            painter.setBrush(QColor(red, green, blue, max(alpha // 5, 3)))
            painter.drawEllipse(QPointF(x, y), radius * 2.6, radius * 2.6)
            painter.setBrush(QColor(red, green, blue, alpha))
            painter.drawEllipse(QPointF(x, y), radius, radius)

        # Slow scan band travelling from top to bottom.
        travel = (t % self.SCAN_PERIOD) / self.SCAN_PERIOD
        band_top = rect.top() - rect.height() * 0.2 + rect.height() * 1.4 * travel
        band_height = rect.height() * (0.14 if self._dark else 0.09)
        band = QLinearGradient(0.0, band_top, 0.0, band_top + band_height)
        band.setColorAt(0.0, QColor(red, green, blue, 0))
        band.setColorAt(0.5, QColor(red, green, blue, int((16 if self._dark else 5) * intensity)))
        band.setColorAt(1.0, QColor(red, green, blue, 0))
        painter.setBrush(QBrush(band))
        painter.drawRect(rect)

        self._paint_orbit(painter, bounds, accent, intensity)

    def _paint_orbit(
        self,
        painter: QPainter,
        bounds: QRectF,
        accent: QColor,
        intensity: float,
    ) -> None:
        t = self._clock
        red, green, blue = accent.red(), accent.green(), accent.blue()

        painter.save()
        painter.translate(bounds.center())
        painter.rotate(-12.0)

        radius_x = max(bounds.width() * 0.64, bounds.height() * 2.1)
        radius_y = radius_x * 0.33
        arc_rect = QRectF(-radius_x, -radius_y, radius_x * 2.0, radius_y * 2.0)

        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(QPen(QColor(red, green, blue, int(38 * intensity)), 1.0))
        painter.drawEllipse(QPointF(0.0, 0.0), radius_x, radius_y)

        start = int((t * 42.0) % 360.0 * 16)
        painter.setPen(
            QPen(
                QColor(red, green, blue, int(120 * intensity)),
                2.0,
                Qt.PenStyle.SolidLine,
                Qt.PenCapStyle.RoundCap,
            )
        )
        painter.drawArc(arc_rect, start, 58 * 16)
        painter.setPen(
            QPen(
                QColor(red, green, blue, int(65 * intensity)),
                1.3,
                Qt.PenStyle.SolidLine,
                Qt.PenCapStyle.RoundCap,
            )
        )
        painter.drawArc(arc_rect, int(180 * 16 - start * 0.5), 34 * 16)

        painter.setPen(Qt.PenStyle.NoPen)
        for index in range(3):
            angle = t * 0.55 + index * _TAU / 3.0
            point = QPointF(radius_x * math.cos(angle), radius_y * math.sin(angle))
            pulse = 5.0 + 1.5 * math.sin(t * 1.2 + index)
            painter.setBrush(QColor(red, green, blue, int(22 * intensity)))
            painter.drawEllipse(point, pulse, pulse)
            painter.setBrush(QColor(red, green, blue, int(200 * intensity)))
            painter.drawEllipse(point, 2.2, 2.2)

        painter.restore()

    # -- foreground ----------------------------------------------------
    def _paint_wordmark(
        self,
        painter: QPainter,
        path: QPainterPath,
        accent: QColor,
        text_light: QColor,
        intensity: float,
    ) -> None:
        red, green, blue = accent.red(), accent.green(), accent.blue()
        breath = 0.5 + 0.5 * math.sin(self._clock * 1.15)

        painter.setBrush(Qt.BrushStyle.NoBrush)
        for width, alpha in ((20.0, 7), (12.0, 13), (6.0, 22)):
            painter.setPen(
                QPen(
                    QColor(red, green, blue, int((alpha + 6 * breath) * intensity)),
                    width,
                    Qt.PenStyle.SolidLine,
                    Qt.PenCapStyle.RoundCap,
                    Qt.PenJoinStyle.RoundJoin,
                )
            )
            painter.drawPath(path)

        bounds = path.boundingRect()
        fill = QLinearGradient(0.0, bounds.top(), 0.0, bounds.bottom())
        fill.setColorAt(0.0, text_light)
        fill.setColorAt(0.58, text_light)
        fill.setColorAt(1.0, accent.lighter(118) if self._dark else accent.darker(108))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(fill))
        painter.drawPath(path)

    def _paint_sweep(
        self,
        painter: QPainter,
        rect: QRectF,
        path: QPainterPath,
        intensity: float,
    ) -> None:
        progress = (self._clock % self.SWEEP_CYCLE) / self.SWEEP_TRAVEL
        if progress > 1.0:
            return

        x = rect.left() - rect.width() * 0.1 + rect.width() * 1.2 * progress
        half_band = max(rect.width() * 0.045, 14.0)
        gradient = QLinearGradient(x - half_band, 0.0, x + half_band, 0.0)
        shine = QColor(214, 255, 246) if self._dark else QColor(18, 155, 139)
        gradient.setColorAt(0.0, QColor(shine.red(), shine.green(), shine.blue(), 0))
        gradient.setColorAt(
            0.5,
            QColor(
                shine.red(),
                shine.green(),
                shine.blue(),
                int((150 if self._dark else 130) * intensity),
            ),
        )
        gradient.setColorAt(1.0, QColor(shine.red(), shine.green(), shine.blue(), 0))

        painter.save()
        painter.setClipPath(path)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(gradient))
        painter.drawRect(rect)
        painter.restore()

    def _paint_subtitle(
        self,
        painter: QPainter,
        rect: QRectF,
        bounds: QRectF,
        font: QFont,
        text_muted: QColor,
    ) -> None:
        subtitle = QFont("Segoe UI")
        subtitle.setPixelSize(max(8, int(font.pixelSize() * 0.17)))
        subtitle.setWeight(QFont.Weight.Medium)
        subtitle.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 5.0)
        painter.setFont(subtitle)
        painter.setPen(text_muted)
        painter.drawText(
            QRectF(
                rect.left(),
                bounds.bottom() + rect.height() * 0.06,
                rect.width(),
                rect.height() * 0.1,
            ),
            Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter,
            "SECURITY  ANALYZER",
        )

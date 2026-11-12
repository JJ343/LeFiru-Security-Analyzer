"""Animated intro shown before the main window.

The splash draws its own wordmark with QPainter so it needs no image assets:
the "LeFiru" text fades in, lights up with a teal glow, receives a light
sweep and finally hands control over to the application.
"""

from __future__ import annotations

from PyQt6.QtCore import (
    QEasingCurve,
    QPropertyAnimation,
    QRectF,
    Qt,
    QTimer,
    pyqtProperty,
    pyqtSignal,
)
from PyQt6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QFontMetricsF,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QRadialGradient,
)
from PyQt6.QtWidgets import QApplication, QWidget

from lefiru import __version__


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def _smoothstep(edge0: float, edge1: float, value: float) -> float:
    if edge1 <= edge0:
        return 1.0 if value >= edge1 else 0.0
    t = _clamp((value - edge0) / (edge1 - edge0))
    return t * t * (3.0 - 2.0 * t)


def _mix(start: QColor, end: QColor, amount: float) -> QColor:
    amount = _clamp(amount)
    return QColor(
        round(start.red() + (end.red() - start.red()) * amount),
        round(start.green() + (end.green() - start.green()) * amount),
        round(start.blue() + (end.blue() - start.blue()) * amount),
        round(start.alpha() + (end.alpha() - start.alpha()) * amount),
    )


class IntroSplash(QWidget):
    """Frameless, animated introduction for the desktop application."""

    # Emitted when the intro animation has finished and the application may
    # build its main window.
    intro_finished = pyqtSignal()
    # Emitted after the fade-out, when the main window should be shown.
    finished = pyqtSignal()

    INTRO_DURATION = 2850
    FADE_IN_DURATION = 550
    FADE_OUT_DURATION = 420

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(
            parent,
            Qt.WindowType.SplashScreen
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint,
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setWindowTitle("LeFiru Security Analyzer")

        self._progress = 0.0
        self._pulse = 0.0
        self._waiting = False
        self._closing = False

        self._resize_and_center()
        self._intro_anim: QPropertyAnimation | None = None
        self._pulse_anim: QPropertyAnimation | None = None
        self._fade_anim: QPropertyAnimation | None = None

    # ------------------------------------------------------------------
    # Animatable properties
    # ------------------------------------------------------------------
    def _get_progress(self) -> float:
        return self._progress

    def _set_progress(self, value: float) -> None:
        self._progress = _clamp(value)
        self.update()

    progress = pyqtProperty(float, fget=_get_progress, fset=_set_progress)

    def _get_pulse(self) -> float:
        return self._pulse

    def _set_pulse(self, value: float) -> None:
        self._pulse = _clamp(value)
        if self._waiting:
            self.update()

    pulse = pyqtProperty(float, fget=_get_pulse, fset=_set_pulse)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        """Show the splash and start the intro sequence."""
        self.setWindowOpacity(0.0)
        self.show()
        self.raise_()
        self.activateWindow()
        self.setFocus()

        fade_in = QPropertyAnimation(self, b"windowOpacity", self)
        fade_in.setStartValue(0.0)
        fade_in.setEndValue(1.0)
        fade_in.setDuration(self.FADE_IN_DURATION)
        fade_in.setEasingCurve(QEasingCurve.Type.OutCubic)
        fade_in.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)
        self._fade_in_anim = fade_in

        self._intro_anim = QPropertyAnimation(self, b"progress", self)
        self._intro_anim.setStartValue(0.0)
        self._intro_anim.setEndValue(1.0)
        self._intro_anim.setDuration(self.INTRO_DURATION)
        self._intro_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._intro_anim.finished.connect(self._on_intro_finished)
        self._intro_anim.start()

    def _on_intro_finished(self) -> None:
        if self._closing:
            return
        self._waiting = True
        self._start_pulse()
        # The application builds the main window while the wordmark keeps
        # breathing; once it is ready `dismiss()` fades the splash out.
        self.intro_finished.emit()

    def _start_pulse(self) -> None:
        self._pulse_anim = QPropertyAnimation(self, b"pulse", self)
        self._pulse_anim.setStartValue(0.0)
        self._pulse_anim.setEndValue(1.0)
        self._pulse_anim.setDuration(1300)
        self._pulse_anim.setEasingCurve(QEasingCurve.Type.InOutSine)
        self._pulse_anim.setLoopCount(-1)
        self._pulse_anim.start()

    def dismiss(self) -> None:
        """Fade the splash out and let the main window take over."""
        if self._closing:
            return
        self._closing = True
        if self._pulse_anim is not None:
            self._pulse_anim.stop()

        self._fade_anim = QPropertyAnimation(self, b"windowOpacity", self)
        self._fade_anim.setStartValue(self.windowOpacity())
        self._fade_anim.setEndValue(0.0)
        self._fade_anim.setDuration(self.FADE_OUT_DURATION)
        self._fade_anim.setEasingCurve(QEasingCurve.Type.InCubic)
        self._fade_anim.finished.connect(self._on_fade_out_finished)
        self._fade_anim.start()

    def _on_fade_out_finished(self) -> None:
        self.finished.emit()
        self.close()

    # ------------------------------------------------------------------
    # Input: clicking or pressing Esc skips the intro
    # ------------------------------------------------------------------
    def mousePressEvent(self, event) -> None:  # noqa: N802 - Qt naming
        if not self._waiting:
            self._skip()
        super().mousePressEvent(event)

    def keyPressEvent(self, event) -> None:  # noqa: N802 - Qt naming
        if event.key() in (Qt.Key.Key_Escape, Qt.Key.Key_Space, Qt.Key.Key_Return):
            self._skip()
            return
        super().keyPressEvent(event)

    def _skip(self) -> None:
        if self._closing:
            return
        if self._intro_anim is not None:
            self._intro_anim.stop()
        self._set_progress(1.0)
        self._on_intro_finished()

    # ------------------------------------------------------------------
    # Geometry
    # ------------------------------------------------------------------
    def _resize_and_center(self) -> None:
        screen = QApplication.primaryScreen()
        available = screen.availableGeometry() if screen is not None else None
        if available is None:
            self.resize(960, 560)
            return

        width = int(min(1040, max(720, available.width() * 0.72)))
        height = int(min(580, max(430, available.height() * 0.62)))
        self.resize(width, height)
        frame = self.frameGeometry()
        frame.moveCenter(available.center())
        self.move(frame.topLeft())

    # ------------------------------------------------------------------
    # Painting
    # ------------------------------------------------------------------
    def paintEvent(self, event) -> None:  # noqa: N802 - Qt naming
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing, True)

        card = QRectF(self.rect()).adjusted(30, 30, -30, -30)
        self._paint_shadow(painter, card)
        self._paint_background(painter, card)
        self._paint_wordmark(painter, card)
        painter.end()

    def _paint_shadow(self, painter: QPainter, card: QRectF) -> None:
        painter.setPen(Qt.PenStyle.NoPen)
        for step in range(18, 0, -1):
            alpha = int(2 + (18 - step) * 1.1)
            painter.setBrush(QColor(0, 0, 0, alpha))
            painter.drawRoundedRect(
                card.adjusted(-step * 1.2, -step * 1.2, step * 1.2, step * 1.2),
                30 + step,
                30 + step,
            )

    def _paint_background(self, painter: QPainter, card: QRectF) -> None:
        painter.setPen(Qt.PenStyle.NoPen)

        base = QLinearGradient(card.topLeft(), card.bottomRight())
        base.setColorAt(0.0, QColor("#0d1319"))
        base.setColorAt(0.55, QColor("#0a0f14"))
        base.setColorAt(1.0, QColor("#070a0d"))
        painter.setBrush(QBrush(base))
        painter.drawRoundedRect(card, 28, 28)

        lit = _smoothstep(0.05, 0.75, self._progress)
        halo = QRadialGradient(card.center(), card.width() * 0.52)
        halo.setColorAt(0.0, QColor(46, 220, 196, int(34 * lit)))
        halo.setColorAt(0.45, QColor(28, 130, 145, int(16 * lit)))
        halo.setColorAt(1.0, QColor(0, 0, 0, 0))
        painter.setBrush(QBrush(halo))
        painter.drawRoundedRect(card, 28, 28)

        border = QPen(QColor(112, 235, 214, int(22 + 18 * lit)), 1.0)
        painter.setPen(border)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRoundedRect(card.adjusted(0.5, 0.5, -0.5, -0.5), 28, 28)

    def _paint_wordmark(self, painter: QPainter, card: QRectF) -> None:
        scale = card.height() / 520.0
        font = QFont("Segoe UI")
        font.setWeight(QFont.Weight.DemiBold)
        font.setPixelSize(int(min(card.height() * 0.215, card.width() * 0.155)))
        font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 1.5 * scale)

        path = QPainterPath()
        path.addText(0.0, 0.0, font, "LeFiru")
        bounds = path.boundingRect()
        if bounds.width() > card.width() * 0.78:
            factor = (card.width() * 0.78) / bounds.width()
            font.setPixelSize(max(24, int(font.pixelSize() * factor)))
            path = QPainterPath()
            path.addText(0.0, 0.0, font, "LeFiru")
            bounds = path.boundingRect()

        target = card.center()
        target.setY(card.center().y() - card.height() * 0.055)
        offset = target - bounds.center()
        path.translate(offset)

        lit = _smoothstep(0.12, 0.72, self._progress)
        pulse = 0.5 + 0.5 * self._pulse if self._waiting else 0.0
        glow = _clamp(lit + 0.18 * pulse)

        # Soft teal halo: several wide strokes behind the glyphs.
        painter.setBrush(Qt.BrushStyle.NoBrush)
        for width, alpha in ((34.0, 8), (22.0, 14), (13.0, 24), (7.0, 36)):
            pen = QPen(
                QColor(62, 238, 212, int(alpha * glow)),
                width * scale,
                Qt.PenStyle.SolidLine,
                Qt.PenCapStyle.RoundCap,
                Qt.PenJoinStyle.RoundJoin,
            )
            painter.setPen(pen)
            painter.drawPath(path)

        # Fill: dim steel -> warm white with a cool lower edge.
        top = _mix(QColor("#33414c"), QColor("#f6fdff"), lit)
        middle = _mix(QColor("#2b3841"), QColor("#ffffff"), lit)
        bottom = _mix(QColor("#202b33"), QColor("#9fe8dc"), lit)
        fill = QLinearGradient(0.0, path.boundingRect().top(), 0.0, path.boundingRect().bottom())
        fill.setColorAt(0.0, top)
        fill.setColorAt(0.55, middle)
        fill.setColorAt(1.0, bottom)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(fill))
        painter.drawPath(path)

        # Light sweep crossing the wordmark once it is lit.
        sweep = _clamp((self._progress - 0.36) / 0.52)
        if 0.0 < sweep < 1.0:
            easing = sweep * sweep * (3.0 - 2.0 * sweep)
            band_width = max(40.0, path.boundingRect().width() * 0.18)
            center_x = (
                path.boundingRect().left()
                - band_width
                + (path.boundingRect().width() + 2 * band_width) * easing
            )
            shine = QLinearGradient(
                center_x - band_width, 0.0, center_x + band_width, 0.0
            )
            strength = int(210 * (1.0 - abs(0.5 - sweep) * 0.7))
            shine.setColorAt(0.0, QColor(255, 255, 255, 0))
            shine.setColorAt(0.5, QColor(220, 255, 250, strength))
            shine.setColorAt(1.0, QColor(255, 255, 255, 0))

            painter.save()
            painter.setClipPath(path)
            painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_Screen)
            painter.fillRect(path.boundingRect(), QBrush(shine))
            painter.restore()

        self._paint_tagline(painter, card, path.boundingRect(), scale, lit)
        self._paint_progress(painter, card, path.boundingRect(), scale, lit)

    def _paint_tagline(
        self,
        painter: QPainter,
        card: QRectF,
        word: QRectF,
        scale: float,
        lit: float,
    ) -> None:
        alpha = _smoothstep(0.5, 0.9, self._progress)
        if alpha <= 0:
            return

        font = QFont("Segoe UI")
        font.setPixelSize(max(9, int(11 * scale)))
        font.setWeight(QFont.Weight.Medium)
        font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 7.0 * scale)
        painter.setFont(font)
        painter.setPen(QColor(156, 206, 204, int(205 * alpha)))
        painter.drawText(
            QRectF(card.left(), word.bottom() + 30 * scale, card.width(), 28 * scale),
            Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter,
            "SECURITY  ANALYZER",
        )

        version_font = QFont("Segoe UI")
        version_font.setPixelSize(max(8, int(9 * scale)))
        version_font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 1.6 * scale)
        painter.setFont(version_font)
        painter.setPen(QColor(120, 150, 154, int(140 * alpha)))
        painter.drawText(
            QRectF(
                card.left(),
                card.bottom() - 34 * scale,
                card.width() - 30 * scale,
                20 * scale,
            ),
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
            f"v{__version__}",
        )

    def _paint_progress(
        self,
        painter: QPainter,
        card: QRectF,
        word: QRectF,
        scale: float,
        lit: float,
    ) -> None:
        track_width = min(card.width() * 0.38, 340 * scale)
        track = QRectF(
            card.center().x() - track_width / 2,
            word.bottom() + 84 * scale,
            track_width,
            3.0 * scale,
        )

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(210, 240, 235, int(20 * lit)))
        painter.drawRoundedRect(track, 1.5 * scale, 1.5 * scale)

        fill_width = track_width * _smoothstep(0.18, 0.95, self._progress)
        if fill_width <= 0:
            return

        filled = QRectF(track.left(), track.top(), fill_width, track.height())
        bar = QLinearGradient(filled.topLeft(), filled.topRight())
        bar.setColorAt(0.0, QColor(42, 140, 144, int(210 * lit)))
        bar.setColorAt(1.0, QColor(120, 255, 226, int(235 * lit)))
        painter.setBrush(QBrush(bar))
        painter.drawRoundedRect(filled, 1.5 * scale, 1.5 * scale)

        if self._waiting:
            glow_rect = QRectF(
                filled.right() - 8 * scale,
                filled.top() - 2 * scale,
                16 * scale,
                filled.height() + 4 * scale,
            )
            pulse_alpha = int(110 + 90 * self._pulse)
            painter.setBrush(QColor(140, 255, 232, pulse_alpha))
            painter.drawRoundedRect(glow_rect, 3 * scale, 3 * scale)

    # Keep a reference so the animation is not garbage-collected.
    _fade_in_anim: QPropertyAnimation | None = None

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt naming
        for animation in (self._intro_anim, self._pulse_anim, self._fade_anim):
            if animation is not None:
                animation.stop()
        # Closing the splash by other means (Alt+F4) must not leave the
        # application without a visible window.
        if not self._closing:
            self._closing = True
            self.finished.emit()
        super().closeEvent(event)


def show_intro_then(window_factory, app: QApplication | None = None) -> None:
    """Run the intro and call ``window_factory`` while it is on screen.

    ``window_factory`` must return the main window. The splash stays visible
    until the window is ready, then fades out and the window is shown.
    """

    application = app or QApplication.instance()
    if application is None:
        raise RuntimeError("A QApplication instance is required")

    previous_quit_policy = application.quitOnLastWindowClosed()
    application.setQuitOnLastWindowClosed(False)

    splash = IntroSplash()
    state: dict[str, object] = {"window": None, "splash": splash}
    # Keep a Python reference to the splash and the main window. They are
    # parentless top-level widgets: if this state only lived in local closures
    # they could be garbage-collected right after the splash closes, destroying
    # the main window and quitting the application.
    application._lefiru_intro_state = state

    def build_main_window() -> None:
        # Building the window can take a moment; the splash keeps its lit
        # state on screen while this runs.
        state["window"] = window_factory()
        QTimer.singleShot(60, splash.dismiss)

    def reveal_main_window() -> None:
        window = state["window"]
        if window is None:
            # The splash was closed before the main window was built.
            window = window_factory()
            state["window"] = window
        window.show()
        window.raise_()
        window.activateWindow()
        application.setQuitOnLastWindowClosed(previous_quit_policy)

    splash.intro_finished.connect(build_main_window)
    splash.finished.connect(reveal_main_window)
    splash.start()

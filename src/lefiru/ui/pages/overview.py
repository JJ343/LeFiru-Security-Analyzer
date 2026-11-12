from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from lefiru.ui.widgets.brand_mark import BrandMarkWidget


class QuickActionCard(QFrame):
    """Clickable card used for the dashboard quick actions."""

    clicked = pyqtSignal()

    def __init__(
        self,
        title: str,
        description: str,
        hint: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("action_card")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(132)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 14)
        layout.setSpacing(6)

        title_label = QLabel(title, self)
        title_label.setObjectName("action_title")
        description_label = QLabel(description, self)
        description_label.setObjectName("action_description")
        description_label.setWordWrap(True)
        hint_label = QLabel(hint, self)
        hint_label.setObjectName("action_hint")

        for label in (title_label, description_label, hint_label):
            label.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)

        layout.addWidget(title_label)
        layout.addWidget(description_label)
        layout.addStretch()
        layout.addWidget(hint_label)

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802 - Qt naming
        if event.button() == Qt.MouseButton.LeftButton and self.rect().contains(event.pos()):
            self.clicked.emit()
        super().mouseReleaseEvent(event)


class OverviewPage(QWidget):
    # Signal to navigate to another page from a quick action card
    navigate_requested = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(36, 26, 36, 26)
        main_layout.setSpacing(18)

        # --------------------------------------------------------------
        # Header
        # --------------------------------------------------------------
        header = QHBoxLayout()
        header.setSpacing(12)

        heading = QVBoxLayout()
        heading.setSpacing(2)

        title = QLabel("Dashboard")
        title.setObjectName("page_title")
        subtitle = QLabel("Security analysis workspace")
        subtitle.setObjectName("page_subtitle")

        heading.addWidget(title)
        heading.addWidget(subtitle)

        header.addLayout(heading)

        main_layout.addLayout(header)

        # --------------------------------------------------------------
        # Hero
        # --------------------------------------------------------------
        hero = QFrame()
        hero.setObjectName("hero_card")
        hero_layout = QVBoxLayout(hero)
        hero_layout.setContentsMargins(24, 18, 24, 20)
        hero_layout.setSpacing(2)

        self.brand_mark = BrandMarkWidget(hero)
        self.brand_mark.setFixedHeight(220)
        hero_layout.addWidget(self.brand_mark)

        hero_caption = QLabel(
            "Security analysis for Excel workbooks and Python code"
        )
        hero_caption.setObjectName("page_subtitle")
        hero_caption.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hero_layout.addWidget(hero_caption)

        main_layout.addWidget(hero)

        # --------------------------------------------------------------
        # Quick actions
        # --------------------------------------------------------------
        actions_label = QLabel("QUICK ACTIONS")
        actions_label.setObjectName("page_subtitle")
        main_layout.addWidget(actions_label)

        actions = QHBoxLayout()
        actions.setSpacing(14)

        self.excel_card = QuickActionCard(
            "Analyze files",
            "Excel workbooks and Python code · protections, VBA, formulas, "
            "connections, AST rules and evidence.",
            "Open analysis  →",
            self,
        )
        self.reports_card = QuickActionCard(
            "Reports",
            "Browse JSON, LaTeX/PDF reports and generated evidence.",
            "View reports  →",
            self,
        )

        self.excel_card.clicked.connect(
            lambda: self.navigate_requested.emit("analysis")
        )
        self.reports_card.clicked.connect(
            lambda: self.navigate_requested.emit("reports")
        )

        actions.addWidget(self.excel_card, 1)
        actions.addWidget(self.reports_card, 1)
        main_layout.addLayout(actions)

        main_layout.addStretch()

    def set_dark_mode(self, dark_mode: bool) -> None:
        """Keep the dashboard brand animation in sync with the theme."""
        self.brand_mark.set_dark_mode(dark_mode)

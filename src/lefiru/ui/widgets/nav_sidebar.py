from PyQt6.QtCore import QSize, Qt, pyqtSignal
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from lefiru.paths import resource
from lefiru.ui.widgets.icons import make_icon


class SidebarNavItem(QFrame):
    """Sidebar row with an icon badge, a title and a subtitle."""

    activated = pyqtSignal(str)

    def __init__(self, key, title, subtitle, icon_name, parent=None):
        super().__init__(parent)
        self.key = key
        self._title = title
        self._subtitle = subtitle
        self._icon_name = icon_name

        self.setObjectName("nav_item")
        self.setProperty("active", False)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setAttribute(Qt.WidgetAttribute.WA_Hover, True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        row = QHBoxLayout(self)
        row.setContentsMargins(8, 7, 8, 7)
        row.setSpacing(10)

        badge = QLabel(self)
        badge.setObjectName("nav_icon")
        badge.setFixedSize(30, 30)
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._badge = badge
        self._paint_badge()

        text = QVBoxLayout()
        text.setSpacing(0)
        title_label = QLabel(title, self)
        title_label.setObjectName("nav_title")
        subtitle_label = QLabel(subtitle, self)
        subtitle_label.setObjectName("nav_subtitle")
        text.addWidget(title_label)
        text.addWidget(subtitle_label)

        row.addWidget(badge)
        row.addLayout(text, 1)

    def search_text(self) -> str:
        return f"{self._title} {self._subtitle}".lower()

    def set_active(self, active: bool):
        active = bool(active)
        if self.property("active") == active:
            return
        self.setProperty("active", active)
        self._paint_badge()
        style = self.style()
        style.unpolish(self)
        style.polish(self)
        self.update()

    def _paint_badge(self):
        color = "#43e6c8" if self.property("active") else "#8fb3b0"
        self._badge.setPixmap(make_icon(self._icon_name, color, 18).pixmap(18, 18))

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and self.rect().contains(
            event.position().toPoint()
        ):
            self.activated.emit(self.key)
        super().mouseReleaseEvent(event)


class NavigationSidebar(QWidget):
    """Floating sidebar: profile header, icon tabs, search and page list."""

    page_requested = pyqtSignal(str)
    queue_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)

        self.setObjectName("sidebar")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setFixedWidth(252)

        self._nav_items: dict[str, SidebarNavItem] = {}
        self._sections: dict[str, tuple[QWidget, list[SidebarNavItem]]] = {}

        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 10, 10, 12)
        outer.setSpacing(0)

        card = QFrame(self)
        card.setObjectName("sidebar_card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(14, 16, 14, 14)
        card_layout.setSpacing(10)

        card_layout.addWidget(self._build_profile())

        workspace_items = [
            self._make_item("dashboard", "Dashboard", "Overview", "dashboard"),
            self._make_item("analysis", "Analyze files", "Excel and Python", "analysis"),
            self._make_item("reports", "Reports", "JSON and PDF", "reports"),
        ]
        system_items = [
            self._make_item("queue", "Analysis queue", "Live progress", "queue"),
            self._make_item("about", "About the tool", "Version and help", "about"),
        ]

        workspace_header = self._section_header("WORKSPACE", len(workspace_items))
        system_header = self._section_header("SYSTEM", len(system_items))
        self._sections = {
            "workspace": (workspace_header, workspace_items),
            "system": (system_header, system_items),
        }

        card_layout.addWidget(workspace_header)
        for item in workspace_items:
            card_layout.addWidget(item)
        card_layout.addWidget(system_header)
        for item in system_items:
            card_layout.addWidget(item)
        card_layout.addStretch()

        outer.addWidget(card)

    # ------------------------------------------------------------------
    # Builders
    # ------------------------------------------------------------------
    def _build_profile(self) -> QWidget:
        profile = QFrame(self)
        profile.setObjectName("sidebar_profile")
        row = QHBoxLayout(profile)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(10)

        avatar = QLabel(profile)
        avatar.setObjectName("profile_avatar")
        avatar.setFixedSize(40, 40)
        avatar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo = resource("ui/resources/icon.png")
        if logo.exists():
            avatar.setPixmap(
                QPixmap(str(logo)).scaled(
                    28,
                    28,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )
            )
        self.brand_icon = avatar

        dot = QLabel(avatar)
        dot.setObjectName("profile_dot")
        dot.setFixedSize(10, 10)
        dot.move(28, 28)

        text = QVBoxLayout()
        text.setSpacing(1)
        name = QLabel("LeFiru", profile)
        name.setObjectName("profile_name")
        status = QLabel("Ready · Security workspace", profile)
        status.setObjectName("profile_status")
        text.addWidget(name)
        text.addWidget(status)

        about = QPushButton(profile)
        about.setObjectName("sidebar_ghost_icon")
        about.setIcon(make_icon("about", "#8fb3b0", 18))
        about.setIconSize(QSize(18, 18))
        about.setFixedSize(30, 30)
        about.setCursor(Qt.CursorShape.PointingHandCursor)
        about.setToolTip("About the tool")
        about.clicked.connect(lambda: self.page_requested.emit("about"))

        row.addWidget(avatar)
        row.addLayout(text, 1)
        row.addWidget(about, 0, Qt.AlignmentFlag.AlignTop)
        return profile

    def _section_header(self, text: str, count: int) -> QWidget:
        header = QFrame(self)
        header.setObjectName("sidebar_section_row")
        row = QHBoxLayout(header)
        row.setContentsMargins(8, 8, 8, 0)
        row.setSpacing(6)

        label = QLabel(text, header)
        label.setObjectName("sidebar_section")
        count_label = QLabel(str(count), header)
        count_label.setObjectName("sidebar_section_count")

        row.addWidget(label)
        row.addStretch()
        row.addWidget(count_label)
        return header

    def _make_item(self, key, title, subtitle, icon_name) -> SidebarNavItem:
        item = SidebarNavItem(key, title, subtitle, icon_name, self)
        if key == "queue":
            item.activated.connect(lambda _key: self.queue_requested.emit())
        else:
            item.activated.connect(self.page_requested.emit)
        self._nav_items[key] = item
        return item

    # ------------------------------------------------------------------
    # Active state
    # ------------------------------------------------------------------
    def set_active_page(self, page_name: str):
        for name, item in self._nav_items.items():
            item.set_active(name == page_name)

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------
    def set_dark_mode(self, dark: bool) -> None:
        """Kept for compatibility: the application only ships a dark theme."""
        return

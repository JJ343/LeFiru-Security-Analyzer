from PyQt6.QtWidgets import (
    QWidget,
    QHBoxLayout,
    QStackedWidget
)
from PyQt6.QtCore import Qt

from lefiru.ui.widgets.nav_sidebar import NavigationSidebar
from lefiru.ui.theme import dark_style
from lefiru.ui.pages.overview import OverviewPage
from lefiru.ui.pages.analysis import AnalysisPage
from lefiru.ui.pages.reports import ReportsPage
from lefiru.ui.pages.product_info import ProductInfoPage
from lefiru.ui.pages.analysis_queue import AnalysisQueueDialog

class ApplicationShell(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("LeFiru Security Analyzer")
        self.resize(1440, 860)
        self.setObjectName("app_shell")
        # Custom QWidget subclasses only paint the stylesheet background when
        # this attribute is enabled; without it the native white shows through
        # around the floating sidebar card.
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)

        # Theme state
        self.dark_mode = True

        # Main layout
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # NavigationSidebar
        self.sidebar = NavigationSidebar(self)

        # Page stack
        self.stack = QStackedWidget(self)
        self.stack.setObjectName("content")

        # Pages
        self.pages = {
            "dashboard": OverviewPage(self),
            "analysis": AnalysisPage(self),
            "reports": ReportsPage(self),
            "about": ProductInfoPage(self),
        }

        for page in self.pages.values():
            self.stack.addWidget(page)

        # Queue popup: aggregates the status of the unified analysis run
        self.queue_dialog = AnalysisQueueDialog(
            self.pages["analysis"],
            self,
        )

        # Connections
        self.sidebar.page_requested.connect(self.show_page)
        self.sidebar.queue_requested.connect(self.open_queue)

        # OverviewPage controls navigation
        self.pages["dashboard"].navigate_requested.connect(self.show_page)

        # Assemble layout
        layout.addWidget(self.sidebar)
        layout.addWidget(self.stack)

        # Initial state
        self.show_page("dashboard")
        self.setStyleSheet(dark_style())
        self.pages["about"].set_dark_mode(self.dark_mode)
        self.pages["dashboard"].set_dark_mode(self.dark_mode)
        self.sidebar.set_dark_mode(self.dark_mode)

    
    # Navigation between pages
    
    def show_page(self, page_name: str):
        """
        Function to show the pages; receives the page name
        and updates the widget

        Args:
            page_name (str): Page name
        """
        page = self.pages.get(page_name)
        if page:
            self.stack.setCurrentWidget(page)
            self.sidebar.set_active_page(page_name)
            if page_name == "reports":
                page.load_analysis()

    def open_queue(self):
        """Open (or bring to front) the popup with the analysis queue."""
        self.queue_dialog.refresh()
        self.queue_dialog.show()
        self.queue_dialog.raise_()
        self.queue_dialog.activateWindow()

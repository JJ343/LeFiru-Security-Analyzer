from lefiru.paths import resource


def dark_style():
    """Dark theme using the same palette as the startup splash."""
    check_icon = resource("ui/resources/check.png").as_posix()
    return """
    QWidget{
        background-color: #0a0f14;
        color: #e8f5f3;
        font-family: "Segoe UI";
        font-size: 13px;
    }

    QStackedWidget#content, QStackedWidget#content > QWidget{
        background-color: #0d1319;
    }

    QStackedWidget#content > QWidget#reportes_page,
    QStackedWidget#content > QWidget#about_page{
        background-color: #0d1319;
    }

    QWidget#botones_widget,
    QWidget#descripcion_page{
        background-color: transparent;
    }

    QWidget#app_shell{
        background-color: #0a0f14;
    }

    QWidget#sidebar{
        background-color: #0a0f14;
        border: none;
    }

    QFrame#sidebar_card{
        background-color: #0b1117;
        border: 1px solid #161f26;
        border-radius: 18px;
    }

    QFrame#sidebar_profile,
    QFrame#sidebar_section_row{
        background-color: transparent;
        border: none;
        padding: 0;
    }

    QLabel#profile_avatar{
        background-color: #18262e;
        border: 1px solid #263a42;
        border-radius: 20px;
    }

    QLabel#profile_dot{
        background-color: #3ee08f;
        border: 2px solid #0b1117;
        border-radius: 6px;
    }

    QLabel#profile_name{
        color: #f2fcff;
        font: 700 14px "Segoe UI";
    }

    QLabel#profile_status{
        color: #7fa19d;
        font: 400 10px "Segoe UI";
    }

    QPushButton#sidebar_ghost_icon{
        background-color: transparent;
        border: none;
        border-radius: 8px;
        padding: 0;
    }

    QPushButton#sidebar_ghost_icon:hover{
        background-color: #15232b;
    }

    QLabel#sidebar_section{
        color: #5b7a76;
        font: 600 9px "Segoe UI";
        letter-spacing: 2px;
        padding: 0;
    }

    QLabel#sidebar_section_count{
        color: #3f5b58;
        font: 600 10px "Segoe UI";
        padding: 0;
    }

    QFrame#nav_item{
        background-color: transparent;
        border: 1px solid transparent;
        border-radius: 10px;
        padding: 0;
    }

    QFrame#nav_item:hover{
        background-color: #111d24;
        border-color: #1a2b32;
    }

    QFrame#nav_item[active="true"]{
        background-color: #12312e;
        border: 1px solid #24695f;
    }

    QLabel#nav_icon{
        background-color: #13212a;
        border-radius: 9px;
    }

    QFrame#nav_item[active="true"] QLabel#nav_icon{
        background-color: #0f2b24;
    }

    QLabel#nav_title{
        color: #dff2ee;
        font: 600 12px "Segoe UI";
    }

    QLabel#nav_subtitle{
        color: #6d918d;
        font: 400 10px "Segoe UI";
    }

    QFrame#nav_item[active="true"] QLabel#nav_title{
        color: #9ff5e4;
    }

    QFrame#nav_item[active="true"] QLabel#nav_subtitle{
        color: #5fb3a4;
    }

    QLabel{
        background-color: transparent;
    }

    QLabel#brand_wordmark{
        color: #43e6c8;
        font: 700 24px "Segoe UI";
        letter-spacing: 1px;
    }

    QLabel#brand_subtitle{
        color: #52716e;
        font: 600 9px "Segoe UI";
        letter-spacing: 3px;
    }

    QLabel#sidebar_section{
        color: #4a6663;
        font: 600 9px "Segoe UI";
        letter-spacing: 2px;
        padding: 12px 12px 4px 12px;
    }

    QLabel#page_title{
        color: #f2fcff;
        font: 600 26px "Segoe UI";
    }

    QLabel#page_subtitle{
        color: #8fb3b0;
        font: 400 13px "Segoe UI";
    }

    QLabel#action_title{
        color: #eaf9f6;
        font: 600 15px "Segoe UI";
    }

    QLabel#action_description{
        color: #82a3a0;
        font: 400 12px "Segoe UI";
    }

    QLabel#action_hint{
        color: #43e6c8;
        font: 600 11px "Segoe UI";
    }

    QFrame#sidebar_separator{
        background-color: #162329;
        border: none;
        max-height: 1px;
    }

    QCheckBox, QRadioButton{
        background-color: transparent;
    }

    QPushButton{
        background-color: #101a21;
        color: #dff7f2;
        border: 1px solid #1c2a31;
        border-radius: 10px;
        padding: 9px 12px;
    }

    QPushButton:hover{
        background-color: #15242b;
        border-color: #2b4a4d;
    }

    QPushButton:pressed{
        background-color: #0d1a1f;
    }

    QPushButton:disabled{
        color: #66807d;
        background-color: #0d151a;
        border-color: #162329;
    }

    QPushButton#page_button{
        background-color: transparent;
        border: 1px solid transparent;
        border-radius: 10px;
        padding: 10px 14px;
        text-align: left;
    }

    QPushButton#page_button:hover{
        background-color: #101c22;
        border-color: #1d3638;
    }

    QPushButton#page_button:checked{
        background-color: #12312e;
        border: 1px solid #2b8f83;
        color: #9ff5e4;
        font-weight: 600;
    }

    QFrame{
        background-color: #111a21;
        border: 1px solid #1c2a31;
        border-radius: 14px;
        padding: 10px;
    }

    /* QLabel inherits QFrame, so undo the card frame for text labels. */
    QLabel{
        background-color: transparent;
        border: none;
        border-radius: 0;
        padding: 0;
    }

    QLabel#sidebar_section{
        padding: 12px 12px 4px 12px;
    }

    QFrame#hero_card{
        background-color: #0e171d;
        border: 1px solid #1d3336;
        border-radius: 18px;
    }

    QFrame#action_card{
        background-color: #101a21;
        border: 1px solid #1c2a31;
        border-radius: 14px;
    }

    QFrame#action_card:hover{
        background-color: #12222a;
        border-color: #2b8f83;
    }

    QFrame#panel{
        background-color: #101a21;
        border: 1px solid #1c2a31;
        border-radius: 14px;
    }

    QFrame#drop_zone{
        background-color: #0e171d;
        border: 1px dashed #2b8f83;
        border-radius: 18px;
    }

    QFrame#drop_zone:hover{
        background-color: #101f25;
        border-color: #43e6c8;
    }

    QLabel#drop_mark{
        color: #43e6c8;
        font-size: 34px;
    }

    QLabel#drop_title{
        color: #f2fcff;
        font: 600 18px "Segoe UI";
    }

    QLabel#drop_subtitle{
        color: #8fb3b0;
        font: 400 12px "Segoe UI";
    }

    QLabel#section_title{
        color: #eaf9f6;
        font: 600 13px "Segoe UI";
    }

    QLabel#section_hint{
        color: #6d918d;
        font: 400 11px "Segoe UI";
    }

    QFrame#test_group_box{
        background-color: #0c151b;
        border: 1px solid #182a31;
        border-radius: 12px;
    }

    QLabel#test_dot{
        font-size: 11px;
        background-color: transparent;
    }

    QLabel#test_group_title{
        color: #dff7f2;
        font: 600 12px "Segoe UI";
    }

    QLabel#test_group_hint{
        color: #5f817d;
        font: 400 10px "Segoe UI";
    }

    QLabel#test_group_count{
        background-color: #12262b;
        color: #8fd9cc;
        border-radius: 8px;
        padding: 0px 7px;
        font: 600 10px "Segoe UI";
    }

    QCheckBox{
        background-color: transparent;
        border: 1px solid transparent;
        border-radius: 8px;
        padding: 3px 4px;
        spacing: 9px;
        color: #cfe9e5;
    }

    QCheckBox:hover{
        background-color: #142229;
        border-color: #1d3638;
    }

    QCheckBox:disabled{
        color: #5c7572;
    }

    QCheckBox::indicator{
        width: 15px;
        height: 15px;
        border-radius: 5px;
        border: 1px solid #2c4d50;
        background-color: #0a1217;
    }

    QCheckBox::indicator:hover{
        border-color: #43e6c8;
    }

    QCheckBox::indicator:checked{
        background-color: #43e6c8;
        border-color: #6ff2da;
        image: url("__CHECK_ICON__");
    }

    QCheckBox::indicator:checked:disabled{
        background-color: #2a5a54;
        border-color: #2f6b62;
        image: none;
    }

    QCheckBox#select_all{
        color: #9ff5e4;
        font: 600 11px "Segoe UI";
        padding: 3px 6px;
    }

    QLabel#activity_status{
        background-color: #101a21;
        border: 1px solid #1c2a31;
        border-radius: 9px;
        padding: 3px 10px;
        color: #8fb3b0;
        font: 600 10px "Segoe UI";
    }

    QLabel#activity_status[state="running"]{
        background-color: #12312e;
        border-color: #2b8f83;
        color: #9ff5e4;
    }

    QLabel#activity_status[state="done"]{
        background-color: #0f2b24;
        border-color: #24695f;
        color: #7ef0d0;
    }

    QLabel#activity_status[state="error"]{
        background-color: #2c1113;
        border-color: #5a2025;
        color: #ff9d9d;
    }

    QFrame#current_file_card{
        background-color: #0c151b;
        border: 1px solid #182a31;
        border-radius: 12px;
    }

    QLabel#current_file_name{
        color: #eaf9f6;
        font: 600 12px "Segoe UI";
    }

    QLabel#current_file_stage{
        color: #6d918d;
        font: 400 10px "Segoe UI";
    }

    QProgressBar#file_bar{
        background-color: #0a1217;
        border: none;
        border-radius: 3px;
        min-height: 6px;
        max-height: 6px;
    }

    QProgressBar#file_bar::chunk{
        background-color: #43e6c8;
        border-radius: 3px;
    }

    QPushButton#primary_button{
        background-color: #43e6c8;
        color: #05201c;
        border: 1px solid #6ff2da;
        border-radius: 12px;
        padding: 10px 24px;
        font: 700 13px "Segoe UI";
    }

    QPushButton#primary_button:hover{
        background-color: #6ff2da;
    }

    QPushButton#primary_button:pressed{
        background-color: #2fc7ad;
    }

    QPushButton#primary_button:disabled{
        background-color: #17332f;
        color: #6c8c87;
        border-color: #1e403b;
    }

    QPushButton#ghost_button{
        background-color: transparent;
        border: 1px solid transparent;
        color: #8fb3b0;
        padding: 4px 8px;
    }

    QPushButton#ghost_button:hover{
        color: #9ff5e4;
        border-color: #1d3638;
    }

    QPushButton#report_ghost{
        background-color: #101a21;
        border: 1px solid #1c2a31;
        border-radius: 10px;
        color: #cfe9e5;
        padding: 8px 14px;
        font: 600 12px "Segoe UI";
    }

    QPushButton#report_ghost:hover{
        background-color: #14262c;
        border-color: #2b8f83;
        color: #9ff5e4;
    }

    QPushButton#report_icon_button{
        background-color: #101a21;
        border: 1px solid #1c2a31;
        border-radius: 10px;
        padding: 0;
    }

    QPushButton#report_icon_button:hover{
        background-color: #14262c;
        border-color: #2b8f83;
    }

    QLineEdit#report_search{
        background-color: #0d161c;
        border: 1px solid #1a2a31;
        border-radius: 11px;
        padding: 8px 12px;
        color: #e8f5f3;
        selection-background-color: #1f7f73;
    }

    QLineEdit#report_search:hover{
        border-color: #245050;
    }

    QLineEdit#report_search:focus{
        border-color: #2b8f83;
    }

    QLabel#report_count{
        color: #6d918d;
        font: 600 11px "Segoe UI";
        padding: 0 4px;
    }

    QScrollArea#report_scroll{
        background: transparent;
        border: none;
    }

    QWidget#report_list{
        background: transparent;
    }

    QFrame#report_row{
        background-color: #0d161c;
        border: 1px solid #182a31;
        border-radius: 12px;
    }

    QFrame#report_row:hover{
        background-color: #11212a;
        border-color: #24695f;
    }

    QLabel#report_icon{
        background-color: #13212a;
        border: 1px solid #1d313a;
        border-radius: 10px;
    }

    QLabel#report_title{
        color: #eaf9f6;
        font: 600 13px "Segoe UI";
    }

    QLabel#report_subtitle{
        color: #6d918d;
        font: 400 10px "Segoe UI";
    }

    QLabel#report_empty{
        color: #6d918d;
        font: 400 12px "Segoe UI";
        padding: 40px 20px;
    }

    QLabel#report_note{
        color: #526f6c;
        font: 400 10px "Segoe UI";
    }

    QFrame#about_menu{
        background-color: #0b1117;
        border: 1px solid #161f26;
        border-radius: 16px;
    }

    QLabel#about_menu_label{
        color: #5b7a76;
        font: 600 9px "Segoe UI";
        letter-spacing: 2px;
        padding: 0 8px;
    }

    QFrame#about_nav_item{
        background-color: transparent;
        border: 1px solid transparent;
        border-radius: 10px;
    }

    QFrame#about_nav_item:hover{
        background-color: #111d24;
        border-color: #1a2b32;
    }

    QFrame#about_nav_item[active="true"]{
        background-color: #12312e;
        border: 1px solid #24695f;
    }

    QLabel#about_nav_icon{
        background-color: #13212a;
        border-radius: 9px;
    }

    QFrame#about_nav_item[active="true"] QLabel#about_nav_icon{
        background-color: #0f2b24;
    }

    QLabel#about_nav_title{
        color: #dff2ee;
        font: 600 12px "Segoe UI";
    }

    QLabel#about_nav_subtitle{
        color: #6d918d;
        font: 400 10px "Segoe UI";
    }

    QFrame#about_nav_item[active="true"] QLabel#about_nav_title{
        color: #9ff5e4;
    }

    QFrame#about_nav_item[active="true"] QLabel#about_nav_subtitle{
        color: #5fb3a4;
    }

    QFrame#about_content_card{
        background-color: #0b1117;
        border: 1px solid #161f26;
        border-radius: 16px;
    }

    QLabel#about_section_title{
        color: #f2fcff;
        font: 600 18px "Segoe UI";
    }

    QLabel#about_section_hint{
        color: #6d918d;
        font: 400 11px "Segoe UI";
    }

    QStackedWidget#about_stack,
    QStackedWidget#about_stack > QWidget,
    QWidget#description_page{
        background: transparent;
    }

    QTextBrowser#about_text{
        background-color: transparent;
        border: none;
        color: #b7d2ce;
        selection-background-color: #1f7f73;
        selection-color: #f2fcff;
    }

    QLabel#about_version{
        background-color: #101a21;
        border: 1px solid #1c2a31;
        border-radius: 10px;
        padding: 4px 10px;
        color: #8fb3b0;
        font: 600 11px "Segoe UI";
    }

    QPushButton#github_button{
        background-color: #43e6c8;
        color: #05201c;
        border: 1px solid #6ff2da;
        border-radius: 10px;
        padding: 0;
    }

    QPushButton#github_button:hover{
        background-color: #6ff2da;
    }

    QPushButton#github_button:pressed{
        background-color: #2fc7ad;
    }

    QLabel#about_hero_title{
        color: #f2fcff;
        font: 600 20px "Segoe UI";
    }

    QLabel#about_hero_tagline{
        color: #8fb3b0;
        font: 400 12px "Segoe UI";
    }

    QLabel#about_fact{
        background-color: #10201f;
        border: 1px solid #1d3b36;
        border-radius: 9px;
        padding: 4px 10px;
        color: #8fd9cc;
        font: 600 10px "Segoe UI";
    }

    QLabel#about_description{
        color: #9db9b6;
        font: 400 12px "Segoe UI";
        line-height: 150%;
    }

    QLabel#about_footer{
        color: #526f6c;
        font: 400 10px "Segoe UI";
    }

    QScrollArea#analysis_scroll{
        background: transparent;
        border: none;
    }

    QScrollArea#analysis_scroll > QWidget > QWidget,
    QWidget#analysis_left{
        background: transparent;
    }

    QListWidget#file_list{
        background-color: #0b1116;
        border: 1px solid #1c2a31;
        border-radius: 10px;
        padding: 4px;
    }

    QListWidget#file_list::item{
        padding: 5px 8px;
        border-radius: 6px;
    }

    QListWidget#file_list::item:selected{
        background-color: #12312e;
        color: #9ff5e4;
    }

    QTextEdit#analysis_output{
        background-color: #0b1116;
        border: 1px solid #1c2a31;
        border-radius: 10px;
        padding: 10px;
        font-family: "Cascadia Mono", "Consolas", monospace;
        font-size: 12px;
        selection-background-color: #1e4d48;
    }

    QTextEdit, QPlainTextEdit, QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox{
        background-color: #0b1116;
        color: #e8f5f3;
        border: 1px solid #1c2a31;
        border-radius: 8px;
        padding: 6px;
        selection-background-color: #1f7f73;
        selection-color: #ffffff;
    }

    QTextEdit:focus, QPlainTextEdit:focus, QLineEdit:focus, QComboBox:focus{
        border-color: #2b8f83;
    }

    QTextEdit#mensaje_edit{
        background-color: #0b1116;
    }

    QComboBox QAbstractItemView{
        background-color: #0d1319;
        color: #e8f5f3;
        border: 1px solid #1c2a31;
        selection-background-color: #12312e;
    }

    QScrollBar:vertical{
        background: transparent;
        width: 10px;
        margin: 2px;
    }

    QScrollBar::handle:vertical{
        background: #1f3a3b;
        min-height: 28px;
        border-radius: 4px;
    }

    QScrollBar::handle:vertical:hover{
        background: #2b8f83;
    }

    QScrollBar::add-line:vertical,
    QScrollBar::sub-line:vertical,
    QScrollBar::add-page:vertical,
    QScrollBar::sub-page:vertical{
        background: transparent;
        height: 0;
    }

    QProgressBar, QProgressBar#cola_barra, QProgressBar#queue_bar{
        background-color: #0b1116;
        border: 1px solid #1c2a31;
        border-radius: 5px;
        text-align: center;
        color: #e8f5f3;
    }

    QProgressBar::chunk, QProgressBar#cola_barra::chunk, QProgressBar#queue_bar::chunk{
        background-color: #2ec4b6;
        border-radius: 4px;
    }

    QWidget#cola_panel{
        background-color: #0a0f14;
        border: 1px solid #1c2a31;
        border-radius: 10px;
    }

    QMenu{
        background-color: #101a21;
        border: 1px solid #1c2a31;
        border-radius: 8px;
        padding: 6px;
    }

    QMenu::item{
        color: #dff7f2;
        padding: 6px 18px;
        border-radius: 6px;
    }

    QMenu::item:selected{
        background-color: #12312e;
        color: #9ff5e4;
    }

    QMenu::item:disabled{
        color: #5c7572;
    }

    QDialog#analysis_queue{
        background-color: #0a1015;
    }

    QLabel#queue_header_icon{
        background-color: #10201f;
        border: 1px solid #1d3b36;
        border-radius: 11px;
    }

    QLabel#queue_title{
        color: #f2fcff;
        font: 600 20px "Segoe UI";
    }

    QLabel#queue_subtitle{
        color: #8fb3b0;
        font: 400 11px "Segoe UI";
    }

    QLabel#queue_chip{
        background-color: #101a21;
        border: 1px solid #1c2a31;
        border-radius: 9px;
        padding: 3px 9px;
        color: #8fb3b0;
        font: 600 10px "Segoe UI";
    }

    QLabel#queue_chip[state="queued"]{
        background-color: #121d24;
        border-color: #253a41;
        color: #9db9b6;
    }

    QLabel#queue_chip[state="running"]{
        background-color: #12312e;
        border-color: #2b8f83;
        color: #9ff5e4;
    }

    QLabel#queue_chip[state="ok"]{
        background-color: #0f2b24;
        border-color: #24695f;
        color: #7ef0d0;
    }

    QLabel#queue_chip[state="warn"]{
        background-color: #2a2214;
        border-color: #5c4823;
        color: #ffcf7d;
    }

    QLabel#queue_chip[state="error"]{
        background-color: #2c1113;
        border-color: #5a2025;
        color: #ff9d9d;
    }

    QLabel#queue_chip[state="muted"]{
        background-color: #141c21;
        border-color: #26343a;
        color: #7d928f;
    }

    QScrollArea#queue_scroll{
        background: transparent;
        border: none;
    }

    QWidget#queue_list{
        background: transparent;
    }

    QFrame#queue_row{
        background-color: #0d161c;
        border: 1px solid #182a31;
        border-radius: 12px;
    }

    QFrame#queue_row:hover{
        background-color: #101e26;
        border-color: #245050;
    }

    QLabel#queue_row_icon{
        background-color: #13212a;
        border: 1px solid #1d313a;
        border-radius: 9px;
    }

    QLabel#queue_file_name{
        color: #eaf9f6;
        font: 600 12px "Segoe UI";
    }

    QLabel#queue_file_stage{
        color: #6d918d;
        font: 400 10px "Segoe UI";
    }

    QPushButton#queue_action{
        background-color: transparent;
        border: 1px solid #243c3d;
        border-radius: 8px;
        color: #8fb3b0;
        padding: 3px 10px;
        font: 600 10px "Segoe UI";
        min-height: 18px;
    }

    QPushButton#queue_action:hover{
        background-color: #17322f;
        border-color: #2b8f83;
        color: #9ff5e4;
    }

    QProgressBar#queue_row_bar{
        background-color: #0a1217;
        border: none;
        border-radius: 3px;
        min-height: 5px;
        max-height: 5px;
    }

    QProgressBar#queue_row_bar::chunk{
        background-color: #43e6c8;
        border-radius: 3px;
    }

    QProgressBar#queue_row_bar[state="idle"]::chunk{
        background-color: #2a4747;
    }

    QProgressBar#queue_row_bar[state="done"]::chunk{
        background-color: #2ec4b6;
    }

    QLabel#queue_empty{
        color: #6d918d;
        font: 400 12px "Segoe UI";
        padding: 56px 24px;
    }

    QFrame#queue_progress_card{
        background-color: #0d161c;
        border: 1px solid #182a31;
        border-radius: 12px;
    }

    QLabel#queue_progress_label{
        color: #dff7f2;
        font: 600 12px "Segoe UI";
    }

    QLabel#queue_progress_text{
        color: #6d918d;
        font: 600 10px "Segoe UI";
    }

    QPushButton#queue_icon_button{
        background-color: #101a21;
        border: 1px solid #1c2a31;
        border-radius: 10px;
        padding: 0;
    }

    QPushButton#queue_icon_button:hover{
        background-color: #14262c;
        border-color: #2b8f83;
    }

    QLabel#queue_note{
        color: #526f6c;
        font: 400 10px "Segoe UI";
    }

    QPushButton#queue_close{
        background-color: #43e6c8;
        color: #05201c;
        border: 1px solid #6ff2da;
        border-radius: 10px;
        padding: 8px 22px;
        font: 700 12px "Segoe UI";
    }

    QPushButton#queue_close:hover{
        background-color: #6ff2da;
    }

    QPushButton#queue_close:pressed{
        background-color: #2fc7ad;
    }

    QToolTip{
        background-color: #101a21;
        color: #e8f5f3;
        border: 1px solid #2b8f83;
        padding: 4px;
    }

    QRadioButton::indicator{
        width: 10px;
        height: 10px;
        background-color: transparent;
    }

    QRadioButton::indicator:unchecked{
        background-color: transparent;
    }

    QRadioButton::indicator:checked{
        background-color: qradialgradient(
            cx:0.5, cy:0.5,
            radius:0.7,
            fx:0.5, fy:0.5,
            stop:0 #43e6c8,
            stop:0.45 #43e6c8,
            stop:0.46 rgba(0,0,0,0)
        );
    }
    """.replace("__CHECK_ICON__", check_icon)

"""
Evidence capture that never disturbs the desktop.

Two problems are solved here:

1. **Excel** can render a range to PNG with no window at all
   (``Range.CopyPicture`` + ``Chart.Export``). The only requirement is that the
   application window exists in the *normal* state, so it is parked outside the
   visible desktop before anything is rendered. Nothing is maximized and no
   window is brought to the foreground.
2. **The VBE** has no equivalent API, so its window is also parked off-screen
   and captured with ``PrintWindow`` + ``PW_RENDERFULLCONTENT``, which asks DWM
   for the composed content of a window even when it is occluded or off-screen.

If the VBE cannot be opened (``AccessVBOM`` disabled) or its capture comes back
blank, callers fall back to :func:`render_code_png`, which draws the exported
source with Pillow and needs neither Excel nor a window.

A capture that produces a blank image is always reported as a failure: Excel
returns a white PNG instead of raising when the window is hidden or minimized,
and a blank evidence image is worse than no image.
"""

from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Coordinates used to park a window outside the visible desktop.
OFFSCREEN_X = -4000
OFFSCREEN_Y = -4000

# Window class of the VBE main frame. The title is localized, so it is never
# used for matching.
VBE_WINDOW_CLASSES = ("wndclass_desked_gsk",)

# Excel constants used through COM.
XL_NORMAL = -4143
XL_BITMAP = 2
XL_PICTURE = -4147

# Bounds applied to the captured area: a stray formatting far away must not
# produce a 1 000-column image, and the result has to stay legible when the
# report scales it to the page width.
MAX_CAPTURE_ROWS = 24
MAX_CAPTURE_COLS = 12
MIN_CAPTURE_ROWS = 12
MIN_CAPTURE_COLS = 8

_SWP_NOSIZE = 0x0001
_SWP_NOZORDER = 0x0004
_SWP_NOACTIVATE = 0x0010

try:  # pragma: no cover - platform dependent
    from PIL import Image, ImageChops, ImageDraw, ImageFont

    PIL_AVAILABLE = True
except ImportError:  # pragma: no cover
    PIL_AVAILABLE = False

try:  # pragma: no cover - Windows only
    import ctypes

    import win32gui
    import win32ui

    WIN32_AVAILABLE = True
except ImportError:  # pragma: no cover
    WIN32_AVAILABLE = False

# Range and window captures need both; the source renderer only needs Pillow.
CAPTURE_AVAILABLE = PIL_AVAILABLE and WIN32_AVAILABLE


class CaptureUnavailable(RuntimeError):
    """Raised when the capture backend cannot run on this platform."""


# ---------------------------------------------------------------------------
# Low level window helpers
# ---------------------------------------------------------------------------
def _require_backend() -> None:
    if not CAPTURE_AVAILABLE:
        raise CaptureUnavailable(
            "pywin32 and Pillow are required to capture evidence images."
        )


def _set_window_position(hwnd: int, x: int, y: int) -> None:
    win32gui.SetWindowPos(
        hwnd, 0, x, y, 0, 0, _SWP_NOSIZE | _SWP_NOZORDER | _SWP_NOACTIVATE
    )


def move_offscreen(hwnd: int) -> Optional[tuple]:
    """Parks a window outside the visible desktop.

    Returns the original ``(left, top, width, height)`` so the caller can put
    it back, or ``None`` when the window has no valid geometry.
    """
    try:
        left, top, right, bottom = win32gui.GetWindowRect(hwnd)
    except Exception as exc:  # noqa: BLE001 - cosmetic only
        logger.debug("Could not read the window rect: %s", exc)
        return None

    width, height = right - left, bottom - top
    if width <= 0 or height <= 0:
        return None

    try:
        _set_window_position(hwnd, OFFSCREEN_X, OFFSCREEN_Y)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not park the window off-screen: %s", exc)
        return None

    return (left, top, width, height)


def restore_position(hwnd: int, rect: Optional[tuple]) -> None:
    """Puts a window back where :func:`move_offscreen` found it."""
    if not rect:
        return
    left, top, width, height = rect
    try:
        win32gui.SetWindowPos(
            hwnd,
            0,
            left,
            top,
            width,
            height,
            _SWP_NOZORDER | _SWP_NOACTIVATE,
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not restore the window position: %s", exc)


def find_window_by_class(class_names) -> Optional[int]:
    """Returns the handle of the first visible window of one of those classes."""
    found = []

    def _callback(hwnd, _param):
        try:
            if not win32gui.IsWindowVisible(hwnd):
                return
            if win32gui.GetClassName(hwnd) in class_names:
                found.append(hwnd)
        except Exception:  # noqa: BLE001 - enumeration must never break
            return

    try:
        win32gui.EnumWindows(_callback, None)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not enumerate windows: %s", exc)
        return None

    return found[0] if found else None


def print_window(hwnd: int, out_path: Path) -> bool:
    """Renders a window (even occluded or off-screen) into a PNG file."""
    _require_backend()
    try:
        left, top, right, bottom = win32gui.GetWindowRect(hwnd)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not read the window rect: %s", exc)
        return False

    width, height = right - left, bottom - top
    if width <= 0 or height <= 0:
        return False

    window_dc = None
    source_dc = None
    memory_dc = None
    bitmap = None
    try:
        window_dc = win32gui.GetWindowDC(hwnd)
        source_dc = win32ui.CreateDCFromHandle(window_dc)
        memory_dc = source_dc.CreateCompatibleDC()
        bitmap = win32ui.CreateBitmap()
        bitmap.CreateCompatibleBitmap(source_dc, width, height)
        memory_dc.SelectObject(bitmap)

        # PW_RENDERFULLCONTENT (2) uses DWM, so occluded content is included.
        ctypes.windll.user32.PrintWindow(hwnd, memory_dc.GetSafeHdc(), 2)
        bitmap.SaveBitmapFile(memory_dc, str(out_path))
        return Path(out_path).is_file()
    except Exception as exc:  # noqa: BLE001 - evidence must never break a test
        logger.debug("PrintWindow failed for handle %s: %s", hwnd, exc)
        return False
    finally:
        if memory_dc is not None:
            try:
                memory_dc.DeleteDC()
            except Exception:  # noqa: BLE001
                pass
        if source_dc is not None:
            try:
                source_dc.DeleteDC()
            except Exception:  # noqa: BLE001
                pass
        if bitmap is not None:
            try:
                win32gui.DeleteObject(bitmap.GetHandle())
            except Exception:  # noqa: BLE001
                pass
        if window_dc is not None:
            try:
                win32gui.ReleaseDC(hwnd, window_dc)
            except Exception:  # noqa: BLE001
                pass


# ---------------------------------------------------------------------------
# Image validation
# ---------------------------------------------------------------------------
def image_has_content(path: Path, min_range: int = 8) -> bool:
    """Rejects blank captures.

    Excel returns a white PNG instead of raising when it could not render, so
    the only reliable check is to look at the pixels.
    """
    if not PIL_AVAILABLE:
        return True
    try:
        with Image.open(path) as image:
            grey = image.convert("L")
            low, high = grey.getextrema()
            return high - low >= min_range
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not inspect the capture %s: %s", path, exc)
        return False


def _trim_white_border(path: Path, margin: int = 8) -> None:
    """Removes the empty canvas around an exported range."""
    try:
        with Image.open(path) as image:
            rgb = image.convert("RGB")
            white = Image.new("RGB", rgb.size, (255, 255, 255))
            box = ImageChops.difference(rgb, white).getbbox()
            if not box:
                return
            left, top, right, bottom = box
            left = max(left - margin, 0)
            top = max(top - margin, 0)
            right = min(right + margin, rgb.width)
            bottom = min(bottom + margin, rgb.height)
            rgb.crop((left, top, right, bottom)).save(path)
    except Exception as exc:  # noqa: BLE001 - trimming is cosmetic
        logger.debug("Could not trim the capture %s: %s", path, exc)


# ---------------------------------------------------------------------------
# Excel range capture
# ---------------------------------------------------------------------------
def evidence_range_address(sheet) -> str:
    """Returns the A1-anchored range that shows the evidence mark.

    The mark is written in A1 (or D1 when A1 is already marked), so the capture
    always starts there. Size is bounded to avoid enormous images.

    ``Range.Resize(rows, cols).Address`` is not used on purpose: with late COM
    binding it resolves to a single cell (the bottom-right corner), which
    captures one cell instead of the range.
    """
    try:
        used = sheet.UsedRange
        rows = int(used.Rows.Count)
        columns = int(used.Columns.Count)
    except Exception:  # noqa: BLE001
        rows, columns = MIN_CAPTURE_ROWS, MIN_CAPTURE_COLS

    rows = min(max(rows, MIN_CAPTURE_ROWS), MAX_CAPTURE_ROWS)
    columns = min(max(columns, MIN_CAPTURE_COLS), MAX_CAPTURE_COLS)

    try:
        last_cell = sheet.Cells(rows, columns)
        # Late binding exposes Address as a string property, not a method.
        last_reference = str(last_cell.Address).replace("$", "")
        return f"A1:{last_reference}"
    except Exception:  # noqa: BLE001
        return "A1:M12"


def _paste_with_retry(chart, attempts: int = 3) -> bool:
    """Pastes the clipboard into the chart, retrying while it is not ready."""
    for attempt in range(attempts):
        try:
            chart.Chart.Paste()
        except Exception as exc:  # noqa: BLE001
            logger.debug("Chart paste attempt %s failed: %s", attempt + 1, exc)
        try:
            if int(chart.Chart.Shapes.Count) > 0:
                return True
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.2)
    return False


def _fit_chart_to_picture(
    chart, target_width: float = 900.0, max_height: float = 600.0
) -> None:
    """Sizes the canvas to the pasted picture, preserving its aspect ratio.

    Without this the export shows the picture clipped to the chart area (top-left
    corner only) surrounded by empty gridlines.
    """
    try:
        shape = chart.Chart.Shapes(1)
        width = float(shape.Width)
        height = float(shape.Height)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not measure the pasted picture: %s", exc)
        return

    if width <= 0 or height <= 0:
        return

    factor = max(target_width / width, 1.0)
    if height * factor > max_height:
        factor = max_height / height

    width *= factor
    height *= factor

    try:
        shape.Left = 0
        shape.Top = 0
        shape.Width = width
        shape.Height = height
        chart.Chart.ChartArea.Width = width
        chart.Chart.ChartArea.Height = height
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not fit the chart to the picture: %s", exc)


def _new_hidden_workbook(excel_app):
    """Creates a throwaway workbook and hides its window.

    Called while Excel is hidden, so no window is ever composed on screen.
    """
    helper = excel_app.Workbooks.Add()
    try:
        helper.Windows(1).Visible = False
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not hide the helper workbook window: %s", exc)
    return helper


def _export_range(excel_app, sheet, address: str, out_path: Path) -> bool:
    """Copies the range to a throwaway workbook and exports it as PNG.

    A separate workbook is used because ``ChartObjects().Add`` fails on a
    protected sheet and because the analyzed file must not gain a chart.
    ``xlPicture`` is required: ``xlBitmap`` pastes nothing on late binding.
    """
    helper = None
    chart = None
    try:
        sheet.Activate()
        sheet.Range(address).CopyPicture(Format=XL_PICTURE)
        time.sleep(0.1)

        helper = _new_hidden_workbook(excel_app)
        chart = helper.Worksheets(1).ChartObjects().Add(0, 0, 700, 400)
        if not _paste_with_retry(chart):
            logger.debug("The range %s could not be pasted into the chart.", address)
            return False

        _fit_chart_to_picture(chart)
        chart.Chart.Export(str(out_path), "PNG")
        return Path(out_path).is_file()
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not export the range %s: %s", address, exc)
        return False
    finally:
        if chart is not None:
            try:
                chart.Delete()
            except Exception:  # noqa: BLE001
                pass
        if helper is not None:
            try:
                helper.Close(SaveChanges=False)
            except Exception:  # noqa: BLE001
                pass


@contextmanager
def visible_offscreen(excel_app):
    """Makes the Excel window renderable without ever showing it.

    The window is parked before being shown, then parked again (Excel may
    re-center a window when it becomes visible). On exit the previous state,
    position and size are restored.
    """
    _require_backend()
    was_visible = None
    was_state = None
    hwnd = None
    original_rect = None

    try:
        was_visible = excel_app.Visible
        was_state = excel_app.WindowState
    except Exception:  # noqa: BLE001
        pass

    try:
        hwnd = int(excel_app.Hwnd)
    except Exception:  # noqa: BLE001
        hwnd = 0

    # Park first so the window never appears on the desktop when shown.
    if hwnd:
        original_rect = move_offscreen(hwnd)

    try:
        excel_app.Visible = True
        try:
            excel_app.WindowState = XL_NORMAL
        except Exception:  # noqa: BLE001
            pass

        if not hwnd:
            try:
                hwnd = int(excel_app.Hwnd)
            except Exception:  # noqa: BLE001
                hwnd = 0
        if hwnd:
            original_rect = original_rect or move_offscreen(hwnd)
            _set_window_position(hwnd, OFFSCREEN_X, OFFSCREEN_Y)

        # Give Excel a moment to paint the window it just created.
        time.sleep(0.25)
        yield hwnd or None
    finally:
        if hwnd:
            restore_position(hwnd, original_rect)
            try:
                if was_state is not None:
                    excel_app.WindowState = was_state
            except Exception:  # noqa: BLE001
                pass
        try:
            if was_visible is not None:
                excel_app.Visible = was_visible
        except Exception:  # noqa: BLE001
            pass


def capture_sheet_range(
    excel_app,
    sheet,
    out_path: Path,
) -> Dict[str, Any]:
    """Captures the evidence area of a sheet as a PNG, without showing Excel.

    Returns ``{"path": str | None, "method": str | None}``. ``method`` is
    ``"range_export"`` for a real render of the range or ``"window_print"`` for
    the window fallback, so the report can say how the image was produced.
    """
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if not CAPTURE_AVAILABLE:
        return {"path": None, "method": None, "error": "capture backend unavailable"}

    try:
        address = evidence_range_address(sheet)
    except Exception as exc:  # noqa: BLE001
        return {"path": None, "method": None, "error": str(exc)}

    try:
        # Preferred path: Excel renders the range while completely hidden.
        # Verified: xlBitmap returns a blank image when hidden, xlPicture works.
        if _export_range(excel_app, sheet, address, out_path) and image_has_content(
            out_path
        ):
            _trim_white_border(out_path)
            logger.info("Evidence captured off-screen: %s", out_path.name)
            return {"path": str(out_path), "method": "range_export"}

        # Fallback: park the window off-screen and capture it through DWM.
        logger.debug(
            "The range capture came back blank (%s); falling back to the window.",
            address,
        )
        with visible_offscreen(excel_app) as hwnd:
            if hwnd and print_window(hwnd, out_path) and image_has_content(out_path):
                logger.info("Evidence captured from the window: %s", out_path.name)
                return {"path": str(out_path), "method": "window_print"}
    except Exception as exc:  # noqa: BLE001 - evidence must never break the test
        logger.debug("Off-screen capture failed: %s", exc)
        return {"path": None, "method": None, "error": str(exc)}

    try:
        out_path.unlink(missing_ok=True)
    except Exception:  # noqa: BLE001
        pass
    return {"path": None, "method": None, "error": "blank capture"}


# ---------------------------------------------------------------------------
# VBE capture
# ---------------------------------------------------------------------------
def _find_vbe_window(timeout: float = 3.0) -> Optional[int]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        hwnd = find_window_by_class(VBE_WINDOW_CLASSES)
        if hwnd:
            return hwnd
        time.sleep(0.15)
    return None


def capture_vbe(excel_app, out_path: Path, component=None) -> Optional[str]:
    """Captures the VBE off-screen, with the given component's code pane shown.

    Requires ``AccessVBOM`` (Trust access to the VBA project object model). When
    it is disabled this returns ``None`` and the caller must render the source
    instead. The VBE window position is restored even on failure, because the
    VBE remembers it between sessions.
    """
    out_path = Path(out_path)
    if not CAPTURE_AVAILABLE:
        return None

    out_path.parent.mkdir(parents=True, exist_ok=True)
    vbe_window = None
    original_rect = None

    try:
        excel_app.VBE.MainWindow.Visible = True
    except Exception as exc:  # noqa: BLE001 - AccessVBOM disabled is the common case
        logger.debug("The VBE could not be opened (%s); rendering the source instead.", exc)
        return None

    try:
        if component is not None:
            try:
                component.CodeModule.CodePane.Show()
            except Exception as exc:  # noqa: BLE001
                logger.debug("Could not show the code pane: %s", exc)

        vbe_window = _find_vbe_window()
        if not vbe_window:
            logger.debug("The VBE window was not found.")
            return None

        original_rect = move_offscreen(vbe_window)
        time.sleep(0.4)

        if not print_window(vbe_window, out_path) or not image_has_content(out_path):
            logger.debug("The VBE capture came back blank.")
            return None

        logger.info("VBE captured off-screen: %s", out_path.name)
        return str(out_path)
    except Exception as exc:  # noqa: BLE001
        logger.debug("VBE capture failed: %s", exc)
        return None
    finally:
        restore_position(vbe_window, original_rect)
        try:
            excel_app.VBE.MainWindow.Visible = False
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# Source rendering (no Excel needed)
# ---------------------------------------------------------------------------
def _load_mono_font(size: int):
    for name in ("consola.ttf", "cour.ttf", "DejaVuSansMono.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except Exception:  # noqa: BLE001
            continue
    return ImageFont.load_default()


def render_code_png(
    module_name: str,
    code: str,
    out_path: Path,
    source_name: Optional[str] = None,
    max_lines: int = 140,
) -> Optional[str]:
    """Draws VBA source into a PNG. Needs neither Excel nor a window.

    The header states that this is a rendering of the source and not a screen
    capture, which keeps the evidence honest.
    """
    if not PIL_AVAILABLE:
        return None

    out_path = Path(out_path)
    try:
        font_size = 12
        line_height = 16
        padding = 20
        header_height = 52
        max_width = 1400
        max_chars = 200

        font = _load_mono_font(font_size)
        lines = code.split("\n")
        omitted = max(len(lines) - max_lines, 0)
        visible = lines[:max_lines]

        measured = [line[:max_chars] for line in visible] or [""]
        try:
            text_width = max(font.getlength(line) for line in measured)
        except Exception:  # noqa: BLE001 - very old Pillow
            text_width = max(len(line) for line in measured) * font_size * 0.6

        img_width = min(int(text_width) + padding * 2 + 60, max_width)
        img_height = len(visible) * line_height + padding * 2 + header_height
        if omitted:
            img_height += line_height

        image = Image.new("RGB", (img_width, img_height), color="white")
        draw = ImageDraw.Draw(image)

        draw.rectangle([0, 0, img_width, header_height], fill=(45, 45, 48))
        draw.text(
            (padding, 8),
            f"VBA module: {module_name}",
            fill="white",
            font=font,
        )
        subtitle = "Source rendered from the file (not a screen capture)"
        if source_name:
            subtitle = f"{source_name} | {subtitle}"
        draw.text((padding, 28), subtitle[:160], fill=(190, 190, 190), font=font)

        y_offset = header_height + padding - 10
        for index, line in enumerate(visible, 1):
            number = f"{index:4d} "
            draw.text((padding, y_offset), number, fill="gray", font=font)
            draw.text((padding + 42, y_offset), line[:max_chars], fill="black", font=font)
            y_offset += line_height

        if omitted:
            draw.text(
                (padding, y_offset),
                f"... {omitted} more lines (see the exported .bas file)",
                fill="gray",
                font=font,
            )

        out_path.parent.mkdir(parents=True, exist_ok=True)
        image.save(out_path)
        logger.info("VBA source rendered as image: %s", out_path.name)
        return str(out_path)
    except Exception as exc:  # noqa: BLE001 - evidence must never break the analysis
        logger.warning("Could not render the VBA source: %s", exc)
        return None

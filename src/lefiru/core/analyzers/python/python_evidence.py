"""
Visual evidence generation for Python findings.

Renders the exact line where a finding was detected (with a few lines of
context) and saves it as a PNG in the analysis evidence folder.
The goal is for the Word report to show the same "snapshot" already taken for
Excel, but focused on the specific Python code line.

If Pillow is not available or the line cannot be located, the renderer
returns ``None`` and the analysis continues without an image.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional, Sequence

try:  # pragma: no cover - availability depends on the environment
    from PIL import Image, ImageDraw, ImageFont  # type: ignore

    PIL_AVAILABLE = True
except ImportError:  # pragma: no cover
    PIL_AVAILABLE = False

logger = logging.getLogger(__name__)

# Image palette (dark code-editor style)
BACKGROUND = "#1E1E1E"
CURRENT_LINE_BG = "#3A2F1D"
GUTTER_BG = "#252526"
GUTTER_FG = "#858585"
GUTTER_CURRENT_FG = "#FF8A65"
TEXT_FG = "#D4D4D4"
COMMENT_FG = "#6A9955"
STRING_FG = "#CE9178"
KEYWORD_FG = "#569CD6"
DANGER_FG = "#F48771"
ACCENT = "#E53935"
HEADER_BG = "#151515"
HEADER_FG = "#FFFFFF"

_SANITIZE_RE = re.compile(r"[^A-Za-z0-9_.-]+")
_TOKEN_RE = re.compile(
    r"(?P<comment>#.*$)"
    r"|(?P<string>'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")"
    r"|(?P<keyword>\b(?:def|class|return|import|from|if|elif|else|for|while|try|except|finally|with|as|lambda|yield|raise|pass|break|continue|global|nonlocal|assert|del|True|False|None|and|or|not|in|is)\b)"
    r"|(?P<danger>\b(?:eval|exec|__import__|compile|subprocess|popen|system|pickle|marshal|base64|os\.system|shell)\b)"
)

_CONTEXT_BEFORE = 3
_CONTEXT_AFTER = 3
_CONTEXT_FILE_LINES = 10
_MAX_COLS = 150


class PythonEvidenceRenderer:
    """Generates PNG captures of a specific Python code line."""

    def __init__(self, output_dir: Path, file_stem: str = "") -> None:
        self.output_dir = Path(output_dir)
        self.file_stem = file_stem
        self.logger = logging.getLogger(__name__)
        self._source_cache: dict[int, object] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def render_line(
        self,
        code: str,
        line: int,
        origin: str,
        label: str = "",
    ) -> Optional[str]:
        """Returns the PNG path for the given line, or ``None``.

        Parameters
        ----------
        code:
            Full source code used to build the line numbers.
        line:
            Line number (1-based) of the finding.
        origin:
            File/module where the finding was located.
        label:
            Finding type or category; shown in the header.
        """
        if not PIL_AVAILABLE:
            self.logger.debug("Pillow is not available: no visual evidence is generated.")
            return None
        if not code or not line or line < 1:
            return None

        lines = code.splitlines()
        if not lines or line > len(lines):
            self.logger.debug(
                "Line %s out of range for the visual evidence of %s.", line, origin
            )
            return None

        try:
            return self._render(code_lines=lines, line=line, origin=origin, label=label)
        except Exception as exc:  # noqa: BLE001 - evidence must never break the analysis
            self.logger.warning(
                "Could not generate the visual evidence for %s (line %s): %s",
                origin,
                line,
                exc,
            )
            return None

    def render_file_context(
        self,
        code: str,
        origin: str,
        label: str = "",
        max_lines: int = 10,
    ) -> Optional[str]:
        """Captures the file header for findings without a specific line.

        Used for global-scope findings (for example ``no_logging`` or
        ``no_main_guard``), where there is no specific line to highlight.
        """
        if not PIL_AVAILABLE:
            self.logger.debug("Pillow is not available: no visual evidence is generated.")
            return None
        if not code:
            return None

        lines = code.splitlines()
        if not lines:
            return None

        try:
            return self._render(
                code_lines=lines,
                line=None,
                origin=origin,
                label=label,
                max_lines=max_lines,
            )
        except Exception as exc:  # noqa: BLE001
            self.logger.warning(
                "Could not generate the visual evidence for %s (file scope): %s",
                origin,
                exc,
            )
            return None

    # ------------------------------------------------------------------
    # Render
    # ------------------------------------------------------------------
    def _render(
        self,
        code_lines: Sequence[str],
        line: Optional[int],
        origin: str,
        label: str,
        max_lines: int = _CONTEXT_FILE_LINES,
    ) -> str:
        font_size = 15
        line_height = 21
        padding = 14
        header_height = 32

        font = self._load_source(font_size)

        if line is None:
            start = 1
            end = min(len(code_lines), max_lines)
        else:
            start = max(1, line - _CONTEXT_BEFORE)
            end = min(len(code_lines), line + _CONTEXT_AFTER)

        texts: list[str] = []
        for number in range(start, end + 1):
            text = code_lines[number - 1].expandtabs(4).rstrip()
            if len(text) > _MAX_COLS:
                text = text[: _MAX_COLS - 3] + "..."
            texts.append(text)

        # Measure with a temporary canvas to compute the real width.
        measure = ImageDraw.Draw(Image.new("RGB", (1, 1)))
        width_text = max(
            (int(measure.textlength(t, font=font)) for t in texts),
            default=0,
        )
        width_number = int(measure.textlength(str(end), font=font))

        gutter_width = width_number + padding
        width = padding + gutter_width + width_text + padding * 2
        high = header_height + padding + len(texts) * line_height + padding

        image = Image.new("RGB", (max(width, 320), high), color=BACKGROUND)
        drawing = ImageDraw.Draw(image)

        # Header with origin, line and finding type.
        drawing.rectangle([0, 0, width, header_height], fill=HEADER_BG)
        scope = f"L{line}" if line is not None else "file scope"
        title = f"{origin}  ·  {scope}"
        if label:
            title = f"{title}  ·  {label}"
        title = title[:120]
        drawing.text((padding, 8), title, fill=HEADER_FG, font=font)

        # Background of the line-number gutter.
        drawing.rectangle(
            [0, header_height, gutter_width + padding, high],
            fill=GUTTER_BG,
        )

        y = header_height + padding
        for index, text in enumerate(texts):
            number = start + index
            highlighted = line is not None and number == line

            if highlighted:
                drawing.rectangle(
                    [0, y - 3, width, y + line_height - 3],
                    fill=CURRENT_LINE_BG,
                )
                # Red bar marking the finding line.
                drawing.rectangle([0, y - 3, 4, y + line_height - 3], fill=ACCENT)

            number_text = str(number).rjust(len(str(end)))
            drawing.text(
                (padding, y),
                number_text,
                fill=GUTTER_CURRENT_FG if highlighted else GUTTER_FG,
                font=font,
            )

            x = padding + gutter_width
            for segment, color in self._segments(text, highlighted):
                drawing.text((x, y), segment, fill=color, font=font)
                x += int(measure.textlength(segment, font=font))

            y += line_height

        path = self._name_output(
            origin=origin,
            line=line if line is not None else "file",
            label=label,
        )
        image.save(path, "PNG")
        self.logger.info("Python evidence saved: %s", path.name)
        return str(path)

    def _segments(self, text: str, highlighted: bool):
        """Splits a line into colored segments (light highlighting)."""
        if not text:
            return [("", TEXT_FG)]

        segments: list[tuple[str, str]] = []
        position = 0
        for match in _TOKEN_RE.finditer(text):
            if match.start() > position:
                segments.append((text[position : match.start()], TEXT_FG))

            token = match.group(0)
            if match.lastgroup == "comment":
                color = COMMENT_FG
            elif match.lastgroup == "string":
                color = STRING_FG
            elif match.lastgroup == "keyword":
                color = KEYWORD_FG
            else:
                color = DANGER_FG if highlighted else KEYWORD_FG
            segments.append((token, color))
            position = match.end()

        if position < len(text):
            segments.append((text[position:], TEXT_FG))
        return segments or [(text, TEXT_FG)]

    def _load_source(self, size: int):
        if size in self._source_cache:
            return self._source_cache[size]

        candidates = (
            "consola.ttf",
            "Consolas.ttf",
            "cour.ttf",
            "DejaVuSansMono.ttf",
            "LiberationMono-Regular.ttf",
        )
        source = None
        for name in candidates:
            try:
                source = ImageFont.truetype(name, size)
                break
            except OSError:
                continue

        if source is None:
            try:
                source = ImageFont.load_default(size=size)
            except TypeError:  # Pillow < 10.1
                source = ImageFont.load_default()

        self._source_cache[size] = source
        return source

    def _name_output(self, origin: str, line: int | str, label: str) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        base = _slug(origin) or self.file_stem or "python"
        label_line = f"L{line}" if isinstance(line, int) else str(line)
        parts = [base, label_line]
        if label:
            parts.append(_slug(label))
        return self.output_dir / ("_".join(p for p in parts if p) + ".png")


def _slug(value: str, limit: int = 48) -> str:
    clean = _SANITIZE_RE.sub("_", str(value or "")).strip("._-")
    return clean[:limit] or "evidence"

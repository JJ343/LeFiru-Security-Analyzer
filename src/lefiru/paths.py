"""Resource path and output folder resolution.

Single source of truth for answering "where is this file?".
Replaces the ``Path(__file__).parents[N]`` calls scattered across the
application, which broke when a module was moved to another folder.
"""

from __future__ import annotations

import os
import sys
from importlib.resources import files
from pathlib import Path

PACKAGE = "lefiru"
OUTPUT_ENV_VAR = "LEFIRU_OUTPUT"
DEFAULT_OUTPUT_DIRNAME = "results"


def resource(*parts: str) -> Path:
    """Return the path of a resource packaged inside ``lefiru``.

    Example: ``resource("ui/resources/icon.png")``.
    """
    return Path(str(files(PACKAGE).joinpath(*parts)))


def is_frozen() -> bool:
    """``True`` when running from a frozen binary (PyInstaller/Nuitka)."""
    return bool(getattr(sys, "frozen", False))


def project_root() -> Path:
    """Repository root when running from source code."""
    return Path(__file__).resolve().parents[2]


def output_root() -> Path:
    """Root folder where logs, reports and evidence are written.

    Resolution order:

    1. ``LEFIRU_OUTPUT`` environment variable.
    2. Frozen application: ``results/`` next to the executable.
    3. Source code: ``results/`` at the project root.

    The location does not depend on the working directory, so the result is the
    same no matter where it is launched from. The folder is created by
    :func:`ensure_output_root`.
    """
    env = os.environ.get(OUTPUT_ENV_VAR)
    if env:
        return Path(env).expanduser()

    if is_frozen():
        base = Path(sys.executable).resolve().parent
    else:
        base = project_root()

    return base / DEFAULT_OUTPUT_DIRNAME


def ensure_output_root() -> Path:
    """Resolve :func:`output_root` and ensure the folder exists.

    Used when starting an analysis so that the results folder is created even
    if no report has been written yet.
    """
    root = output_root()
    root.mkdir(parents=True, exist_ok=True)
    return root

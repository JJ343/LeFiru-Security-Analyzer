"""
Common utilities for security analysis
"""

import hashlib
import logging
import re
import unicodedata
from pathlib import Path


def calculate_file_hash(file_path: Path, algorithm: str = "sha256") -> str:
    """
    Calculates the hash of a file
    """
    hash_obj = hashlib.new(algorithm)
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()


def setup_logging(
    output_dir: str,
    level: int = logging.INFO,
    enable_file: bool = True,
) -> str | None:
    """
    Configures logging SAFELY:
    - Closes existing handlers
    - Releases locked files (Windows)
    - Creates a new log file only when ``enable_file`` is true

    Returns the log file path, or ``None`` when file logging is disabled.
    """

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    #  CLOSE AND REMOVE EXISTING HANDLERS 
    for handler in root_logger.handlers[:]:
        try:
            handler.close()
        except Exception:
            pass
        root_logger.removeHandler(handler)

    formatter = logging.Formatter(
        fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    log_file = None
    if enable_file:
        # Create log directory
        log_dir = Path(output_dir) / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)

        log_file = log_dir / "lefiru_analysis.log"

        # File handler
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        file_handler.setLevel(level)
        root_logger.addHandler(file_handler)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)
    root_logger.addHandler(console_handler)

    return str(log_file) if log_file is not None else None


def sanitize_string(text: str, max_length: int = 50) -> str:
    """
    Sanitizes and truncates strings for safe logging
    """
    if not text:
        return ""

    sanitized = text.replace('\r', '').replace('\n', ' ')
    if len(sanitized) > max_length:
        return sanitized[:max_length] + "..."
    return sanitized


_CRITICAL_SHEET_KEYWORDS = frozenset({
    # Inputs / outputs
    "input", "inputs", "input", "inputs",
    "output", "outputs", "output", "outputs",
    # Configuration / parameters
    "config", "configuration", "settings", "setup", "settings",
    "parameter", "parametros", "param", "params",
    # Data / bases
    "data", "data", "dataset", "base", "bases", "bd", "db",
    # Calculation / results
    "calculation", "calculations", "calc", "calcs",
    "result", "results", "result", "results",
    "formula", "formulas",
    # Processes / control
    "process", "processes", "process",
    "control", "controls",
    "validation", "validations",
    "conciliation", "reconciliations",
    # Reports / consolidation
    "report", "reports", "report", "reports",
    "report", "reports",
    "consolidated", "consolidacion",
    "summary", "summary",
    # Indicators
    "kpi", "kpis", "metric", "metricas",
    "indicator", "indicators",
    # Master sheets
    "main", "main", "master", "master", "master",
    # Financial
    "balance", "balances",
})

# Minimum length to enable the substring fallback (avoids false
# positives with short tokens such as "bd", "db", "kpi" embedded in other names).
_MIN_SUBSTRING_KEYWORD_LEN = 6

_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")


def _strip_accents(text: str) -> str:
    """Removes diacritics for accent-insensitive comparisons."""
    return "".join(
        ch for ch in unicodedata.normalize("NFD", text)
        if unicodedata.category(ch) != "Mn"
    )


def is_critical_sheet(sheet_name: str) -> bool:
    """
    Determines whether a sheet is critical based on its name.

    Rules:
      - Case-insensitive, accent-insensitive (`Calculation` == `calculation`)
        and separator-insensitive (spaces, dashes, underscores, dots, etc.).
      - Exact token match on the normalized name, to avoid false positives
        with words that contain the keyword incidentally.
      - Substring fallback reserved for keywords of at least
        `_MIN_SUBSTRING_KEYWORD_LEN` characters, useful for compact names
        such as `BD_DatosClientes2024`.
      - Empty, non-string or alphanumeric-free entries → False.
    """
    if not isinstance(sheet_name, str) or not sheet_name.strip():
        return False

    normalized = _strip_accents(sheet_name).lower()
    cleaned = _NON_ALNUM_RE.sub(" ", normalized).strip()
    if not cleaned:
        return False

    tokens = set(cleaned.split())
    if tokens & _CRITICAL_SHEET_KEYWORDS:
        return True

    compact = cleaned.replace(" ", "")
    return any(
        keyword in compact
        for keyword in _CRITICAL_SHEET_KEYWORDS
        if len(keyword) >= _MIN_SUBSTRING_KEYWORD_LEN
    )


def anonymize_credential(text: str) -> str:
    """
    Anonymizes credentials for reports
    """
    if len(text) <= 4:
        return "***"
    return text[:2] + "*" * (len(text) - 4) + text[-2:]


def tests_by_key(tests) -> dict:
    """Converts the internal list of tests into a ``key -> section`` map.

    The key is the test slug (``structure_protection``, ``vba``, ...); the
    section exposes only name, status and detail, without numbering.
    It also accepts an already converted dictionary so it is idempotent.
    """
    if isinstance(tests, dict):
        return tests

    result: dict = {}
    for test in tests or []:
        key = test.get("key") or test.get("id")
        if not key:
            continue
        result[key] = {
            "name": test.get("name", ""),
            "status": test.get("status", ""),
            "detail": test.get("detail", ""),
        }
    return result


def tests_as_list(tests) -> list[dict]:
    """Returns the tests as a list of dictionaries with ``key``.

    It is the format consumed by the LaTeX/PDF report and other internal traversals;
    the public JSON uses ``tests`` by key.
    """
    if isinstance(tests, dict):
        return [
            {"key": key, **section}
            for key, section in tests.items()
        ]
    return [
        {
            "key": test.get("key") or test.get("id", ""),
            "name": test.get("name", ""),
            "status": test.get("status", ""),
            "detail": test.get("detail", ""),
        }
        for test in (tests or [])
    ]

def prepare_output_directories(
    base_output: str,
    excel_file: Path,
    mode: str = None
) -> dict:
    """
    Creates the output structure per file (without mode subfolders).
    The mode parameter is accepted for compatibility but ignored.
    """
    base_output = Path(base_output)

    file_name = excel_file.stem
    root = base_output / file_name

    paths = {
        "root": root,
        "logs": root / "logs",
        "reports": root / "reports",
        "evidence": root / "reports" / "evidence",
        "backups": root / "backups",
    }

    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)

    return paths
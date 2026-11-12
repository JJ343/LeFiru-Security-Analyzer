"""openpyxl compatibility with ``.xlam`` add-ins.

openpyxl validates the file extension against its internal ``SUPPORTED_FORMATS``
list before reading the container. An ``.xlam`` add-in is an OOXML container just
like ``.xlsx`` or ``.xlsm``: it is excluded only because of its name, not because
of its content. This module extends that list once, when importing the
:mod:`lefiru.core.analyzers.excel` subpackage, and does not modify anything else
in the library.
"""

import logging

logger = logging.getLogger(__name__)

# Workbook extensions the engine must be able to read with openpyxl.
OPENPYXL_EXTENSIONS = (".xlsx", ".xlsm", ".xltx", ".xltm", ".xlam")

_enabled = False


def enable_extensions_openpyxl() -> None:
    """Allow openpyxl to read ``.xlam`` in addition to its native formats."""
    global _enabled
    if _enabled:
        return

    try:
        import openpyxl.reader.excel as reader
    except ImportError:  # pragma: no cover - openpyxl is a required dependency
        return

    formats = tuple(getattr(reader, "SUPPORTED_FORMATS", ()))
    if formats and ".xlam" not in formats:
        reader.SUPPORTED_FORMATS = formats + (".xlam",)
        logger.debug("openpyxl: .xlam extension enabled for reading")

    _enabled = True

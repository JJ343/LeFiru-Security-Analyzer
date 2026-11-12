"""Excel COM engine detection and bitness-aware activation.

Excel may be installed as 32-bit or 64-bit, while Python runs in either flavor.
Windows keeps two registry views and each one may point to a different server
(or to an impostor, such as WPS Office, which registers ``et.exe /Automation``).

To activate Excel regardless of bitness, this module uses **local activation with
an explicit architecture preference**:

* ``CLSCTX_LOCAL_SERVER`` avoids ``InprocServer32`` (the .NET interop assembly),
  which cannot be loaded across different bitnesses;
* ``CLSCTX_ACTIVATE_32_BIT_SERVER`` / ``CLSCTX_ACTIVATE_64_BIT_SERVER`` tell COM
  which registry view to use when the client and the server do not match.

With that, a 64-bit Python can automate a 32-bit Excel (and vice versa) without
installing another interpreter or modifying the registry.
"""

from __future__ import annotations

import logging
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Excel.Application CLSID (independent of the Office version).
CLSID_EXCEL = "{00024500-0000-0000-C000-000000000046}"

# COM activation flags.
CLSCTX_LOCAL_SERVER = 0x4
CLSCTX_ACTIVATE_32_BIT_SERVER = 0x40000
CLSCTX_ACTIVATE_64_BIT_SERVER = 0x80000

# Registry subkeys where the CLSID's local server may appear.
_LOCAL_SERVER_SUBCLAVES = (
    ("HKLM", r"SOFTWARE\Classes\CLSID\{clsid}\LocalServer32"),
    ("HKCU", r"Software\Classes\CLSID\{clsid}\LocalServer32"),
)

_NAME_EXCEL = "excel.exe"


class ComNotAvailableError(RuntimeError):
    """No Excel installation is registered for automation."""


@dataclass(frozen=True)
class OfficeEngine:
    """Excel COM engine registered in one registry view."""

    bits: int
    exe: Path
    view: str

    def __str__(self) -> str:
        return f"Excel {self.bits} bits ({self.exe}) [{self.view}]"


@dataclass(frozen=True)
class ComPlan:
    """Decision on how to activate Excel on this machine."""

    type: str  # "direct" | "no_available"
    engine: Optional[OfficeEngine] = None
    reason: str = ""

    @property
    def available(self) -> bool:
        return self.type == "direct" and self.engine is not None


def python_bits() -> int:
    """Bitness of the interpreter running this process (32 or 64)."""
    return struct.calcsize("P") * 8


def _separate_server(value: str) -> str:
    """Extract the executable path from a ``LocalServer32`` value.

    The value may be quoted and include arguments
    (``"C:\\...\\EXCEL.EXE" /automation``) or be unquoted.
    """

    value = value.strip()
    if not value:
        return ""

    if value.startswith('"'):
        end = value.find('"', 1)
        return value[1:end] if end != -1 else value.strip('"')

    index = value.lower().find(".exe")
    if index != -1:
        return value[: index + 4]

    return value.split(" ", 1)[0]


def _read_value(key: str, view: int) -> Optional[str]:
    """Read the default value of a registry key in a given view."""

    try:
        import winreg
    except ImportError:  # pragma: no cover - Windows only
        return None

    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            key,
            0,
            winreg.KEY_READ | view,
        ) as handler:
            value, _ = winreg.QueryValueEx(handler, "")
            return str(value)
    except OSError:
        return None


def servers_registered() -> List[Dict[str, Any]]:
    """List the ``LocalServer32`` entries for the Excel CLSID in both views.

    Entries that are **not** Excel are included so the user can be told what is
    intercepting the ProgID. The order is: 64-bit view (HKLM, HKCU) and then the
    32-bit view (HKLM, HKCU).
    """

    if sys.platform != "win32":
        return []

    try:
        import winreg
    except ImportError:  # pragma: no cover - Windows only
        return []

    views = (
        (64, winreg.KEY_WOW64_64KEY),
        (32, winreg.KEY_WOW64_32KEY),
    )

    entries: List[Dict[str, Any]] = []
    seen = set()

    for bits, flag in views:
        for hive, template in _LOCAL_SERVER_SUBCLAVES:
            key = template.format(clsid=CLSID_EXCEL)
            value = _read_value(key, flag)
            if not value:
                continue

            exe = _separate_server(value)
            if not exe:
                continue

            key = (bits, exe.lower())
            if key in seen:
                continue
            seen.add(key)

            entries.append(
                {
                    "bits": bits,
                    "exe": Path(exe),
                    "view": f"{hive} {bits} bits",
                    "value": value,
                }
            )

    return entries


def detect_engines() -> List[OfficeEngine]:
    """Registered Excel engines, ignoring servers that are not Excel."""

    engines: List[OfficeEngine] = []
    for entry in servers_registered():
        exe: Path = entry["exe"]
        if exe.name.lower() != _NAME_EXCEL:
            logger.debug(
                "COM server discarded (not Excel): %s [%s]",
                exe,
                entry["view"],
            )
            continue

        engine = OfficeEngine(
            bits=entry["bits"],
            exe=exe,
            view=entry["view"],
        )
        if engine not in engines:
            engines.append(engine)

    return engines


def describe_servers() -> str:
    """Human-readable summary of what is registered, for logs and messages."""

    entries = servers_registered()
    if not entries:
        return "No COM server is registered for Excel.Application."

    parts = []
    for entry in entries:
        exe: Path = entry["exe"]
        label = "Excel" if exe.name.lower() == _NAME_EXCEL else "OTHER"
        parts.append(f"{entry['view']}: {exe} ({label})")
    return "; ".join(parts)


def clsctx_for(engine_bits: int, client_bits: Optional[int] = None) -> int:
    """``CLSCTX`` flags to activate an Excel of the given bitness.

    Local activation is always used (never ``InprocServer32``). If the client and
    the server do not match, the architecture preference is added.
    """

    client = client_bits if client_bits is not None else python_bits()
    flags = CLSCTX_LOCAL_SERVER

    if client == 64 and engine_bits == 32:
        flags |= CLSCTX_ACTIVATE_32_BIT_SERVER
    elif client == 32 and engine_bits == 64:
        flags |= CLSCTX_ACTIVATE_64_BIT_SERVER

    return flags


def plan_com() -> ComPlan:
    """Decide how to activate Excel on this machine.

    If more than one Excel is registered, the one matching the interpreter's
    bitness is preferred (it avoids the architecture flag). If there is only one,
    it is used with the corresponding flag.
    """

    engines = detect_engines()
    if not engines:
        return ComPlan(
            type="no_available",
            reason=(
                "No Excel installation registered for automation was found. "
                f"{describe_servers()}"
            ),
        )

    process_bits = python_bits()
    engine = next((m for m in engines if m.bits == process_bits), engines[0])

    return ComPlan(
        type="direct",
        engine=engine,
        reason=(
            f"Excel {engine.bits}-bit and Python {process_bits}-bit; "
            f"activation with CLSCTX 0x{clsctx_for(engine.bits, process_bits):X}."
        ),
    )


def create_excel_application():
    """Create a new Excel instance with local, bitness-explicit activation.

    ``CoCreateInstance`` is used instead of ``Dispatch`` for two reasons:

    * ``Dispatch`` tries ``GetActiveObject`` first and could attach to an Excel
      instance the user already has open;
    * ``Dispatch`` uses ``CLSCTX_SERVER`` (in-proc + local) and on a 64-bit
      machine tries to load the .NET ``InprocServer32``, which fails with
      ``0x800700C1``.

    With ``CLSCTX_LOCAL_SERVER`` plus the architecture flag, COM starts a new
    Excel of the correct bitness and ``IDispatch`` marshaling handles the rest.
    """

    import pythoncom
    import win32com.client as win32

    plan = plan_com()
    if plan.available and plan.engine is not None:
        flags = clsctx_for(plan.engine.bits)
        logger.info("Activating Excel with CLSCTX 0x%X (%s)", flags, plan.engine)
        object = pythoncom.CoCreateInstance(
            CLSID_EXCEL, None, flags, pythoncom.IID_IDispatch
        )
        return win32.Dispatch(object)

    return win32.Dispatch("Excel.Application")


def create_analyzer_com(
    file_path: Path,
    output_root: Path,
    password: Optional[str] = None,
    plan: Optional[ComPlan] = None,
):
    """Return the ``LiveExcelInspector`` configured for this machine.

    Raises :class:`ComNotAvailableError` when no Excel is registered or
    ``pywin32`` is missing. Bitness is not an impediment: ``LiveExcelInspector``
    activates Excel with the flags computed by :func:`clsctx_for`.
    """

    from lefiru.core.analyzers.excel.excel_com import LiveExcelInspector, WIN32COM_AVAILABLE

    plan = plan or plan_com()

    if not plan.available:
        raise ComNotAvailableError(plan.reason)

    if not WIN32COM_AVAILABLE:
        raise ComNotAvailableError(
            "pywin32 is not installed; COM mode cannot run. "
            'Install the Windows extra: pip install -e ".[windows]"'
        )

    logger.info("COM: %s", plan.reason)
    return LiveExcelInspector(
        file_path,
        output_root=output_root,
        password=password,
    )

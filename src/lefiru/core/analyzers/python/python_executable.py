"""
Code extraction module for Python-generated executables (.exe).

Supports multiple packagers and extraction strategies:
  - PyInstaller: ZIP extraction, pyinstaller hooks detection
  - py2exe / cx_Freeze: embedded ZIP
  - Nuitka: compiled files
  - Fallback: binary pattern scanning

Extraction strategies:
  1. Packager type detection
  2. Extraction as an embedded ZIP (py2exe/cx_Freeze/PyInstaller)
  3. Binary pattern analysis (fallback)
  4. Search for .py/.pyc files inside
"""

from __future__ import annotations

import importlib
import dis
import io
import marshal
import logging
import types
import re
import struct
import tempfile
import zipfile
import zlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

RUNTIME_DIR_MARKERS = {
    "site-packages",
    "dist-packages",
    "lib-dynload",
    "__pycache__",
}
RUNTIME_FILE_PREFIXES = (
    "pyi_rth",
    "pyiboot",
    "pyimod",
    "_pyi_",
)

COMMON_MODULE_PREFIXES = (
    "encodings",
    "importlib",
    "collections",
    "concurrent",
    "asyncio",
    "http",
    "urllib",
    "xml",
    "email",
    "logging",
    "argparse",
    "pathlib",
    "inspect",
    "typing",
    "zipfile",
    "json",
    "re",
    "os",
    "sys",
    "site",
    "pkgutil",
    "platform",
)

COMMON_MODULE_NAMES = {
    "__future__",
    "__main__",
    "abc",
    "ast",
    "base64",
    "binascii",
    "calendar",
    "codecs",
    "contextlib",
    "copy",
    "csv",
    "datetime",
    "decimal",
    "functools",
    "hashlib",
    "heapq",
    "itertools",
    "math",
    "operator",
    "pickle",
    "queue",
    "random",
    "selectors",
    "shutil",
    "socket",
    "sqlite3",
    "ssl",
    "statistics",
    "string",
    "subprocess",
    "tempfile",
    "threading",
    "time",
    "traceback",
    "types",
    "uuid",
}


# ─── Detection Signatures and Patterns ─────────────────────────────────────
PYINSTALLER_MAGIC = b"PyInstaller"
PYINSTALLER_CARCHIVE_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
PE_HEADER = b"MZ"
PYC_MAGIC = b"\x42\x0d\x0d\x0a"  # Python 3.10+

# Known packager patterns
PACKAGER_PATTERNS = {
    "PyInstaller": [
        PYINSTALLER_MAGIC,
        PYINSTALLER_CARCHIVE_MAGIC,
        b"pyi-windows-manifest-filename",
        b"_MEIPASS",
        b"pyi_rth",
        b"pyiboot01_bootstrap",
        b"PYZ\x00",
    ],
    "py2exe": [
        b"py2exe",
        b"library.zip",
    ],
    "cx_Freeze": [
        b"cx_Freeze",
        b"library.zip",
    ],
    "Nuitka": [
        b"Nuitka",
        b"nuitka",
    ],
}


class PackagedExecutableExtractor:
    """
    Extractor for Python executables with support for multiple strategies.
    """

    def __init__(self, exe_path: Path, evidence_dir: Path, max_members: int = 100):
        """
        Initializes the extractor.

        Args:
            exe_path: path to the .exe executable
            evidence_dir: directory where the extracted evidence is saved
            max_members: maximum number of members to extract
        """
        self.exe_path = exe_path
        self.evidence_dir = evidence_dir
        self.max_members = max_members
        self.packager_type = None
        self.extraction_info: Dict[str, Any] = {
            "status": "no_initialized",
            "packager": None,
            "method": None,
            "extracted_files": 0,
            "files_discarded": 0,
            "analyzed_files": 0,
            "files_decompiled": 0,
            "directory": None,
            "modules": [],
            "pyz_detected": False,
            "pyz_folder": "PYZ.pyz_extracted",
            "pyz_modules": 0,
            "pyz_modules_list": [],
            "pyz_directory": None,
            "errors": [],
        }
        

    def detect_packager(self) -> Tuple[str, Dict[str, Any]]:
        """
        Detects the executable's packager type.

        Returns:
            (packager_type, metadata)
        """
        info = {"size": 0, "is_pe": False}

        def _result(packager: str) -> Tuple[str, Dict[str, Any]]:
            logger.info(
                "Packager detected for %s: %s (is_pe=%s, detail=%s)",
                self.exe_path.name,
                packager,
                info.get("is_pe"),
                info.get("detail", "no detail"),
            )
            return packager, info

        if not self.exe_path.exists():
            info["detail"] = "file does not exist"
            return _result("unknown")

        try:
            size = self.exe_path.stat().st_size
            info["size"] = size

            with open(self.exe_path, "rb") as fh:
                # Read the header and the tail
                head = fh.read(4096)
                fh.seek(max(0, size - 2 * 1024 * 1024))
                tail = fh.read()
        except OSError as e:
            info["error"] = str(e)
            info["detail"] = "read error"
            return _result("unknown")

        # Check whether it is a PE (Portable Executable)
        if head[:2] != PE_HEADER:
            if self._is_embedded_zip():
                info["detail"] = "ZIP file renamed to .exe (no PE header)"
                self.packager_type = "zip_embedded_no_pe"
                return _result("zip_embedded_no_pe")
            info["detail"] = "does not contain a PE header (MZ)"
            return _result("no_pe")
        
        info["is_pe"] = True

        # Packager detection by patterns
        for packager, patterns in PACKAGER_PATTERNS.items():
            for pattern in patterns:
                if pattern in tail or pattern in head:
                    self.packager_type = packager
                    info["detail"] = "packager signature found"
                    return _result(packager)

        # Specific detection of the PyInstaller CArchive cookie at the end.
        if self._find_pyinstaller_cookie(tail) >= 0:
            self.packager_type = "PyInstaller"
            info["detail"] = "PyInstaller CArchive cookie detected"
            return _result("PyInstaller")

        # Fallback: check whether it is an embedded ZIP
        if self._is_embedded_zip():
            info["detail"] = "PE with embedded ZIP detected"
            self.packager_type = "zip_embedded"
            return _result("zip_embedded")

        info["detail"] = "PE without known PyInstaller/py2exe/cx_Freeze/Nuitka signatures"
        return _result("unknown")

    def _is_embedded_zip(self) -> bool:
        """Checks whether the executable contains an embedded ZIP."""
        try:
            return zipfile.is_zipfile(self.exe_path)
        except Exception:
            return False

    def extract_zip_embedded(self) -> List[Tuple[str, bytes]]:
        """
        Extracts files from a ZIP embedded in the executable.

        Returns:
            List of tuples (filename, content_bytes)
        """
        results = []

        if not self._is_embedded_zip():
            self.extraction_info["errors"].append("Not a valid ZIP")
            return results

        try:
            with zipfile.ZipFile(self.exe_path, "r") as zf:
                members = zf.infolist()

                python_member_names = self._prioritize_member_names(
                    [
                        m.filename
                        for m in members
                        if not m.is_dir()
                        and self._is_python_member_name(m.filename)
                    ]
                )[: self.max_members]
                allowed_names = set(python_member_names)

                for member in members:
                    if member.filename not in allowed_names:
                        continue
                    try:
                        raw = zf.read(member)
                        results.append((member.filename, raw))
                    except KeyError as e:
                        self.extraction_info["errors"].append(
                            f"Could not read {member.filename}: {e}"
                        )

        except (zipfile.BadZipFile, OSError) as e:
            self.extraction_info["errors"].append(f"ZIP error: {e}")
            self.extraction_info["status"] = "error"

        return results

    def extract_pyinstaller(self) -> List[Tuple[str, bytes]]:
        """
        Extracts files from a PyInstaller executable.

        Tries:
          1. Direct embedded ZIP
          2. PyInstaller TOC (Table of Contents) search
          3. Known PyInstaller structure patterns
        """
        results = []

        # Strategy 1: real PyInstaller CArchive (one-file)
        try:
            carchive_results = self._extract_pyinstaller_carchive()
            results.extend(carchive_results)
            if results:
                logger.info("Successful PyInstaller CArchive extraction")
                self.extraction_info["method"] = "pyinstaller_carchive"
                return results
        except Exception as e:
            logger.warning(f"Error extracting PyInstaller CArchive: {e}")

        # Strategy 2: direct embedded ZIP
        results.extend(self.extract_zip_embedded())
        if results:
            logger.info("Successful embedded ZIP extraction for PyInstaller")
            self.extraction_info["method"] = "pyinstaller_zip_embedded"
            return results

        # Strategy 3: look for the PyInstaller TOC
        try:
            toc_results = self._extract_pyinstaller_toc()
            results.extend(toc_results)
            if results:
                logger.info("Successful PyInstaller TOC extraction")
                self.extraction_info["method"] = "pyinstaller_toc"
                return results
        except Exception as e:
            logger.warning(f"Error extracting PyInstaller TOC: {e}")

        # Fallback: pattern scanning
        self.extraction_info["method"] = "pyinstaller_patterns"
        logger.info("Pattern-based extraction for PyInstaller (fallback)")
        return results

    @staticmethod
    def _find_pyinstaller_cookie(data: bytes) -> int:
        """Returns the CArchive magic cookie offset, or -1 if it does not exist."""
        return data.rfind(PYINSTALLER_CARCHIVE_MAGIC)

    def _extract_pyinstaller_carchive(self) -> List[Tuple[str, bytes]]:
        """
        Tries to extract modules from the PyInstaller CArchive (one-file).

        Based on the cookie/TOC structure documented for PyInstaller.
        """
        results: List[Tuple[str, bytes]] = []

        with open(self.exe_path, "rb") as fh:
            blob = fh.read()

        file_size = len(blob)
        cookie_offset = self._find_pyinstaller_cookie(blob[-2 * 1024 * 1024 :])
        if cookie_offset < 0:
            return results

        # Adjust the offset relative to the last read segment.
        cookie_offset += max(0, file_size - 2 * 1024 * 1024)
        cookie = blob[cookie_offset:]

        parsed = self._parse_pyinstaller_cookie(cookie)
        if not parsed:
            return results

        package_length, toc_offset, toc_len = parsed
        overlay_start = file_size - package_length
        toc_start = overlay_start + toc_offset
        toc_end = toc_start + toc_len
        if not (0 <= overlay_start < file_size and 0 <= toc_start < toc_end <= file_size):
            self.extraction_info["errors"].append("PyInstaller TOC out of range")
            return results

        cursor = toc_start
        candidate_results: List[Tuple[str, bytes]] = []
        candidate_budget = max(self.max_members * 10, self.max_members)
        while cursor < toc_end and len(candidate_results) < candidate_budget:
            if cursor + 4 > toc_end:
                break
            entry_size = struct.unpack("!i", blob[cursor:cursor + 4])[0]
            if entry_size <= 18 or cursor + entry_size > toc_end:
                break

            base = cursor + 4
            entry_pos, cmprs_size, _uncmprs_size = struct.unpack("!III", blob[base:base + 12])
            cmprs_flag = blob[base + 12]
            type_code = bytes([blob[base + 13]])
            name_raw = blob[base + 14:cursor + entry_size]
            name = name_raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()

            data_start = overlay_start + entry_pos
            data_end = data_start + cmprs_size
            if not (0 <= data_start < data_end <= file_size):
                cursor += entry_size
                continue

            payload = blob[data_start:data_end]
            if cmprs_flag == 1:
                try:
                    payload = zlib.decompress(payload)
                except Exception:
                    cursor += entry_size
                    continue

            extracted = self._map_pyinstaller_entry_to_files(name, type_code, payload)
            for item_name, item_content in extracted:
                if len(candidate_results) >= candidate_budget:
                    break
                candidate_results.append((item_name, item_content))

            cursor += entry_size

        if candidate_results:
            results = self._prioritize_extracted_files(candidate_results)

        return results

    @staticmethod
    def _parse_pyinstaller_cookie(cookie: bytes) -> Optional[Tuple[int, int, int]]:
        """Parses the CArchive cookie and returns (package_length, toc_offset, toc_len)."""
        if len(cookie) < 24 or not cookie.startswith(PYINSTALLER_CARCHIVE_MAGIC):
            return None

        try:
            # Formato corto: magic + package_len + toc + toc_len + pyver
            if len(cookie) >= 24:
                package_len, toc_offset, toc_len, _pyver = struct.unpack("!iiii", cookie[8:24])
                if package_len > 0 and toc_offset >= 0 and toc_len > 0:
                    return package_len, toc_offset, toc_len
        except struct.error:
            return None

        return None

    def _map_pyinstaller_entry_to_files(
        self,
        name: str,
        type_code: bytes,
        payload: bytes,
    ) -> List[Tuple[str, bytes]]:
        """Maps a CArchive entry to one or more extractable files."""
        extracted: List[Tuple[str, bytes]] = []
        if not name:
            return extracted

        lowered = name.lower()

        if self._looks_like_pyz_archive(name, type_code, payload):
            pyz_members = self._extract_pyz_members(payload, pyz_name=name)
            if pyz_members:
                self.extraction_info["pyz_detected"] = True
                return pyz_members

        if type_code in {b"m", b"M", b"s"}:
            out_name = name if lowered.endswith(".pyc") else f"{name}.pyc"
            extracted.append((out_name, payload))
            return extracted

        if lowered.endswith(".py") or lowered.endswith(".pyc"):
            extracted.append((name, payload))

        return extracted

    @staticmethod
    def _looks_like_pyz_archive(name: str, type_code: bytes, payload: bytes) -> bool:
        lowered = name.lower()
        if lowered.endswith(".pyz"):
            return True
        if lowered.startswith("pyz") and payload.startswith(b"PYZ\x00"):
            return True
        if type_code in {b"z", b"Z"} and payload.startswith(b"PYZ\x00"):
            return True
        return False

    def _extract_pyz_members(self, payload: bytes, pyz_name: str) -> List[Tuple[str, bytes]]:
        """
        Extracts members from a PYZ (pyinstxtractor style) as rebuilt .pyc files.

        Output under the virtual folder `PYZ.pyz_extracted/` so that, when
        persisted, the expected tree is materialized in the evidence.
        """
        if len(payload) < 16 or not payload.startswith(b"PYZ\x00"):
            return []

        pyz_data = payload
        toc_pos = self._read_pyz_toc_offset(pyz_data)
        if toc_pos is None:
            self.extraction_info["errors"].append(
                f"PYZ not parsable (invalid TOC): {pyz_name}"
            )
            return []

        try:
            toc_obj = marshal.loads(pyz_data[toc_pos:])
        except Exception as exc:  # noqa: BLE001
            self.extraction_info["errors"].append(
                f"PYZ not parsable (TOC marshal): {pyz_name} -> {exc}"
            )
            return []

        unpacked: List[Tuple[str, bytes, bool]] = []
        toc_entries = self._iter_pyz_toc_entries(toc_obj)
        if not toc_entries:
            self.extraction_info["errors"].append(
                f"Unexpected PYZ TOC for {pyz_name} ({type(toc_obj).__name__})"
            )
            return []

        for raw_name, raw_entry in toc_entries:
            module_name = self._normalize_pyz_module_name(raw_name)
            entry_info = self._parse_pyz_toc_entry(raw_entry)
            if not entry_info:
                continue
            pos, length, is_pkg = entry_info
            if pos < 0 or length <= 0 or pos + length > len(pyz_data):
                continue
            chunk = pyz_data[pos:pos + length]
            try:
                chunk = zlib.decompress(chunk)
            except Exception:
                # Some bundles may come without per-entry compression.
                pass

            pyc_bytes = self._build_pyc_from_pyz_entry(chunk)
            if not pyc_bytes:
                continue

            out_name = self._build_pyz_output_name(module_name, is_pkg)
            unpacked.append((out_name, pyc_bytes, self._is_uncommon_module_name(module_name)))

        if not unpacked:
            return []

        ordered = [
            (name, data)
            for name, data, _is_uncommon in sorted(
                unpacked,
                key=lambda item: self._pyz_member_priority_key(item[0], item[2]),
            )
        ]
        selected = ordered[: self.max_members]
        self._register_pyz_modules([name for name, _ in selected])
        return selected

    def _register_pyz_modules(self, module_paths: List[str]) -> None:
        if not module_paths:
            return
        current = list(self.extraction_info.get("pyz_modules_list", []))
        seen = set(current)
        for module_path in module_paths:
            if module_path not in seen:
                current.append(module_path)
                seen.add(module_path)
        self.extraction_info["pyz_modules_list"] = current[:200]
        self.extraction_info["pyz_modules"] = len(current)

    @staticmethod
    def _iter_pyz_toc_entries(toc_obj: Any) -> List[Tuple[Any, Any]]:
        """Normalizes PYZ TOC structures into (module_name, entry) pairs."""
        if isinstance(toc_obj, dict):
            return list(toc_obj.items())

        if isinstance(toc_obj, (list, tuple, set)):
            normalized: List[Tuple[Any, Any]] = []
            for item in toc_obj:
                if not isinstance(item, tuple) or len(item) < 2:
                    continue
                # Common variant: (name, entry_tuple)
                if len(item) == 2:
                    normalized.append((item[0], item[1]))
                    continue
                # Variant: (name, pos, len)
                if (
                    len(item) >= 3
                    and isinstance(item[1], int)
                    and isinstance(item[2], int)
                ):
                    if len(item) >= 4 and isinstance(item[3], int) and item[3] in {0, 1}:
                        normalized.append((item[0], (item[1], item[2], item[3])))
                    else:
                        normalized.append((item[0], (item[1], item[2], 0)))
            return normalized

        return []

    @staticmethod
    def _read_pyz_toc_offset(pyz_data: bytes) -> Optional[int]:
        if len(pyz_data) < 12:
            return None
        candidates = [
            struct.unpack("!I", pyz_data[8:12])[0],
            struct.unpack("<I", pyz_data[8:12])[0],
        ]
        for pos in candidates:
            if 0 <= pos < len(pyz_data):
                return pos
        return None

    @staticmethod
    def _normalize_pyz_module_name(raw_name: Any) -> str:
        if isinstance(raw_name, bytes):
            return raw_name.decode("utf-8", errors="replace")
        return str(raw_name)

    @staticmethod
    def _parse_pyz_toc_entry(raw_entry: Any) -> Optional[Tuple[int, int, bool]]:
        # Observed formats:
        #  - (ispkg, pos, len)
        #  - (pos, len, ispkg)
        #  - (ispkg, pos, len, typecode)
        #  - (typecode, pos, len, ispkg)
        if not isinstance(raw_entry, tuple) or len(raw_entry) < 3:
            return None

        if (
            len(raw_entry) >= 4
            and isinstance(raw_entry[0], int)
            and raw_entry[0] in {0, 1}
            and isinstance(raw_entry[1], int)
            and isinstance(raw_entry[2], int)
            and raw_entry[1] >= 0
            and raw_entry[2] > 0
        ):
            return raw_entry[1], raw_entry[2], bool(raw_entry[0])

        if (
            len(raw_entry) >= 4
            and isinstance(raw_entry[3], int)
            and raw_entry[3] in {0, 1}
            and isinstance(raw_entry[1], int)
            and isinstance(raw_entry[2], int)
            and raw_entry[1] >= 0
            and raw_entry[2] > 0
        ):
            return raw_entry[1], raw_entry[2], bool(raw_entry[3])

        a, b, c = raw_entry[:3]
        if isinstance(a, int) and isinstance(b, int) and isinstance(c, int):
            # Heuristic: if a is 0/1, take (ispkg, pos, len)
            if a in {0, 1} and b >= 0 and c > 0:
                return b, c, bool(a)
            # Alternative: (pos, len, ispkg)
            if c in {0, 1} and a >= 0 and b > 0:
                return a, b, bool(c)
        return None

    @staticmethod
    def _build_pyc_from_pyz_entry(entry_data: bytes) -> Optional[bytes]:
        try:
            maybe_obj = marshal.loads(entry_data)
        except Exception:
            return None

        if isinstance(maybe_obj, types.CodeType):
            # Minimal modern pyc header (magic + 12 null bytes)
            header = importlib.util.MAGIC_NUMBER + (b"\x00" * 12)
            return header + marshal.dumps(maybe_obj)
        return None

    @staticmethod
    def _build_pyz_output_name(module_name: str, is_pkg: bool) -> str:
        normalized = module_name.replace(".", "/")
        if is_pkg:
            normalized = f"{normalized}/__init__"
        return f"PYZ.pyz_extracted/{normalized}.pyc"

    @staticmethod
    def _is_uncommon_module_name(module_name: str) -> bool:
        lowered = module_name.lower().strip()
        if not lowered:
            return False
        if lowered in COMMON_MODULE_NAMES:
            return False
        if lowered.startswith(("pyi_", "_pyi_")):
            return False
        return not lowered.startswith(COMMON_MODULE_PREFIXES)

    def _extract_pyinstaller_toc(self) -> List[Tuple[str, bytes]]:
        """Looks for the PyInstaller TOC (Table of Contents)."""
        results = []

        try:
            with open(self.exe_path, "rb") as fh:
                data = fh.read()

            # Pattern: find 'pyi-windows-manifest-filename' and cut from there
            toc_marker = b"pyi-windows-manifest-filename"
            pos = data.find(toc_marker)

            if pos > 0:
                # Try to parse the structure (simplified)
                logger.debug(f"TOC marker found at offset {pos}")

                # Search for an embedded ZIP after the marker
                for i in range(pos, len(data) - 4):
                    if data[i:i+2] == b"PK":  # ZIP local header
                        try:
                            # Try to open as ZIP from this offset
                            zip_data = data[i:]
                            results = self._parse_zip_bytes(zip_data)
                            if results:
                                return results
                        except Exception:
                            pass

        except Exception as e:
            logger.warning(f"Error in _extract_pyinstaller_toc: {e}")

        return results

    def _parse_zip_bytes(self, zip_bytes: bytes) -> List[Tuple[str, bytes]]:
        """Tries to parse bytes as a ZIP."""
        results = []

        try:
            # Create an in-memory temporary file
            import io
            zip_buffer = io.BytesIO(zip_bytes)
            
            with zipfile.ZipFile(zip_buffer, "r") as zf:
                members = zf.infolist()
                python_member_names = self._prioritize_member_names(
                    [
                        member.filename
                        for member in members
                        if not member.is_dir() and self._is_python_member_name(member.filename)
                    ]
                )[: self.max_members]
                allowed_names = set(python_member_names)

                for member in members:
                    if member.filename not in allowed_names:
                        continue
                    try:
                        raw = zf.read(member)
                        results.append((member.filename, raw))
                    except KeyError:
                        pass

        except (zipfile.BadZipFile, Exception):
            pass

        return results

    def extract_cx_freeze(self) -> List[Tuple[str, bytes]]:
        """Extracts files from a cx_Freeze executable."""
        # cx_Freeze uses an embedded ZIP similar to py2exe
        self.extraction_info["method"] = "cx_freeze_zip"
        return self.extract_zip_embedded()

    def extract_py2exe(self) -> List[Tuple[str, bytes]]:
        """Extracts files from a py2exe executable."""
        # py2exe packs into library.zip at the end
        results = []

        try:
            # Look for the library.zip signature
            with open(self.exe_path, "rb") as fh:
                data = fh.read()

            # library.zip is usually preceded by its name
            library_zip_marker = b"library.zip"
            pos = data.rfind(library_zip_marker)

            if pos > 0:
                # Try to extract from 4 bytes before (ZIP header)
                for offset in range(max(0, pos - 512), pos):
                    if data[offset:offset+2] == b"PK":
                        try:
                            zip_data = data[offset:]
                            results = self._parse_zip_bytes(zip_data)
                            if results:
                                self.extraction_info["method"] = "py2exe_library_zip"
                                return results
                        except Exception:
                            pass

            # Fallback: direct embedded ZIP
            self.extraction_info["method"] = "py2exe_zip_embedded"
            return self.extract_zip_embedded()

        except Exception as e:
            self.extraction_info["errors"].append(f"Error py2exe: {e}")

        return results

    def extract_by_packager(self) -> List[Tuple[str, bytes]]:
        """
        Extracts content according to the detected packager type.

        Returns:
            List of tuples (filename, content_bytes)
        """
        if not self.packager_type:
            packager, _ = self.detect_packager()
            self.packager_type = packager

        self.extraction_info["packager"] = self.packager_type

        if self.packager_type == "PyInstaller":
            return self.extract_pyinstaller()
        elif self.packager_type in ("py2exe", "zip_embedded", "zip_embedded_no_pe"):
            return self.extract_py2exe()
        elif self.packager_type == "cx_Freeze":
            return self.extract_cx_freeze()
        elif self.packager_type == "Nuitka":
            return self._extract_nuitka()
        else:
            # Fallback: try a generic embedded ZIP
            return self.extract_zip_embedded()

    def _extract_nuitka(self) -> List[Tuple[str, bytes]]:
        """Extracts files from a Nuitka executable."""
        # Nuitka compiles to C++, so there are usually no internal .py files
        self.extraction_info["method"] = "nuitka_no_supported"
        self.extraction_info["errors"].append(
            "Nuitka compiles to C++; source code extraction is not available"
        )
        return []

    def extract_binary_patterns(self) -> List[Dict[str, Any]]:
        """
        Extracts patterns from the binary when there is no direct extraction.

        Looks for:
          - ASCII/Unicode strings of Python code
          - URLs, connections, credentials
          - Import and definition patterns
        """
        patterns = []

        try:
            with open(self.exe_path, "rb") as fh:
                data = fh.read()

            # Extract printable strings
            strings = self._extract_strings(data)

            # Look for Python code patterns
            python_patterns = [
                r"^import\s+\w+",
                r"^from\s+\w+\s+import",
                r"^def\s+\w+",
                r"^class\s+\w+",
                r"password\s*=",
                r"api[_-]?key\s*=",
                r"token\s*=",
                r"https?://\S+",
            ]

            for s in strings:
                for pattern in python_patterns:
                    if re.match(pattern, s, re.IGNORECASE):
                        patterns.append({
                            "type": "pattern_binary",
                            "content": s,
                            "pattern": pattern,
                        })

        except Exception as e:
            self.extraction_info["errors"].append(f"Binary scan error: {e}")

        self.extraction_info["method"] = "scan_binary"
        return patterns

    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extracts readable strings from binary data."""
        strings = []

        # ASCII strings
        current = bytearray()
        for byte in data:
            if 32 <= byte < 127:  # Printable ASCII range
                current.append(byte)
            else:
                if len(current) >= min_length:
                    try:
                        strings.append(current.decode("ascii"))
                    except Exception:
                        pass
                current = bytearray()

        if len(current) >= min_length:
            try:
                strings.append(current.decode("ascii"))
            except Exception:
                pass

        # Unicode strings (UTF-16)
        try:
            text = data.decode("utf-16", errors="ignore")
            for line in text.split("\x00"):
                if len(line) >= min_length and line.isprintable():
                    strings.append(line)
        except Exception:
            pass

        return strings

    def full_extraction(self) -> List[Tuple[str, bytes]]:
        """
        Performs a full extraction with all the strategies.

        First tries specific extraction, then falls back to patterns.
        """
        # 1. Detect type
        packager, packager_info = self.detect_packager()
        self.packager_type = packager
        self.extraction_info["packager"] = packager

        # 2. Try specific extraction
        extracted_files = self.extract_by_packager()
        extracted_files = self._prioritize_extracted_files(extracted_files)
        logger.info(f"Number of extracted files: {len(extracted_files)}")

        if extracted_files:
            self._persist_extracted_files(extracted_files)
            self.extraction_info["status"] = "successful"
            logger.info("File extraction successful")
            return extracted_files

        # 3. Fallback to binary patterns
        logger.info(
            f"Specific extraction failed for {packager}; "
            f"falling back to pattern scanning"
        )
        patterns = self.extract_binary_patterns()

        self.extraction_info["status"] = "successful_partial"
        self.extraction_info["patterns_binary"] = patterns

        return []

    def get_extraction_info(self) -> Dict[str, Any]:
        """Returns information about the performed extraction."""
        return self.extraction_info.copy()

    @staticmethod
    def _is_python_member_name(member_name: str) -> bool:
        normalized = member_name.replace("\\", "/")
        return normalized.endswith((".py", ".pyc")) or "__main__" in normalized

    def _prioritize_extracted_files(
        self,
        extracted_files: List[Tuple[str, bytes]],
    ) -> List[Tuple[str, bytes]]:
        """
        Keeps first the modules that look like they belong to the executable.

        If a clear entrypoint is detected (`__main__`, `main`, exe name), those
        modules and their siblings of the same root package are prioritized.
        Otherwise, typical paths of bundled dependencies are discarded first.
        """
        if not extracted_files:
            self.extraction_info["modules"] = []
            self.extraction_info["extracted_files"] = 0
            self.extraction_info["files_discarded"] = 0
            return extracted_files

        by_name: Dict[str, bytes] = {}
        ordered_names: List[str] = []
        for name, content in extracted_files:
            if name in by_name:
                continue
            by_name[name] = content
            ordered_names.append(name)

        selected_names = self._prioritize_member_names(ordered_names)[: self.max_members]
        selected_files = [(name, by_name[name]) for name in selected_names if name in by_name]

        self.extraction_info["modules"] = selected_names
        self.extraction_info["extracted_files"] = len(selected_files)
        self.extraction_info["files_discarded"] = max(0, len(ordered_names) - len(selected_names))

        return selected_files

    def _prioritize_member_names(self, member_names: List[str]) -> List[str]:
        normalized_names: List[str] = []
        seen = set()
        for member_name in member_names:
            if not self._is_python_member_name(member_name):
                continue
            if member_name in seen:
                continue
            seen.add(member_name)
            normalized_names.append(member_name)

        if not normalized_names:
            return []

        preferred_roots = {
            parts[0]
            for parts in (self._member_parts(name) for name in normalized_names)
            if len(parts) > 1 and self._is_primary_member_name(name="/".join(parts))
        }

        ranked = sorted(normalized_names, key=self._member_priority_key)
        primary_or_root = [
            name for name in ranked
            if self._is_primary_member_name(name)
            or self._member_root(name) in preferred_roots
        ]
        if primary_or_root:
            remaining = [name for name in ranked if name not in primary_or_root]
            non_dependency = [name for name in remaining if not self._looks_like_runtime_dependency(name)]
            return primary_or_root + non_dependency

        non_dependency = [name for name in ranked if not self._looks_like_runtime_dependency(name)]
        if non_dependency:
            return non_dependency

        return ranked

    def _member_priority_key(self, member_name: str) -> Tuple[int, int, int, str]:
        is_primary = self._is_primary_member_name(member_name)
        is_dependency = self._looks_like_runtime_dependency(member_name)
        is_generic = self._looks_like_generic_python_module(member_name)
        has_affinity = self._has_executable_name_affinity(member_name)
        parts = self._member_parts(member_name)
        bucket = (
            0 if is_primary else
            1 if has_affinity and not is_dependency else
            2 if not is_dependency and not is_generic else
            3 if not is_dependency else
            4
        )
        return bucket, len(parts), len(member_name), member_name.lower()

    def _is_primary_member_name(self, name: str) -> bool:
        parts = self._member_parts(name)
        stem = Path(parts[-1]).stem.lower().replace("-", "_").replace(" ", "_")
        exe_stem = self.exe_path.stem.lower().replace("-", "_").replace(" ", "_")
        return stem in {"__main__", "main", exe_stem}

    @staticmethod
    def _member_parts(member_name: str) -> Tuple[str, ...]:
        normalized = member_name.replace("\\", "/").strip("/")
        if not normalized:
            return tuple()
        return tuple(part.lower() for part in normalized.split("/") if part)

    def _member_root(self, member_name: str) -> str:
        parts = self._member_parts(member_name)
        return parts[0] if parts else ""

    def _looks_like_generic_python_module(self, member_name: str) -> bool:
        parts = [part for part in self._member_parts(member_name) if part != "pyz.pyz_extracted"]
        if not parts:
            return False

        stem = Path(parts[-1]).stem.lower()
        root = parts[0]
        if stem in COMMON_MODULE_NAMES or root in COMMON_MODULE_NAMES:
            return True
        if any(stem.startswith(prefix) for prefix in COMMON_MODULE_PREFIXES):
            return True
        if any(root.startswith(prefix) for prefix in COMMON_MODULE_PREFIXES):
            return True
        return False

    def _has_executable_name_affinity(self, member_name: str) -> bool:
        parts = [part for part in self._member_parts(member_name) if part != "pyz.pyz_extracted"]
        if not parts:
            return False

        normalized_name = "/".join(parts)
        for token in self._executable_name_tokens():
            if token in normalized_name:
                return True
        return False

    def _executable_name_tokens(self) -> Tuple[str, ...]:
        stem = self.exe_path.stem.lower().replace("-", "_").replace(" ", "_")
        raw_tokens = [token for token in stem.split("_") if token]
        ranked: List[str] = []
        seen = set()
        for token in raw_tokens:
            if len(token) < 3:
                continue
            if token in seen:
                continue
            ranked.append(token)
            seen.add(token)
        return tuple(ranked)

    def _pyz_member_priority_key(self, member_name: str, is_uncommon: bool) -> Tuple[int, int, int, str]:
        is_dependency = self._looks_like_runtime_dependency(member_name)
        has_affinity = self._has_executable_name_affinity(member_name)
        is_generic = self._looks_like_generic_python_module(member_name)
        parts = self._member_parts(member_name)
        bucket = (
            0 if has_affinity and is_uncommon else
            1 if has_affinity else
            2 if is_uncommon and not is_generic else
            3 if not is_dependency and not is_generic else
            4 if not is_dependency else
            5
        )
        return bucket, len(parts), len(member_name), member_name.lower()

    def _looks_like_runtime_dependency(self, member_name: str) -> bool:
        parts = self._member_parts(member_name)
        if not parts:
            return False

        if any(part in RUNTIME_DIR_MARKERS for part in parts[:-1]):
            return True

        stem = Path(parts[-1]).stem.lower()
        return stem.startswith(RUNTIME_FILE_PREFIXES)

    def _persist_extracted_files(self, extracted_files: List[Tuple[str, bytes]]) -> None:
        """
        Saves the extracted files into the evidence folder.

        A subfolder per executable is created to preserve the structure and
        avoid collisions between analyses.
        """
        extraction_dir = self.evidence_dir / f"{self.exe_path.stem}_extracted"
        extraction_dir.mkdir(parents=True, exist_ok=True)

        written = 0
        decompiled = 0
        for filename, content in extracted_files:
            destination = self._safe_destination_path(extraction_dir, filename)
            if destination is None:
                self.extraction_info["errors"].append(
                    f"Unsafe path skipped while saving: {filename}"
                )
                continue

            destination.parent.mkdir(parents=True, exist_ok=True)
            try:
                destination.write_bytes(content)
                written += 1
                if destination.suffix.lower() == ".pyc":
                    if self._persist_decompiled_pyc(destination):
                        decompiled += 1
            except OSError as exc:
                self.extraction_info["errors"].append(
                    f"Could not save {filename} to evidence: {exc}"
                    
                )

        self.extraction_info["directory"] = str(extraction_dir)
        pyz_relative = str(self.extraction_info.get("pyz_folder", "PYZ.pyz_extracted"))
        pyz_directory = extraction_dir / pyz_relative
        if pyz_directory.exists() and pyz_directory.is_dir():
            self.extraction_info["pyz_directory"] = str(pyz_directory)
        logger.info(f"Files saved to {str(extraction_dir)}")
        self.extraction_info["files_saved"] = written
        self.extraction_info["files_decompiled"] = decompiled

    @staticmethod
    def _safe_destination_path(base_dir: Path, member_name: str) -> Optional[Path]:
        """
        Builds a safe output path for an extracted member.

        Avoids path traversal and absolute paths coming from the artifact.
        """
        normalized = Path(member_name.replace("\\", "/"))
        if normalized.is_absolute():
            return None

        destination = base_dir / normalized
        try:
            destination.resolve().relative_to(base_dir.resolve())
        except ValueError:
            return None

        return destination

    def _persist_decompiled_pyc(self, pyc_path: Path) -> bool:
        """
        Tries to decompile an extracted .pyc and save a .py next to it.

        Uses external decompilers when available. If none works, leaves the
        original .pyc and records the event in the metadata/errors.
        """
        source_code, engine, error = self._decompile_pyc_file(pyc_path)
        if not source_code:
            is_marshal_payload = self._is_headerless_marshaled_code(pyc_path)
            if is_marshal_payload and error and "Unknown magic number" in error:
                logger.info(
                    "%s appears to be a marshal payload without a standard .pyc header "
                    "(common in artifacts extracted from PyInstaller).",
                    pyc_path.name,
                )

            # Useful fallback when the decompiler does not support the Python version.
            if error and (
                "Unsupported Python version" in error
                or "Unknown magic number" in error
            ):
                dis_ok = self._persist_disassembly_pyc(pyc_path)
                recovered_ok = self._persist_recovered_source_pyc(pyc_path)
                if dis_ok or recovered_ok:
                    logger.info(
                        "Could not decompile %s due to a format/version incompatibility; "
                        "fallback evidence was generated (.dis/.recovered).",
                        pyc_path.name,
                    )
                    return False
            if error:
                logger.warning(
                    "Failed to decompile %s. Reason: %s",
                    pyc_path.name,
                    error,
                )
                if is_marshal_payload and "Unknown magic number" in error:
                    error = (
                        f"{error} | marshal payload without a standard .pyc header "
                        "(PyInstaller)"
                    )
                self.extraction_info["errors"].append(
                    f"Could not decompile {pyc_path.name}: {error}"
                )
            return False

        py_destination = self._build_artifact_path(pyc_path, ".py")
        try:
            py_destination.write_text(source_code, encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning(
                "Decompilation succeeded but %s could not be saved: %s",
                py_destination.name,
                exc,
            )
            self.extraction_info["errors"].append(
                f"Could not save decompiled output {py_destination.name}: {exc}"
            )
            return False

        if engine:
            self.extraction_info.setdefault("decompilers_used", [])
            if engine not in self.extraction_info["decompilers_used"]:
                self.extraction_info["decompilers_used"].append(engine)

        logger.info(
            "Decompilation completed: %s -> %s (engine=%s)",
            pyc_path.name,
            py_destination.name,
            engine or "unknown",
        )
        return True

    def _decompile_pyc_file(self, pyc_path: Path) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Tries to decompile a .pyc using known engines.

        Attempt order:
          1. decompyle3
          2. uncompyle6
          3. internal recovery from marshal/code object
        """
        errors_by_engine: List[str] = []
        attempts: List[Tuple[str, str, str]] = [
            ("decompyle3", "library", "decompyle3.main"),
            ("uncompyle6", "library", "uncompyle6.main"),
            ("marshal_recovery", "internal", "marshal"),
        ]

        decompile_target = pyc_path
        synthetic_temp: Optional[Path] = self._build_synthetic_pyc_if_needed(pyc_path)
        if synthetic_temp is not None:
            decompile_target = synthetic_temp
            logger.info(
                "Attempting to decompile %s using a synthetic .pyc with a standard header",
                pyc_path.name,
            )

        try:
            for engine, mode, target in attempts:
                try:
                    logger.info("Attempting to decompile %s with %s", pyc_path.name, engine)
                    if mode == "library":
                        source = self._decompile_with_library(target, decompile_target)
                    elif mode == "internal":
                        source = self._decompile_with_internal_recovery(
                            decompile_target,
                            source_name=pyc_path.name,
                        )
                    else:
                        raise RuntimeError(f"Unsupported decompilation mode: {mode}")
                except (
                    ImportError,
                    AttributeError,
                    FileNotFoundError,
                    ValueError,
                    RuntimeError,
                    OSError,
                ) as exc:
                    logger.info(
                        "Engine %s could not decompile %s: %s",
                        engine,
                        pyc_path.name,
                        exc,
                    )
                    errors_by_engine.append(f"{engine}: {exc}")
                    continue

                if source:
                    return source, engine, None

                errors_by_engine.append(f"{engine}: produced no useful output")
        finally:
            if synthetic_temp is not None:
                synthetic_temp.unlink(missing_ok=True)

        if errors_by_engine:
            return None, None, " | ".join(errors_by_engine)
        return None, None, "No decompiler was attempted"

    def _persist_disassembly_pyc(self, pyc_path: Path) -> bool:
        """
        Generates a disassembly file (.py.dis) as a fallback.

        This allows manual inspection when high-level decompilation is not
        possible due to a version incompatibility.
        """
        try:
            raw = pyc_path.read_bytes()
            code_obj = self._load_code_object_from_pyc_like(raw)

            out_path = self._build_artifact_path(pyc_path, ".py.dis")
            out_text = io.StringIO()
            out_text.write(f"# Fallback disassembly for: {pyc_path.name}\n")
            out_text.write("# Reason: the decompiler does not support this Python version\n\n")
            out_text.write(dis.code_info(code_obj))
            out_text.write("\n\n")
            out_text.write(dis.Bytecode(code_obj).dis())
            out_path.write_text(out_text.getvalue(), encoding="utf-8", errors="replace")

            self.extraction_info["files_disassembled"] = (
                int(self.extraction_info.get("files_disassembled", 0)) + 1
            )
            return True
        except Exception as exc:  # noqa: BLE001
            self.extraction_info["errors"].append(
                f"Could not generate disassembly for {pyc_path.name}: {exc}"
            )
            return False

    def _persist_recovered_source_pyc(self, pyc_path: Path) -> bool:
        """
        Generates a .py.recovered file with approximate pseudocode.

        This file does not replace a real decompilation, but it is useful for a
        quick analysis of constants, assignments and function signatures.
        """
        try:
            raw = pyc_path.read_bytes()
            code_obj = self._load_code_object_from_pyc_like(raw)
            recovered_text = self._build_recovered_source(code_obj, pyc_path.name)

            out_path = self._build_artifact_path(pyc_path, ".py.recovered")
            out_path.write_text(recovered_text, encoding="utf-8", errors="replace")

            self.extraction_info["files_recovered"] = (
                int(self.extraction_info.get("files_recovered", 0)) + 1
            )
            return True
        except Exception as exc:  # noqa: BLE001
            self.extraction_info["errors"].append(
                f"Could not generate recovered code for {pyc_path.name}: {exc}"
            )
            return False

    def _build_artifact_path(self, pyc_path: Path, artifact_suffix: str) -> Path:
        """
        Builds an artifact name next to the original .pyc.

        Examples:
          module.pyc + .py -> module.py
          module.pyc + .py.recovered -> module.py.recovered
        """
        return pyc_path.with_name(f"{pyc_path.stem}{artifact_suffix}")

    @staticmethod
    def _load_code_object_from_pyc_like(raw: bytes) -> types.CodeType:
        """
        Tries to obtain a code object from .pyc payload variants.

        Accepts:
          - .pyc with a modern header (16 bytes)
          - .pyc with a legacy header (12 bytes)
          - marshal payload without a header (frequent in PyInstaller entries)
        """
        candidates: List[bytes] = []
        if len(raw) > 16:
            candidates.append(raw[16:])
        if len(raw) > 12:
            candidates.append(raw[12:])
        candidates.append(raw)

        last_error: Optional[Exception] = None
        for payload in candidates:
            try:
                obj = marshal.loads(payload)
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                continue
            if isinstance(obj, types.CodeType):
                return obj

        if last_error:
            raise ValueError(f"could not parse marshal payload: {last_error}")
        raise ValueError("could not parse marshal payload")

    @staticmethod
    def _is_headerless_marshaled_code(pyc_path: Path) -> bool:
        """
        Detects whether the file looks like a marshal payload without a standard
        pyc header.

        This is common in PyInstaller CArchive entries that do not store a
        complete .pyc file (header + payload), but directly the code object
        serialized with marshal.
        """
        try:
            raw = pyc_path.read_bytes()
            obj = marshal.loads(raw)
            if not isinstance(obj, types.CodeType):
                return False

            if len(raw) < 4:
                return True

            return raw[:4] != importlib.util.MAGIC_NUMBER
        except Exception:
            return False

    def _build_synthetic_pyc_if_needed(self, pyc_path: Path) -> Optional[Path]:
        """
        If the file is a pure marshal payload, creates a synthetic temporary .pyc.

        Some decompilers do not accept a marshal payload without a header, but
        they do work when given a standard pyc header.
        """
        if not self._is_headerless_marshaled_code(pyc_path):
            return None

        try:
            payload = pyc_path.read_bytes()
            code_obj = marshal.loads(payload)
            if not isinstance(code_obj, types.CodeType):
                return None

            # Modern pyc header (16 bytes): magic + flags + hash/timestamp.
            header = importlib.util.MAGIC_NUMBER + (b"\x00" * 12)
            synthetic = header + marshal.dumps(code_obj)

            temp = tempfile.NamedTemporaryFile(
                prefix=f"{pyc_path.stem}_synthetic_",
                suffix=".pyc",
                delete=False,
            )
            temp_path = Path(temp.name)
            temp.close()
            temp_path.write_bytes(synthetic)
            return temp_path
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "Could not build a synthetic .pyc for %s: %s",
                pyc_path.name,
                exc,
            )
            return None

    def _build_recovered_source(self, module_code: types.CodeType, source_name: str) -> str:
        """Builds readable pseudocode from a module code object."""
        # First attempt: advanced recovery via mini-stack (dedicated module).
        try:
            from lefiru.core.analyzers.python.python_bytecode import BytecodeRestorer

            advanced = BytecodeRestorer(module_code, source_name).recover()
            if advanced and advanced.count("\n") > 3:
                return advanced
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "Advanced recovery failed for %s: %s; using the simple heuristic.",
                source_name,
                exc,
            )

        # Fallback: original simple heuristic.
        lines: List[str] = []
        lines.append(f"# Recovered code (approximate) from: {source_name}")
        lines.append("# Automatically generated from bytecode due to a version incompatibility")
        lines.append("")

        instructions = list(dis.get_instructions(module_code))
        recovered_items = 0
        i = 0
        while i < len(instructions):
            inst = instructions[i]

            # Pattern: LOAD_CONST value; STORE_NAME var  -> var = value
            if (
                inst.opname == "LOAD_CONST"
                and i + 1 < len(instructions)
                and instructions[i + 1].opname == "STORE_NAME"
                and not isinstance(inst.argval, types.CodeType)
            ):
                target = instructions[i + 1].argval
                lines.append(f"{target} = {repr(inst.argval)}")
                recovered_items += 1
                i += 2
                continue

            # Typical pattern: LOAD_CONST <code>; MAKE_FUNCTION; STORE_NAME fn
            if (
                inst.opname == "LOAD_CONST"
                and isinstance(inst.argval, types.CodeType)
                and i + 2 < len(instructions)
                and instructions[i + 1].opname == "MAKE_FUNCTION"
                and instructions[i + 2].opname == "STORE_NAME"
            ):
                fn_code = inst.argval
                fn_name = instructions[i + 2].argval
                lines.extend(self._recovered_function_stub(fn_name, fn_code))
                lines.append("")
                recovered_items += 1
                i += 3
                continue

            i += 1

        entrypoint = self._detect_main_entrypoint(instructions)
        if entrypoint:
            lines.append("if __name__ == '__main__':")
            lines.append(f"    {entrypoint}()")
            lines.append("")
            recovered_items += 1

        if recovered_items == 0:
            lines.append("# High-level structure could not be rebuilt.")
            lines.append("# Review the .py.dis file for detailed manual analysis.")

        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _recovered_function_stub(fn_name: str, fn_code: types.CodeType) -> List[str]:
        """Generates an approximate function stub from its bytecode."""
        total_args = fn_code.co_argcount + fn_code.co_kwonlyargcount
        arg_names = list(fn_code.co_varnames[:total_args])
        if not arg_names:
            signature = ""
        else:
            signature = ", ".join(arg_names)

        lines = [f"def {fn_name}({signature}):"]

        fn_instructions = list(dis.get_instructions(fn_code))
        body_lines = PackagedExecutableExtractor._recover_function_body_lines(fn_instructions)
        if body_lines:
            lines.extend(body_lines)
        else:
            lines.append("    # TODO: logic not recoverable with this heuristic")
            lines.append("    pass")
        return lines

    @staticmethod
    def _recover_function_body_lines(fn_instructions: List[dis.Instruction]) -> List[str]:
        """Recovers simple lines (assignments, calls and returns) from bytecode."""
        lines: List[str] = []
        i = 0
        while i < len(fn_instructions):
            inst = fn_instructions[i]

            # LOAD_CONST x; STORE_* var -> var = x
            if (
                inst.opname == "LOAD_CONST"
                and i + 1 < len(fn_instructions)
                and fn_instructions[i + 1].opname in {"STORE_FAST", "STORE_NAME", "STORE_GLOBAL"}
                and not isinstance(inst.argval, types.CodeType)
            ):
                lines.append(f"    {fn_instructions[i + 1].argval} = {repr(inst.argval)}")
                i += 2
                continue

            # LOAD_* x; RETURN_VALUE -> return x
            if (
                inst.opname in {"LOAD_GLOBAL", "LOAD_NAME", "LOAD_FAST", "LOAD_DEREF"}
                and i + 1 < len(fn_instructions)
                and fn_instructions[i + 1].opname == "RETURN_VALUE"
            ):
                lines.append(f"    return {inst.argval}")
                i += 2
                continue

            # LOAD_CONST x; RETURN_VALUE -> return x
            if (
                inst.opname == "LOAD_CONST"
                and i + 1 < len(fn_instructions)
                and fn_instructions[i + 1].opname == "RETURN_VALUE"
            ):
                lines.append(f"    return {repr(inst.argval)}")
                i += 2
                continue

            # CALL -> func(...), var = func(...), return func(...)
            if inst.opname == "CALL":
                call_name = PackagedExecutableExtractor._find_call_name(fn_instructions, i)
                if call_name:
                    call_expr = f"{call_name}(...)"
                    if i + 1 < len(fn_instructions):
                        nxt = fn_instructions[i + 1]
                        if nxt.opname in {"STORE_FAST", "STORE_NAME", "STORE_GLOBAL"}:
                            lines.append(f"    {nxt.argval} = {call_expr}")
                            i += 2
                            continue
                        if nxt.opname == "RETURN_VALUE":
                            lines.append(f"    return {call_expr}")
                            i += 2
                            continue
                        if nxt.opname == "POP_TOP":
                            lines.append(f"    {call_expr}")
                            i += 2
                            continue

            i += 1

        return PackagedExecutableExtractor._deduplicate_preserve_order(lines)

    @staticmethod
    def _find_call_name(instructions: List[dis.Instruction], call_index: int) -> Optional[str]:
        """Looks for the function/method name associated with a CALL instruction."""
        for j in range(call_index - 1, max(-1, call_index - 12), -1):
            op = instructions[j]
            if op.opname in {"LOAD_GLOBAL", "LOAD_NAME", "LOAD_METHOD", "LOAD_ATTR"}:
                arg = op.argval
                if isinstance(arg, str) and arg:
                    return arg
        return None

    @staticmethod
    def _detect_main_entrypoint(instructions: List[dis.Instruction]) -> Optional[str]:
        """Detects the if __name__ == '__main__': <func>() guard pattern."""
        saw_main_const = any(i.opname == "LOAD_CONST" and i.argval == "__main__" for i in instructions)
        if not saw_main_const:
            return None

        preferred = {"main", "run", "start"}
        for idx, inst in enumerate(instructions):
            if inst.opname not in {"LOAD_NAME", "LOAD_GLOBAL"}:
                continue
            if not isinstance(inst.argval, str):
                continue
            if inst.argval in {"__name__"}:
                continue
            if idx + 2 < len(instructions):
                callish = any(
                    instructions[k].opname == "CALL"
                    for k in range(idx + 1, min(idx + 4, len(instructions)))
                )
                if callish and inst.argval in preferred:
                    return inst.argval

        for idx, inst in enumerate(instructions):
            if inst.opname in {"LOAD_NAME", "LOAD_GLOBAL"} and isinstance(inst.argval, str):
                if inst.argval == "__name__":
                    continue
                callish = any(
                    instructions[k].opname == "CALL"
                    for k in range(idx + 1, min(idx + 4, len(instructions)))
                )
                if callish:
                    return inst.argval
        return None

    @staticmethod
    def _deduplicate_preserve_order(lines: List[str]) -> List[str]:
        """Removes duplicates while preserving the order of appearance."""
        seen = set()
        result: List[str] = []
        for line in lines:
            if line in seen:
                continue
            seen.add(line)
            result.append(line)
        return result

    def _decompile_with_library(self, module_name: str, pyc_path: Path) -> Optional[str]:
        """Uses a Python decompilation module directly by import."""
        module = importlib.import_module(module_name)
        decompile_file = getattr(module, "decompile_file", None)
        if decompile_file is None:
            raise AttributeError("does not expose the decompile_file function")

        outstream = io.StringIO()
        result = decompile_file(str(pyc_path), outstream=outstream)

        output = outstream.getvalue()
        if not output and isinstance(result, str):
            output = result

        source = self._normalize_decompiler_output(output)
        if source:
            return source

        if result is not None and not isinstance(result, str):
            raise RuntimeError("the library produced no decompiled text")
        return None

    def _decompile_with_internal_recovery(self, pyc_path: Path, source_name: Optional[str] = None) -> Optional[str]:
        """
        Third internal engine: rebuilds approximate text from marshal.

        Does not depend on external tools and works with the headerless marshal
        payload typical of PyInstaller.
        """
        raw = pyc_path.read_bytes()
        code_obj = self._load_code_object_from_pyc_like(raw)
        recovered = self._build_recovered_source(code_obj, source_name or pyc_path.name)
        source = self._normalize_decompiler_output(recovered)
        if source:
            return source
        raise RuntimeError("internal recovery produced no useful output")

    @staticmethod
    def _normalize_decompiler_output(output: str) -> Optional[str]:
        """Normalizes the output of an external decompiler."""
        if not output:
            return None

        text = output.replace("\r\n", "\n").strip()
        if not text:
            return None

        # Many decompilers prepend banners/comments; they are kept.
        return text + "\n"

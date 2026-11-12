"""
Opening password analysis for Excel files.

CURRENT SCOPE:
- File OPENING password

The module keeps historical helpers for internal protection analysis, but the
active flow is focused solely on the opening password, obtained through patterns
inferred from the document and local dictionaries.
"""

import hashlib
import struct
import base64
import os
import zipfile
import logging
import time
import threading
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, List, Optional

from lefiru.paths import resource

# ──────────────────────────────────────────────────────────────────────────────
# Bundled base dictionary. It is complemented with the additional .txt files in
# the same directory so the wordlist can be extended without touching the code.
# ──────────────────────────────────────────────────────────────────────────────
DEFAULT_DICTIONARY_PATH = resource("data/passwords/password_dictionary.txt")
DEFAULT_EXTENDED_DICTIONARY_GLOB = "password_dictionary_*.txt"

# Excel XML namespace
NS = {
    "main": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    "r":    "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
}


class PasswordChecker:
    """
    Checks the opening password on Excel files (.xlsx / .xlsm / .xlsb).

    Features:
    1. Checks an already known opening password against the dictionary
    2. Looks for the opening password by inference from metadata and local dictionaries
    """

    # ──────────────────────────────────────────────────────────────────────────
    # Risk thresholds by iteration count (spinCount)
    # NIST SP 800-132 recommends >= 10 000 iterations
    # ──────────────────────────────────────────────────────────────────────────
    SPIN_COUNT_MINIMUM = 10_000
    SPIN_COUNT_EXCEL_DEFAULT = 100_000
    DICTIONARY_LEVEL_LIMITS = {
        "fast": 5_000,
        "balanced": 25_000,
        "deep": 100_000,
    }

    def __init__(self, file_path: Path, dictionary_path: Optional[Path] = None, stop_event: Optional[threading.Event] = None):
        self.file_path = Path(file_path)
        self.logger = logging.getLogger(__name__)
        self.extension = self.file_path.suffix.lower()
        self.dictionary_path = Path(dictionary_path) if dictionary_path else DEFAULT_DICTIONARY_PATH
        self.dictionary_level = self._resolve_dictionary_level()
        self.max_dictionary_candidates = self._resolve_max_dictionary_candidates()
        self.common_passwords = self._load_password_dictionary()
        self.stop_event: threading.Event = stop_event if stop_event is not None else threading.Event()

    def _resolve_dictionary_level(self) -> str:
        level = os.getenv("PASSWORD_DICTIONARY_LEVEL", "balanced").strip().lower()
        if level not in self.DICTIONARY_LEVEL_LIMITS:
            self.logger.warning(
                "Dictionary level '%s' not recognized; using 'balanced'",
                level,
            )
            return "balanced"
        return level

    def _resolve_max_dictionary_candidates(self) -> int:
        override = os.getenv("PASSWORD_DICTIONARY_MAX_CANDIDATES", "").strip()
        if override:
            try:
                value = int(override)
                if value > 0:
                    return value
            except ValueError:
                self.logger.warning(
                    "Invalid value in PASSWORD_DICTIONARY_MAX_CANDIDATES='%s'; using level '%s'",
                    override,
                    self.dictionary_level,
                )
        return self.DICTIONARY_LEVEL_LIMITS[self.dictionary_level]

    def _get_dictionary_sources(self) -> List[Path]:
        sources: List[Path] = []
        seen = set()

        def _add_source(path: Path) -> None:
            resolved = str(path.resolve()) if path.exists() else str(path)
            if resolved in seen:
                return
            seen.add(resolved)
            sources.append(path)

        _add_source(self.dictionary_path)

        if self.dictionary_path.parent.exists():
            for extra_path in sorted(self.dictionary_path.parent.glob(DEFAULT_EXTENDED_DICTIONARY_GLOB)):
                if extra_path.name == self.dictionary_path.name:
                    continue
                _add_source(extra_path)

        return sources

    def _load_password_dictionary(self) -> List[str]:
        """Loads passwords from local sources and caps the total to control timing."""
        normalized: List[str] = []
        seen = set()
        source_paths = self._get_dictionary_sources()
        loaded_raw_passwords = 0

        def _register_password(password: str) -> bool:
            for variant in self._expand_password_variants(password):
                if variant in seen:
                    continue
                seen.add(variant)
                normalized.append(variant)
                if len(normalized) >= self.max_dictionary_candidates:
                    return True
            return False

        for source_path in source_paths:
            if len(normalized) >= self.max_dictionary_candidates:
                break

            if not source_path.exists():
                self.logger.info(
                    f"Dictionary not found at {source_path}; skipping this source"
                )
                continue

            try:
                with source_path.open("r", encoding="utf-8") as handler:
                    for raw_line in handler:
                        candidate = raw_line.strip()
                        if not candidate or candidate.startswith("#"):
                            continue
                        loaded_raw_passwords += 1
                        if _register_password(candidate):
                            break
            except OSError as exc:
                self.logger.warning(
                    f"Could not read the external dictionary {source_path}: {exc}"
                )

        if not normalized:
            self.logger.warning(
                "No candidate passwords were loaded: no local dictionaries are available"
            )

        self.logger.info(
            "Password dictionary loaded with %d candidate passwords "
            "(level=%s, limit=%d, external_sources=%d)",
            len(normalized),
            self.dictionary_level,
            self.max_dictionary_candidates,
            loaded_raw_passwords,
        )
        return normalized

    @staticmethod
    def _expand_password_variants(password: str) -> List[str]:
        """Generates common variants without multiplying the dictionary too much."""
        variants = [password]

        if not password:
            return variants

        if password.isalpha() and len(password) > 2:
            variants.extend([
                password.lower(),
                password.upper(),
                password.capitalize(),
            ])

        if password.isalnum() and len(password) >= 4:
            variants.extend([
                f"{password}1",
                f"{password}123",
            ])

        return variants

    # ══════════════════════════════════════════════════════════════════════════
    # Main entry point
    # ══════════════════════════════════════════════════════════════════════════

    def check(self) -> Dict[str, Any]:
        """
        Keeps compatibility with legacy calls.

        The active sheet/workbook/VBA check was disabled to focus the module
        exclusively on the opening password.
        """
        self.logger.info(
            "Internal sheet/workbook/VBA check disabled; "
            "the module is used only for the opening password"
        )
        return {
            "opening": {},
            "summary": {
                "risk_level": "NOT_APPLICABLE",
                "bypassable_protection": False,
                "weak_password_found": False,
                "findings": [],
                "recommendations": [],
            }
        }

    # ══════════════════════════════════════════════════════════════════════════
    # Workbook check (workbook structure protection)
    # ══════════════════════════════════════════════════════════════════════════

    def _check_workbook(self, zf: zipfile.ZipFile) -> Dict[str, Any]:
        """Checks the workbook structure protection."""
        try:
            wb_xml = zf.read("xl/workbook.xml")
            root = ET.fromstring(wb_xml)
            prot_elem = root.find("main:workbookProtection", NS)

            if prot_elem is None:
                return {
                    "protected": False,
                    "algorithm": None,
                    "risk_level": "WITHOUT_PROTECTION",
                    "weak_password": None,
                    "detail": "Workbook without structure protection"
                }

            return self._analyze_element_protection(
                prot_elem, "workbook", "workbook", attr_prefix="workbook"
            )

        except (KeyError, ET.ParseError) as e:
            self.logger.warning(f"Could not read workbook.xml: {e}")
            return {"status": "ERROR", "detail": str(e)}

    # ══════════════════════════════════════════════════════════════════════════
    # VBA check (marker analysis in vbaProject.bin)
    # ══════════════════════════════════════════════════════════════════════════

    def _check_vba(self, zf: zipfile.ZipFile) -> Dict[str, Any]:
        """
        Analyzes the VBA project to detect whether it has a password and whether it is weak.
        Uses the same approach as BypassTester: search for DPB/CMG markers.
        """
        try:
            vba_data = zf.read("xl/vbaProject.bin")
        except KeyError:
            return {"status": "NOT_APPLICABLE", "message": "vbaProject.bin not found"}

        result = {
            "has_password": False,
            "algorithm": "LEGACY_VBA_HASH",
            "risk_level": "WITHOUT_PROTECTION",
            "weak_password": None,
            "detail": "",
            "markers_found": []
        }

        # Detect the DPB marker (Document Protection Binary) — indicates a password
        markers = {
            b"DPB=": "DPB",
            b"CMG=": "CMG",
            b"GC=":  "GC",
        }

        for marker_bytes, name in markers.items():
            if marker_bytes in vba_data:
                result["markers_found"].append(name)

        has_dpb = b"DPB=" in vba_data

        if not has_dpb:
            result["risk_level"] = "WITHOUT_PROTECTION"
            result["detail"] = "VBA project with no password detected"
            return result

        result["has_password"] = True
        result["detail"] = (
            "VBA project protected with a password. "
            "The algorithm is legacy (Microsoft Office proprietary hash), "
            "vulnerable to binary marker bypass tools."
        )

        # The legacy VBA hash is intrinsically weak (bypassable by modifying DPB/CMG)
        result["risk_level"] = "HIGH"
        result["bypassable_protection"] = True
        result["note_security"] = (
            "VBA password protection is NOT cryptographically secure: "
            "it can be removed by modifying binary markers in vbaProject.bin "
            "without knowing the original password."
        )

        # Try the dictionary (limited — the VBA hash is not exposed directly)
        result["attack_dictionary"] = {
            "executed": False,
            "reason": (
                "The VBA hash is embedded in a proprietary binary format; "
                "a dictionary attack would require opening the file with COM to verify each key."
            )
        }

        return result

    # ══════════════════════════════════════════════════════════════════════════
    # Analysis of an XML protection element (sheet or workbook)
    # ══════════════════════════════════════════════════════════════════════════

    def _analyze_element_protection(
        self,
        elem: ET.Element,
        name: str,
        type: str,
        attr_prefix: str = ""
    ) -> Dict[str, Any]:
        """
        Extracts hash metadata and runs a dictionary attack
        on a <sheetProtection> or <workbookProtection> element.

        attr_prefix: attribute prefix in the XML.
          - ""         for <sheetProtection password=... algorithmName=... hashValue=...>
          - "workbook" for <workbookProtection workbookPassword=... workbookAlgorithmName=...>
        """
        def _attr(name: str) -> str | None:
            """Reads the attribute with or without prefix depending on the element type."""
            if attr_prefix:
                # first try with the prefix (e.g. workbookAlgorithmName)
                val = elem.get(f"{attr_prefix}{name[0].upper()}{name[1:]}")
                if val is not None:
                    return val
            return elem.get(name)

        # Element attributes
        algorithm   = _attr("algorithmName")      # SHA-512, SHA-256, etc.
        hash_val    = _attr("hashValue")
        salt_val    = _attr("saltValue")
        spin_count  = _attr("spinCount")
        legacy_hash = _attr("password")            # legacy XOR hash (4 hex chars)

        result: Dict[str, Any] = {
            "name": name,
            "type": type,
            "algorithm": algorithm or ("LEGACY_XOR" if legacy_hash else None),
            "spin_count": int(spin_count) if spin_count else None,
            "has_hash": bool(hash_val or legacy_hash),
            "risk_level": "UNKNOWN",
            "bypassable_protection": False,
            "weak_password": None,
            "password_found": None,
            "detail": ""
        }

        # ── Case 1: No password ─────────────────────────────────────────────
        if not result["has_hash"]:
            result["risk_level"] = "WITHOUT_PROTECTION"
            result["detail"] = f"{type.capitalize()} '{name}' active but without a password hash"
            return result

        # ── Case 2: LEGACY XOR hash (Excel 97-2003) ─────────────────────────
        if legacy_hash and not algorithm:
            result["bypassable_protection"] = True
            result["risk_level"] = "CRITICAL"
            result["detail"] = (
                f"LEGACY XOR hash ('{legacy_hash}'): trivially bypassable. "
                "This type of protection can be removed without knowing the password."
            )
            # Try the dictionary on the legacy hash
            found = self._dictionary_legacy_xor(legacy_hash)
            if found is not None:
                result["weak_password"] = True
                result["password_found"] = found
                result["detail"] += f" Password found: '{found}'"
            return result

        # ── Case 3: Modern hash (ECMA-376 SHA) ──────────────────────────────
        if not (hash_val and salt_val and algorithm):
            result["risk_level"] = "NOT_EVALUABLE"
            result["detail"] = "Hash data is incomplete in the XML"
            return result

        # Evaluate the algorithm
        algorithms_strong = {"SHA-512", "SHA-256", "SHA-384"}
        if algorithm not in algorithms_strong:
            result["bypassable_protection"] = True
            result["risk_level"] = "HIGH"
            result["detail"] = f"Algorithm '{algorithm}' is considered weak"
        else:
            result["risk_level"] = "LOW"
            result["detail"] = f"Modern {algorithm} algorithm"

        # Evaluate spinCount
        spin = result["spin_count"] or 0
        if spin < self.SPIN_COUNT_MINIMUM:
            result["bypassable_protection"] = True
            result["risk_level"] = "HIGH"
            result["detail"] += (
                f". SpinCount={spin} is lower than the recommended minimum "
                f"({self.SPIN_COUNT_MINIMUM:,})"
            )

        # Dictionary attack
        self.logger.info(
            f"  Testing {len(self.common_passwords)} common passwords "
            f"against {type} '{name}' ({algorithm}, spinCount={spin})..."
        )

        found = self._dictionary_ecma376(
            hash_val, salt_val, algorithm, spin
        )

        if found is not None:
            result["weak_password"] = True
            result["password_found"] = found
            result["risk_level"] = "CRITICAL"
            result["detail"] += (
                f". WEAK PASSWORD FOUND: '{found}'"
            )
            self.logger.warning(
                f"Weak password found in {type} '{name}': '{found}'"
            )
        else:
            result["weak_password"] = False
            result["detail"] += ". Not found in the common password dictionary"
            self.logger.info(f"{type} '{name}': password is not in the dictionary")

        return result

    # ══════════════════════════════════════════════════════════════════════════
    # Hash algorithms
    # ══════════════════════════════════════════════════════════════════════════

    def _dictionary_ecma376(
        self,
        hash_b64: str,
        salt_b64: str,
        algorithm: str,
        spin_count: int
    ) -> Optional[str]:
        """
        Dictionary attack using the ECMA-376 algorithm (modern Excel).

        Formula:
            H0 = HASH(salt + password_utf16le)
            Hi = HASH(H(i-1) + i_as_4bytes_LE)  for i in range(spinCount)
        """
        algorithm_map = {
            "SHA-512":  hashlib.sha512,
            "SHA-256":  hashlib.sha256,
            "SHA-384":  hashlib.sha384,
            "SHA-1":    hashlib.sha1,
            "MD5":      hashlib.md5,
        }

        hash_func = algorithm_map.get(algorithm)
        if hash_func is None:
            self.logger.warning(f"Algorithm '{algorithm}' is not implemented")
            return None

        try:
            salt_bytes = base64.b64decode(salt_b64)
            target = base64.b64decode(hash_b64)
        except Exception as e:
            self.logger.debug(f"Error decoding hash/salt: {e}")
            return None

        spin = spin_count or 0

        for password in self.common_passwords:
            try:
                pwd_bytes = password.encode("utf-16-le")

                # H0
                h = hash_func(salt_bytes + pwd_bytes).digest()

                # Hi
                for i in range(spin):
                    h = hash_func(h + struct.pack("<I", i)).digest()

                if h == target:
                    return password

            except Exception as e:
                self.logger.debug(f"Error computing hash for '{password}': {e}")
                continue

        return None

    def _dictionary_legacy_xor(self, legacy_hex: str) -> Optional[str]:
        """
        Dictionary attack against the legacy Excel XOR hash (2 hex bytes).
        Algorithm defined in MS-OFFCRYPTO 2.3.7.1
        """
        try:
            target = int(legacy_hex, 16)
        except ValueError:
            return None

        for password in self.common_passwords:
            if self._compute_legacy_hash(password) == target:
                return password

        return None

    @staticmethod
    def _compute_legacy_hash(password: str) -> int:
        """
        Computes the legacy Excel XOR hash for a given password.
        Reference: MS-OFFCRYPTO section 2.3.7.1
        """
        if not password:
            return 0

        chars = password[:15]  # maximum 15 characters
        n = len(chars)

        # Step 1: accumulate the hash through XOR rotation
        acc = 0
        for char in reversed(chars):
            acc = ((acc >> 14) & 0x01) | ((acc << 1) & 0x7FFF)
            acc ^= ord(char)

        # Step 2: final XOR with the length and the constant
        acc = ((acc >> 14) & 0x01) | ((acc << 1) & 0x7FFF)
        acc ^= n
        acc ^= 0xCE4B

        return acc & 0xFFFF

    def brute_force_opening_password(self) -> Dict[str, Any]:
        result = {
            "type": "opening_cracking",
            "password_found": None,
            "attempts": 0,
            "risk_level": "LOW",
            "detail": ""
        }
        try:
            with zipfile.ZipFile(self.file_path, 'r') as zf:
                # NOTE: this exact text is compared verbatim by
                # AnalysisOrchestrator (orchestrator.py, opening status), so it
                # must not change until that comparison is updated in sync.
                result["detail"] = "File is not encrypted"
                return result
        except zipfile.BadZipFile:
            pass

        self.logger.info("=" * 80)
        self.logger.info("STARTING STAGED OPENING STRATEGY")
        self.logger.info("=" * 80)

        attempts_accumulated = 0

        def _register_partial_result(partial: Dict[str, Any], description: str) -> bool:
            nonlocal attempts_accumulated
            attempts_accumulated += partial.get("attempt", partial.get("total_attempts", 0))

            if partial.get("password_found"):
                result["password_found"] = partial["password_found"]
                result["attempts"] = attempts_accumulated
                result["risk_level"] = "CRITICAL"
                result["detail"] = (
                    f"Found: '{partial['password_found']}' "
                    f"via {description}"
                )
                self.logger.warning(
                    "OPENING CRACKING: Password found via %s — '%s' (accumulated attempts %d)",
                    description,
                    partial["password_found"],
                    attempts_accumulated,
                )
                return True

            if partial.get("stopped_by_user"):
                result["attempts"] = attempts_accumulated
                result["detail"] = partial.get("detail", "Stopped by the user")
                result["stopped_by_user"] = True
                self.logger.warning(
                    "OPENING: attack stopped by the user after %d accumulated attempts",
                    attempts_accumulated,
                )
                return True  # return True to stop the following phases

            self.logger.info(
                "OPENING: %s unsuccessful (%d accumulated attempts)",
                description,
                attempts_accumulated,
            )
            return False

        self.logger.info("OPENING: Phase 1/2 - pattern inference from metadata")
        patterns = self.infer_user_patterns()
        if patterns:
            partial = self._brute_force_candidates(patterns, "USER_PATTERNS")
            if _register_partial_result(partial, "USER_PATTERNS"):
                return result
        else:
            self.logger.info("OPENING: USER_PATTERNS skipped because no candidates were inferred")

        self.logger.info(
            "OPENING: Phase 2/2 - full dictionary (%d candidates loaded from local sources)",
            len(self.common_passwords),
        )
        partial = self._brute_force_candidates(self.common_passwords, "FULL_DICTIONARY")
        if _register_partial_result(partial, "FULL_DICTIONARY"):
            return result

        result["attempts"] = attempts_accumulated
        result["detail"] = (
            "Not found after pattern inference and the full dictionary "
            f"({attempts_accumulated} attempts)"
        )
        self.logger.info("OPENING: Attack unsuccessful after %d accumulated attempts", attempts_accumulated)
        return result

    def infer_user_patterns(self) -> List[str]:
        """
        Analyzes the file metadata to infer potential password patterns.
        Fast and surprisingly effective (lazy users).
        
        Extracts patterns from:
        - File author
        - Sheet names
        - Document title and subject
        - Keywords in properties
        
        Returns:
            List of inferred patterns
        """
        import re
        from openpyxl import load_workbook
        
        patterns = set()
        
        self.logger.info("=" * 80)
        self.logger.info("ANALYZING FILE METADATA TO INFER PATTERNS")
        self.logger.info("=" * 80)
        
        try:
            # Load the workbook without full data (fast)
            try:
                wb = load_workbook(self.file_path, data_only=False)
                props = wb.properties
                self.logger.info("File properties loaded successfully")
            except Exception as e:
                self.logger.warning(f"Could not read the file properties: {e}")
                return []
            
            # ── Extract from the author ────────────────────────────────
            if props.creator:
                self.logger.info(f"\n[AUTHOR] '{props.creator}'")
                parts = props.creator.split()
                for part in parts:
                    if len(part) >= 3:  # Only meaningful words
                        self.logger.info(f"  → Added: {part} (variants: {part.lower()}, {part.capitalize()}, {part.upper()})")
                        patterns.add(part.lower())
                        patterns.add(part.capitalize())
                        patterns.add(part.upper())
            else:
                self.logger.info("\n[AUTHOR] Not specified")
            
            # ── Extract from sheet names ──────────────────────────────
            self.logger.info(f"\n[SHEETS] Analyzing {len(wb.sheetnames)} sheets...")
            for idx, sheet in enumerate(wb.sheetnames, 1):
                # Remove digits and special characters
                words = re.findall(r'[A-Za-z]{3,}', sheet)
                if words:
                    self.logger.info(f"  Sheet {idx}: '{sheet}' → words: {words}")
                    for word in words:
                        if len(word) >= 3:
                            self.logger.info(f"    → Added: {word.lower()}, {word.capitalize()}")
                            patterns.add(word.lower())
                            patterns.add(word.capitalize())
                else:
                    self.logger.info(f"  Sheet {idx}: '{sheet}' → no meaningful words")
            
            # ── Extract from the title ────────────────────────────────
            if props.title:
                self.logger.info(f"\n[TITLE] '{props.title}'")
                words = re.findall(r'[A-Za-z]{3,}', props.title)
                for word in words:
                    if len(word) >= 3:
                        self.logger.info(f"  → Added: {word.lower()}, {word.capitalize()}")
                        patterns.add(word.lower())
                        patterns.add(word.capitalize())
            else:
                self.logger.info("\n[TITLE] Not specified")
            
            # ── Extract from the subject ──────────────────────────────
            if props.subject:
                self.logger.info(f"\n[SUBJECT] '{props.subject}'")
                words = re.findall(r'[A-Za-z]{3,}', props.subject)
                for word in words:
                    if len(word) >= 3:
                        self.logger.info(f"  → Added: {word.lower()}")
                        patterns.add(word.lower())
            else:
                self.logger.info("\n[SUBJECT] Not specified")
            
            # ── Add common variants ──────────────────────────────────
            self.logger.info(f"\n[VARIANTS] Generating variants (pattern1, pattern123, pattern2026)...")
            extended_patterns = set(patterns)
            for pattern in list(patterns):
                # Add with numbers
                extended_patterns.add(f"{pattern}1")
                extended_patterns.add(f"{pattern}123")
                extended_patterns.add(f"{pattern}2026")
                # Add combinations with common words
                for extra in ["2026", "1234", "admin", "pass"]:
                    extended_patterns.add(f"{pattern}{extra}")
            
            patterns = extended_patterns
            
            self.logger.info("\n" + "=" * 80)
            if patterns:
                self.logger.info(f"PATTERNS INFERRED: {len(patterns)} total")
                self.logger.info(f"  Examples: {list(patterns)[:20]}")
            else:
                self.logger.info("No patterns could be inferred from metadata")
            self.logger.info("=" * 80 + "\n")
            
            return list(patterns)[:1000]  # Limit to 1000 patterns
        
        except Exception as e:
            self.logger.error(f"Error inferring user patterns: {e}")
            self.logger.debug(f"Traceback: {e}", exc_info=True)
            return []

    def _brute_force_candidates(
        self,
        candidates: List[str],
        attack_name: str = "CUSTOM"
    ) -> Dict[str, Any]:
        """
        Runs brute force against an arbitrary list of candidates.
        Reusable code that can be called from multiple methods.
        
        Args:
            candidates: list of passwords to try
            attack_name: name of the attack method (for logging)
        
        Returns:
            Dict with {password_found, attempt, total_candidates, time_seconds, method}
        """
        try:
            import io
            import msoffcrypto
        except ImportError:
            return {
                "password_found": None,
                "method": attack_name,
                "error": "msoffcrypto-tool is not available"
            }
        
        # Check whether the file is an encrypted XLSX
        try:
            with zipfile.ZipFile(self.file_path, 'r') as zf:
                return {
                    "password_found": None,
                    "method": attack_name,
                    "error": "File is not encrypted or is not XLSX"
                }
        except zipfile.BadZipFile:
            # OK, it is an encrypted file
            pass
        
        try:
            encrypted_bytes = self.file_path.read_bytes()
        except OSError as exc:
            return {
                "password_found": None,
                "method": attack_name,
                "error": f"Could not read the file: {exc}"
            }
        
        total_passwords = len(candidates)

        if total_passwords == 0:
            self.logger.warning("[%s] no candidates to try; attack skipped", attack_name)
            return {
                "password_found": None,
                "total_attempts": 0,
                "time_seconds": 0,
                "method": attack_name,
                "detail": "No candidates available",
            }

        self.logger.info("=" * 80)
        self.logger.info(f"STARTING ATTACK: {attack_name}")
        self.logger.info("=" * 80)
        self.logger.info(f"Total candidates to try: {total_passwords}")
        self.logger.info(f"Target file: {self.file_path.name}")
        self.logger.info("First 20 candidates to try:")
        for idx, pwd in enumerate(candidates[:20], 1):
            self.logger.info(f"  {idx:2d}. {pwd}")
        if total_passwords > 20:
            self.logger.info(f"  ... and {total_passwords - 20} more")
        self.logger.info("=" * 80 + "\n")
        
        start = time.monotonic()
        next_log = start + 180  # Log every 3 minutes

        for attempt, pwd in enumerate(candidates, 1):
            # Check whether the user requested a stop
            if self.stop_event.is_set():
                elapsed = int(time.monotonic() - start)
                self.logger.warning(
                    "[%s] STOPPED BY USER after %d attempts (%ds)",
                    attack_name, attempt - 1, elapsed,
                )
                return {
                    "password_found": None,
                    "total_attempts": attempt - 1,
                    "time_seconds": elapsed,
                    "method": attack_name,
                    "stopped_by_user": True,
                    "detail": f"Stopped by the user after {attempt - 1} attempts",
                }

            # Progress log every 3 minutes
            now = time.monotonic()
            if now >= next_log:
                elapsed_seg = int(now - start)
                min_t = elapsed_seg // 60
                seg_t = elapsed_seg % 60
                percentage = (attempt / total_passwords) * 100
                rate = attempt / (now - start) if (now - start) > 0 else 0
                time_remaining = int((total_passwords - attempt) / rate) if rate > 0 else 0
                rest_min = time_remaining // 60
                rest_seg = time_remaining % 60
                
                self.logger.info(
                    "%s: dictionary attack progress: attempt %d of %d (%02d:%02d elapsed) | %.1f%% | %.1f pwd/sec | ETA %02d:%02d",
                    attack_name,
                    attempt,
                    total_passwords,
                    min_t,
                    seg_t,
                    percentage,
                    rate,
                    rest_min,
                    rest_seg,
                )
                next_log = now + 180
            
            try:
                office_file = msoffcrypto.OfficeFile(io.BytesIO(encrypted_bytes))
                office_file.load_key(password=pwd, verify_password=True)
                
                # SUCCESS!
                elapsed = int(time.monotonic() - start)
                self.logger.warning("\n" + "=" * 80)
                self.logger.warning("PASSWORD FOUND!!!")
                self.logger.warning("=" * 80)
                self.logger.warning(f"Password: '{pwd}'")
                self.logger.warning(f"Method: {attack_name}")
                self.logger.warning(f"Attempt: {attempt}/{total_passwords}")
                self.logger.warning(f"Total time: {elapsed} seconds ({elapsed//60}m {elapsed%60}s)")
                self.logger.warning(f"Average speed: {attempt/elapsed:.2f} pwd/sec")
                self.logger.warning("=" * 80 + "\n")
                
                return {
                    "password_found": pwd,
                    "attempt": attempt,
                    "total_candidates": total_passwords,
                    "time_seconds": elapsed,
                    "method": attack_name
                }
            
            except Exception:
                # This password failed, continue
                if attempt % max(1, total_passwords // 10) == 0:
                    self.logger.debug(
                        f"[{attack_name}] {attempt}/{total_passwords} attempts without success"
                    )
                continue
        
        # Unsuccessful after trying all of them
        elapsed = int(time.monotonic() - start)
        self.logger.warning("\n" + "=" * 80)
        self.logger.warning(f"ATTACK UNSUCCESSFUL: {attack_name}")
        self.logger.warning("=" * 80)
        self.logger.warning(f"All {total_passwords:,} candidates were tried without finding the password")
        self.logger.warning(f"Total time: {elapsed} seconds ({elapsed//60}m {elapsed%60}s)")
        self.logger.warning(f"Average speed: {total_passwords/elapsed:.2f} pwd/sec")
        self.logger.warning("=" * 80 + "\n")
        
        return {
            "password_found": None,
            "total_attempts": total_passwords,
            "time_seconds": elapsed,
            "method": attack_name,
            "detail": f"None of the {total_passwords} candidates worked"
        }

    # ══════════════════════════════════════════════════════════════════════════
    # Opening password check
    # ══════════════════════════════════════════════════════════════════════════

    def check_opening_password(self, password: str) -> Dict[str, Any]:
        """
        Checks whether an opening password is in the weak-password dictionary.
        Used when the caller provides a known password.
        
        Args:
            password: opening password provided by the user
        
        Returns:
            Dict with password weakness information
        """
        result = {
            "type": "opening",
            "has_password": True,
            "password_in_dictionary": False,
            "risk_level": "LOW",
            "detail": ""
        }
        
        if not password:
            result["has_password"] = False
            result["detail"] = "No password was provided"
            return result
        
        # Check whether the password is in the dictionary
        if password in self.common_passwords:
            result["password_in_dictionary"] = True
            result["risk_level"] = "CRITICAL"
            result["detail"] = (
                f"Opening password '{password}' found in the common password dictionary. "
                f"CRITICAL: The password is very weak."
            )
            self.logger.warning(
                "OPENING PASSWORD AUDIT: Opening password found in the dictionary — '%s'",
                password
            )
        else:
            result["risk_level"] = "LOW"
            result["detail"] = (
                f"Opening password not found in the dictionary of {len(self.common_passwords)} common passwords. "
                f"The password may be more robust."
            )
            self.logger.info(
                "OPENING PASSWORD AUDIT: Opening password is not in the dictionary (probably strong)"
            )
        
        return result

    # ══════════════════════════════════════════════════════════════════════════
    # Utilities
    # ══════════════════════════════════════════════════════════════════════════

    def _generate_summary(self, result: Dict[str, Any]) -> None:
        """Consolidates findings and generates the final risk summary."""
        summary = result["summary"]
        findings = []
        recommendations = []
        max_level = "WITHOUT_RISK"

        ORDER_RISK = {
            "WITHOUT_RISK": 0,
            "WITHOUT_PROTECTION": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }

        def _update_level(new: str) -> None:
            nonlocal max_level
            if ORDER_RISK.get(new, 0) > ORDER_RISK.get(max_level, 0):
                max_level = new

        # ── Workbook ───────────────────────────────────────────────────────
        workbook = result.get("workbook", {})
        _update_level(workbook.get("risk_level", ""))

        if workbook.get("bypassable_protection"):
            summary["bypassable_protection"] = True
            findings.append(
                f"Workbook: weak protection algorithm "
                f"({workbook.get('algorithm')}, spinCount={workbook.get('spin_count')})"
            )
            recommendations.append(
                "Re-apply the workbook structure protection using a modern Excel version"
            )

        if workbook.get("weak_password"):
            summary["weak_password_found"] = True
            findings.append(
                f"CRITICAL — Workbook protection: weak password found "
                f"('{workbook.get('password_found')}')"
            )
            recommendations.append(
                "Change the workbook protection password to a strong password"
            )

        # ── VBA ────────────────────────────────────────────────────────────
        vba = result.get("vba", {})
        if vba.get("bypassable_protection"):
            summary["bypassable_protection"] = True
            _update_level("HIGH")
            findings.append(
                "VBA project: password protection uses a legacy binary hash that is "
                "bypassable without knowing the original password"
            )
            recommendations.append(
                "Consider additional VBA code protection measures "
                "(obfuscation, digital signature, machine access control)"
            )

        summary["risk_level"] = max_level
        summary["findings"] = findings
        summary["recommendations"] = recommendations

"""
Security analyzer for files developed in Python.

Supports:
  - Source files: .py
  - Bytecode: .pyc
  - Packaged executables: .exe (PyInstaller, cx_Freeze, py2exe)

Checks are aligned with the Excel analyzer tests:
  - Insecure patterns (eval/exec, shell, deserialization, etc.)
  - Hardcoded credentials and secrets
  - External connections (URLs, connection strings, UNC paths)
  - Traceability and logging (logging, error handling, data input)
"""

from __future__ import annotations

import ast
import marshal
import logging
import re
import zipfile
import types
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from lefiru.core.analyzers.python.python_evidence import PythonEvidenceRenderer
from lefiru.core.analyzers.python.python_executable import PackagedExecutableExtractor


# ─── Credential / secret patterns in literals ────────────────────────────────
CREDENTIAL_VAR_KEYWORDS = frozenset({
    "password", "passwd", "pwd", "pass", "key", "password", "contra",
    "token", "secret", "apikey", "api_key", "authkey", "auth",
    "credential", "credential", "private",
})

# Tokens that indicate a variable holds cryptographic material when
# they appear combined with "key".
_CRYPTO_KEY_CONTEXT = frozenset({
    "sign", "signing", "public", "private",
    "encrypt", "decrypt", "cipher", "symmetric", "asymmetric",
    "rsa", "aes", "hmac", "ecdsa", "ecdh", "dh",
    "jwt", "cert", "certificate", "pem", "pkcs",
    "master", "session", "shared", "derived",
})

# Tokens that usually represent internal control states, not credentials.
NON_CREDENTIAL_CONTEXT_TOKENS = frozenset({
    "status", "status", "result", "result", "flag", "enabled", "disabled",
    "ok", "error", "mode", "method", "type", "bypass", "analysis", "analysis",
})

NON_SECRET_STATUS_VALUES = frozenset({
    "ok", "error", "success", "failed", "true", "false",
    "compliant", "vulnerable", "compliant_with_observations",
    "valid", "invalid", "not_applicable", "requires_review",
})

BENIGN_SECRET_LITERALS = frozenset({
    "",
    "none",
    "null",
    "n/a",
    "na",
    "tbd",
    "all",
    "changeme",
    "change_me",
    "change-me",
    "replace_me",
    "replace-me",
    "example",
    "dummy",
    "test",
    "<password>",
    "<token>",
    "<secret>",
})

CONNECTION_STRING_HINTS = (
    re.compile(r"(?i)\b(?:server|data\s+source|initial\s+catalog|uid|user\s*id|pwd|password)\s*=", re.IGNORECASE),
    re.compile(r"(?i)\b(?:driver|provider)\s*=\s*\{?", re.IGNORECASE),
    re.compile(r"(?i)\bjdbc:[a-z0-9]+://", re.IGNORECASE),
    re.compile(r"(?i)\bmongodb(?:\+srv)?://", re.IGNORECASE),
    re.compile(r"(?i)\bpostgres(?:ql)?://", re.IGNORECASE),
    re.compile(r"(?i)\bmysql://", re.IGNORECASE),
)

URL_PATTERN = re.compile(r"(?i)\b(?:https?|ftp|ftps|sftp|smb)://[^\s\"'<>]+")
UNC_PATTERN = re.compile(r"\\\\[A-Za-z0-9._-]+\\[^\s\"'<>]+")
FS_PATH_HARDCODED_PATTERNS = (
    re.compile(r"(?i)\b[A-Z]:\\(?:[^\\\r\n]+\\)*[^\\\r\n]*"),
    re.compile(r"(?i)\b[A-Z]:/(?:[^/\r\n]+/)*[^/\r\n]*"),
    re.compile(r"(?:(?<=\s)|^)/(?:[^\s\"'<>]+/)*[^\s\"'<>]*"),
)
IPV4_HARDCODED_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)

# Strings that clearly look like secrets by their shape
HIGH_ENTROPY_HINTS = (
    re.compile(r"^[A-Za-z0-9+/=]{32,}$"),     # long base64
    re.compile(r"^[A-Fa-f0-9]{32,}$"),         # long hex (md5/sha)
    re.compile(r"^eyJ[A-Za-z0-9_\-\.]{20,}$"), # JWT
    re.compile(r"^sk-[A-Za-z0-9]{20,}$"),      # OpenAI-style API keys
    re.compile(r"^ghp_[A-Za-z0-9]{20,}$"),     # GitHub PAT
    re.compile(r"^xox[abprs]-[A-Za-z0-9-]{10,}$"),  # Slack tokens
)

# Dangerous calls via AST
DANGEROUS_CALLS = {
    "eval": ("dynamic_execution", "critical", "Use of eval() allows arbitrary code execution"),
    "exec": ("dynamic_execution", "critical", "Use of exec() allows arbitrary code execution"),
    "compile": ("dynamic_execution", "medium", "Use of compile() can facilitate dynamic execution"),
    "__import__": ("dynamic_execution", "medium", "Dynamic import via __import__"),
    "input": ("unvalidated_input", "low", "User input without explicit validation"),
}

DANGEROUS_ATTR_CALLS = {
    ("os", "system"): ("dangerous_commands", "critical", "os.system executes system commands"),
    ("os", "popen"): ("dangerous_commands", "critical", "os.popen executes system commands"),
    ("subprocess", "call"): ("dangerous_commands", "medium", "subprocess.call: check shell=True"),
    ("subprocess", "run"): ("dangerous_commands", "medium", "subprocess.run: check shell=True"),
    ("subprocess", "Popen"): ("dangerous_commands", "medium", "subprocess.Popen: check shell=True"),
    ("subprocess", "check_output"): ("dangerous_commands", "medium", "subprocess.check_output: check shell=True"),
    ("pickle", "load"): ("deserialization", "critical", "pickle.load deserializes arbitrary code"),
    ("pickle", "loads"): ("deserialization", "critical", "pickle.loads deserializes arbitrary code"),
    ("yaml", "load"): ("deserialization", "critical", "yaml.load without SafeLoader allows code execution"),
    ("marshal", "load"): ("deserialization", "critical", "marshal.load deserializes arbitrary bytecode"),
    ("marshal", "loads"): ("deserialization", "critical", "marshal.loads deserializes arbitrary bytecode"),
    ("shelve", "open"): ("deserialization", "medium", "shelve uses pickle internally"),
}

DANGEROUS_IMPORTS = {
    "pickle": ("deserialization", "medium", "Import of pickle (insecure deserialization)"),
    "marshal": ("deserialization", "medium", "Import of marshal"),
    "ctypes": ("low_level_access", "medium", "Use of ctypes (native API access)"),
    "telnetlib": ("connections", "medium", "Use of telnet (insecure protocol)"),
    "ftplib": ("connections", "low", "Use of FTP (check credentials and TLS)"),
}

# Suspicious strings in PyInstaller/exe binaries (byte search)
EXE_STRING_PATTERNS = [
    (re.compile(rb"(?i)password\s*[:=]\s*[\"']?([^\"'\s\r\n]{4,})"), "credential_in_binary", "critical"),
    (re.compile(rb"(?i)api[_-]?key\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{16,})"), "credential_in_binary", "critical"),
    (re.compile(rb"(?i)secret\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{16,})"), "credential_in_binary", "critical"),
    (re.compile(rb"(?i)token\s*[:=]\s*[\"']?([A-Za-z0-9_\-\.]{20,})"), "credential_in_binary", "critical"),
    (re.compile(rb"\bjdbc:[a-z0-9]+://[^\s\"']+"), "connections", "medium"),
    (re.compile(rb"\b(?:https?|ftp|smb)://[^\s\"'<>]{5,}"), "connections", "low"),
    (re.compile(rb"\\\\[A-Za-z0-9._-]+\\[^\s\"'<>]+"), "connections", "low"),
]

PYINSTALLER_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"

CORS_RISKY_PATTERNS = (
    re.compile(r"Access-Control-Allow-Origin\s*[:=]\s*['\"]\*['\"]", re.IGNORECASE),
    re.compile(r"origins?\s*=\s*\[\s*['\"]\*['\"]\s*\]", re.IGNORECASE),
)

REDOS_RISKY_PATTERNS = (
    re.compile(r"\([^)]*[+*][^)]*\)[+*]"),
    re.compile(r"\([^)]*\{\d+,?\d*\}[^)]*\)[+*]"),
    re.compile(r"\(\.\*\)\+|\(\.\+\)\+"),
    re.compile(r"\(\?:[^)]*[+*][^)]*\)[+*]"),
)

# Internal analysis rule catalog: only rules with an implemented detector.
RULES_ANALYSIS_IMPLEMENTED = [
    {
        "name": "Use an iterator instead of materializing the list",
        "priority": "medium",
        "characteristic": "efficiency",
        "vulnerability_type": "",
        "category": "quality",
    },
    {
        "name": "Empty sequences are False",
        "priority": "low",
        "characteristic": "maintainability",
        "vulnerability_type": "",
        "category": "quality",
    },
    {
        "name": "Use literals to initialize dictionaries",
        "priority": "low",
        "characteristic": "efficiency",
        "vulnerability_type": "",
        "category": "quality",
    },
    {
        "name": "Class methods not accessing instance fields must be static",
        "priority": "low",
        "characteristic": "maintainability",
        "vulnerability_type": "",
        "category": "quality",
    },
    {
        "name": "Not using items() to iterate over a dictionary",
        "priority": "medium",
        "characteristic": "efficiency",
        "vulnerability_type": "",
        "category": "quality",
    },
    {
        "name": "Not using zip() to iterate over a pair of lists",
        "priority": "medium",
        "characteristic": "efficiency",
        "vulnerability_type": "",
        "category": "quality",
    },
    {
        "name": "Do not use concatenation to extend lists",
        "priority": "medium",
        "characteristic": "efficiency",
        "vulnerability_type": "",
        "category": "quality",
    },
    {
        "name": "Hardcoded filesystem paths in code",
        "priority": "medium",
        "characteristic": "maintainability",
        "vulnerability_type": "",
        "category": "connections",
    },
    {
        "name": "Hardcoded IP addresses in code",
        "priority": "medium",
        "characteristic": "maintainability",
        "vulnerability_type": "",
        "category": "credentials",
    },
    {
        "name": "Avoid SQL code formed with non neutralized user input",
        "priority": "very high",
        "characteristic": "security",
        "vulnerability_type": "injection",
        "category": "dangerous_commands",
    },
    {
        "name": "Improper neutralization of special elements in data query logic (NoSQL injection)",
        "priority": "very high",
        "characteristic": "security",
        "vulnerability_type": "injection",
        "category": "dangerous_commands",
    },
    {
        "name": "CORS policy too broad",
        "priority": "very high",
        "characteristic": "security",
        "vulnerability_type": "misconfiguration",
        "category": "connections"
    },
    {
        "name": "Cookie Poisoning",
        "priority": "very high",
        "characteristic": "security",
        "vulnerability_type": "injection",
        "category": "connections"
    },
    {
        "name": "Avoid too complex functions",
        "priority": "high",
        "characteristic": "maintainability",
        "vulnerability_type": "",
        "category": "quality",
    },
    {
        "name": "XML entity injection",
        "priority": "very high",
        "characteristic": "security",
        "vulnerability_type": "injection",
        "category": "dangerous_commands"   
    },
    {
        "name": "Mail Command Injection",
        "priority": "very high",
        "characteristic": "security",
        "vulnerability_type": "injection",
        "category": "dangerous_commands"
    },
    {
        "name": "Potential denial-of-service attack through malicious regular expression (ReDoS)",
        "priority": "very high",
        "characteristic": "security",
        "vulnerability_type": "injection",
        "category": "dangerous_commands",
    },
    
]


class PythonCodeInspector:
    """Analyzes Python files: source code, bytecode or packaged executables."""

    MAX_BINARY_SCAN_BYTES = 50 * 1024 * 1024   # 50 MB cap for string scanning
    MAX_BINARY_FINDINGS = 200
    MAX_EXTRACTED_MEMBERS = 300
    MAX_COMPANION_MEMBERS = 800
    RULES_ANALYSIS_IMPLEMENTED = RULES_ANALYSIS_IMPLEMENTED
    VALID_RULE_CATEGORIES = {
        "quality",
        "credentials",
        "connections",
        "unvalidated_input",
        "dangerous_commands",
        "deserialization",
        "dynamic_execution",
        "traceability",
        "low_level_access",
    }

    def __init__(self, file_path: Path, output_root: Path):
        self.file_path = Path(file_path)
        self.output_root = Path(output_root)
        self.evidence_dir = self.output_root / "reports" / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)
        self.file_type = self.file_path.suffix.lower()
        self.rules_implemented = self._normalize_rules(self.RULES_ANALYSIS_IMPLEMENTED)
        self._evidence_renderer: Optional[PythonEvidenceRenderer] = None
        self._evidence_cache: Dict[Tuple[str, int], Optional[str]] = {}

    @classmethod
    def _normalize_rules(cls, rules: List[Dict[str, str]]) -> List[Dict[str, str]]:
        normalized_rules: List[Dict[str, str]] = []
        for rule in rules:
            normalized_rule = dict(rule)
            normalized_rule["category"] = cls._map_category_rule(normalized_rule)
            normalized_rules.append(normalized_rule)
        return normalized_rules

    # ──────────────────────────────────────────────────────────────────────
    # Main entry point
    # ──────────────────────────────────────────────────────────────────────
    def analyze(self) -> Dict[str, Any]:
        """Runs the full analysis of the Python file and returns a results dict."""
        result: Dict[str, Any] = {
            "file": str(self.file_path),
            "file_type": self.file_type,
            "application_type": "unknown",
            "status": "NOT_APPLICABLE",
            "findings": [],
            "summary": {
                "critical": 0,
                "medium": 0,
                "low": 0,
                "by_category": {},
            },
            "metadata": {},
        }

        try:
            if self.file_type == ".py":
                result["application_type"] = "source_python"
                self._analyze_source(result)
            elif self.file_type == ".pyc":
                result["application_type"] = "bytecode_python"
                self._analyze_pyc(result)
            elif self.file_type == ".exe":
                result["application_type"] = "executable_python"
                self._analyze_exe(result)
            else:
                result["detail"] = (
                    f"Extension '{self.file_type}' not supported by PythonCodeInspector"
                )
                return result

            self._consolidate_summary(result, self.rules_implemented)

        except Exception as exc:  # noqa: BLE001
            self.logger.exception("Error in Python analysis: %s", exc)
            result["status"] = "ERROR"
            result["error"] = str(exc)

        return result


    # Analysis of .py source code
    def _analyze_source(self, result: Dict[str, Any]) -> None:
        result["metadata"]["source_modules"] = []
        result["metadata"]["local_imports"] = []
        result["metadata"]["imports_declared"] = []
        root_dir = self._resolve_root_source()
        result["metadata"]["root_source"] = str(root_dir)

        try:
            self._analyze_module_source(
                module_path=self.file_path,
                result=result,
                visited=set(),
                root_dir=root_dir,
                is_main_module=True,
            )
        except OSError as exc:
            result["status"] = "ERROR"
            result["error"] = f"Could not read the file: {exc}"
            return

        result["metadata"]["total_modules_source"] = len(result["metadata"]["source_modules"])

    def _resolve_root_source(self) -> Path:
        """Determines a broad analysis root to follow local imports."""
        file_parent = self.file_path.parent.resolve()
        cwd = Path.cwd().resolve()
        markers = (
            "requirements.txt",
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            ".git",
            "main.py",
        )

        # If the file is inside the cwd, using cwd usually captures sibling packages.
        if self._is_inside_root(file_parent, cwd):
            return cwd

        # Otherwise, walk up from the file looking for a typical project root marker.
        for candidate in (file_parent, *file_parent.parents):
            if any((candidate / marker).exists() for marker in markers):
                return candidate

        return file_parent

    def _analyze_module_source(
        self,
        module_path: Path,
        result: Dict[str, Any],
        visited: Set[Path],
        root_dir: Path,
        is_main_module: bool,
    ) -> None:
        module_path = module_path.resolve()
        if module_path in visited or module_path.suffix.lower() != ".py":
            return
        if not module_path.exists():
            return
        if not self._is_inside_root(module_path, root_dir):
            return

        visited.add(module_path)
        code = module_path.read_text(encoding="utf-8", errors="replace")

        origin = self._format_module_origin(module_path, root_dir)
        result["metadata"]["source_modules"].append(origin)

        if is_main_module:
            result["metadata"]["lines"] = code.count("\n") + 1
            result["metadata"]["bytes"] = len(code.encode("utf-8", errors="ignore"))

        findings = self._analyze_code_python(
            code,
            origin=origin,
            is_main_module=is_main_module,
        )
        result["findings"].extend(findings)

        for import_decl in self._list_declared_imports(code):
            if import_decl not in result["metadata"]["imports_declared"]:
                result["metadata"]["imports_declared"].append(import_decl)

        for imported_path in self._resolve_local_imports(code, module_path, root_dir):
            imported_origin = self._format_module_origin(imported_path, root_dir)
            if imported_origin not in result["metadata"]["local_imports"]:
                result["metadata"]["local_imports"].append(imported_origin)
            self._analyze_module_source(
                module_path=imported_path,
                result=result,
                visited=visited,
                root_dir=root_dir,
                is_main_module=False,
            )

    # ──────────────────────────────────────────────────────────────────────
    # .pyc bytecode analysis
    # ──────────────────────────────────────────────────────────────────────
    def _analyze_pyc(self, result: Dict[str, Any]) -> None:
        try:
            data = self.file_path.read_bytes()
        except OSError as exc:
            result["status"] = "ERROR"
            result["error"] = f"Could not read the file: {exc}"
            return

        result["metadata"]["bytes"] = len(data)
        result["metadata"]["note"] = (
            "The .pyc bytecode is not decompiled automatically. "
            "Only a search for suspicious strings is performed. "
            "For a full analysis use tools such as decompile3 or pycdc."
        )

        findings = self._analyze_pyc_with_priority(
            data,
            origin_metadata=self.file_path.name,
            source_name=self.file_path.name,
        )
        result["findings"].extend(findings)

    # ──────────────────────────────────────────────────────────────────────
    # Analysis of .exe executables (PyInstaller, cx_Freeze, py2exe)
    # ──────────────────────────────────────────────────────────────────────
    def _analyze_exe(self, result: Dict[str, Any]) -> None:
        """
        Analyzes a Python executable using the specialized extraction module.

        Strategy:
          1. Packager detection
          2. Extraction of internal files (.py/.pyc)
          3. Analysis of the extracted code
          4. Fallback to binary scanning if nothing is extracted
        """
        # Initialize extractor
        extractor = PackagedExecutableExtractor(
            self.file_path,
            self.evidence_dir,
            max_members=self.MAX_EXTRACTED_MEMBERS
        )

        # Detect packager type
        packager, packager_info = extractor.detect_packager()
        result["metadata"]["packer"] = packager
        result["metadata"].update(packager_info)

        # Try extraction with all strategies
        extracted_files = extractor.full_extraction()
        extraction_info = extractor.get_extraction_info()

        # Update extraction metadata
        result["metadata"]["internal_extraction"] = {
            "status": extraction_info["status"],
            "packager": extraction_info["packager"],
            "method": extraction_info["method"],
            "extracted_files": extraction_info["extracted_files"],
            "modules": extraction_info["modules"][:50],
        }

        if extraction_info.get("pyz_detected"):
            result["metadata"]["internal_extraction"]["pyz_detected"] = True
            result["metadata"]["internal_extraction"]["pyz_folder"] = extraction_info.get("pyz_folder")
            result["metadata"]["internal_extraction"]["pyz_modules"] = int(extraction_info.get("pyz_modules", 0))
            result["metadata"]["internal_extraction"]["pyz_modules_list"] = (
                extraction_info.get("pyz_modules_list", [])[:50]
            )
            if extraction_info.get("pyz_directory"):
                result["metadata"]["internal_extraction"]["pyz_directory"] = extraction_info.get("pyz_directory")

        if extraction_info["errors"]:
            result["metadata"]["internal_extraction"]["errors"] = (
                extraction_info["errors"][:5]
            )

        analyzed_count = 0

        # Process extracted files
        for filename, content in extracted_files:
            origin = f"{self.file_path.name}!{filename}"

            if filename.endswith(".py"):
                try:
                    code = content.decode("utf-8", errors="replace")
                    is_main = "__main__" in filename
                    findings = self._analyze_code_python(
                        code,
                        origin=origin,
                        is_main_module=is_main,
                    )
                    result["findings"].extend(findings)
                    analyzed_count += 1
                except Exception as exc:
                    self.logger.warning(f"Error analyzing {origin}: {exc}")
            elif filename.endswith(".pyc"):
                try:
                    findings = self._analyze_pyc_with_priority(
                        content,
                        origin_metadata=origin,
                        source_name=filename,
                    )
                    result["findings"].extend(findings)
                    analyzed_count += 1
                except Exception as exc:
                    self.logger.warning(f"Error analyzing bytecode {origin}: {exc}")

        # Analyze the executable's companion folder(s) (e.g. internal/)
        companion_findings, companion_meta = self._analyze_companion_directories_exe()
        result["findings"].extend(companion_findings)
        analyzed_count += int(companion_meta.get("analyzed_files", 0))

        result["metadata"]["internal_extraction"]["analyzed_files"] = analyzed_count
        result["metadata"]["analysis_companion"] = companion_meta

        has_internal_extract = bool(extracted_files)
        has_companion_files = bool(companion_meta.get("analyzed_files", 0))

        # Complementary binary scan: always runs to cover strings that did not
        # end up in extracted/companion modules (packer metadata, etc.).
        binary_findings, binary_meta = self._scan_executable_binary(origin=self.file_path.name)
        result["metadata"]["scan_binary_complementary"] = binary_meta
        result["findings"].extend(
            self._filter_metadata_findings_prefer_existing_code(
                metadata_findings=binary_findings,
                existing_findings=result["findings"],
            )
        )

        if has_internal_extract and has_companion_files:
            result["metadata"]["exe_analysis_method"] = "internal_extraction_and_companion"
            return
        if has_internal_extract:
            result["metadata"]["exe_analysis_method"] = "internal_extraction"
            return
        if has_companion_files:
            result["metadata"]["exe_analysis_method"] = "companion_folder"
            return

        # Fallback: binary scan
        self.logger.info(
            f"Extraction of {self.file_path.name} produced no analyzable files; "
            f"applying binary pattern scan"
        )

        result["metadata"]["bytes"] = int(binary_meta.get("bytes", 0))
        if bool(binary_meta.get("truncated")):
            result["metadata"]["truncated"] = True
            result["metadata"]["bytes_scanned"] = int(binary_meta.get("bytes_scanned", 0))
        result["metadata"]["exe_analysis_method"] = "scan_binary_fallback"

    def _analyze_companion_directories_exe(self) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Analyzes companion folders next to the executable (e.g. internal/).

        This covers one-folder distributions where the .exe is accompanied by
        loose modules outside the binary's internal container.
        """
        meta: Dict[str, Any] = {
            "status": "without_companion",
            "directories": [],
            "files_detected": 0,
            "analyzed_files": 0,
            "files_truncated": 0,
            "modules": [],
        }

        findings: List[Dict[str, Any]] = []
        candidate_directories = self._find_companion_directories()
        if not candidate_directories:
            return findings, meta

        meta["status"] = "detected"
        meta["directories"] = [str(path) for path in candidate_directories]

        members = self._collect_companion_members(candidate_directories)
        meta["files_detected"] = len(members)

        if len(members) > self.MAX_COMPANION_MEMBERS:
            meta["files_truncated"] = len(members) - self.MAX_COMPANION_MEMBERS
            members = members[: self.MAX_COMPANION_MEMBERS]

        exe_stem = self.file_path.stem.lower()

        for member in members:
            rel = self._format_companion_origin(member, candidate_directories)
            origin = f"{self.file_path.name}!companion/{rel}"
            suffix = member.suffix.lower()

            try:
                if suffix == ".py":
                    code = member.read_text(encoding="utf-8", errors="replace")
                    stem = member.stem.lower()
                    is_main = stem in {"__main__", "main", exe_stem}
                    findings.extend(
                        self._analyze_code_python(
                            code,
                            origin=origin,
                            is_main_module=is_main,
                        )
                    )
                    meta["analyzed_files"] = int(meta["analyzed_files"]) + 1
                    meta["modules"].append(rel)
                elif suffix == ".pyc":
                    raw = member.read_bytes()
                    findings.extend(
                        self._analyze_pyc_with_priority(
                            raw,
                            origin_metadata=origin,
                            source_name=rel,
                        )
                    )
                    meta["analyzed_files"] = int(meta["analyzed_files"]) + 1
                    meta["modules"].append(rel)
            except OSError as exc:
                self.logger.warning("Could not analyze companion %s: %s", member, exc)

        if meta["analyzed_files"]:
            meta["status"] = "analyzed"

        if len(meta["modules"]) > 50:
            meta["modules"] = meta["modules"][:50]

        return findings, meta

    def _find_companion_directories(self) -> List[Path]:
        """Detects common companion folders for one-folder distributions."""
        base = self.file_path.parent
        stem = self.file_path.stem
        candidates = [
            base / "_internal",
            base / "internal",
            base / "lib",
            base / "app",
            base / f"{stem}_internal",
            base / f"{stem}_files",
        ]

        # Consider any sibling folder with an _internal suffix.
        for sibling in base.glob("*_internal"):
            candidates.append(sibling)

        discovered: List[Path] = []
        seen: Set[Path] = set()
        for candidate in candidates:
            resolved = candidate.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            if candidate.exists() and candidate.is_dir():
                discovered.append(candidate)
        return discovered

    @staticmethod
    def _collect_companion_members(companion_directories: List[Path]) -> List[Path]:
        members: List[Path] = []
        seen: Set[Path] = set()

        for directory in companion_directories:
            for path in directory.rglob("*.py"):
                resolved = path.resolve()
                if resolved not in seen and path.is_file():
                    seen.add(resolved)
                    members.append(path)
            for path in directory.rglob("*.pyc"):
                resolved = path.resolve()
                if resolved not in seen and path.is_file():
                    seen.add(resolved)
                    members.append(path)

        members.sort(key=lambda p: str(p).lower())
        return members

    def _format_companion_origin(self, member: Path, companion_directories: List[Path]) -> str:
        member_resolved = member.resolve()
        for companion_dir in companion_directories:
            try:
                return str(member_resolved.relative_to(companion_dir.resolve()))
            except ValueError:
                continue
        return member.name

    # ──────────────────────────────────────────────────────────────────────
    # AST + regex analysis of source code
    # ──────────────────────────────────────────────────────────────────────
    # NOTE: Packager detection and embedded ZIP extraction
    # were moved to the specialized module:
    # lefiru/core/analyzers/python/python_executable.py
    # ──────────────────────────────────────────────────────────────────────
    def _analyze_code_python(
        self,
        code: str,
        origin: str,
        is_main_module: bool = True,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        # 1) AST: dangerous calls, imports, credential assignments
        tree, exc, recovered = self._parse_python_with_recovery(code, origin)
        if tree is not None:
            self._annotate_parents(tree)
            if recovered and exc is not None:
                findings.append({
                    "type": "syntax_error",
                    "category": "traceability",
                    "severity": "medium",
                    "origin": origin,
                    "line": exc.lineno or 0,
                    "description": (
                        f"The file is not valid Python ({exc.msg}), but a partial "
                        "AST was recovered and the analysis continued over the rest of the code."
                    ),
                })
        elif exc is not None:
            self.logger.warning(
                "SyntaxError while parsing '%s' (line %s): %s — "
                "AST checks will be skipped for this file.",
                origin, exc.lineno, exc.msg,
            )
            findings.append({
                "type": "syntax_error",
                "category": "traceability",
                "severity": "medium",
                "origin": origin,
                "line": exc.lineno or 0,
                "description": (
                    f"The file is not valid Python ({exc.msg}). "
                    "Possible incorrect indentation or non-functional code. "
                    "AST security tests were skipped."
                ),
            })

        has_logging = False
        has_main_guard = False

        if tree is not None:
            for node in ast.walk(tree):
                # Direct calls: eval(), exec(), etc.
                if isinstance(node, ast.Call):
                    func_name = self._get_call_name(node.func)
                    if func_name in DANGEROUS_CALLS:
                        cat, sev, desc = DANGEROUS_CALLS[func_name]
                        findings.append({
                            "type": func_name,
                            "category": cat,
                            "severity": sev,
                            "origin": origin,
                            "line": node.lineno,
                            "description": desc,
                        })

                    # Attribute calls: subprocess.run(..., shell=True), os.system, etc.
                    attr = self._get_attr_call(node.func)
                    if attr in DANGEROUS_ATTR_CALLS:
                        cat, sev, desc = DANGEROUS_ATTR_CALLS[attr]
                        shell_true = self._has_shell_true(node)
                        if attr[0] == "subprocess" and shell_true:
                            sev = "critical"
                            desc = f"{attr[0]}.{attr[1]} with shell=True (command injection risk)"
                        findings.append({
                            "type": f"{attr[0]}.{attr[1]}",
                            "category": cat,
                            "severity": sev,
                            "origin": origin,
                            "line": node.lineno,
                            "description": desc,
                        })

                    if attr == ("logging", "getLogger") or attr == ("logging", "basicConfig"):
                        has_logging = True

                # Dangerous imports
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    names = []
                    if isinstance(node, ast.Import):
                        names = [n.name.split(".")[0] for n in node.names]
                    else:
                        if node.module:
                            names = [node.module.split(".")[0]]
                    for mod in names:
                        if mod == "logging":
                            has_logging = True
                        if mod in DANGEROUS_IMPORTS:
                            cat, sev, desc = DANGEROUS_IMPORTS[mod]
                            findings.append({
                                "type": f"import_{mod}",
                                "category": cat,
                                "severity": sev,
                                "origin": origin,
                                "line": node.lineno,
                                "description": desc,
                            })

                # Hardcoded credentials: assignments such as password = "..."
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        var_name = self._get_target_name(target)
                        if not var_name:
                            continue
                        if not self._is_credential_name(var_name):
                            continue
                        value = self._get_constant_str(node.value)
                        if self._is_probable_credential_value(var_name, value):
                            findings.append({
                                "type": "hardcoded_credential",
                                "category": "credentials",
                                "severity": "critical",
                                "origin": origin,
                                "line": node.lineno,
                                "variable": var_name,
                                "value": value,
                                "description": (
                                    f"Variable '{var_name}' assigned a literal "
                                    f"suggests a hardcoded credential"
                                ),
                            })

                # Detection of the if __name__ == "__main__" guard
                if isinstance(node, ast.If) and self._is_main_guard(node):
                    has_main_guard = True
                    
        cors_detected_ast = False
        
        # 2) Run the analysis rules first.
        
        rule_findings = self._apply_rules_analysis(tree,origin)
        
        # Detect whether CORS was already found by the AST (analysis rules)
        for h in rule_findings:
            if h.get("rule_name","").lower() == "cors policy too broad":
                cors_detected_ast= True
                break
        
        findings.extend(rule_findings)
        # 3) Inspect literals (regex)
        if tree is not None:
            for literal, line in self._iter_string_literals(tree):
                if not self._is_literal_relevant(literal):
                    continue

                for m in URL_PATTERN.finditer(literal):
                    url = m.group(0)
                    sev = "medium" if url.startswith(("http://", "ftp://")) else "low"
                    findings.append({
                        "type": "hardcoded_url",
                        "category": "connections",
                        "severity": sev,
                        "origin": origin,
                        "line": line,
                        "value": url,
                        "description": "Hardcoded URL in code",
                    })

                for m in UNC_PATTERN.finditer(literal):
                    path = m.group(0)
                    findings.append({
                        "type": "unc_path",
                        "category": "connections",
                        "severity": "medium",
                        "origin": origin,
                        "line": line,
                        "value": path,
                        "description": "Hardcoded UNC path (network resource)",
                    })
                    
                if not cors_detected_ast:
                    for m in CORS_RISKY_PATTERNS:
                        if m.search(literal):
                            findings.append({
                                "type": "cors_regex",
                                "category" : "connections",
                                "severity":"critical",
                                "origin": origin,
                                "line" : line,
                                "value": literal,
                                "description": "CORS too permissive detected by regex"
                                
                            })

                if self._seems_connection_string(literal):
                    findings.append({
                        "type": "connection_string",
                        "category": "connections",
                        "severity": "critical",
                        "origin": origin,
                        "line": line,
                        "value": literal,
                        "description": "Possible connection string in code",
                    })

                if self._seems_secret_by_shape(literal):
                    findings.append({
                        "type": "hardcoded_secret",
                        "category": "credentials",
                        "severity": "critical",
                        "origin": origin,
                        "line": line,
                        "value": literal,
                        "description": "Literal highly likely to represent a hardcoded secret",
                    })
                    
       

        # 2.5) Traceability: detect duplicated function blocks.
        if tree is not None:
            for duplicate in self._detector_code_duplicate_traceability(tree):
                functions = ", ".join(duplicate["functions"])
                findings.append({
                    "type": "duplicated_code",
                    "category": "traceability",
                    "severity": "low",
                    "origin": origin,
                    "line": duplicate["line"],
                    "description": (
                        "Possible duplicated code detected between functions "
                        f"({functions})"
                    ),
                    "functions": duplicate["functions"],
                    "lines_duplicates": duplicate["lines"],
                })

        # 3) Traceability / logging
        if is_main_module and not has_logging:
            findings.append({
                "type": "no_logging",
                "category": "traceability",
                "severity": "medium",
                "origin": origin,
                "line": 0,
                "description": "The script does not configure the logging module (weak traceability)",
            })
        if is_main_module and not has_main_guard and tree is not None:
            findings.append({
                "type": "no_main_guard",
                "category": "quality",
                "severity": "low",
                "origin": origin,
                "line": 0,
                "description": "The script lacks an if __name__ == '__main__' block",
            })

        findings = self._normalize_findings_credentials(findings)
        return self._attach_evidence_image(findings, code, origin)

    def _attach_evidence_image(
        self,
        findings: List[Dict[str, Any]],
        code: str,
        origin: str,
    ) -> List[Dict[str, Any]]:
        """Attaches to each finding the path of a screenshot of its exact line.

        The image is reused for all findings on the same line and is skipped
        when the line does not exist (e.g. whole-module findings or binary
        metadata findings, which use ``line = 0``).
        """
        if not findings or not code:
            return findings

        if self._evidence_renderer is None:
            self._evidence_renderer = PythonEvidenceRenderer(
                self.evidence_dir,
                file_stem=self.file_path.stem,
            )

        for finding in findings:
            try:
                line = int(finding.get("line") or 0)
            except (TypeError, ValueError):
                continue

            origin_finding = str(finding.get("origin") or origin)
            label = str(finding.get("type") or finding.get("category") or "")

            if line > 0:
                key = (origin_finding, line)
                if key not in self._evidence_cache:
                    self._evidence_cache[key] = self._evidence_renderer.render_line(
                        code=code,
                        line=line,
                        origin=origin_finding,
                        label=label,
                    )
            else:
                # Global-scope finding (no specific line): the file header is
                # captured as context evidence.
                key = (origin_finding, 0)
                if key not in self._evidence_cache:
                    self._evidence_cache[key] = (
                        self._evidence_renderer.render_file_context(
                            code=code,
                            origin=origin_finding,
                            label=label,
                        )
                    )

            path = self._evidence_cache[key]
            if path:
                finding["evidence_image"] = path

        return findings

    @staticmethod
    def _normalize_findings_credentials(
        findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Merges duplicate credentials per line and marks crypto context."""
        if not findings:
            return findings

        normalized: List[Dict[str, Any]] = []
        index_credential_by_line: Dict[Tuple[str, int], int] = {}

        for finding in findings:
            category = str(finding.get("category", "")).lower()
            type = str(finding.get("type", "")).lower()

            if category != "credentials" or type not in {"hardcoded_credential", "hardcoded_secret"}:
                copy = dict(finding)
                PythonCodeInspector._annotate_context_cryptographic(copy)
                normalized.append(copy)
                continue

            origin = str(finding.get("origin", ""))
            line = int(finding.get("line") or 0)
            key = (origin, line)
            idx_existing = index_credential_by_line.get(key)

            if idx_existing is None:
                copy = dict(finding)
                PythonCodeInspector._annotate_context_cryptographic(copy)
                copy.setdefault("related_types", [copy.get("type")])
                normalized.append(copy)
                index_credential_by_line[key] = len(normalized) - 1
                continue

            existing = normalized[idx_existing]

            # Prefer hardcoded_credential because it provides variable and context.
            if existing.get("type") == "hardcoded_secret" and type == "hardcoded_credential":
                replacement = dict(finding)
                replacement.setdefault("value", existing.get("value"))
                replacement.setdefault("variable", existing.get("variable"))
                related = set(existing.get("related_types", []))
                related.add(existing.get("type"))
                related.add(replacement.get("type"))
                replacement["related_types"] = sorted(str(t) for t in related if t)
                PythonCodeInspector._annotate_context_cryptographic(replacement)
                normalized[idx_existing] = replacement
                continue

            if not existing.get("variable") and finding.get("variable"):
                existing["variable"] = finding.get("variable")
            if not existing.get("value") and finding.get("value"):
                existing["value"] = finding.get("value")

            related = set(existing.get("related_types", []))
            related.add(existing.get("type"))
            related.add(finding.get("type"))
            existing["related_types"] = sorted(str(t) for t in related if t)
            PythonCodeInspector._annotate_context_cryptographic(existing)

        return normalized

    @staticmethod
    def _is_cryptographic_finding(finding: Dict[str, Any]) -> bool:
        category = str(finding.get("category", "")).lower()
        if category != "credentials":
            return False

        variable = str(finding.get("variable", "")).strip()
        value = str(finding.get("value", "")).strip()

        if variable:
            tokens = PythonCodeInspector._tokenize_name(variable)
            crypto_tokens = {
                "key", "secret", "token", "jwt", "private", "public",
                "encrypt", "decrypt", "cipher", "rsa", "aes", "hmac",
                "sign", "signing", "cert", "certificate", "pem", "session",
            }
            if tokens & crypto_tokens:
                return True

        # Compact JWT usually starts with eyJ...
        if value.startswith("eyJ") and "." in value:
            return True

        return False

    @staticmethod
    def _annotate_context_cryptographic(finding: Dict[str, Any]) -> None:
        if not PythonCodeInspector._is_cryptographic_finding(finding):
            return

        labels = finding.get("labels")
        if isinstance(labels, list):
            if "cryptography" not in labels:
                labels.append("cryptography")
        else:
            finding["labels"] = ["cryptography"]

        finding["subcategory"] = "cryptography"

        description = str(finding.get("description", "")).strip()
        if description and "cryptography" not in description.lower():
            finding["description"] = f"{description} [Context: cryptography]"

    def _apply_rules_analysis(
        self,
        tree: Optional[ast.AST],
        origin: str,
    ) -> List[Dict[str, Any]]:
        if not self.rules_implemented or tree is None:
            return []

        findings: List[Dict[str, Any]] = []
        detectors = {
            "use an iterator instead of materializing the list": self._detector_iterator_without_materialize,
            "empty sequences are false": self._detector_empty_sequences_false,
            "use literals to initialize dictionaries": self._detector_dict_literal_in_loop,
            "class methods not accessing instance fields must be static": self._detector_method_of_instance_without_self,
            "not using items() to iterate over a dictionary": self._detector_not_using_items,
            "not using zip() to iterate over a pair of lists": self._detector_not_using_zip,
            "do not use concatenation to extend lists": self._detector_concatenation_extends_list,
            "hardcoded filesystem paths in code": self._detector_paths_hardcoded_connections,
            "hardcoded ip addresses in code": self._detector_hardcoded_ips_traceability,
            "avoid sql code formed with non neutralized user input": self._detector_sql_no_neutralized,
            "improper neutralization of special elements in data query logic (nosql injection)": self._detector_nosql_no_neutralized,
            "cors policy too broad": self._detector_cors_misconfigured,
            "cookie poisoning": self._detector_cookie_poisoning,
            "avoid too complex functions": self._detector_functions_complex,
            "xml entity injection": self._detector_xxe_xml,
            "mail command injection": self._detector_mail_command_injection,
            "potential denial-of-service attack through malicious regular expression (redos)": self._detector_redos_regex_malicious,
        }

        for rule in self.rules_implemented:
            name = rule.get("name", "").strip()
            detector = detectors.get(name.lower())
            if not detector:
                continue
            for line, evidence in detector(tree):
                findings.append({
                    "type": "rule_analysis",
                    "category": self._map_category_rule(rule),
                    "severity": self._map_severity_rule(rule),
                    "origin": origin,
                    "line": line,
                    "description": f"Rule '{name}' detected",
                    "rule_name": name,
                    "rule_priority": rule.get("priority", ""),
                    "identifier": "[analysis]",
                    "evidence": evidence,
                })
                self.logger.debug(
                    "Rule violated '%s' in %s:%s (%s)",
                    name,
                    origin,
                    line,
                    evidence,
                )

        return findings

    @classmethod
    def _map_category_rule(cls, rule: Dict[str, str]) -> str:
        category = str(rule.get("category", "")).strip().lower()
        if category in cls.VALID_RULE_CATEGORIES:
            return category

        name = str(rule.get("name", "")).strip().lower()
        characteristic = str(rule.get("characteristic", "")).strip().lower()
        vulnerability = str(rule.get("vulnerability_type", "")).strip().lower()
        content = " ".join((name, characteristic, vulnerability))

        if any(token in content for token in (
            "hard-coded credential",
            "hardcoded",
            "password",
            "credential",
            "token",
            "secret",
            "cryptographic key",
            "salt",
        )):
            return "credentials"

        if any(token in content for token in (
            "os command",
            "command injection",
            "mail command",
        )):
            return "dangerous_commands"

        if any(token in content for token in (
            "deserialization",
            "deserialize",
            "pickle",
            "yaml.load",
            "marshal",
        )):
            return "deserialization"

        if any(token in content for token in (
            "exec()",
            "dynamic code",
            "execution after redirect",
            "control flow management",
            "loop",
        )):
            return "dynamic_execution"

        if any(token in content for token in (
            "sql injection",
            "xpath",
            "xss",
            "cross-site",
            "csrf",
            "xml entity",
            "json injection",
            "nosql injection",
            "ldap",
            "resource injection",
            "neutralized user",
            "untrusted input",
            "improper neutralization",
            "input validation",
        )):
            return "unvalidated_input"

        if any(token in content for token in (
            "connection",
            "http",
            "https",
            "transport",
            "cookie",
            "cors",
            "session",
            "ssrf",
            "url",
        )):
            return "connections"

        if any(token in content for token in (
            "reflection",
            "native api",
            "ctypes",
            "low level",
        )):
            return "low_level_access"

        if any(token in content for token in (
            "log",
            "audit",
            "traceability",
        )):
            return "traceability"

        if characteristic in {"efficiency", "maintainability", "style", "readability"}:
            return "quality"
        return "quality"

    @staticmethod
    def _map_severity_rule(rule: Dict[str, str]) -> str:
        priority = rule.get("priority", "").strip().lower()
        if priority in {"high", "very high", "critical"}:
            return "critical"
        if priority in {"medium", "normal"}:
            return "medium"
        return "low"
    
    def _binop_contains_command_mail(self, node: ast.BinOp) -> bool:
        parts_str: List[str] = []
        has_variable = False

        stack = [node.left, node.right]

        while stack:
            part = stack.pop()

            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                parts_str.append(part.value.lower())

            elif isinstance(part, ast.BinOp) and isinstance(part.op, ast.Add):
                stack.extend([part.left, part.right])

            elif isinstance(part, (ast.Name, ast.Attribute, ast.Call)):
                has_variable = True

        return has_variable and any(cmd in text for text in parts_str for cmd in ["mail", "sendmail"])

    @staticmethod
    def _string_contains_command_mail(text: str) -> bool:
        text_normalized = text.lower()
        return any(cmd in text_normalized for cmd in ("mail", "sendmail", "smtp"))

    @staticmethod
    def _scope_contains_node(scope: ast.AST, target: ast.AST) -> bool:
        return any(node is target for node in ast.walk(scope))

    def _get_enclosing_scope(self, node: ast.AST) -> ast.AST:
        current = node
        while getattr(current, "parent", None) is not None:
            current = current.parent
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
                return current
        return node

    def _resolve_last_assignment_name(
        self,
        scope: ast.AST,
        name: str,
        before_lineno: int,
    ) -> Optional[ast.AST]:
        last_assignment: Optional[ast.AST] = None

        for node in ast.walk(scope):
            if not isinstance(node, ast.Assign):
                continue
            if getattr(node, "lineno", 0) >= before_lineno:
                continue

            nested_scope = self._get_enclosing_scope(node)
            if nested_scope is not scope:
                continue

            for target in node.targets:
                target_name = self._get_target_name(target)
                if target_name == name:
                    last_assignment = node.value

        return last_assignment

    def _analyze_expression_mail(
        self,
        expr: ast.AST,
        scope: ast.AST,
        before_lineno: int,
        resolving: Optional[Set[str]] = None,
    ) -> Optional[str]:
        if resolving is None:
            resolving = set()

        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            if self._string_contains_command_mail(expr.value):
                return f"Direct use of mail command: {expr.value.lower()}"
            return None

        if isinstance(expr, ast.JoinedStr):
            literal = [
                part.value.lower()
                for part in expr.values
                if isinstance(part, ast.Constant) and isinstance(part.value, str)
            ]
            if any(self._string_contains_command_mail(literal) for literal in literal):
                return "Mail command built with an f-string (injection risk)"
            return None

        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            if self._binop_contains_command_mail(expr):
                return "Mail command built dynamically (injection risk)"
            left = self._analyze_expression_mail(expr.left, scope, before_lineno, resolving)
            if left:
                return left
            return self._analyze_expression_mail(expr.right, scope, before_lineno, resolving)

        if isinstance(expr, ast.Name):
            if expr.id in resolving:
                return None
            resolving.add(expr.id)
            assignment = self._resolve_last_assignment_name(scope, expr.id, before_lineno)
            if assignment is None:
                return None
            return self._analyze_expression_mail(assignment, scope, before_lineno, resolving)

        return None
            

    @staticmethod
    def _inside_loop(node: ast.AST) -> bool:
        current = getattr(node, "parent", None)
        while current is not None:
            if isinstance(current, (ast.For, ast.While, ast.AsyncFor)):
                return True
            current = getattr(current, "parent", None)
        return False
    
    def _detector_mail_command_injection(self, tree: ast.AST) -> List[Tuple[int,str]]:
        hits : List[Tuple[int,str]]= []
        FUNCTIONS_RISK = {"system", "popen", "run", "Popen", "call"}
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                attr = self._get_attr_call(node.func)
                if not attr:
                    continue

                _module, method = attr
                if method not in FUNCTIONS_RISK:
                    continue

                scope = self._get_enclosing_scope(node)
                for arg in node.args:
                    evidence = self._analyze_expression_mail(
                        arg,
                        scope=scope,
                        before_lineno=getattr(node, "lineno", 0),
                    )
                    if evidence:
                        hits.append((node.lineno, evidence))
                        break
        return hits
                        
                
    
    def _detector_xxe_xml(self, tree: ast.AST) -> List[Tuple[int,str]]:
        hits : List[Tuple[int,str]] = []
        
       
        
        functions_dangerous = {
            "parse",
            "fromstring",
            "XMLParser"
        }
        
        usa_defused = False
        
        # Detect safe libraries 
        
        for node in ast.walk(tree):
            # Case 1: from defusedxml import...
            if isinstance(node,ast.ImportFrom):
                if node.module and "defusedxml" in node.module:
                    usa_defused  = True
                    
            # Case 2: import defusedxml
            elif isinstance(node, ast.Import):
                for name in node.names:
                    if "defusedxml" in name.name:
                        usa_defused = True
                        
        
        for node in ast.walk(tree):
            
            
            # Detect dangerous calls
            if isinstance(node, ast.Call):
                
                func_name = self._get_call_name(node.func)
                attr = self._get_attr_call(node.func)
                
                # Case 1: direct call (parse, fromstring)
                if func_name in functions_dangerous:
                    if not usa_defused:
                        hits.append((
                            node.lineno,
                            f"Use of '{func_name}' for XML parsing without XXE protection"
                        ))
                
                # Case 2: call such as xml.etree.parse
                if attr:
                    module, method = attr
                    if method in functions_dangerous:
                        hits.append((
                            node.lineno,
                            f"{module}.{method} could allow XML external Entity"
                        ))
                
                # Critical case: XMLParser(resolve_entities=True)
                if attr and attr[1] == "XMLParser":
                    for kw in node.keywords:
                        if kw.arg == "resolve_entities":
                            if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                
                                hits.append((
                                        node.lineno,
                                        "XMLParser with resolve_entities=True allows XXE"
                                ))
                        
                    
        return hits
        
    
    def _detector_functions_complex(self, tree: ast.AST) -> List[Tuple[int,str]]:
        hits: List[Tuple[int,str]] = []
        
        MAX_LINES = 60
        MAX_NODES = 30
        
        for node in ast.walk(tree):
            if not isinstance(node,(ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            
            # Size in lines
            start = getattr(node, "lineno", 0)
           
            end = getattr(node, "end_lineno", start)
            num_lines = max(0, end - start)

            
            # Complexity
            complexity_nodes = 0
            for sub in ast.walk(node):
                if isinstance(sub,(
                   ast.If,
                   ast.For,
                   ast.While,
                   ast.Try,
                   ast.With,
                   ast.BoolOp,
                   ast.IfExp 
                )):
                    complexity_nodes+=1
            
            # Evaluation
            if num_lines> MAX_LINES or complexity_nodes > MAX_NODES:
                evidence = (
                    f"Function '{node.name}' with "
                    f"{num_lines} lines and {complexity_nodes} control nodes"
                )
                
                hits.append((node.lineno,evidence))
                
        return hits
        
    
    def _detector_cors_misconfigured(self, tree: ast.AST) -> List[Tuple[int, str]]:
        hits: List[Tuple[int, str]] = []
        cors_all = False
        cors_credentials = False
        for node in ast.walk(tree):
            # Look for CORS(..., origins="*")
            
            # Flask - CORS
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node.func)

                # Detect use of CORS
                if func_name == "CORS" or (
                    isinstance(node.func, ast.Attribute) and node.func.attr.lower() == "cors"
                ):
                    for kw in node.keywords:
                        if kw.arg in {"origins", "resources"}:
                            if isinstance(kw.value, ast.Constant) and kw.value.value == "*":
                                hits.append((node.lineno ,"CORS allows all origins '*'"))
                                cors_all = True
                            
                            if isinstance(kw.value, ast.List):
                                if any(isinstance(e , ast.Constant) and e.value == "*" for e in kw.value.elts ):
                                    hits.append((node.lineno,"CORS allows lists with '*'"))  
                                    
                                    cors_all = True
              
            #Fast API
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr == "add_middleware":
                        for kw in node.keywords:
                            if kw.arg == "allow_origins":
                                if isinstance(kw.value, ast.List):
                                    if any(isinstance(e,ast.Constant) and e.value == "*" for e in kw.value.elts):
                                        hits.append((node.lineno, "FASTAPI CORS allows all origins ['*']") )
                                        cors_all = True
                                        
                            if kw.arg == "allow_credentials":
                                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                    cors_credentials = True
            #Django 
            
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    var_name = self._get_target_name(target)
                    if var_name == "CORS_ALLOW_ALL_ORIGINS":
                        if isinstance(node.value, ast.Constant) and node.value.value is True:
                            hits.append((node.lineno, "Django CORS_ALLOW_ALL_ORIGIN=True"))
                            cors_all = True
                    if var_name == "CORS_ALLOW_CREDENTIALS":
                        if isinstance(node.value, ast.Constant) and node.value.value is True:
                            cors_credentials = True
                        
                    if var_name and "origin" in var_name.lower():
                        if isinstance(node.value, ast.List):
                            if any(isinstance(e, ast.Constant) and e.value == "*" for e in node.value.elts):
                                hits.append((node.lineno, f"Variable '{var_name}' allows '*'" ))
                                cors_all = True
                    

            # Manual headers
            if isinstance(node, ast.Assign):
                if isinstance(node.targets[0], ast.Subscript):
                    target = node.targets[0]
                    if isinstance(target.slice, ast.Constant):
                        key = str(target.slice.value)
                        if "Access-Control-Allow-Origin" in key:
                            value = self._get_constant_str(node.value)
                            if value == "*":
                                hits.append((node.lineno, "CORS header allows any origin '*'"))
                                
                                cors_all = True
                
        if cors_all and cors_credentials:
            hits.append((0, "CORS allows '*' + credentials (critical risk)"))
        return hits

    @classmethod
    def _expr_is_untrusted_source(cls, node: ast.AST) -> bool:
        """True if the expression accesses user-controlled input.

        Covers typical web framework sources (Flask/FastAPI/Django/Tornado):
        request parameters, forms, query string, incoming cookies,
        headers and direct reads of cookies or input().
        """
        if node is None:
            return False

        sources_request = {
            "cookies", "args", "form", "values", "data", "json",
            "query_params", "headers",
        }
        sources_django = {"COOKIES", "GET", "POST", "META"}

        for sub in ast.walk(node):
            if isinstance(sub, ast.Attribute):
                if sub.attr in sources_django:
                    return True
                if sub.attr in sources_request:
                    base = sub.value
                    base_name = getattr(base, "id", None) or getattr(base, "attr", None)
                    if base_name and "request" in str(base_name).lower():
                        return True
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                if sub.func.attr.lower() == "get_cookie":
                    return True
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                if sub.func.id == "input":
                    return True
        return False

    def _detector_cookie_poisoning(self, tree: ast.AST) -> List[Tuple[int, str]]:
        """Detects cookie poisoning (CWE-565).

        Flags when the value of a response cookie comes from untrusted input
        (request parameters, forms, query string or another incoming cookie),
        which lets an attacker manipulate the cookie contents.
        """
        hits: List[Tuple[int, str]] = []

        # "Tainted" variables: assigned from an untrusted source.
        tainted: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and self._expr_is_untrusted_source(node.value):
                for target in node.targets:
                    name = self._get_target_name(target)
                    if name:
                        tainted.add(name)

        def _is_unreliable_value(value: Optional[ast.AST]) -> bool:
            if value is None:
                return False
            if self._expr_is_untrusted_source(value):
                return True
            if isinstance(value, ast.Name) and value.id in tainted:
                return True
            return False

        for node in ast.walk(tree):
            # set_cookie(...) / set_signed_cookie(...) on response objects.
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                method = node.func.attr.lower()
                if method in {"set_cookie", "set_signed_cookie"}:
                    value_node: Optional[ast.AST] = None
                    if len(node.args) >= 2:
                        value_node = node.args[1]
                    for kw in node.keywords:
                        if kw.arg == "value":
                            value_node = kw.value
                    if _is_unreliable_value(value_node):
                        hits.append((
                            node.lineno,
                            "Cookie set with an untrusted input value (cookie poisoning)",
                        ))

            # Manual assignment of the 'Set-Cookie' header with tainted value.
            if isinstance(node, ast.Assign) and node.targets and isinstance(node.targets[0], ast.Subscript):
                target = node.targets[0]
                if isinstance(target.slice, ast.Constant):
                    key = str(target.slice.value).lower()
                    if "set-cookie" in key and _is_unreliable_value(node.value):
                        hits.append((
                            node.lineno,
                            "'Set-Cookie' header built with untrusted input (cookie poisoning)",
                        ))

        return hits

    def _detector_iterator_without_materialize(self, tree: ast.AST) -> List[Tuple[int, str]]:
        hits: List[Tuple[int, str]] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func_name = self._get_call_name(node.func)
            if func_name in {"any", "all"} and node.args and isinstance(node.args[0], ast.ListComp):
                hits.append((node.lineno, "any/all with a materialized list comprehension"))
            if func_name in {"set", "list", "dict"} and node.args:
                if isinstance(node.args[0], (ast.ListComp, ast.SetComp, ast.DictComp)):
                    hits.append((node.lineno, f"{func_name}() materializes comprehension"))
        return hits

    def _detector_empty_sequences_false(self, tree: ast.AST) -> List[Tuple[int, str]]:
        hits: List[Tuple[int, str]] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.If, ast.While)):
                continue
            test = node.test
            if isinstance(test, ast.Call) and self._get_call_name(test.func) == "len":
                hits.append((node.lineno, "Use of len(seq) as a condition"))
            if (
                isinstance(test, ast.UnaryOp)
                and isinstance(test.op, ast.Not)
                and isinstance(test.operand, ast.Call)
                and self._get_call_name(test.operand.func) == "len"
            ):
                hits.append((node.lineno, "Use of not len(seq) as a condition"))
        return hits

    def _detector_dict_literal_in_loop(self, tree: ast.AST) -> List[Tuple[int, str]]:
        hits: List[Tuple[int, str]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and self._get_call_name(node.func) == "dict" and self._inside_loop(node):
                hits.append((node.lineno, "dict() inside a loop"))
        return hits

    def _detector_method_of_instance_without_self(self, tree: ast.AST) -> List[Tuple[int, str]]:
        hits: List[Tuple[int, str]] = []
        for class_node in ast.walk(tree):
            if not isinstance(class_node, ast.ClassDef):
                continue
            for item in class_node.body:
                if not isinstance(item, ast.FunctionDef) or not item.args.args:
                    continue
                first_arg = item.args.args[0].arg
                if first_arg != "self":
                    continue
                if any(isinstance(dec, ast.Name) and dec.id in {"staticmethod", "classmethod"} for dec in item.decorator_list):
                    continue
                if not self._arg_is_used(item, first_arg):
                    hits.append((item.lineno, f"Method '{item.name}' does not use self"))
        return hits

    @staticmethod
    def _arg_is_used(func_node: ast.FunctionDef, arg_name: str) -> bool:
        for node in ast.walk(func_node):
            if isinstance(node, ast.Name) and node.id == arg_name and isinstance(node.ctx, ast.Load):
                return True
        return False

    def _detector_not_using_items(self, tree: ast.AST) -> List[Tuple[int, str]]:
        hits: List[Tuple[int, str]] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.For):
                continue
            if not isinstance(node.target, ast.Name) or not isinstance(node.iter, ast.Name):
                continue
            key_name = node.target.id
            dict_name = node.iter.id
            for sub in ast.walk(node):
                if isinstance(sub, ast.Subscript) and isinstance(sub.value, ast.Name) and sub.value.id == dict_name:
                    if isinstance(sub.slice, ast.Name) and sub.slice.id == key_name:
                        hits.append((node.lineno, "Dict iteration without .items()"))
                        break
        return hits

    def _detector_not_using_zip(self, tree: ast.AST) -> List[Tuple[int, str]]:
        hits: List[Tuple[int, str]] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.For) or not isinstance(node.iter, ast.Call):
                continue
            if self._get_call_name(node.iter.func) != "range" or not node.iter.args:
                continue
            first = node.iter.args[0]
            if isinstance(first, ast.Call) and self._get_call_name(first.func) == "len":
                hits.append((node.lineno, "range(len(...)) to iterate lists in parallel instead of zip()"))
        return hits

    def _detector_concatenation_extends_list(self, tree: ast.AST) -> List[Tuple[int, str]]:
        hits: List[Tuple[int, str]] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if not isinstance(target, ast.Name):
                continue
            if not isinstance(node.value, ast.BinOp) or not isinstance(node.value.op, ast.Add):
                continue
            if isinstance(node.value.left, ast.Name) and node.value.left.id == target.id:
                hits.append((node.lineno, "Concatenation to extend a list"))
        return hits

    def _detector_paths_hardcoded_connections(self, tree: ast.AST) -> List[Tuple[int, str]]:
        hits: List[Tuple[int, str]] = []
        for literal, line in self._iter_string_literals(tree):
            text = literal.strip()
            if not self._is_literal_relevant(text):
                continue
            if URL_PATTERN.search(text):
                continue
            for pattern in FS_PATH_HARDCODED_PATTERNS:
                match = pattern.search(text)
                if not match:
                    continue
                candidate = match.group(0)
                if len(candidate) < 4:
                    continue
                hits.append((line, f"hardcoded path detected: {candidate}"))
                break
        return hits

    def _detector_hardcoded_ips_traceability(self, tree: ast.AST) -> List[Tuple[int, str]]:
        hits: List[Tuple[int, str]] = []
        for literal, line in self._iter_string_literals(tree):
            text = literal.strip()
            if not self._is_literal_relevant(text):
                continue
            if URL_PATTERN.search(text):
                continue
            match = IPV4_HARDCODED_PATTERN.search(text)
            if not match:
                continue
            hits.append((line, f"hardcoded IP detected: {match.group(0)}"))
        return hits

    # Pattern that indicates SQL built with concatenation/f-string and a user variable.
    _SQL_KEYWORDS_RE = re.compile(
        r"(?i)\b(select|insert|update|delete|drop|alter|create|exec|execute)\b"
    )

    def _detector_sql_no_neutralized(
        self, tree: ast.AST
    ) -> List[Tuple[int, str]]:
        """Detects SQL built by concatenating strings with variables."""
        hits: List[Tuple[int, str]] = []
        for node in ast.walk(tree):
            # Case 1: BinOp str + variable (concatenation)
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                if self._binop_sql_with_variable(node):
                    hits.append((
                        node.lineno,
                        "SQL built by concatenating an unvalidated variable",
                    ))
            # Case 2: f-string with an expression and an SQL keyword
            elif isinstance(node, ast.JoinedStr) and node.values:
                has_sql = any(
                    isinstance(v, ast.Constant)
                    and isinstance(v.value, str)
                    and self._SQL_KEYWORDS_RE.search(v.value)
                    for v in node.values
                )
                has_variable = any(
                    isinstance(v, ast.FormattedValue)
                    for v in node.values
                )
                if has_sql and has_variable:
                    hits.append((
                        node.lineno,
                        "SQL built with an f-string and an unvalidated variable",
                    ))
        return hits

    def _detector_redos_regex_malicious(self, tree: ast.AST) -> List[Tuple[int, str]]:
        """Detects possible ReDoS risks from malicious or untrusted regexes."""
        hits: List[Tuple[int, str]] = []
        functions_re = {"compile", "search", "match", "fullmatch", "findall", "finditer", "sub", "subn"}

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            attr = self._get_attr_call(node.func)
            if not attr:
                continue

            module, method = attr
            if module != "re" or method not in functions_re:
                continue

            if not node.args and not node.keywords:
                continue

            scope = self._get_enclosing_scope(node)
            pattern_expr: Optional[ast.AST] = node.args[0] if node.args else None
            if pattern_expr is None:
                for kw in node.keywords:
                    if kw.arg == "pattern":
                        pattern_expr = kw.value
                        break
            if pattern_expr is None:
                continue

            evidence = self._evaluate_expression_regex_redos(
                pattern_expr,
                scope=scope,
                before_lineno=getattr(node, "lineno", 0),
            )
            if evidence:
                hits.append((node.lineno, f"{method} uses {evidence}"))

        return hits

    def _evaluate_expression_regex_redos(
        self,
        expr: ast.AST,
        scope: ast.AST,
        before_lineno: int,
        resolving: Optional[Set[str]] = None,
    ) -> Optional[str]:
        if resolving is None:
            resolving = set()

        if expr is None:
            return None

        if self._expr_is_untrusted_source(expr):
            return "regex pattern built from untrusted input"

        if isinstance(expr, ast.Name):
            if expr.id in resolving:
                return None
            resolving.add(expr.id)
            assignment = self._resolve_last_assignment_name(scope, expr.id, before_lineno)
            if assignment is None:
                return None
            return self._evaluate_expression_regex_redos(assignment, scope, before_lineno, resolving)

        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            if self._regex_seems_redos(expr.value):
                pattern = expr.value.strip()
                if len(pattern) > 60:
                    pattern = pattern[:57] + "..."
                return f"pattern potentially vulnerable to backtracking: {pattern!r}"
            return None

        if isinstance(expr, ast.JoinedStr):
            if any(
                self._expr_is_untrusted_source(v.value)
                for v in expr.values
                if isinstance(v, ast.FormattedValue)
            ):
                return "dynamic regex pattern (f-string) with untrusted input"
            return None

        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            if self._expr_is_untrusted_source(expr.left) or self._expr_is_untrusted_source(expr.right):
                return "dynamic regex pattern built by concatenation with untrusted input"
            left = self._evaluate_expression_regex_redos(expr.left, scope, before_lineno, resolving)
            if left:
                return left
            return self._evaluate_expression_regex_redos(expr.right, scope, before_lineno, resolving)

        return None

    @staticmethod
    def _regex_seems_redos(pattern: str) -> bool:
        text = pattern.strip()
        if not text:
            return False
        return any(hint.search(text) for hint in REDOS_RISKY_PATTERNS)


    def _detector_nosql_no_neutralized(
        self, tree: ast.AST
    ) -> List[Tuple[int, str]]:
        """Detects NoSQL queries built with untrusted input."""
        hits: List[Tuple[int, str]] = []
        methods_query = {
            "find",
            "find_one",
            "count_documents",
            "delete_one",
            "delete_many",
            "replace_one",
            "update_one",
            "update_many",
            "aggregate",
        }

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue

            method = node.func.attr
            if method not in methods_query:
                continue

            scope = self._get_enclosing_scope(node)
            for arg in list(node.args) + [kw.value for kw in node.keywords if kw.arg != "session"]:
                evidence = self._analyze_expression_nosql(
                    arg,
                    scope=scope,
                    before_lineno=getattr(node, "lineno", 0),
                )
                if evidence:
                    hits.append((node.lineno, f"NoSQL query in '{method}' with {evidence}"))
                    break

        return hits

    def _analyze_expression_nosql(
        self,
        expr: ast.AST,
        scope: ast.AST,
        before_lineno: int,
        resolving: Optional[Set[str]] = None,
    ) -> Optional[str]:
        if resolving is None:
            resolving = set()

        if expr is None:
            return None

        if self._expr_is_untrusted_source(expr):
            return "direct untrusted input"

        if isinstance(expr, ast.Name):
            if expr.id in resolving:
                return None
            resolving.add(expr.id)
            assignment = self._resolve_last_assignment_name(scope, expr.id, before_lineno)
            if assignment is None:
                return None
            return self._analyze_expression_nosql(assignment, scope, before_lineno, resolving)

        if isinstance(expr, ast.Dict):
            for key_node, value_node in zip(expr.keys, expr.values):
                key_text = self._get_constant_str(key_node) if key_node is not None else None
                if key_text == "$where":
                    if isinstance(value_node, (ast.JoinedStr, ast.BinOp)):
                        return "dynamic use of the $where operator"
                    if self._expr_is_untrusted_source(value_node):
                        return "$where operator with untrusted input"
                evidence = self._analyze_expression_nosql(value_node, scope, before_lineno, resolving)
                if evidence:
                    if key_text:
                        return f"untrusted value in filter '{key_text}'"
                    return evidence
            return None

        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            for item in expr.elts:
                evidence = self._analyze_expression_nosql(item, scope, before_lineno, resolving)
                if evidence:
                    return evidence
            return None

        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            if self._expr_is_untrusted_source(expr.left) or self._expr_is_untrusted_source(expr.right):
                return "concatenation with untrusted input"
            left = self._analyze_expression_nosql(expr.left, scope, before_lineno, resolving)
            if left:
                return left
            return self._analyze_expression_nosql(expr.right, scope, before_lineno, resolving)

        if isinstance(expr, ast.JoinedStr):
            if any(self._expr_is_untrusted_source(value.value) for value in expr.values if isinstance(value, ast.FormattedValue)):
                return "f-string with untrusted input"
            return None

        if isinstance(expr, ast.Call):
            if self._expr_is_untrusted_source(expr):
                return "call with untrusted input"
            for arg in expr.args:
                evidence = self._analyze_expression_nosql(arg, scope, before_lineno, resolving)
                if evidence:
                    return evidence
            for kw in expr.keywords:
                evidence = self._analyze_expression_nosql(kw.value, scope, before_lineno, resolving)
                if evidence:
                    return evidence
            return None

        return None

    def _binop_sql_with_variable(self, node: ast.BinOp) -> bool:
        """Checks whether a concatenation has an SQL keyword and a variable somewhere."""
        parts_str: List[str] = []
        has_variable = False
        stack = [node.left, node.right]
        while stack:
            part = stack.pop()
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                parts_str.append(part.value)
            elif isinstance(part, ast.BinOp) and isinstance(part.op, ast.Add):
                stack.extend([part.left, part.right])
            elif isinstance(part, (ast.Name, ast.Attribute, ast.Subscript, ast.Call)):
                has_variable = True
        return has_variable and any(
            self._SQL_KEYWORDS_RE.search(s) for s in parts_str
        )

    def _parse_python_with_recovery(
        self,
        code: str,
        origin: str,
        max_attempts: int = 8,
    ) -> Tuple[Optional[ast.AST], Optional[SyntaxError], bool]:
        """Tries to recover a partial AST by neutralizing syntactically invalid blocks."""
        try:
            return ast.parse(code, filename=origin), None, False
        except SyntaxError as exc:
            last_error = exc

        lines = code.splitlines()
        work = list(lines)
        recovered = False

        for _ in range(max_attempts):
            line_error = int(getattr(last_error, "lineno", 0) or 0)
            if line_error <= 0 or line_error > len(work):
                break

            start, end = self._range_block_to_neutralize(work, line_error - 1)
            if start >= end:
                break

            for idx in range(start, end):
                work[idx] = ""

            recovered = True
            try:
                return ast.parse("\n".join(work), filename=origin), last_error, True
            except SyntaxError as exc:
                last_error = exc

        return None, last_error, recovered

    @staticmethod
    def _range_block_to_neutralize(
        lines: List[str],
        index: int,
    ) -> Tuple[int, int]:
        """Computes a contiguous block to neutralize from a line with a SyntaxError."""
        total = len(lines)
        if not (0 <= index < total):
            return index, index

        line = lines[index]
        indent_base = len(line) - len(line.lstrip(" \t"))
        end = index + 1

        while end < total:
            current = lines[end]
            stripped = current.strip()
            if not stripped:
                end += 1
                continue
            indent_current = len(current) - len(current.lstrip(" \t"))
            if indent_current <= indent_base:
                break
            end += 1

        return index, end

    @staticmethod
    def _detector_code_duplicate_traceability(tree: ast.AST) -> List[Dict[str, Any]]:
        """Detects functions with identical bodies (potential code duplication)."""
        signatures: Dict[Tuple[str, ...], List[ast.AST]] = {}

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not node.body:
                continue

            signature = tuple(
                ast.dump(stmt, annotate_fields=True, include_attributes=False)
                for stmt in node.body
            )
            if not signature:
                continue

            signatures.setdefault(signature, []).append(node)

        findings: List[Dict[str, Any]] = []
        for nodes in signatures.values():
            if len(nodes) < 2:
                continue

            functions = [getattr(n, "name", "<anonymous>") for n in nodes]
            lines = [int(getattr(n, "lineno", 0) or 0) for n in nodes]

            # Uses the second occurrence as the reported line for the duplicate.
            findings.append({
                "line": lines[1] if len(lines) > 1 else lines[0],
                "functions": functions,
                "lines": lines,
            })

        return findings

    def _resolve_local_imports(self, code: str, module_path: Path, root_dir: Path) -> List[Path]:
        try:
            tree = ast.parse(code, filename=str(module_path))
        except SyntaxError:
            return []

        found: List[Path] = []
        seen: Set[Path] = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    candidate = self._resolve_import_absolute(alias.name, module_path, root_dir)
                    if candidate and candidate not in seen:
                        seen.add(candidate)
                        found.append(candidate)

            elif isinstance(node, ast.ImportFrom):
                candidates = self._resolve_import_from(node, module_path, root_dir)
                for candidate in candidates:
                    if candidate not in seen:
                        seen.add(candidate)
                        found.append(candidate)

        return found

    def _resolve_import_absolute(self, module_name: str, module_path: Path, root_dir: Path) -> Optional[Path]:
        for base_dir in self._iter_bases_resolution_import(module_path, root_dir):
            candidate = self._resolve_module_in_base(module_name, base_dir)
            if candidate:
                return candidate
        return None

    def _resolve_import_from(self, node: ast.ImportFrom, module_path: Path, root_dir: Path) -> List[Path]:
        candidates: List[Path] = []
        base_directories = self._iter_bases_resolution_import(module_path, root_dir)
        base_dir = base_directories[0] if base_directories else root_dir

        if node.level:
            base_dir = module_path.parent
            for _ in range(max(0, node.level - 1)):
                base_dir = base_dir.parent

        if node.module:
            if node.level:
                bases_module = [base_dir]
            else:
                bases_module = base_directories
            for base in bases_module:
                candidate = self._resolve_module_in_base(node.module, base)
                if candidate and candidate not in candidates:
                    candidates.append(candidate)
                    break

        # Also try to resolve submodules imported from the package.
        # Example: from pkg import submod
        prefix = f"{node.module}." if node.module else ""
        for alias in node.names:
            if alias.name == "*":
                continue
            if node.level:
                bases_alias = [base_dir]
            else:
                bases_alias = base_directories
            for base in bases_alias:
                candidate = self._resolve_module_in_base(f"{prefix}{alias.name}", base)
                if candidate and candidate not in candidates:
                    candidates.append(candidate)
                    break

        return candidates

    @staticmethod
    def _iter_bases_resolution_import(module_path: Path, root_dir: Path) -> List[Path]:
        """Candidate bases for resolving local absolute imports."""
        bases: List[Path] = []
        seen: Set[Path] = set()

        current = module_path.parent.resolve()
        root_resolved = root_dir.resolve()

        while True:
            if current not in seen:
                bases.append(current)
                seen.add(current)
            if current == root_resolved:
                break
            if current.parent == current:
                break
            current = current.parent

        if root_resolved not in seen:
            bases.append(root_resolved)

        return bases

    @staticmethod
    def _list_declared_imports(code: str) -> List[str]:
        """Extracts the imports declared in the module for logging traceability."""
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return []

        declared: List[str] = []
        seen: Set[str] = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.name
                    if name not in seen:
                        seen.add(name)
                        declared.append(name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                prefix = "." * int(getattr(node, "level", 0) or 0)
                for alias in node.names:
                    if alias.name == "*":
                        name = f"{prefix}{module}.*" if module else f"{prefix}*"
                    elif module:
                        name = f"{prefix}{module}.{alias.name}"
                    else:
                        name = f"{prefix}{alias.name}"
                    if name not in seen:
                        seen.add(name)
                        declared.append(name)

        return declared

    def _resolve_module_in_base(self, module_name: str, base_dir: Path) -> Optional[Path]:
        relative_parts = [part for part in module_name.split(".") if part]
        if not relative_parts:
            return None

        module_file = base_dir.joinpath(*relative_parts).with_suffix(".py")
        package_init = base_dir.joinpath(*relative_parts, "__init__.py")

        for candidate in (module_file, package_init):
            if candidate.exists() and candidate.is_file() and self._is_importable_local(candidate):
                return candidate.resolve()
        return None

    @staticmethod
    def _is_inside_root(path: Path, root_dir: Path) -> bool:
        try:
            path.resolve().relative_to(root_dir.resolve())
            return True
        except ValueError:
            return False

    @staticmethod
    def _format_module_origin(module_path: Path, root_dir: Path) -> str:
        try:
            return str(module_path.resolve().relative_to(root_dir.resolve()))
        except ValueError:
            return module_path.name

    @staticmethod
    def _is_importable_local(path: Path) -> bool:
        parts = {part.lower() for part in path.parts}
        if "site-packages" in parts or "dist-packages" in parts:
            return False
        return True

    # Search for suspicious strings in raw bytes (pyc / exe)
   
    def _analyze_pyc_with_priority(
        self,
        data: bytes,
        origin_metadata: str,
        source_name: str,
    ) -> List[Dict[str, Any]]:
        """
        Analyzes a .pyc payload, prioritizing binary metadata over recovered
        code.

        Rule:
          - If a finding appears both in binary metadata and in recovered code,
            the binary metadata one is kept.
          - Recovered code only contributes findings with no equivalent in the
            metadata, since its reconstruction may be inaccurate or may pull in
            imports that do not belong to the original files.
        """
        recovered_findings: List[Dict[str, Any]] = []
        metadata_findings = self._search_patterns_en_bytes(data, origin=origin_metadata)
        recovered_code = self._recover_source_from_pyc_bytes(data, source_name)

        if recovered_code:
            recovered_origin = f"{origin_metadata}.recovered"
            recovered_findings = self._analyze_code_python(
                recovered_code,
                origin=recovered_origin,
                is_main_module="__main__" in source_name.lower() or "main" in source_name.lower(),
            )
            for finding in recovered_findings:
                finding.setdefault("source_evidence", "code_recovered")

        for finding in metadata_findings:
            finding.setdefault("source_evidence", "metadata_binary")

        if not recovered_findings:
            return metadata_findings

        merged = list(metadata_findings)
        for recovered_finding in recovered_findings:
            if not self._is_duplicate_of_recovered(recovered_finding, metadata_findings):
                merged.append(recovered_finding)

        return merged

    @staticmethod
    def _recover_source_from_pyc_bytes(data: bytes, source_name: str) -> Optional[str]:
        """Tries to recover pseudocode from .pyc/marshal bytes without failing."""
        payload_candidates: List[bytes] = []
        if len(data) > 16:
            payload_candidates.append(data[16:])
        if len(data) > 12:
            payload_candidates.append(data[12:])
        payload_candidates.append(data)

        code_obj: Optional[types.CodeType] = None
        for payload in payload_candidates:
            try:
                loaded = marshal.loads(payload)
            except Exception:  # noqa: BLE001
                continue
            if isinstance(loaded, types.CodeType):
                code_obj = loaded
                break

        if code_obj is None:
            return None

        try:
            from lefiru.core.analyzers.python.python_bytecode import recover_source

            recovered = recover_source(code_obj, source_name)
            if isinstance(recovered, str) and recovered.strip():
                return recovered
        except Exception:  # noqa: BLE001
            return None
        return None

    def _is_duplicate_of_recovered(
        self,
        finding: Dict[str, Any],
        reference_findings: List[Dict[str, Any]],
    ) -> bool:
        """Determines whether a finding is already covered by another evidence source.

        Compares the category and the primary token against `reference_findings`
        to avoid duplicates regardless of which source has priority.
        """
        finding_category = str(finding.get("category", "")).lower()
        finding_token = self._extract_primary_token(finding)
        if not finding_token:
            return False

        for reference in reference_findings:
            ref_category = str(reference.get("category", "")).lower()
            if ref_category != finding_category:
                continue
            ref_token = self._extract_primary_token(reference)
            if not ref_token:
                continue
            if finding_token == ref_token:
                return True
            if finding_token in ref_token or ref_token in finding_token:
                return True
        return False

    @staticmethod
    def _extract_primary_token(finding: Dict[str, Any]) -> str:
        """Extracts a comparable token between code and metadata findings."""
        raw = finding.get("value")
        if raw is None:
            raw = finding.get("variable")
        if raw is None:
            raw = finding.get("type")
        text = str(raw).strip().strip("\"'").lower()
        if not text:
            return ""

        # Normalizes "key=value" and "key: value" forms to compare by value.
        key_value = re.split(r"[:=]", text, maxsplit=1)
        if len(key_value) == 2:
            right = key_value[1].strip()
            if right:
                return right.strip("\"'")
        return text

    def _search_patterns_en_bytes(self, data: bytes, origin: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for pattern, type, sev in EXE_STRING_PATTERNS:
            for m in pattern.finditer(data):
                try:
                    value = m.group(0).decode("utf-8", errors="replace")
                except Exception:  # noqa: BLE001
                    value = repr(m.group(0))
                findings.append({
                    "type": type,
                    "category": "credentials" if "credential" in type else "connections",
                    "severity": sev,
                    "origin": origin,
                    "line": 0,
                    "offset": m.start(),
                    "value": value,
                    "description": f"Suspicious string found in binary ({type})",
                })
                if len(findings) >= self.MAX_BINARY_FINDINGS:
                    return findings
        return findings

    def _scan_executable_binary(self, origin: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Scans the executable as a binary and returns findings + scan metadata."""
        meta: Dict[str, Any] = {
            "status": "error",
            "bytes": 0,
            "bytes_scanned": 0,
            "truncated": False,
            "findings": 0,
        }

        try:
            size = self.file_path.stat().st_size
            meta["bytes"] = size
            read_size = min(size, self.MAX_BINARY_SCAN_BYTES)
            meta["bytes_scanned"] = read_size
            meta["truncated"] = size > self.MAX_BINARY_SCAN_BYTES
            with open(self.file_path, "rb") as fh:
                data = fh.read(read_size)
            findings = self._search_patterns_en_bytes(data, origin=origin)
            meta["findings"] = len(findings)
            meta["status"] = "ok"
            return findings, meta
        except OSError as exc:
            meta["error"] = str(exc)
            return [], meta

    def _filter_metadata_findings_prefer_existing_code(
        self,
        metadata_findings: List[Dict[str, Any]],
        existing_findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Avoids metadata duplicates when equivalent evidence already exists in code."""
        if not metadata_findings:
            return []

        filtered: List[Dict[str, Any]] = []
        for finding in metadata_findings:
            finding.setdefault("source_evidence", "metadata_binary")
            if not self._is_duplicate_of_recovered(finding, existing_findings):
                filtered.append(finding)
        return filtered

    # ──────────────────────────────────────────────────────────────────────
    # Helpers AST
    # ──────────────────────────────────────────────────────────────────────
    @staticmethod
    def _get_call_name(node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        return None

    @staticmethod
    def _get_attr_call(node: ast.AST) -> Optional[Tuple[str, str]]:
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            return (node.value.id, node.attr)
        return None

    @staticmethod
    def _has_shell_true(call: ast.Call) -> bool:
        for kw in call.keywords:
            if kw.arg == "shell":
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    return True
        return False

    @staticmethod
    def _get_target_name(node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return None

    @staticmethod
    def _get_constant_str(node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    @staticmethod
    def _is_probable_credential_value(name: str, value: Optional[str]) -> bool:
        if not value:
            return False
        text = value.strip()
        if not text:
            return False
        if text.lower() in BENIGN_SECRET_LITERALS:
            return False

        name_lower = name.lower()
        if "email" in name_lower or "email" in name_lower or "mail" in name_lower:
            return False

        # Avoid false positives on state variables, e.g. bypass_status = "VULNERABLE"
        tokens = PythonCodeInspector._tokenize_name(name)
        if tokens & NON_CREDENTIAL_CONTEXT_TOKENS:
            if text.lower() in NON_SECRET_STATUS_VALUES:
                return False

        if len(text) < 4 and not any(char.isdigit() for char in text):
            return False
        return True

    @staticmethod
    def _tokenize_name(name: str) -> Set[str]:
        parts = re.split(r"[^A-Za-z0-9]+", name)
        tokens: Set[str] = set()
        for part in parts:
            if not part:
                continue
            # Splits camelCase/PascalCase to improve semantic precision.
            fragments = re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)|\d+", part)
            if fragments:
                tokens.update(f.lower() for f in fragments if f)
            else:
                tokens.add(part.lower())
        return tokens

    @staticmethod
    def _is_literal_relevant(literal: str) -> bool:
        text = literal.strip()
        return bool(text) and len(text) >= 4

    @staticmethod
    def _seems_connection_string(literal: str) -> bool:
        if "\n" in literal or "\r" in literal:
            return False
        clues = sum(1 for pat in CONNECTION_STRING_HINTS if pat.search(literal))
        return clues >= 2

    @staticmethod
    def _seems_path_file(literal: str) -> bool:
        """Detects file paths to avoid secret false positives."""
        text = literal.strip()
        if not text:
            return False

        if URL_PATTERN.search(text) or UNC_PATTERN.search(text):
            return True

        # Typical absolute paths (Windows/POSIX) using the existing patterns.
        for pattern in FS_PATH_HARDCODED_PATTERNS:
            if pattern.search(text):
                return True

        # Common relative paths: folder/subfolder/file.
        if re.match(r"^[A-Za-z0-9_.-]+(?:[\\/][A-Za-z0-9_.-]+){1,}[\\/]?$", text):
            return True

        return False

    @staticmethod
    def _seems_secret_by_shape(literal: str) -> bool:
        text = literal.strip()
        if text.lower() in BENIGN_SECRET_LITERALS:
            return False
        if PythonCodeInspector._seems_path_file(text):
            return False
        return any(pat.match(text) for pat in HIGH_ENTROPY_HINTS)

    @staticmethod
    def _iter_string_literals(tree: ast.AST) -> List[Tuple[str, int]]:
        literal: List[Tuple[str, int]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if PythonCodeInspector._is_docstring_literal(node):
                    continue
                literal.append((node.value, getattr(node, "lineno", 0)))
        return literal

    @staticmethod
    def _is_docstring_literal(node: ast.Constant) -> bool:
        return isinstance(getattr(node, "parent", None), ast.Expr)

    @staticmethod
    def _annotate_parents(tree: ast.AST) -> None:
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                setattr(child, "parent", parent)

    @staticmethod
    def _is_main_guard(node: ast.If) -> bool:
        test = node.test
        if not isinstance(test, ast.Compare):
            return False
        if not (isinstance(test.left, ast.Name) and test.left.id == "__name__"):
            return False
        for comp in test.comparators:
            if isinstance(comp, ast.Constant) and comp.value == "__main__":
                return True
        return False

    @staticmethod
    def _is_credential_name(name: str) -> bool:
        tokens = PythonCodeInspector._tokenize_name(name)
        if not tokens:
            return False

        # Direct token match to avoid misleading substrings (pass inside bypass).
        if tokens & CREDENTIAL_VAR_KEYWORDS:
            return True

        # Compounds: *_key when the context is cryptographic
        # (signing_key, rsa_key, public_key, encrypt_key, etc.)
        if "key" in tokens and (tokens & _CRYPTO_KEY_CONTEXT):
            return True

        # Common compound cases without a specific crypto context
        if "api" in tokens and "key" in tokens:
            return True
        if "auth" in tokens and "key" in tokens:
            return True

        return False

    # ──────────────────────────────────────────────────────────────────────
    # Result consolidation
    # ──────────────────────────────────────────────────────────────────────
    @staticmethod
    def _consolidate_summary(
        result: Dict[str, Any],
        rules_implemented: List[Dict[str, str]],
    ) -> None:
        summary = result["summary"]
        for h in result["findings"]:
            sev = h.get("severity", "low")
            if sev == "critical":
                summary["critical"] += 1
            elif sev == "medium":
                summary["medium"] += 1
            else:
                summary["low"] += 1
            cat = h.get("category", "others")
            summary["by_category"][cat] = summary["by_category"].get(cat, 0) + 1

        duplicates = [
            h for h in result.get("findings", [])
            if h.get("type") == "duplicated_code"
        ]
        result.setdefault("metadata", {})
        result["metadata"].setdefault("traceability", {})
        result["metadata"]["traceability"]["duplicated_code"] = {
            "total": len(duplicates),
            "findings": [
                {
                    "origin": h.get("origin"),
                    "line": h.get("line"),
                    "functions": h.get("functions", []),
                    "lines_duplicates": h.get("lines_duplicates", []),
                }
                for h in duplicates
            ],
        }

        rule_findings = [
            h for h in result.get("findings", [])
            if h.get("type") == "rule_analysis"
        ]
        result["metadata"]["rules_analysis"] = {
            "source": "internal_engine",
            "identifier": "[analysis]",
            "rules": [
                {
                    "name": rule.get("name"),
                    "category": rule.get("category"),
                    "priority": rule.get("priority"),
                }
                for rule in rules_implemented
            ],
            "total_rules": len(rules_implemented),
            "total_findings": len(rule_findings),
            "findings": [
                {
                    "rule": h.get("rule_name"),
                    "category": h.get("category"),
                    "severity": h.get("severity"),
                    "line": h.get("line"),
                    "origin": h.get("origin"),
                    "identifier": h.get("identifier", "[analysis]"),
                }
                for h in rule_findings
            ],
        }

        total = summary["critical"] + summary["medium"] + summary["low"]
        if total == 0:
            result["status"] = "COMPLIANT"
            result["detail"] = "No security findings were detected"
        elif summary["critical"] > 0:
            result["status"] = "VULNERABLE"
            result["detail"] = (
                f"Detected {summary['critical']} critical finding(s) "
                f"and {summary['medium']} medium"
            )
        else:
            result["status"] = "REQUIRES_REVIEW"
            result["detail"] = (
                f"Detected {summary['medium']} medium finding(s) "
                f"and {summary['low']} low"
            )

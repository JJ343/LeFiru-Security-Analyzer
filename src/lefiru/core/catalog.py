"""Catalog of analysis tests and checks.

Single source of truth for:

- which tests exist (``TESTS_AVAILABLE``),
- which checks each one covers (``TESTS_BY_TEST``),
- which tests apply to each extension (``TESTS_BY_EXTENSION``).

It is consumed by the orchestrator, the CLI and the graphical interface. The keys of
``TESTS`` are public report API: do not rename them without a migration note.
"""

# Extensions analyzed with PythonCodeInspector instead of the Excel pipeline
PYTHON_EXTENSIONS = {".py", ".pyc", ".exe"}

# Excel container families. The suffix decides the set of tests, not the
# analyzer: OOXML families are read the same way (ZIP + XML) and .xlsb is separate.
EXCEL_WITHOUT_MACROS = frozenset({".xlsx", ".xltx"})                 # workbooks and templates
EXCEL_WITH_MACROS = frozenset({".xlsm", ".xltm", ".xlam"})        # macros / add-ins
EXCEL_BINARY = frozenset({".xlsb"})
EXCEL_OOXML = EXCEL_WITHOUT_MACROS | EXCEL_WITH_MACROS
EXCEL_EXTENSIONS = EXCEL_OOXML | EXCEL_BINARY

# BIFF8 family (.xls/.xlt/.xla): the password detector already recognizes it, but
# there is still no static analyzer, so it stays outside EXCEL_EXTENSIONS.
EXCEL_LEGACY = frozenset({".xls", ".xlt", ".xla"})


EXCEL_TESTS_AVAILABLE = {
    "protections": {
        "label": "Workbook and sheet protections",
        "order": 1,
        "dependencies": [],
    },
    "vba": {
        "label": "VBA project analysis",
        "order": 2,
        "dependencies": [],
    },
    "patterns": {
        "label": "Insecure patterns in code",
        "order": 3,
        "dependencies": ["vba"],
    },
    "connections": {
        "label": "External connections",
        "order": 4,
        "dependencies": [],
    },
    "formulas": {
        "label": "Critical formula analysis",
        "order": 6,
        "dependencies": [],
    },
    "password": {
        "label": "Opening password",
        "order": 7,
        "dependencies": [],
    },
}

PYTHON_TESTS_AVAILABLE = {
    "python_dynamic_execution": {
        "label": "Dynamic execution (eval/exec)",
        "order": 10,
        "dependencies": [],
    },
    "python_dangerous_commands": {
        "label": "Dangerous commands (os/subprocess)",
        "order": 11,
        "dependencies": [],
    },
    "python_deserialization": {
        "label": "Insecure deserialization",
        "order": 12,
        "dependencies": [],
    },
    "python_credentials": {
        "label": "Hardcoded credentials/secrets",
        "order": 13,
        "dependencies": [],
    },
    "python_connections": {
        "label": "Hardcoded external connections",
        "order": 14,
        "dependencies": [],
    },
    "python_traceability": {
        "label": "Traceability/logging",
        "order": 15,
        "dependencies": [],
    },
}

# Compatibility alias to run all Python tests from the CLI.
PYTHON_TESTS_ALIAS = {
    "python_analysis": {
        "label": "Python: full analysis (ALL alias)",
        "order": 16,
        "dependencies": [],
    },
}

TESTS_AVAILABLE = {
    **EXCEL_TESTS_AVAILABLE,
    **PYTHON_TESTS_AVAILABLE,
    **PYTHON_TESTS_ALIAS,
}


#: Report sections. The key is stable and carries no numbering.
TESTS = {
    # Excel
    "structure_protection": "Workbook structure protection",
    "critical_sheets_protection": "Critical sheet protection",
    "vba": "VBA code protection",
    "insecure_patterns": "Insecure patterns in code",
    "external_connections": "External connection management",
    "formulas": "Critical formula integrity",
    "opening_bypass": "Resistance to opening bypass",
    "password_opening": "Opening password",
    # Python
    "dynamic_execution": "Absence of dynamic code execution",
    "dangerous_commands": "Absence of unsafe operating system invocation",
    "deserialization": "Absence of insecure deserialization",
    "credentials": "Absence of hardcoded credentials/secrets",
    "connections": "Absence of hardcoded external connections",
    "traceability": "Traceability through logging",
    "without_tests": "No applicable tests",
}


def test_name(key: str) -> str:
    """Readable name of a test; if the key does not exist, returns the key."""
    return TESTS.get(key, key)


TESTS_BY_TEST = {
    "protections": ["structure_protection", "critical_sheets_protection"],
    "vba": ["vba"],
    "patterns": ["insecure_patterns"],
    "connections": ["external_connections"],
    "formulas": ["formulas"],
    "password": ["password_opening"],
    "python_dynamic_execution": ["dynamic_execution"],
    "python_dangerous_commands": ["dangerous_commands"],
    "python_deserialization": ["deserialization"],
    "python_credentials": ["credentials"],
    "python_connections": ["connections"],
    "python_traceability": ["traceability"],
    "python_analysis": [
        "dynamic_execution",
        "dangerous_commands",
        "deserialization",
        "credentials",
        "connections",
        "traceability",
    ],
}

# Map of Python finding category -> test that backs it
PYTHON_CATEGORY_TO_TEST = {
    "dynamic_execution": ("dynamic_execution", TESTS["dynamic_execution"]),
    "dangerous_commands": ("dangerous_commands", TESTS["dangerous_commands"]),
    "deserialization": ("deserialization", TESTS["deserialization"]),
    "credentials": ("credentials", TESTS["credentials"]),
    "connections": ("connections", TESTS["connections"]),
    "traceability": ("traceability", TESTS["traceability"]),
}

PYTHON_TEST_TO_CATEGORIES = {
    "python_dynamic_execution": {"dynamic_execution"},
    "python_dangerous_commands": {"dangerous_commands"},
    "python_deserialization": {"deserialization"},
    "python_credentials": {"credentials"},
    "python_connections": {"connections"},
    "python_traceability": {"traceability"},
}

RULE_TO_CATEGORY_PY = {
    # Quality rules are routed to traceability.
    "use an iterator instead of materializing the list": "traceability",
    "empty sequences are false": "traceability",
    "use literals to initialize dictionaries": "traceability",
    "class methods not accessing instance fields must be static": "traceability",
    "not using items() to iterate over a dictionary": "traceability",
    "not using zip() to iterate over a pair of lists": "traceability",
    "do not use concatenation to extend lists": "traceability",
    "avoid sql code formed with non neutralized user input": "dangerous_commands",
    "hardcoded filesystem paths in code": "connections",
    "hardcoded ip addresses in code": "credentials",
}

PYTHON_INDIVIDUAL_TESTS = tuple(PYTHON_TESTS_AVAILABLE.keys())
EXCEL_INDIVIDUAL_TESTS = tuple(EXCEL_TESTS_AVAILABLE.keys())

_TESTS_EXCEL_WITHOUT_MACROS = {"protections", "connections", "formulas", "password"}
_TESTS_EXCEL_WITH_MACROS = _TESTS_EXCEL_WITHOUT_MACROS | {"vba", "patterns"}

TESTS_BY_EXTENSION = {
    **{ext: set(_TESTS_EXCEL_WITHOUT_MACROS) for ext in EXCEL_WITHOUT_MACROS},
    **{ext: set(_TESTS_EXCEL_WITH_MACROS) for ext in EXCEL_WITH_MACROS},
    **{ext: set(_TESTS_EXCEL_WITH_MACROS) for ext in EXCEL_BINARY},
    ".py":   set(PYTHON_INDIVIDUAL_TESTS),
    ".pyc":  set(PYTHON_INDIVIDUAL_TESTS),
    ".exe":  set(PYTHON_INDIVIDUAL_TESTS),
}

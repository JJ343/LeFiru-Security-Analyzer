# Tests

Each test in the catalog produces one or more **tests** with a stable key (without
numbering) and a human-readable name. The report JSON publishes `tests` as a
dictionary `key -> {name, status, detail}`, so adding a test does not
renumber the existing ones.

## Excel

| Test | Tests | What it evaluates |
|---|---|---|
| `protections` | structure_protection, critical_sheets_protection | Workbook and sheet protection, and whether it is bypassable |
| `vba` | vba | Existence, access and metadata of the VBA project |
| `patterns` | insecure_patterns | Insecure patterns in VBA code |
| `connections` | external_connections | External connections and data sources |
| `formulas` | formulas | Formula integrity and traceability in critical sheets |
| `password` | opening_bypass, password_opening | Structural bypass and opening password |

`password` is hidden in the GUI and only applies to encrypted files.

## Python

| Test | Test | What it evaluates |
|---|---|---|
| `python_dynamic_execution` | dynamic_execution | `eval`, `exec`, `compile` with untrusted data |
| `python_dangerous_commands` | dangerous_commands | `os.system`, `subprocess` with `shell=True` |
| `python_deserialization` | deserialization | `pickle`, `marshal`, insecure `yaml.load` |
| `python_credentials` | credentials | Hardcoded secrets and credentials |
| `python_connections` | connections | Hardcoded external connections |
| `python_traceability` | traceability | Traceability and logging |
| `python_analysis` | dynamic_execution, dangerous_commands, deserialization, credentials, connections, traceability | Alias of all of the above |

## States

| Status | Meaning | Exit code |
|---|---|---|
| `COMPLIANT` | No open findings | 0 |
| `VULNERABLE` | At least one critical test fails | 1 |
| `COMPLIANT_WITH_OBSERVATIONS` | Only low/medium severity findings | 2 |
| Fatal error | The analysis could not be completed | 99 |

`opening_bypass` is reserved for the structural opening bypass
(`XML_REMOVE_WORKBOOK_PASSWORD`, `BINARY_REMOVE_XLSB_PASSWORD`,
`EXTRACT_CONTENT_NO_PASSWORD`). Other password findings are reported as
`password_opening` and do not count as `opening_bypass`.

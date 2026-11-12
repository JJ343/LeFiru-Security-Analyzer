# Security policy

## Scope of use

`LeFiru Security Analyzer` is a **defensive analysis** tool. Some of its
tests are intrusive by design:

- opening password test (inference from metadata and dictionary),
- attempt at structural bypass of workbook protections,
- extraction and decompilation of Python bytecode.

Run it **only** on your own files or with the owner's written authorization.
Files may be modified temporarily during the tests; the system creates
copies in `backups/` and restores them when finished, but do not use it on originals without
a backup.



## Sensitive data

The project **does not** send telemetry or analysis data to any server. Logs
and reports are written only to the configured output folder. If
you attach evidence in an issue, anonymize paths, file names and credentials.

"""Excel analyzers: static, COM, formulas, VBA, passwords and bypass."""

from lefiru.core.analyzers.excel.openpyxl_compat import enable_extensions_openpyxl

# .xlam add-ins are valid OOXML; openpyxl only needs its accepted extension
# list to include them before reading the workbook.
enable_extensions_openpyxl()

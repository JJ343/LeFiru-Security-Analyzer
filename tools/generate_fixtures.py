"""
Test file generator for lefiru analyzer.

Includes cases for:
- Excel (.xlsx, .xlsm, .xltx, .xltm, .xlam)
- Python source/bytecode/synthetic binary (.py, .pyc, .exe)

Usage:
    python tools/generate_fixtures.py
    python tools/generate_fixtures.py --output-dir tests/fixtures/generated
    python tools/generate_fixtures.py --skip-com
"""

from __future__ import annotations

import argparse
import logging
import py_compile
import shutil
import sys
import tempfile
import textwrap
import zipfile
from pathlib import Path

import openpyxl
from openpyxl.styles import Protection

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = REPO_ROOT / "tests" / "fixtures" / "generated"

# Active directory. main() replaces it with --output-dir.
OUTPUT_DIR = DEFAULT_OUTPUT_DIR

logger = logging.getLogger(__name__)


def _create_excel():
    """Activate Excel with the same logic as the analyzer (CLSCTX per bitness).

    Does not use ``win32com.client.Dispatch("Excel.Application")``: that path can
    attach to an already-open Excel instance or end up in the WPS registry.
    """
    if str(REPO_ROOT / "src") not in sys.path:
        sys.path.insert(0, str(REPO_ROOT / "src"))

    from lefiru.core.analyzers.excel.com_runtime import (
        ComNotAvailableError,
        create_excel_application,
        plan_com,
    )

    plan = plan_com()
    if not plan.available:
        raise ComNotAvailableError(plan.reason)
    return create_excel_application()


def create_simple_xlsx():
    """Create a simple .xlsx file without macros or protections"""
    logger.info("Creating test_simple.xlsx...")
    
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Data"
    
    # Sample data
    ws['A1'] = "Product"
    ws['B1'] = "Quantity"
    ws['C1'] = "Price"
    ws['D1'] = "Total"
    
    ws['A2'] = "Product A"
    ws['B2'] = 10
    ws['C2'] = 25.50
    ws['D2'] = "=B2*C2"
    
    ws['A3'] = "Product B"
    ws['B3'] = 5
    ws['C3'] = 40.00
    ws['D3'] = "=B3*C3"
    
    # Save
    output_path = OUTPUT_DIR / "test_simple.xlsx"
    wb.save(output_path)
    logger.info(f"OK: Created: {output_path}")


def create_protected_xlsm():
    """Create an .xlsm file with protections (without real VBA due to limitations)"""
    logger.info("Creating test_protected.xlsm...")
    
    wb = openpyxl.Workbook()
    
    # INPUT sheet (unprotected for input)
    ws_input = wb.active
    ws_input.title = "INPUT"
    ws_input['A1'] = "Parameter"
    ws_input['B1'] = "Value"
    ws_input['A2'] = "Date"
    ws_input['B2'] = "2025-11-27"
    ws_input['A3'] = "Factor"
    ws_input['B3'] = 1.15
    
    # Protect but allow editing in B2:B3
    for row in ws_input['B2:B3']:
        for cell in row:
            cell.protection = Protection(locked=False)
    
    ws_input.protection.sheet = True
    ws_input.protection.password = "test123"
    
    # CALCULATION sheet (fully protected)
    ws_calc = wb.create_sheet("CALCULATION")
    ws_calc['A1'] = "Description"
    ws_calc['B1'] = "Result"
    ws_calc['A2'] = "Calculation 1"
    ws_calc['B2'] = "=INPUT!B3*100"
    ws_calc['A3'] = "Calculation 2"
    ws_calc['B3'] = "=B2*1.5"
    
    ws_calc.protection.sheet = True
    ws_calc.protection.password = "test123"
    
    # OUTPUT sheet (protected)
    ws_output = wb.create_sheet("OUTPUT")
    ws_output['A1'] = "Summary"
    ws_output['A2'] = "Total"
    ws_output['B2'] = "=CALCULATION!B3"
    
    ws_output.protection.sheet = True
    ws_output.protection.password = "test123"
    
    # Protect workbook structure
    wb.security.workbookPassword = "workbook123"
    wb.security.lockStructure = True
    
    # Save as .xlsm (even though it has no real VBA)
    output_path = OUTPUT_DIR / "test_protected.xlsm"
    wb.save(output_path)
    logger.info(f"OK: Created: {output_path}")
    logger.info("  Passwords: sheets='test123', workbook='workbook123'")


def create_template_xltx():
    """Create an .xltx template (OOXML without macros)"""
    logger.info("Creating test_template.xltx...")

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "INPUT"
    ws['A1'] = "Parameter"
    ws['B1'] = "Value"
    ws['A2'] = "Period"
    ws['B2'] = "2026"
    ws['A3'] = "Factor"
    ws['B3'] = 1.10
    ws['B4'] = "=B3*2"

    wb.template = True
    output_path = OUTPUT_DIR / "test_template.xltx"
    wb.save(output_path)
    logger.info(f"OK: Created: {output_path}")


def create_macro_templates():
    """Duplicate the protected .xlsm as a macro-enabled template and add-in.

    The OOXML container is the same; the suffix only changes the applicable
    test set, so these fixtures verify routing by extension and the
    renamed-file case.
    """
    logger.info("Creating test_template_macro.xltm and test_addin.xlam...")

    origin = OUTPUT_DIR / "test_protected.xlsm"
    if not origin.exists():
        create_protected_xlsm()

    for name in ("test_template_macro.xltm", "test_addin.xlam"):
        destination = OUTPUT_DIR / name
        shutil.copyfile(origin, destination)
        logger.info(f"OK: Created: {destination}")


def create_connections_xlsx():
    """Create a file with defined names that simulate external connections"""
    logger.info("Creating test_connections.xlsx...")
    
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Data"
    
    ws['A1'] = "ID"
    ws['B1'] = "Description"
    ws['A2'] = 1
    ws['B2'] = "Item 1"
    ws['A3'] = 2
    ws['B3'] = "Item 2"
    
    # Create defined names with (simulated) external references
    # Note: openpyxl has limitations for creating real connections
    # In production, these would be created manually in Excel
    
    from openpyxl.workbook.defined_name import DefinedName
    
    # Simulate an external reference (although it is not functional)
    defined_name = DefinedName(
        name="DataExternal",
        attr_text="'C:\\Lefiru\\[external_file.xlsx]Sheet1'!$A$1:$B$10"
    )
    wb.defined_names["DataExternal"] = defined_name
    
    # Add CONFIG sheet
    ws_config = wb.create_sheet("CONFIG")
    ws_config['A1'] = "Configuration"
    ws_config['B1'] = "Value"
    ws_config['A2'] = "Data path"
    ws_config['B2'] = "\\\\lefiru-server\\shared\\data"
    ws_config['A3'] = "Server"
    ws_config['B3'] = "LEFIRU-SQL"
    ws_config['A4'] = "Database"
    ws_config['B4'] = "lefiru_db"
    
    # Protect CONFIG
    ws_config.protection.sheet = True
    ws_config.protection.password = "config123"
    
    output_path = OUTPUT_DIR / "test_connections.xlsx"
    wb.save(output_path)
    logger.info(f"OK: Created: {output_path}")


def create_secondary_logic_xlsx():
    """
    Create an Excel file designed to test secondary logic.
    
    Contains:
    - CONFIG_HIDDEN sheet (hidden)
    - Hidden secondary factor
    - Named Range that points to that logic
    - Visible output affected indirectly
    """
    logger.info("Creating test_secondary_logic.xlsx...")

    wb = openpyxl.Workbook()

    # CONFIG_HIDDEN sheet
    
    ws_hidden = wb.active
    ws_hidden.title = "CONFIG_HIDDEN"
    ws_hidden["A1"] = "Secondary factor"
    ws_hidden["B1"] = 1.20  # Secondary logic

    # Hide the sheet
    ws_hidden.sheet_state = "hidden"

    # Create Named Range pointing to the hidden factor
    from openpyxl.workbook.defined_name import DefinedName

    factor_name = DefinedName(
        name="FACTOR_HIDDEN",
        attr_text="CONFIG_HIDDEN!$B$1"
    )

    wb.defined_names["FACTOR_HIDDEN"] = factor_name
    
    # DATA sheet
    ws_data = wb.create_sheet("DATA")
    ws_data["A1"] = "Base"
    ws_data["B1"] = 1000

    ws_data["A2"] = "Intermediate result"
    ws_data["B2"] = "=B1*FACTOR_HIDDEN"
    
    # OUTPUT sheet (VISIBLE)
    ws_output = wb.create_sheet("OUTPUT")
    ws_output["A9"] = "Final result"
    ws_output["B10"] = "=DATA!B2"

    # Save
    output_path = OUTPUT_DIR / "test_secondary_logic.xlsx"
    wb.save(output_path)

    logger.info(f"OK: Created: {output_path}")
    logger.info("  Contains secondary logic in a hidden sheet + Named Range")


def create_formula_protection_test_xlsx():
    """
    Create a file designed to test formulas (formula integrity and traceability).

    Contains:
    - Consistent formulas in a contiguous range
    - One inconsistent formula in the same range
    - A simulated external reference
    - A formula with INDIRECT
    - A formula with IFERROR
    - A hidden sheet with a support parameter
    """
    logger.info("Creating test_formula_protection.xlsx...")

    wb = openpyxl.Workbook()

    ws_control = wb.active
    ws_control.title = "CONTROL"
    ws_control["A1"] = "Base"
    ws_control["B1"] = "Factor"
    ws_control["C1"] = "Result"
    ws_control["D1"] = "Observation"

    ws_control["A2"] = 100
    ws_control["B2"] = 1.2
    ws_control["C2"] = "=A2*B2"
    ws_control["D2"] = "Expected pattern"

    ws_control["A3"] = 200
    ws_control["B3"] = 1.1
    ws_control["C3"] = "=A3*B3"
    ws_control["D3"] = "Expected pattern"

    ws_control["A4"] = 300
    ws_control["B4"] = 0.9
    ws_control["C4"] = "=A4+B4"
    ws_control["D4"] = "Intentional inconsistency"

    ws_control["F1"] = "External reference"
    ws_control["F2"] = "='[Budget2026.xlsx]Base'!$B$2"

    ws_control["G1"] = "Dynamic reference"
    ws_control["G2"] = '=INDIRECT("A"&2)*B2'

    ws_control["H1"] = "Error hiding"
    ws_control["H2"] = "=IFERROR(VLOOKUP(A2,Parameters!A:B,2,FALSE),0)"

    ws_control["I1"] = "Calculated error"
    ws_control["I2"] = "=1/0"

    ws_param = wb.create_sheet("Parameters")
    ws_param["A1"] = 100
    ws_param["B1"] = "Factor A"
    ws_param["A2"] = 200
    ws_param["B2"] = "Factor B"

    ws_hidden = wb.create_sheet("CONFIG_HIDDEN")
    ws_hidden["A1"] = "Threshold"
    ws_hidden["B1"] = 0.95
    ws_hidden.sheet_state = "hidden"

    output_path = OUTPUT_DIR / "test_formula_protection.xlsx"
    wb.save(output_path)

    logger.info(f"OK: Created: {output_path}")
    logger.info("  Contains inconsistencies, external reference, INDIRECT, IFERROR and calculated error")


def create_insecure_vba_sample():
    """
    Create a text file with an example of insecure VBA code
    (Real VBA cannot be created with openpyxl)
    """
    logger.info("Creating sample_insecure_vba.txt...")
    
    vba_code = """
' Example of VBA code with INSECURE patterns (for testing purposes)
' WARNING: This code contains deliberate bad practices

Sub ConnectDatabase()
    Dim conn As Object
    Set conn = CreateObject("ADODB.Connection")
    
    'BAD: Hardcoded credentials
    Dim user As String
    Dim password As String
    user = "lefiru_user"
    password = "lefiru_password_2026"
    
    'BAD: Connection string with plain-text credentials
    Dim connString As String
    connString = "Provider=SQLOLEDB;Data Source=LEFIRU-SQL;" & _
                 "Initial Catalog=lefiru_db;" & _
                 "User ID=" & user & ";" & _
                 "Password=" & password
    
    conn.ConnectionString = connString
    conn.Open
    
    'RISK: SQL with concatenation (SQL injection)
    Dim sql As String
    Dim userName As String
    userName = Range("A1").Value
    sql = "SELECT * FROM Users WHERE Name = '" & userName & "'"
    
    Dim rs As Object
    Set rs = CreateObject("ADODB.Recordset")
    rs.Open sql, conn
    
    ' ... process results ...
    
    rs.Close
    conn.Close
    Set rs = Nothing
    Set conn = Nothing
End Sub

Sub RunExternalCommand()
    'RISK: Shell usage without validation
    Dim command As String
    command = Range("B1").Value
    Shell "cmd.exe /c " & command, vbHide
End Sub

Sub GetAPIData()
    'BAD: Hardcoded API key
    Dim apiKey As String
    apiKey = "lefiru_api_key_1234567890abcdef"
    
    Dim http As Object
    Set http = CreateObject("WinHttp.WinHttpRequest.5.1")
    
    http.Open "GET", "https://api.lefiru.local/data", False
    http.SetRequestHeader "Authorization", "Bearer " & apiKey
    http.Send
    
    ' ... process response ...
End Sub

Sub InsecureConfiguration()
    'RISK: Error suppression
    On Error Resume Next
    
    'BAD: Hardcoded token
    Dim token As String
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.lefiru-token..."
    
    'BAD: Secret key
    Dim secretKey As String
    secretKey = "lefiru_secret_key_2026"
    
    ' Code that could fail but errors are ignored
    ' ...
End Sub

'GOOD PRACTICE: Use Windows Credential Manager
Sub ConnectSecurely()
    ' Read credentials from Windows Credential Manager or an encrypted config file
    Dim user As String
    Dim password As String
    
    ' This would require a function that reads from Credential Manager
    ' user = GetCredential("DBUser")
    ' password = GetCredential("DBPassword")
    
    ' Or use Windows integrated authentication
    Dim connString As String
    connString = "Provider=SQLOLEDB;Data Source=LEFIRU-SQL;" & _
                 "Initial Catalog=lefiru_db;" & _
                 "Integrated Security=SSPI"
End Sub

'GOOD PRACTICE: Use parameterized queries
Sub RunSecureQuery()
    Dim conn As Object
    Dim cmd As Object
    
    Set conn = CreateObject("ADODB.Connection")
    Set cmd = CreateObject("ADODB.Command")
    
    ' Open connection...
    
    ' Use parameters instead of concatenation
    cmd.CommandText = "SELECT * FROM Users WHERE Name = ?"
    cmd.Parameters.Append cmd.CreateParameter("name", 200, 1, 50, Range("A1").Value)
    
    Dim rs As Object
    Set rs = cmd.Execute
    
    ' ... process results ...
End Sub
"""
    
    output_path = OUTPUT_DIR / "sample_insecure_vba.txt"
    output_path.parent.mkdir(exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(vba_code)
    
    logger.info(f"OK: Created: {output_path}")
    logger.info("  Contains examples of insecure and secure VBA code")


def create_opening_password_hit_xlsx():
    """
    Create a file with a weak OPENING password (in the dictionary).
    Uses Excel COM to encrypt the file.
    Password: 'password123' (it is in the dictionary)
    """
    logger.info("Creating test_opening_password_hit.xlsx...")

    # Create base file
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "DATA"
    ws["A1"] = "Test Opening Password - HIT"
    ws["A2"] = "This password is in the dictionary"
    ws["A3"] = "Password: password123"
    
    temp_path = OUTPUT_DIR / "_temp_opening_hit.xlsx"
    wb.save(temp_path)
    
    try:
        # Same COM activation used by the analyzer (CLSCTX per bitness)
        excel = _create_excel()
        excel.Visible = False
        excel.DisplayAlerts = False
        excel.ScreenUpdating = False
        
        try:
            wb_com = excel.Workbooks.Open(str(temp_path.absolute()))
            output_path = OUTPUT_DIR / "test_opening_password_hit.xlsx"
            
            # SaveAs with opening Password (parameter 3)
            # FileFormat 51 = xlOpenXMLWorkbook (.xlsx)
            wb_com.SaveAs(
                str(output_path.absolute()),
                51,  # FileFormat: xlOpenXMLWorkbook
                "password123",  # Password for opening
                ""  # WriteResPassword (empty)
            )
            wb_com.Close(False)
            
            logger.info(f"OK: Created: {output_path}")
            logger.info("  Password: password123 (in dictionary)")
            logger.info("  Expected in the opening test: dictionary hit")
        finally:
            excel.Quit()
            
    except Exception as e:
        logger.error(f"Error encrypting file with Excel COM: {str(e)}")
        logger.info("  Verify that Excel is installed and available")
    finally:
        if temp_path.exists():
            temp_path.unlink()


def create_opening_password_miss_xlsx():
    """
    Create a file with a strong OPENING password (not in the dictionary).
    Password: 'lefiru_vault_2026#Qa2' (NOT in the dictionary)
    """
    logger.info("Creating test_opening_password_miss.xlsx...")

    # Create base file
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "DATA"
    ws["A1"] = "Test Opening Password - MISS"
    ws["A2"] = "This password is NOT in the dictionary"
    ws["A3"] = "Password: lefiru_vault_2026#Qa2"
    
    temp_path = OUTPUT_DIR / "_temp_opening_miss.xlsx"
    wb.save(temp_path)
    
    try:
        # Same COM activation used by the analyzer (CLSCTX per bitness)
        excel = _create_excel()
        excel.Visible = False
        excel.DisplayAlerts = False
        excel.ScreenUpdating = False
        
        try:
            wb_com = excel.Workbooks.Open(str(temp_path.absolute()))
            output_path = OUTPUT_DIR / "test_opening_password_miss.xlsx"
            strong_pwd = "lefiru_vault_2026#Qa2"
            
            # SaveAs with opening Password
            wb_com.SaveAs(
                str(output_path.absolute()),
                51,  # FileFormat: xlOpenXMLWorkbook
                strong_pwd,  # Password for opening
                ""  # WriteResPassword (empty)
            )
            wb_com.Close(False)
            
            logger.info(f"OK: Created: {output_path}")
            logger.info(f"  Password: {strong_pwd} (NOT in dictionary)")
            logger.info("  Expected in the opening test: no dictionary hit")
        finally:
            excel.Quit()
            
    except Exception as e:
        logger.error(f"Error encrypting file with Excel COM: {str(e)}")
        logger.info("  Verify that Excel is installed and available")
    finally:
        if temp_path.exists():
            temp_path.unlink()


def create_real_xlsm_with_vba() -> bool:
    """
    Create an .xlsm file with real VBA using Excel COM.

    Requires Excel installed, pywin32 and the trust option
    "Trust access to the VBA project object model".
    """
    logger.info("Creating test_real_vba.xlsm with Excel COM...")

    excel = None
    try:
        excel = _create_excel()
        excel.Visible = False
        excel.DisplayAlerts = False

        wb = excel.Workbooks.Add()
        ws = wb.ActiveSheet
        ws.Name = "Data"

        # Add some data
        ws.Range("A1").Value = "ID"
        ws.Range("B1").Value = "Description"
        ws.Range("A2").Value = 1
        ws.Range("B2").Value = "Item 1"

        # Read VBA code from the text file (if it exists)
        vba_file = OUTPUT_DIR / "sample_insecure_vba.txt"
        if vba_file.exists():
            vba_code = vba_file.read_text(encoding="utf-8")
        else:
            # Sample VBA code if the file does not exist
            vba_code = '''
Sub TestMacro()
    MsgBox "Test macro executed!"
End Sub

Sub InsecureExample()
    ' Insecure code example
    Dim password As String
    password = "lefiru_vba_password_2026"
    MsgBox "Password: " & password
End Sub
'''

        # Add VBA module
        vb_module = wb.VBProject.VBComponents.Add(1)  # 1 = vbext_ct_StdModule
        vb_module.Name = "InsecureModule"
        vb_module.CodeModule.AddFromString(vba_code)

        # Save as .xlsm
        output_path = OUTPUT_DIR / "test_real_vba.xlsm"
        wb.SaveAs(str(output_path.absolute()), FileFormat=52)  # 52 = xlOpenXMLWorkbookMacroEnabled
        wb.Close(SaveChanges=False)

        logger.info(f"OK: Created: {output_path}")
        logger.info("  Contains real VBA extracted from sample_insecure_vba.txt")
        return True

    except Exception as exc:
        message = str(exc)
        if "Visual Basic" in message or "-2146827284" in message:
            logger.warning("WARNING: Excel blocked access to the VBA project.")
            logger.info("  To enable it:")
            logger.info("  1. Open Excel")
            logger.info("  2. File > Options > Trust Center > Trust Center Settings")
            logger.info("  3. Macro Settings > check 'Trust access to the VBA project object model'")
            logger.info("  4. Restart Excel and run again")
            return False
        logger.error(f"ERROR creating file with VBA: {message}")
        return False
    finally:
        if excel is not None:
            try:
                excel.Quit()
            except Exception:
                pass


def create_clean_python_script():
    """Create a clean Python script that should pass the analysis."""
    logger.info("Creating fixture_python_clean.py...")

    code = '''import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def calculate_total(quantity: int, price: float) -> float:
    return quantity * price


if __name__ == "__main__":
    total = calculate_total(5, 12.5)
    logger.info("Calculated total: %s", total)
'''

    output_path = OUTPUT_DIR / "fixture_python_clean.py"
    output_path.write_text(code, encoding="utf-8")
    logger.info(f"OK: Created: {output_path}")


def create_insecure_python_script():
    """Create a Python script with several deliberate insecure patterns."""
    logger.info("Creating fixture_python_insecure.py...")

    code = textwrap.dedent("""\
        import os
        import pickle
        import subprocess
        import yaml


        password = "lefiru_password_2026"
        api_key = "lefiru_api_key_1234567890abcdef"
        connection_string = "Server=LEFIRU-SQL;Database=lefiru_db;User ID=lefiru_user;Password=lefiru_password_2026"
        network_share = r"\\\\lefiru-server\\shared\\fixtures"
        endpoint = "http://api.lefiru.local/reports"
        secret_key = "lefiru_secret_key_2026"
        jwt_secret = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.lefiru.signature"
        PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----lefiru-private-key"
        AES_KEY = "lefiru_aes_key_2026"


        def load_data(path):
            with open(path, "rb") as handler:
                return pickle.load(handler)


        def run_command(command):
            return subprocess.run(command, shell=True, check=False)


        def evaluate_expression(expr):
            return eval(expr)


        def load_yaml(text):
            return yaml.load(text, Loader=yaml.Loader)


        if __name__ == "__main__":
            os.system("echo Analyzing Lefiru fixture")
        """)

    output_path = OUTPUT_DIR / "fixture_python_insecure.py"
    output_path.write_text(code, encoding="utf-8")
    logger.info(f"OK: Created: {output_path}")


def create_suspicious_pyc_sample():
    """Create a synthetic .pyc file with strings detectable by binary scanning."""
    logger.info("Creating test_python_suspicious.pyc...")

    payload = (
        b"\x42\x0d\x0d\x0a"
        + b"\x00" * 64
        + b"token=lefiru_token_1234567890\n"
        + b"https://api.lefiru.local/api\n"
        + b"jdbc:sqlserver://LEFIRU-SQL;databaseName=lefiru_db\n"
    )

    output_path = OUTPUT_DIR / "test_python_suspicious.pyc"
    output_path.write_bytes(payload)
    logger.info(f"OK: Created: {output_path}")
    logger.info("  Contains suspicious strings for binary detection in .pyc")


def create_suspicious_python_exe():
    """Create a synthetic .exe with an MZ header and suspicious strings."""
    logger.info("Creating test_python_bundle.exe...")

    payload = (
        b"MZ"
        + b"\x00" * 128
        + b"password=lefiru_bundle_password\n"
        + b"secret=lefiru-signing-key\n"
        + b"https://api.lefiru.local/v1\n"
        + b"\\\\lefiru-server\\finance\\closings\n"
        + b"PYZ\x00"
    )

    output_path = OUTPUT_DIR / "test_python_bundle.exe"
    output_path.write_bytes(payload)
    logger.info(f"OK: Created: {output_path}")
    logger.info("  Synthetic .exe to test PyInstaller-style binary detection")


def create_extractable_python_exe_sample():
    """
    Create an extractable .exe to test exe_extractor.

    The file is a valid ZIP with an .exe extension and contains
    internal Python modules (.py and .pyc).
    """
    logger.info("Creating test_python_extractable.exe...")

    with tempfile.TemporaryDirectory(prefix="real_pyc_") as temp_dir:
        temp_dir_path = Path(temp_dir)
        py_source_path = temp_dir_path / "module_real.py"
        pyc_output_path = temp_dir_path / "module_real.pyc"

        py_source_path.write_text(
            "token = 'lefiru_compiled_token_123456'\n"
            "def get_token():\n"
            "    return token\n",
            encoding="utf-8",
        )

        py_compile.compile(
            str(py_source_path),
            cfile=str(pyc_output_path),
            doraise=True,
        )

        module_pyc_bytes = pyc_output_path.read_bytes()

    output_path = OUTPUT_DIR / "test_python_extractable.exe"
    with zipfile.ZipFile(output_path, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "app/__main__.py",
            "import logging\n"
            "logging.basicConfig(level=logging.INFO)\n"
            "password = 'lefiru_internal_password'\n"
            "if __name__ == '__main__':\n"
            "    print('ok')\n",
        )
        zf.writestr("app/utils.py", "def helper():\n    return 42\n")
        zf.writestr("app/module.pyc", module_pyc_bytes)

    logger.info(f"OK: Created: {output_path}")
    logger.info("  Case: EXTRACTION_SUCCESSFUL (contains .py and REAL compiled .pyc)")


def create_non_extractable_python_exe_sample():
    """
    Create a non-extractable .exe to test exe_extractor fallback.

    The file simulates a PE header (MZ) with binary content, but does not
    contain a valid internal ZIP.
    """
    logger.info("Creating test_python_non_extractable.exe...")

    payload = (
        b"MZ"
        + b"\x00" * 128
        + b"this_is_not_a_zip_payload\x00\x01\x02"
        + b"password=lefiru_fallback_password\n"
        + b"https://api.lefiru.local/fallback\n"
        + b"random_binary_tail"
    )

    output_path = OUTPUT_DIR / "test_python_non_extractable.exe"
    output_path.write_bytes(payload)
    logger.info(f"OK: Created: {output_path}")
    logger.info("  Case: NO_EXTRACTION (must use the binary fallback)")


def generate_fixtures(
    output_dir: Path | str = DEFAULT_OUTPUT_DIR,
    include_com: bool = True,
) -> list[Path]:
    """Generate the fixture set and return the created paths.

    Parameters:
        output_dir: destination folder; created if it does not exist.
        include_com: if ``False``, skip the files that need Excel
            (opening encryption and real VBA).
    """
    global OUTPUT_DIR

    OUTPUT_DIR = Path(output_dir).expanduser().resolve()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 60)
    logger.info("GENERATING TEST FILES IN %s", OUTPUT_DIR)
    logger.info("=" * 60)

    generators = [
        create_simple_xlsx,
        create_protected_xlsm,
        create_template_xltx,
        create_macro_templates,
        create_connections_xlsx,
        create_secondary_logic_xlsx,
        create_formula_protection_test_xlsx,
        create_insecure_vba_sample,
        create_clean_python_script,
        create_insecure_python_script,
        create_suspicious_pyc_sample,
        create_suspicious_python_exe,
        create_extractable_python_exe_sample,
        create_non_extractable_python_exe_sample,
    ]

    failures: list[str] = []

    for generator in generators:
        try:
            generator()
        except Exception as exc:
            logger.error("ERROR in %s: %s", generator.__name__, exc, exc_info=True)
            failures.append(generator.__name__)

    if include_com:
        for generator in (
            create_opening_password_hit_xlsx,
            create_opening_password_miss_xlsx,
        ):
            try:
                generator()
            except Exception as exc:
                logger.error("ERROR in %s: %s", generator.__name__, exc, exc_info=True)
                failures.append(generator.__name__)

        # Requires Excel + "Trust access to the VBA project object model".
        try:
            if not create_real_xlsm_with_vba():
                failures.append("test_real_vba.xlsm")
        except Exception as exc:
            logger.error("ERROR in create_real_xlsm_with_vba: %s", exc, exc_info=True)
            failures.append("create_real_xlsm_with_vba")
    else:
        logger.info("Skipping files that require Excel (--skip-com)")

    expected = [
        "test_simple.xlsx",
        "test_protected.xlsm",
        "test_template.xltx",
        "test_template_macro.xltm",
        "test_addin.xlam",
        "test_connections.xlsx",
        "test_secondary_logic.xlsx",
        "test_formula_protection.xlsx",
        "sample_insecure_vba.txt",
        "fixture_python_clean.py",
        "fixture_python_insecure.py",
        "test_python_suspicious.pyc",
        "test_python_bundle.exe",
        "test_python_extractable.exe",
        "test_python_non_extractable.exe",
    ]
    if include_com:
        expected += [
            "test_opening_password_hit.xlsx",
            "test_opening_password_miss.xlsx",
            "test_real_vba.xlsm",
        ]

    created = [OUTPUT_DIR / name for name in expected if (OUTPUT_DIR / name).exists()]
    missing = [name for name in expected if not (OUTPUT_DIR / name).exists()]

    logger.info("")
    logger.info("=" * 60)
    logger.info("GENERATED FIXTURES: %d/%d", len(created), len(expected))
    logger.info("=" * 60)
    logger.info("Folder: %s", OUTPUT_DIR)

    if missing:
        logger.warning("Missing: %s", ", ".join(missing))
    if failures:
        logger.warning("Generators with errors: %s", ", ".join(failures))

    return created


def main(argv: list[str] | None = None) -> int:
    """Entry point of the fixture generator."""
    parser = argparse.ArgumentParser(
        description="Generate test files for lefiru analyzer.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help=f"Destination folder (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--skip-com",
        action="store_true",
        help="Do not generate files that require Excel (encrypted and real VBA).",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show debug detail.",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
    )

    try:
        generate_fixtures(args.output_dir, include_com=not args.skip_com)
    except Exception:
        logger.exception("ERROR generating fixtures")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

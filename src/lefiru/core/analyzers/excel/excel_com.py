"""
COM analyzer for Excel files (Windows mode + Excel installed)
Uses win32com to interact with Excel through COM Automation
"""

# Annotations are evaluated lazily: if win32com/PIL are not installed, the names
# imported in the `try` block do not exist and the module must not fail on import.
from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Any
import re
import sys
import os
try:
    import win32com.client
    import pythoncom
    import win32gui
    import time
    WIN32COM_AVAILABLE = True
except ImportError as e:
    WIN32COM_AVAILABLE = False

from lefiru.core.analysis_support import is_critical_sheet, sanitize_string
from lefiru.core.analyzers.excel import evidence_capture as evidence
from lefiru.core.analyzers.excel.com_runtime import create_excel_application
from lefiru.core.analyzers.excel.excel_formulas import FormulaIntegrityInspector
from lefiru.paths import resource

# Evidence image written into unprotected sheets (protection test).
IMAGE_SHEET_UNPROTECTED = resource("assets/unprotected_sheet.png")


class LiveExcelInspector:
    """COM analyzer for Excel files using win32com"""

    _EXTERNAL_CONN_PATTERNS = (
        "[",
        "http://",
        "https://",
        "provider=",
        "dsn=",
        "odbc;",
        "oledb;",
        "jdbc:",
    )
    
    def __init__(self, file_path: Path, output_root: Path, password: str = None):
        if not WIN32COM_AVAILABLE:
            raise ImportError(
                "pywin32 is not installed. Run: pip install pywin32\n"
                "COM mode is only available on Windows with Excel installed."
            )
        
        self.file_path = file_path.absolute()
        self.password = password
        self.logger = logging.getLogger(__name__)
        self.excel = None
        self.workbook = None
        self.output_root = Path(output_root)
        self.evidence_dir = self.output_root / "reports" / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.vba_export_dir = self.evidence_dir / "vba"
        self.vba_export_dir.mkdir(parents=True, exist_ok=True)
        self.backups_dir = self.output_root /  "backups"
        self.backups_dir.mkdir(parents=True, exist_ok=True)
        self.evidence = {
            "screenshots": []
        }
        self.status_com = "OK"
        self.reason_status = None
        self.vba_exported_paths = []
        

        
        self._open_workbook()
        
        # Save a backup copy in the backups folder
        try:
            backup_path = self.backups_dir / f"{self.file_path.name}.bak"
            import shutil
            # Copy the original file before any modification
            shutil.copy2(str(self.file_path), str(backup_path))
            self.logger.info(f"Backup copy saved to: {backup_path}")
        except Exception as e:
            self.logger.warning(f"Could not save backup copy: {e}")
    
    def _reset_pywin32_cache(self):
        """Removes corrupted pywin32 cache and generates Excel types automatically"""
        try:
            import shutil
            import win32com.client
            from win32com.client import makepy

            # 1. Remove corrupted cache
            cache_path = win32com.client.gencache.GetGeneratePath()
            if os.path.exists(cache_path):
                shutil.rmtree(cache_path, ignore_errors=True)
                self.logger.warning(f"pywin32 cache removed: {cache_path}")

            # 2. Reset gencache
            win32com.client.gencache.is_readonly = False
            win32com.client.gencache.Rebuild()

            # 3. Generate Excel types automatically (no user interaction)
            self.logger.info("Generating Excel types automatically...")
            try:
                # Try modern Excel versions (2016+)
                # GUID: {00020813-0000-0000-C000-000000000046} is the standard ID
                # Version 1.9 covers Excel 2016-2024
                excel_versions = [
                    ('{00020813-0000-0000-C000-000000000046}', 1, 9),   # Excel 2016-2024 (1.9)
                    ('{00020813-0000-0000-C000-000000000046}', 1, 8),   # Excel 2010-2013 (1.8)
                    ('{00020813-0000-0000-C000-000000000046}', 1, 7),   # Excel 2007 (1.7)
                ]
                
                generated = False
                for libid, major, minor in excel_versions:
                    try:
                        self.logger.debug(
                            f"  Trying to generate types for Excel version {major}.{minor}..."
                        )
                        makepy.GenerateFromTypeLibSpec(
                            libid,
                            major,
                            minor,
                            bForce=True  # Force regeneration
                        )
                        self.logger.info(
                            f"Excel types {major}.{minor} generated successfully"
                        )
                        generated = True
                        break
                    except Exception as version_err:
                        self.logger.debug(
                            f"Version {major}.{minor} not available: {version_err}"
                        )
                        continue
                
                if generated:
                    self.logger.info("pywin32 cache and Excel types regenerated successfully")
                else:
                    self.logger.warning(
                        "Could not generate Excel types, continuing with dynamic generation"
                    )
                    
            except Exception as makepy_err:
                self.logger.warning(f"Error generating Excel types: {makepy_err}")
                self.logger.info("Continuing with dynamic type generation...")

        except Exception as e:
            self.logger.error(f"Error resetting pywin32 cache: {e}")
            raise
        
    def _export_vba_module(self, module_name: str, code: str) -> str:
        """Exports a VBA module to a .bas file
        
        Args:
            module_name: VBA module name
            code: Module source code
            
        Returns:
            Path of the generated .bas file
        """
        try:
            # Clean the module name for the filename
            safe_name = "".join(c for c in module_name if c.isalnum() or c in ('_', '-'))
            filename = f"{self.file_path.stem}_{safe_name}.bas"
            filepath = self.vba_export_dir / filename
            
            # Write the .bas file in standard VBA format
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(f"Attribute VB_Name = \"{module_name}\"\n")
                f.write(code)
            path =str(filepath)
            self.logger.info(f"VBA module exported: {filepath.name}")
            self.vba_exported_paths.append(path)
            return path
            
        except Exception as e:
            self.logger.warning(f"Could not export VBA module: {e}")
            return None
    
    @staticmethod
    def _range_has_content(range: Any) -> bool:
        """Indicates whether a COM range has at least one cell with content."""
        try:
            value = range.Value
        except Exception:
            return False
        if value is None:
            return False
        if isinstance(value, str):
            return value != ""
        if isinstance(value, (list, tuple)):
            for row in value:
                if isinstance(row, (list, tuple)):
                    if any(cell not in (None, "") for cell in row):
                        return True
                elif row not in (None, ""):
                    return True
            return False
        return True

    def _test_sheet_modification(self, sheet_name: str) -> Dict[str, Any]:
        """Tests whether a sheet can be modified and captures evidence
        
        Args:
            sheet_name: Name of the sheet to test
            
        Returns:
            Dict with the test result
        """
        try:
            sheet = self.workbook.Worksheets(sheet_name)
            
            # Write a test value in A1; if there is content, shift 2 rows down
            # Try to write
            try:
                sheet.Activate()
                time.sleep(0.2)
                test_cell = "A1"
                try:
                    current_value = sheet.Range(test_cell).Value
                except Exception:
                    current_value = None
                if current_value not in (None, ""):
                    try:
                        sheet.Range("A1:A5").EntireRow.Insert(Shift=-4121)
                    except Exception as e:
                        self.logger.debug(f"Could not insert 5 rows in '{sheet_name}': {e}")
                    test_cell = "A1"

                # Try to insert the evidence image in the target cell
                # Check the sheet protection status before inserting the image
                # Use ProtectContents instead of relying only on exception handling
                sheet_protected = False
                try:
                    sheet_protected = sheet.ProtectContents
                except Exception:
                    sheet_protected = True

                # Only insert the LARGE image in cell A1 (merged version with fixed size)
                # The small insertion in A1 is skipped to avoid duplicate images
                mark_written = False
                if not sheet_protected:
                    if IMAGE_SHEET_UNPROTECTED and Path(IMAGE_SHEET_UNPROTECTED).exists():
                        cell = sheet.Range(test_cell)
                        try:
                            range_destination = cell.Resize(5, 3)
                            
                            # Merge the cells in the range
                            range_destination.Merge()
                            
                            image = sheet.Shapes.AddPicture(
                                Filename=str(IMAGE_SHEET_UNPROTECTED),
                                LinkToFile=False,
                                SaveWithDocument=True,
                                Left=0, Top=0, 
                                Width=150, 
                                Height=60
                            )

                            # The image is already inserted: the red text must NOT be used
                            # even if the subsequent cosmetic adjustment fails.
                            mark_written = True

                            try:
                                image.ShapeRange.LockAspectRatio = -1

                                image.Placement = 1 
                            except Exception as style_error:
                                self.logger.debug(
                                    f"Image inserted in '{sheet_name}' without anchoring adjustment: {style_error}"
                                )

                            self.logger.info(" unprotected sheet image placed successfully (large version)")
                        except Exception as e:
                            self.logger.debug(f"Could not insert the large image in '{sheet_name}': {e}")
                            mark_written = False
                    else:
                        self.logger.debug(f"Image file '{IMAGE_SHEET_UNPROTECTED}' not found")
                else:
                    self.logger.debug(f"Sheet '{sheet_name}' is protected, skipping image insertion")

                if not mark_written:
                    # Fallback: neutral evidence text (only if the image could not be placed)
                    sheet.Range(test_cell).Value = "UNPROTECTED SHEET"
                    sheet.Range(test_cell).Font.Color = 0x0000FF  # Red (BGR)
                    sheet.Range(test_cell).Font.Bold = True
                    sheet.Range(test_cell).Font.Size = 14
                    self.logger.info(" unprotected sheet text placed as fallback")

                # If we got here, the write was successful
                self.logger.error(f"VULNERABILITY: Sheet '{sheet_name}' is MODIFIABLE without restriction")
                
                # Capture the evidence area (the mark is anchored at A1/D1).
                try:
                    screenshot_path = self._take_screenshot(
                        f"successful_mod_{sheet_name}", sheet=sheet
                    )
                except Exception as cap_error:
                    self.logger.debug(f"Could not capture the successful modification: {cap_error}")
                    screenshot_path = None
                
                return {
                    "modifiable": True,
                    "cell_test": test_cell,
                    "mark_type": "image" if mark_written else "text",
                    "evidence": screenshot_path if screenshot_path else "Successful modification (no capture)",
                    "value_written": "UNPROTECTED SHEET"
                }
                
            except Exception as write_error:
                # The write failed = protected sheet. Keep the raw (localized)
                # COM message in the log only; the JSON stays in English.
                self.logger.debug(
                    "Modification test failed for '%s': %s", sheet_name, write_error
                )
                
                # Try to capture evidence of protection
                try:
                    screenshot_path = self._take_screenshot(
                        f"protected_{sheet_name}", sheet=sheet
                    )
                except Exception as cap_error:
                    self.logger.debug(f"Could not capture the protected sheet: {cap_error}")
                    screenshot_path = None
                
                self.logger.info(f"Sheet '{sheet_name}' is protected (not modifiable)")
                return {
                    "modifiable": False,
                    "error": "The sheet is protected: the write test could not modify it",
                    "evidence": screenshot_path if screenshot_path else "Protection verified"
                }
                
        except Exception as e:
            self.logger.error(f"Error testing modification in '{sheet_name}': {e}")
            return {
                "modifiable": None,
                "error": "The modification test could not be completed"
            }
    
    def _evidence_path(self, name: str) -> Path:
        """Builds the evidence file name, keeping the identifier in the stem."""
        safe_name = "".join(c for c in name if c.isalnum() or c in ("_", "-"))
        return self.evidence_dir / f"{self.file_path.stem}_{safe_name}.png"

    def _register_capture(self, path: str, method: str) -> str:
        """Records an evidence image and how it was produced."""
        if not path:
            return None
        self.evidence["screenshots"].append(path)
        self.evidence.setdefault("capture_methods", {})[Path(path).name] = method
        self.logger.info(f"Evidence saved: {Path(path).name} ({method})")
        return path

    def _take_screenshot(self, name: str, sheet=None) -> str:
        """Captures sheet evidence without showing or focusing Excel.

        The window is parked outside the desktop and the range is rendered
        through a throwaway workbook, so the analyzed file never gains a chart
        and the capture does not depend on the window being in front.
        """
        if not evidence.CAPTURE_AVAILABLE:
            self.logger.warning("Pillow/pywin32 not available: no evidence image.")
            return None

        target = sheet
        if target is None:
            try:
                target = self.workbook.ActiveSheet
            except Exception as exc:
                self.logger.debug(f"Could not resolve the sheet to capture: {exc}")
                return None

        try:
            result = evidence.capture_sheet_range(
                self.excel, target, self._evidence_path(name)
            )
        except Exception as exc:
            self.logger.debug(f"Could not capture '{name}': {exc}")
            return None

        if not result.get("path"):
            self.logger.warning(
                f"No visual evidence for '{name}': {result.get('error', 'unknown error')}"
            )
            return None
        return self._register_capture(result["path"], result.get("method") or "unknown")

    def _capture_vba_evidence(self, module_name: str, code: str) -> str:
        """Captures the VBA editor off-screen, or renders the source instead.

        The VBE needs "Trust access to the VBA project object model". When that
        is disabled (the common case) the exported source is drawn with Pillow,
        which needs neither Excel nor a window.
        """
        if not evidence.CAPTURE_AVAILABLE:
            return None

        safe_name = "".join(
            c for c in (module_name or "project") if c.isalnum() or c in ("_", "-")
        )
        path = self._evidence_path(f"vba_{safe_name}")

        if module_name:
            try:
                component = self.workbook.VBProject.VBComponents(module_name)
                captured = evidence.capture_vbe(self.excel, path, component=component)
            except Exception as exc:
                self.logger.debug(f"The VBE is not available ({exc}); rendering the source.")
                captured = None
            if captured:
                return self._register_capture(captured, "vbe_window")

        if not code:
            self.logger.warning(f"No source available to render for module '{module_name}'.")
            return None

        rendered = evidence.render_code_png(
            module_name or "project",
            code,
            path,
            source_name=self.file_path.name,
        )
        if rendered:
            return self._register_capture(rendered, "source_render")
        return None

    @staticmethod
    def _unblock_file_windows(path: str) -> bool:
        """
        Removes the Mark-Of-The-Web (Zone.Identifier) to avoid Protected View.
        It does NOT modify the file contents.
        """
        ads = f"{path}:Zone.Identifier"
        try:
            os.remove(ads)
            return True
        except FileNotFoundError:
            return False
        except Exception:
            return False
    
    def _open_workbook(self):
        """Opens the workbook in Excel (safe mode, without running macros)"""
        try:
            self.logger.info("Starting Excel COM...")
            
         
            
           
            # Initialize COM explicitly
            pythoncom.CoInitialize()

            # Create a CLEAN Excel instance (NO cache, NO gen_py)
            self.excel = create_excel_application()
            self.excel.Visible = False
            self.excel.DisplayAlerts = False
            self.excel.EnableEvents = False
            self.excel.AskToUpdateLinks = False

            self.logger.info("+ New clean Excel instance created (DispatchEx)")

            # Open the workbook without running macros
            # IMPORTANT: ReadOnly=False so writing to sheets can be tested
            # Changes will not be saved (Close without Save)
            
            
            if LiveExcelInspector._unblock_file_windows(str(self.file_path)):
                        self.logger.info(
                            "File unblocked (Zone.Identifier removed) "
                            "- Protected View disabled"
                        )

            # --- Prepare open parameters (before the inner try) ---
            open_params = {
                "Filename": str(self.file_path),
                "UpdateLinks": 0,  # Do not update links
                "ReadOnly": False,  # Allow writing to test protections
                "IgnoreReadOnlyRecommended": True,
                "Notify": False
            }
            
            # Add the password if one was provided
            if self.password:
                open_params["Password"] = self.password
                self.logger.info("Using the provided password...")
            
            # --- ATTEMPT 1: direct open ---
            try:
                self.workbook = self.excel.Workbooks.Open(**open_params)
                self.logger.info(f"Workbook opened normally: {self.workbook.Name}")
                return

            except Exception as e:
                msg = str(e)
                self.logger.warning(
                    "Direct open failed, evaluating Protected View..."
                )
                self.logger.debug(msg)

                # --- FALLBACK: Protected View ---
                # The strings below match Excel's own localized error messages and
                # must stay as-is: they are used for detection.
                if (
                    "Vista protegida" in msg
                    or "Protected View" in msg
                    or "formato o la extensión no son válidos" in msg.lower()
                ):
                    self.logger.info(
                        "↪ Trying to open via ProtectedViewWindows..."
                    )

                    pvw = self.excel.ProtectedViewWindows.Open(
                        str(self.file_path),
                        self.password if self.password else None
                    )

                    self.workbook = pvw.Edit()
                    self.logger.info(
                        f"Workbook opened from Protected View: {self.workbook.Name}"
                    )
                    return

                raise
    
        except Exception as e:
            
           
            self.logger.warning("COM error detected, trying to repair the pywin32 cache...")
            self.logger.debug(f"Detail: {e}")

            # Repair the cache
            self._reset_pywin32_cache()

            # Clean retry
            pythoncom.CoUninitialize()
            pythoncom.CoInitialize()

            self.excel = create_excel_application()
            self.excel.Visible = False
            self.excel.DisplayAlerts = False
            self.excel.EnableEvents = False
            self.excel.AskToUpdateLinks = False
            self.logger.info("Excel restarted after repairing the cache")
            
            # Unblock the file again
            if LiveExcelInspector._unblock_file_windows(str(self.file_path)):
                self.logger.info("File unblocked (retry)")
            
            # --- RETRY: open the workbook with the rebuilt cache ---
            self.logger.info("Retrying workbook open...")
            open_params = {
                "Filename": str(self.file_path),
                "UpdateLinks": 0,
                "ReadOnly": False,
                "IgnoreReadOnlyRecommended": True,
                "Notify": False
            }
            
            if self.password:
                open_params["Password"] = self.password
            
            try:
                self.workbook = self.excel.Workbooks.Open(**open_params)
                self.logger.info(f"Workbook opened successfully after repair: {self.workbook.Name}")
                return
            except Exception as retry_err:
                retry_msg = str(retry_err)
                self.logger.error(f"Open retry failed: {retry_msg}")
                
                # Last attempt: Protected View after rebuilding the cache
                # These strings match Excel's localized error messages (detection data).
                if (
                    "Vista protegida" in retry_msg
                    or "Protected View" in retry_msg
                    or "formato o la extensión no son válidos" in retry_msg.lower()
                ):
                    try:
                        self.logger.info("↪ Last attempt: opening via ProtectedViewWindows...")
                        pvw = self.excel.ProtectedViewWindows.Open(
                            str(self.file_path),
                            self.password if self.password else None
                        )
                        self.workbook = pvw.Edit()
                        self.logger.info(f"Workbook opened from Protected View: {self.workbook.Name}")
                        return
                    except Exception as final_err:
                        self.logger.error(f"Open via Protected View failed: {final_err}")
                        raise
                else:
                    raise


    
    
    @staticmethod
    def _map_sheet_visibility(value: int) -> str:
        """Maps the Excel visibility state to readable text"""
        if value == -1:
            return "VISIBLE"
        elif value == 0:
            return "HIDDEN"
        elif value == 2:
            return "VERY_HIDDEN"
        else:
            return f"UNKNOWN({value})"
        
    def check_workbook_protection(self) -> Dict[str, Any]:
        """Checks workbook and sheet protections using COM"""
        self.logger.info("Analyzing protections (COM)...")
        
        try:
            # Workbook structure protection
            workbook_protected = self.workbook.ProtectStructure or self.workbook.ProtectWindows
            
            # Sheet information
            sheets_info = []
            critical_sheets_without_protection = []
            protected_sheets = 0
            total_sheets = self.workbook.Worksheets.Count
            
            for sheet_index in range(1, total_sheets + 1):
                try:
                    sheet = self.workbook.Worksheets(sheet_index)
                    sheet_name = sheet.Name
                except Exception as sheet_err:
                    self.logger.warning(
                        f"Could not resolve the sheet at index {sheet_index}: {sheet_err}"
                    )
                    sheets_info.append({
                        "index": sheet_index,
                        "name": f"<sheet_{sheet_index}_unresolved>",
                        "protected": None,
                        "critical": False,
                        "visible": None,
                        "error": str(sheet_err),
                    })
                    continue

                is_critical = is_critical_sheet(sheet_name)
                
                # Check protection through a REAL write test
                # Do NOT rely only on ProtectContents (it may be inaccurate)
                is_protected = False
                try:
                    # Real write test on a distant cell
                    test_range = sheet.Range("ZZ1000")
                    old_val = test_range.Value
                    test_range.Value = "TEST_TEMP_CHECK"
                    test_range.Value = old_val  # Restore immediately
                    
                    # If we got here WITHOUT an exception, the sheet is NOT protected
                    is_protected = False
                    
                    # Compare with ProtectContents for debugging
                    protect_contents = sheet.ProtectContents
                    if protect_contents:
                        self.logger.debug(f"Sheet '{sheet_name}': ProtectContents=True but writing works (NOT PROTECTED)")
                    
                except Exception as write_err:
                    # The write failed = the sheet IS protected
                    is_protected = True
                
                visible_state = sheet.Visible
                # Protection details
                protection_detail = {
                    "index": sheet_index,
                    "name": sheet_name,
                    "protected": is_protected,
                    "critical": is_critical,
                    "visible": self._map_sheet_visibility(visible_state)  # xlSheetVisible
                }
                
                # If protected, get more details
                if is_protected:
                    protected_sheets += 1
                    try:
                        protection_detail.update({
                            "protect_drawing_objects": sheet.ProtectDrawingObjects,
                            "protect_scenarios": sheet.ProtectScenarios,
                        })
                    except:
                        pass
                
                sheets_info.append(protection_detail)
                
                if is_critical and not is_protected:
                    critical_sheets_without_protection.append(sheet_name)
            
            # Detailed logging of findings
            self.logger.info("\n" + "="*60)
            self.logger.info("PROTECTION FINDINGS")
            self.logger.info("="*60)
            
            # Workbook
            if workbook_protected:
                self.logger.info(f"Workbook protected: YES")
            else:
                self.logger.warning(f"CRITICAL FINDING: Workbook is NOT protected")
                self.logger.warning(f"     Risk: Users can add/remove sheets without restriction")
            
            # Sheets
            if protected_sheets == total_sheets:
                self.logger.info(f"All sheets protected: {protected_sheets}/{total_sheets}")
            elif protected_sheets == 0:
                self.logger.error(f"CRITICAL FINDING: NO sheet is protected (0/{total_sheets})")
                self.logger.error(f"     Risk: All sheets are modifiable without restriction")
            else:
                self.logger.warning(f"Partial protection: {protected_sheets}/{total_sheets} sheets protected")
                self.logger.warning(f"     {total_sheets - protected_sheets} sheets WITHOUT protection")
            
            # Critical sheets
            if critical_sheets_without_protection:
                self.logger.error(f"CRITICAL FINDING: {len(critical_sheets_without_protection)} critical sheet(s) WITHOUT protection:")
                for sheet in critical_sheets_without_protection:
                    self.logger.error(f"     • {sheet}")
            
            self.logger.info("="*60 + "\n")
            
            # Capture general visual evidence
            self._take_screenshot("protections")
            
            # Test modification on unprotected critical sheets
            # For an executor: test ALL sheets to verify protections
            # For a developer: only critical sheets
            modification_tests = {}
            
            # Test ALL sheets to confirm protection
            sheets_a_test = [
                sheet_info["name"]
                for sheet_info in sheets_info
                if sheet_info.get("name") and not str(sheet_info["name"]).startswith("<sheet_")
            ]
            self.logger.warning("TESTING MODIFICATION...")
            self.logger.warning(f"     All {len(sheets_a_test)} sheets will be tested")
            for sheet_name in sheets_a_test:
                modification_tests[sheet_name] = self._test_sheet_modification(sheet_name)

            #Save modified
            try:
            # Build the new name and output path (e.g. file_analysis.xlsx)
                unlocked_filename =self.backups_dir / f"{self.file_path.stem}_analysis{self.file_path.suffix}"
                unlocked_path = self.output_root / unlocked_filename
                
                # Save a copy with the new name via COM (FileFormat optional depending on the version)
                self.workbook.SaveAs(Filename=str(unlocked_path))
                self.logger.info(f" File modified by the sheet test in {unlocked_path}")
            except Exception as save_err:
                self.logger.error(f"Error saving the file in the test_sheets step")

            return {
                "protected_workbook": workbook_protected,
                "protect_structure": self.workbook.ProtectStructure,
                "protect_windows": self.workbook.ProtectWindows,
                "total_sheets": total_sheets,
                "protected_sheets": protected_sheets,
                "critical_sheets_without_protection": critical_sheets_without_protection,
                "sheet_details": sheets_info,
                "modification_tests": modification_tests,
                "method": "com_automation"
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing protections: {str(e)}")
            return {"error": "Protection analysis could not be completed"}
    
    def check_vba_protection(self) -> Dict[str, Any]:
        """Checks protection and extracts VBA metadata using COM"""
        self.logger.info("Analyzing VBA project (COM)...")
        
        #Check whether the environment allows VBA access
       
        vba_trust = self.is_vba_trust_enabled() or {}

        if not vba_trust.get("enabled", True):

            self.logger.warning("VBA model access NOT enabled in Excel")
            
            return {
                        "status": "VBA_ACCESS_DISABLED",
                        "detail_environment": vba_trust,
                        "message": (
                            "Trust access to the VBA project object model "
                            "has not been enabled."
                        ),
                        "action_required": (
                            "Excel > File > Options > Trust Center > "
                            "Trust Center Settings > Macro Settings > "
                            "Trust access to the VBA project object model"
                        )
                    }

        try:
            # Check whether it has VBA
            vba_project = self.workbook.VBProject
            
            if vba_project is None:
                self.logger.info("No VBA project")
                return {
                    "has_vba": False,
                    "protected_project": None,
                    "accessible_code": False,
                    "status": "WITHOUT_VBA"
                }
            
            # Try to access protection
            try:
                is_protected = vba_project.Protection
                if is_protected:
                    self.logger.info(f"VBA project protected: YES")
                else:
                    self.logger.error(f"CRITICAL FINDING: VBA project is NOT protected")
                    self.logger.error(f"     Risk: Source code accessible and modifiable without a password")
            except:
                # If accessing it fails, it is probably protected
                is_protected = True
                self.logger.info("VBA project protected (access denied)")
            
            modules = {}
            signatures_digital = []
            
            # Only try to read modules if it is not protected or if we are a developer
            if not is_protected:
                try:
                    # Extract module information
                    vb_components = vba_project.VBComponents
                    
                    for component in vb_components:
                        try:
                            module_name = component.Name
                            module_type = component.Type
                            
                            # Types: 1=Module, 2=Class, 3=Form, 100=Document
                            type_names = {
                                1: "StandardModule",
                                2: "ClassModule",
                                3: "UserForm",
                                100: "DocumentModule"
                            }
                            
                            module_info = {
                                "name": module_name,
                                "type": type_names.get(module_type, f"Unknown({module_type})"),
                                "lines": 0,
                                "code": None
                            }
                            
                            # Try to read the code
                            try:
                                code_module = component.CodeModule
                                line_count = code_module.CountOfLines
                                
                                module_info["lines"] = line_count
                                
                                # Extract the code always (for evidence)
                                if line_count > 0:
                                    vba_code = code_module.Lines(1, line_count)
                                    # Always save it in the JSON
                                    module_info["code"] = vba_code
                                    
                                    # Export the module to a .bas file (always)
                                    self._export_vba_module(module_name, vba_code)
                                
                                self.logger.info(f"  • Module: {module_name} ({module_info['type']}, {line_count} lines)")
                                
                            except Exception as e:
                                self.logger.warning(f"Could not read code from {module_name}: {str(e)}")
                            
                            modules[module_name] = module_info
                            
                        except Exception as e:
                            self.logger.warning(f"Error processing component: {str(e)}")
                    
                except Exception as e:
                    self.logger.warning(f"Could not access VBA components: {str(e)}")
            
            # Check digital signatures
            try:
                if hasattr(vba_project, 'VBASigned'):
                    is_signed = vba_project.VBASigned
                    if is_signed:
                        signatures_digital.append({
                            "signed": True,
                            "detail": "VBA project digitally signed"
                        })
                        self.logger.info("VBA project digitally signed")
            except:
                pass
            
            accessible_code = (not is_protected)
            
            # Capture VBA evidence: the editor off-screen when possible,
            # otherwise the exported source rendered with Pillow.
            if modules:
                # Try to capture the first module with code
                first_module = None
                for mod_name, mod_info in modules.items():
                    if mod_info.get("lines", 0) > 0:
                        first_module = mod_name
                        break
                
                if first_module:
                    self.logger.info(f"  Capturing VBA evidence for module: {first_module}")
                    self._capture_vba_evidence(
                        first_module,
                        (modules.get(first_module) or {}).get("code") or "",
                    )
                else:
                    self.logger.debug("No VBA module with code to capture.")
            
            return {
                "has_vba": True,
                "protected_project": is_protected,
                "accessible_code": accessible_code,
                "total_modules": len(modules),
                "modules": modules,
                "signatures_digital": signatures_digital,
                "method": "com_automation"
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing VBA: {str(e)}")
            
            # It may fail if VBA is blocked by a security setting
            if "programmatic access" in str(e).lower():
                return {
                    "has_vba": None,
                    "protected_project": True,
                    "accessible_code": False,
                    "error": "Programmatic access to VBA blocked by a security setting",
                    "note": "Enable 'Trust access to the VBA project object model' in Excel > Options > Trust Center"
                }
            
            return {
                "has_vba": None,
                "error": str(e)
            }
    
    def check_external_connections(self) -> Dict[str, Any]:
        """Checks external connections and links using COM"""
        self.logger.info("Checking external connections (COM)...")
        
        try:
            external_links = []
            data_connections = []
            defined_names = []
            locations = []
            
            # 1. External Links (links to other files)
            try:
                link_sources = self.workbook.LinkSources(1)  # xlExcelLinks
                if link_sources:
                    for link in link_sources:
                        external_links.append({
                            "type": "ExternalLink",
                            "origin": sanitize_string(str(link), 100)
                        })
                        self.logger.warning(f"External link: {sanitize_string(str(link), 50)}")
            except:
                pass  # No external links
            
            # 2. Data Connections (QueryTables, Connections)
            try:
                if self.workbook.Connections.Count > 0:
                    for conn in self.workbook.Connections:
                        conn_info = {
                            "type": "DataConnection",
                            "name": conn.Name,
                            "description": getattr(conn, 'Description', ''),
                        }
                        
                        # Try to get the connection string (it may contain credentials)
                        try:
                            if hasattr(conn, 'OLEDBConnection'):
                                conn_info["connection_string"] = sanitize_string(
                                    conn.OLEDBConnection.Connection, 100
                                )
                            elif hasattr(conn, 'ODBCConnection'):
                                conn_info["connection_string"] = sanitize_string(
                                    conn.ODBCConnection.Connection, 100
                                )
                        except:
                            pass
                        
                        data_connections.append(conn_info)
                        self.logger.warning(f"Data connection: {conn.Name}")
            except:
                pass

            # 2.1. Locate connections by QueryTables (target sheet/cell)
            try:
                for sheet in self.workbook.Worksheets:
                    try:
                        if sheet.QueryTables.Count <= 0:
                            continue
                        for qt in sheet.QueryTables:
                            destination = None
                            conn_str = ""
                            try:
                                destination = qt.Destination.Address(False, False)
                            except Exception:
                                destination = None
                            try:
                                conn_str = str(qt.Connection or "")
                            except Exception:
                                conn_str = ""

                            evidence = {
                                "type": "QueryTable",
                                "name": sanitize_string(str(getattr(qt, "Name", "QueryTable")), 100),
                                "sheet": sheet.Name,
                                "cell": destination,
                                "code_line": f"{sheet.Name}!{destination}" if destination else f"{sheet.Name} (QueryTable)",
                            }
                            if conn_str:
                                evidence["connection_string"] = sanitize_string(conn_str, 180)

                            data_connections.append(evidence)
                            locations.append(evidence)
                    except Exception:
                        continue
            except Exception:
                pass
            
            # 3. Defined Names with external references
            try:
                for name in self.workbook.Names:
                    name_value = name.RefersTo

                    
                    if '[' in str(name_value) or 'http' in str(name_value).lower():
                        record = {
                            "name": name.Name,
                            "reference": sanitize_string(str(name_value), 100)
                        }
                        
                        match = re.search(r"(?:\[[^\]]+\])?([^!]+)!([\$A-Z]+\$?\d+(?::[\$A-Z]+\$?\d+)?)", str(name_value))
                        if match:
                            sheet = match.group(1).strip("'")
                            cell = match.group(2)
                            record["sheet"] = sheet
                            record["cell"] = cell
                            record["code_line"] = f"{sheet}!{cell}"

    
                        defined_names.append(record)
                        locations.append(record)
                        self.logger.warning(f"Defined name with external ref.: {name.Name}")
            except:
                pass

            # 4. External references in formulas (sheet/cell)
            try:
                for sheet in self.workbook.Worksheets:
                    formula_records = self._collect_external_formulas_from_sheet(sheet)
                    external_links.extend(formula_records)
                    locations.extend(formula_records)
            except Exception:
                pass
            
            total_external = len(external_links) + len(data_connections) + len(defined_names)
            
            # Detailed logging of external connections
            self.logger.info("\n" + "="*60)
            self.logger.info("EXTERNAL CONNECTION FINDINGS")
            self.logger.info("="*60)
            
            if total_external == 0:
                self.logger.info("No external connections were found")
            else:
                self.logger.warning(f"Total external connections: {total_external}")
                
                if external_links:
                    self.logger.warning(f"\nExternal links ({len(external_links)}):")
                    for link in external_links:
                        self.logger.warning(f"     • {link['origin']}")
                
                if data_connections:
                    self.logger.warning(f"\nData connections ({len(data_connections)}):")
                    for conn in data_connections:
                        self.logger.warning(f"     • {conn['name']}")
                        if conn.get('description'):
                            self.logger.info(f"       Description: {conn['description']}")
                
                if defined_names:
                    self.logger.warning(f"\nDefined names with external references ({len(defined_names)}):")
                    for name in defined_names:
                        self.logger.warning(f"     • {name['name']}: {name['reference'][:50]}...")

                if locations:
                    self.logger.warning(f"\nLocations detected ({len(locations)}):")
                    for loc in locations[:20]:
                        ref = loc.get("code_line") or f"{loc.get('sheet', 'N/A')}!{loc.get('cell', 'N/A')}"
                        self.logger.warning(f"     • {ref}")
            
            self.logger.info("="*60 + "\n")
            
            return {
                "external_links": external_links,
                "data_connections": data_connections,
                "defined_names": defined_names,
                "locations": locations,
                "total_external": total_external,
                "method": "com_automation"
            }
            
        except Exception as e:
            self.logger.error(f"Error checking connections: {str(e)}")
            return {"error": str(e)}

    @classmethod
    def _is_external_reference(cls, value: str) -> bool:
        if not value:
            return False
        content = str(value).lower()
        return any(pattern in content for pattern in cls._EXTERNAL_CONN_PATTERNS)

    @staticmethod
    def _column_letter(index: int) -> str:
        """Converts a 1-based column index to an Excel letter (A, B, ..., AA)."""
        result = ""
        while index > 0:
            index, remainder = divmod(index - 1, 26)
            result = chr(65 + remainder) + result
        return result

    @staticmethod
    def _normalize_com_matrix(data: Any, rows: int, cols: int) -> List[List[Any]]:
        """Normalizes the COM result of Range.Formula into a 2D matrix."""
        if rows <= 0 or cols <= 0:
            return []

        if rows == 1 and cols == 1:
            return [[data]]

        if rows == 1 and not isinstance(data, (list, tuple)):
            return [[data]]

        if cols == 1 and isinstance(data, (list, tuple)) and data and not isinstance(data[0], (list, tuple)):
            return [[value] for value in data]

        if isinstance(data, (list, tuple)):
            matrix: List[List[Any]] = []
            for row in data:
                if isinstance(row, (list, tuple)):
                    matrix.append(list(row))
                else:
                    matrix.append([row])
            return matrix

        return [[data]]

    def _collect_external_formulas_from_sheet(self, sheet: Any) -> List[Dict[str, Any]]:
        """Detects external formulas by reading only formula cells per COM areas."""
        records: List[Dict[str, Any]] = []
        try:
            # xlCellTypeFormulas = -4123
            formula_cells = sheet.UsedRange.SpecialCells(-4123)
            areas = getattr(formula_cells, "Areas", None)
            if areas is None:
                areas = [formula_cells]

            for area in areas:
                row_count = int(getattr(area.Rows, "Count", 0) or 0)
                col_count = int(getattr(area.Columns, "Count", 0) or 0)
                if row_count <= 0 or col_count <= 0:
                    continue

                start_row = int(getattr(area, "Row", 1) or 1)
                start_col = int(getattr(area, "Column", 1) or 1)
                formulas = self._normalize_com_matrix(area.Formula, row_count, col_count)

                for row_offset, row_values in enumerate(formulas):
                    row_number = start_row + row_offset
                    for col_offset, formula in enumerate(row_values):
                        if not isinstance(formula, str):
                            continue
                        if not self._is_external_reference(formula):
                            continue

                        col_number = start_col + col_offset
                        cell = f"{self._column_letter(col_number)}{row_number}"
                        records.append(
                            {
                                "type": "FormulaExternalRef",
                                "sheet": sheet.Name,
                                "cell": cell,
                                "formula": sanitize_string(formula, 180),
                                "code_line": f"{sheet.Name}!{cell}: {sanitize_string(formula, 140)}",
                            }
                        )
        except Exception as exc:
            # When there are no formulas, Excel raises an exception in SpecialCells.
            # It is handled as a normal case to avoid per-cell fallback overhead.
            if "specialcells" in str(exc).lower() or "no cells" in str(exc).lower():
                return records
            self.logger.debug(
                "Could not read formulas by block on sheet %s: %s",
                getattr(sheet, "Name", "<unknown>"),
                exc,
            )

        return records
    
    def check_formula_integrity(self) -> Dict[str, Any]:
        """Analyzes formulas using the workbook already opened via COM."""
        self.logger.info("Analyzing critical formulas (COM)...")
        analyzer = FormulaIntegrityInspector(self.file_path)
        return analyzer.analyze_com_workbook(self.workbook)
    
    def close(self):
        """Closes the workbook and Excel"""
        self._cleanup()
    
    
    

    def is_vba_trust_enabled(self) -> Dict[str, bool]:
        """
        Checks whether programmatic access to the VBA model is enabled
        """
        registry_enabled = False
        com_accessible = False

        # --- 1) Windows registry ---
        try:
            import winreg
            office_versions = ["16.0", "15.0", "14.0"]  # 365/2019, 2013, 2010

            for version in office_versions:
                try:
                    key_path = rf"Software\Microsoft\Office\{version}\Excel\Security"
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                        value, _ = winreg.QueryValueEx(key, "AccessVBOM")
                        registry_enabled = (value == 1)
                        break
                except FileNotFoundError:
                    continue
        except Exception:
            registry_enabled = False

        # --- 2) Real COM test ---
        try:
            _ = self.workbook.VBProject.VBComponents.Count
            com_accessible = True
        
        except Exception as e:
            msg = str(e).lower()

            if "programmatic access" in msg or "vbproject" in msg:
                com_accessible = False
            else:
                # Technical COM error → do NOT assume VBA is disabled
                self.logger.debug(f"Technical COM error, VBA assumed enabled: {e}")
                com_accessible = True


        return {
            "registry_enabled": registry_enabled,
            "com_accessible": com_accessible,
            "enabled": registry_enabled and com_accessible
        }
        
    def get_evidence(self) -> Dict[str, Any]:
        """
        Returns the evidence generated during the COM analysis
        """
        return {
            "com_mode": {           
                "screenshots": self.evidence.get("screenshots", []),
                "capture_methods": self.evidence.get("capture_methods", {}),
                "exported_vba": {                
                    "modules": self.vba_exported_paths            
                    }        
                }
        }
        
    def _cleanup(self):
        """Releases COM resources"""
        try:
            if self.workbook:
                self.workbook.Close(SaveChanges=False)
                self.workbook = None
            
            if self.excel:
                self.excel.Quit()
                self.excel = None
            
            
            self.logger.info("COM resources released")
            
        except Exception as e:
            self.logger.warning(f"Error cleaning up resources: {str(e)}")

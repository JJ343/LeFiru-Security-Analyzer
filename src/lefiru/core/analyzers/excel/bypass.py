"""
Advanced security testing module.
Attempts to bypass protections with explicit authorization.

WARNING: This module must only be used with explicit authorization from
the file owner. Unauthorized use may violate computer security laws.
"""

import logging
import shutil
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, List
import zipfile
import tempfile
import time

try:
    import pythoncom
    WIN32COM_AVAILABLE = True
except ImportError:
    WIN32COM_AVAILABLE = False

from lefiru.core.analyzers.excel import evidence_capture as evidence
from lefiru.core.analyzers.excel.com_runtime import create_excel_application
from lefiru.core.catalog import EXCEL_BINARY, EXCEL_WITH_MACROS, EXCEL_LEGACY, EXCEL_OOXML

try:
    import openpyxl
    OPENPYXL_AVAILABLE = True
except ImportError:
    OPENPYXL_AVAILABLE = False

from lefiru.paths import resource

# Evidence image written into the cells after a successful bypass.
IMAGE_BYPASS = resource("assets/bypass_image.png")
TAM_IMAGE_WIDTH = 120   # points
TAM_IMAGE_HEIGHT = 56     # points


class BypassTester:
    """
    Class for advanced security testing on Excel files.
    For authorized use only.
    """
    
    def __init__(self, file_path: Path, output_root: Path, password: Optional[str] = None):
        self.file_path = Path(file_path)
        self.logger = logging.getLogger(__name__)
        self.backup_dir = output_root / "backups"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir = output_root / "reports" / "evidence"
        self.vba_output_dir = self.evidence_dir / "vba_bypass"
        self.password = password
        self.backup_path = None
        self.evidence = {
                "screenshots": [],
                "generated_files": [],
                "backup_original": None
            }

        
        
        
    def _sheet_already_marked(self, ws) -> bool:
        """
        Indicates whether the sheet already has an evidence image in the top area.

        excel_com.py inserts the "unprotected sheet" image (range A1:C5) before
        saving the analysis copy. If the bypass runs on that copy, it must not
        shift 3 rows again: it is enough to place its own image.
        """
        try:
            shapes = ws.Shapes
            total = int(shapes.Count)
        except Exception:
            return False

        for index in range(1, total + 1):
            try:
                shape = shapes.Item(index)
            except Exception:
                continue

            is_image = False
            try:
                is_image = int(getattr(shape, "Type", 0) or 0) == 13  # msoPicture
            except Exception:
                is_image = False
            if not is_image:
                # Fallback by name when the COM type is not available.
                try:
                    is_image = str(shape.Name).lower().startswith("picture")
                except Exception:
                    is_image = False
            if not is_image:
                continue

            try:
                cell = shape.TopLeftCell
                if int(cell.Row) <= 6 and int(cell.Column) <= 6:
                    return True
            except Exception:
                continue
        return False

    def _mark_with_image_or_text(self, ws, path_image, text_fallback):
        """
        Places the bypass image following the excel_com.py pattern (combined
        5x3 range, fixed size, locked aspect ratio and anchored to cells).

        - If the sheet was NOT marked by excel_com.py, the image goes in A1.
        - If the sheet was ALREADY marked (image in the top area), the image goes
          3 columns to the right, in D1, to avoid overlapping.

        If the destination cell already has content, inserts 2 columns at the
        start to shift it without destroying it. If the image cannot be inserted,
        writes text_fallback with red formatting (fallback).
        """
        # If the sheet already has an excel_com image, use D1; otherwise A1
        already_marked = self._sheet_already_marked(ws)
        cell_destination = "D1" if already_marked else "A1"

        # Do not destroy whatever is already in the destination cell: shift 2 columns
        try:
            value = ws.Range(cell_destination).Value
        except Exception:
            value = None
        if value not in (None, ""):
            try:
                ws.Columns("A:B").Insert()
            except Exception as e:
                self.logger.debug(f"Could not insert 2 columns: {e}")

        # Insert the image anchored to the combined range starting at the destination cell
        image_inserted = False
        try:
            if path_image and Path(path_image).exists():
                cell = ws.Range(cell_destination)
                range_destination = cell.Resize(5, 3)
                range_destination.Merge()

                image = ws.Shapes.AddPicture(
                    Filename=str(path_image),
                    LinkToFile=False,
                    SaveWithDocument=True,
                    Left=cell.Left,
                    Top=cell.Top,
                    Width=TAM_IMAGE_WIDTH,
                    Height=TAM_IMAGE_HEIGHT,
                )

                # The image is already inserted: the red text must NOT be used
                # even if the later cosmetic adjustment fails.
                image_inserted = True

                try:
                    image.ShapeRange.LockAspectRatio = -1
                    image.Placement = 1
                except Exception as style_error:
                    self.logger.debug(
                        f"Image inserted in {cell_destination} without anchoring adjustment: {style_error}"
                    )
        except Exception as e:
            self.logger.debug(f"Could not insert bypass image: {e}")

        if image_inserted:
            location = "3 columns to the right of A1 (sheet already marked)" if already_marked else "A1"
            self.logger.info(
                f"Evidence image inserted in {cell_destination} ({location})"
            )
            return

        # Fallback: impact text in the destination cell (only if the image could not be placed)
        ws.Range(cell_destination).Value = text_fallback
        ws.Range(cell_destination).Font.Color = 0x0000FF  # Red (BGR)
        ws.Range(cell_destination).Font.Bold = True
        ws.Range(cell_destination).Font.Size = 14
        self.logger.info(
            f"Fallback: evidence text written in {cell_destination} (red)"
        )

    def _file_analysis(self) -> Path:
        """Path of the analysis copy generated by excel_com.py (<stem>_analysis<ext>)."""
        return self.backup_dir / f"{self.file_path.stem}_analysis{self.file_path.suffix}"

    def _working_file(self) -> Path:
        """
        File the bypass operates on: the analysis copy created by excel_com.py
        if it exists; otherwise, the original.
        """
        candidate = self._file_analysis()
        if candidate.is_file():
            self.logger.info(
                f"Bypass on the analysis copy: {candidate.name}"
            )
            return candidate

        self.logger.info(
            "Analysis copy not available; the bypass will use the original file"
        )
        return self.file_path

    @property
    def file_modified(self) -> Path:
        """File that the bypass actually modifies (analysis copy or original)."""
        return self._working_file()

    def create_backup(self) -> Path:
        """Creates a backup of the file before any modification"""
        try:
            backup_name = f"{self.file_path.stem}_backup{self.file_path.suffix}"
            self.backup_path = self.backup_dir / backup_name
            
            shutil.copy2(self.file_path, self.backup_path)
            self.evidence["backup_original"] = str(self.backup_path)
            self.logger.info(f"Backup created at: {self.backup_path.name}")
            
            return self.backup_path
            
        except Exception as e:
            self.logger.error(f"Error creating backup: {e}")
            raise
    
    def restore_backup(self) -> bool:
        """Restores the file from the backup"""
        if not self.backup_path or not self.backup_path.exists():
            self.logger.warning("No backup available to restore")
            return False
        
        try:
            shutil.copy2(self.backup_path, self.file_path)
            self.logger.info("File restored from backup")
            return True
            
        except Exception as e:
            self.logger.error(f"Error restoring backup: {e}")
            return False

    def unhide_very_hidden_sheets(self, target_file: Path = None):
        if not WIN32COM_AVAILABLE:
            return {"successful": False, "error": "pywin32 not available"}

        try:
            import pythoncom
            pythoncom.CoInitialize()

            excel = create_excel_application()
            excel.Visible = False
            excel.DisplayAlerts = False
            excel.EnableEvents = False
            excel.AskToUpdateLinks = False
            

            file_to_open = target_file if target_file else self._working_file()
            wb = excel.Workbooks.Open(str(Path(file_to_open).absolute()), 
                                      ReadOnly=False, 
                                      UpdateLinks= 1, 
                                      IgnoreReadOnlyRecommended = True)

            
            try:
                wb.Unprotect()
            except:
                pass

            sheets_changed = []

            for ws in wb.Worksheets:
                try:
                    if ws.Visible == 2:  # 2 = xlSheetVeryHidden
                        self.logger.info(f"VeryHidden sheet found: {ws.Name}")

                        # FORCE visible
                        ws.Visible = -1  # xlSheetVisible

                        # Force internal refresh
                        ws.Activate()
                        excel.ScreenUpdating = True
                        time.sleep(0.2)

                        sheets_changed.append(ws.Name)
                        self.logger.info(f"Converted to visible: {ws.Name}")
                    
                    elif ws.Visible == 0 : 
                        self.logger (f"Hidden (concealed) sheet found: {ws.Name}")
                        
                        ws.Visible = -1
                        
                        # Force internal refresh
                        ws.Activate()
                        excel.ScreenUpdating = True
                        time.sleep(0.2)

                        sheets_changed.append(ws.Name)
                        self.logger.info(f"Converted to visible: {ws.Name}")

                except Exception as e:
                    self.logger.warning(f"Error with {ws.Name}: {e}")

            if sheets_changed:
                wb.Save()

            wb.Close()
            excel.Quit()
            pythoncom.CoUninitialize()

            return {
                "successful": len(sheets_changed) > 0,
                "sheets_modified": sheets_changed
            }

        except Exception as e:
            return {"successful": False, "error": str(e)}
        
    def _take_screenshot_bypass(
        self,
        sheet_name: str,
        excel_app=None,
        worksheet=None,
    ) -> str:
        """Captures the marked sheet without showing or focusing Excel.

        The window is parked outside the desktop, so the evidence is produced
        in the background and the user keeps working in another application.
        """
        if not evidence.CAPTURE_AVAILABLE:
            return None

        if excel_app is None or worksheet is None:
            self.logger.warning(
                f"Bypass evidence skipped for '{sheet_name}': no Excel instance or sheet."
            )
            return None

        try:
            self.evidence_dir.mkdir(parents=True, exist_ok=True)

            safe_name = "".join(c if c.isalnum() else "_" for c in sheet_name)
            out_path = (
                self.evidence_dir
                / f"{self.file_path.stem}_bypass_marks_{safe_name}.png"
            )

            result = evidence.capture_sheet_range(excel_app, worksheet, out_path)
            if not result.get("path"):
                self.logger.warning(
                    f"Bypass evidence not available for '{sheet_name}': "
                    f"{result.get('error', 'unknown error')}"
                )
                return None

            self.evidence["screenshots"].append(result["path"])
            self.evidence.setdefault("capture_methods", {})[
                Path(result["path"]).name
            ] = result.get("method") or "unknown"

            self.logger.info(f"Bypass evidence saved: {Path(result['path']).name}")
            return result["path"]

        except Exception as e:
            self.logger.warning(f"Error capturing bypass evidence: {e}")
            return None
    
    def _write_marks_after_xml_bypass(self, sheet_name: str = None, target_file: Path = None) -> Dict[str, Any]:
        """
        Writes evidence marks after the XML bypass removed protections.
        Opens the file, writes red marks in cells, takes screenshots, re-protects.
        If target_file is provided, it operates on that file instead of self.file_path.
        """
        if not WIN32COM_AVAILABLE:
            return {"successful": False, "error": "pywin32 not available"}
        
        try:
            import pythoncom
            pythoncom.CoInitialize()
            
            excel = create_excel_application()
            # The workbook stays hidden: the marks are written through COM and
            # the evidence is captured off-screen by _take_screenshot_bypass.
            excel.Visible = False
            excel.DisplayAlerts = False
            excel.EnableEvents = False
            excel.AskToUpdateLinks = False
            
            # Open the already unprotected file (the unlocked one if provided,
            # the excel_com analysis copy or, failing that, the original)
            file_to_open = Path(target_file) if target_file else self._working_file()
            wb = excel.Workbooks.Open(str(file_to_open.absolute()), 
                                      ReadOnly=False,
                                      UpdateLinks = 0,
                                      IgnoreReadOnlyRecommended = True
                                      
                                      )
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            marked_sheets = []
            
            # Iterate all sheets
            for sheet in wb.Sheets:
                # If a sheet was specified, process only that one
                if sheet_name and sheet.Name != sheet_name:
                    continue
                
                try:
                    ws = wb.Worksheets(sheet.Name)
                    
                    # Make visible if hidden
                    if ws.Visible != -1:  # -1 = xlSheetVisible
                        ws.Visible = -1
                    
                    ws.Activate()
                    time.sleep(0.5)
                    
                    self.logger.info(f"Writing marks on sheet '{sheet.Name}'...")
                    
                    # Insert 3 rows at the top (without overwriting data).
                    # If the sheet was already marked with an image (e.g. by excel_com),
                    # do not shift the content again.
                    if not self._sheet_already_marked(ws):
                        ws.Rows("1:3").Insert()
                    
                    # Insert the evidence image (or fallback text if the image is missing)
                    self._mark_with_image_or_text(
                        ws, IMAGE_BYPASS,
                        "*** SUCCESSFUL BYPASS - TEST_WRITE_LEFIRU ***"
                    )
                    
                    marked_sheets.append(sheet.Name)
                    self.logger.info("Evidence mark written on: " + sheet.Name)
                    # Capture the evidence without showing Excel.
                    self._take_screenshot_bypass(sheet.Name, excel, ws)
                    
                    # Re-protect WITHOUT a password (to demonstrate the bypass)
                    ws.Protect(DrawingObjects=False, Contents=True, Scenarios=False)
                    self.logger.debug(f"RE-PROTECTED without password: {sheet.Name}")
                    
                except Exception as e:
                    self.logger.error(f"Error writing mark on '{sheet.Name}': {e}")
                    import traceback
                    self.logger.debug(traceback.format_exc())
            
            # Save changes
            wb.Save()
            wb.Close()
            excel.Quit()
            pythoncom.CoUninitialize()
            
            return {
                "successful": len(marked_sheets) > 0,
                "marked_sheets": marked_sheets,
                "timestamp": timestamp
            }
            
        except Exception as e:
            self.logger.error(f"Error writing post-XML marks: {e}")
            import traceback
            self.logger.debug(traceback.format_exc())
            return {"successful": False, "error": str(e)}
    
    def test_workbook_password_bypass(self) -> Dict[str, Any]:
        """
        Attempts to bypass the workbook opening password.
        This is the most critical protection that prevents opening the file.
        
        Returns:
            Dict with the result of the bypass attempt
        """
        results = {
            "attempted_methods": [],
            "successful_bypass": False,
            "effective_method": None,
            "unlocked_file": None
        }
        
        self.logger.info("="*60)
        self.logger.info("TESTING OPENING PASSWORD BYPASS")
        self.logger.info("="*60)

        # Step 0: decryption with a trivial/empty password (< 1 s, all formats)
        self.logger.info("Step 0: checking whether the encryption uses a trivial or empty password...")
        trivial_result = self._try_trivial_password_decrypt()
        results["attempted_methods"].append({
            "name": "TRIVIAL_PASSWORD_DECRYPT",
            "successful": trivial_result["successful"],
            "file": trivial_result.get("unlocked_file"),
        })
        if trivial_result["successful"]:
            results["successful_bypass"] = True
            results["effective_method"] = "TRIVIAL_PASSWORD_DECRYPT"
            results["unlocked_file"] = trivial_result["unlocked_file"]
            self.logger.warning(
                "Trivial encryption detected: the file opened without a real attack (password: %s)",
                trivial_result.get("trivial_password"),
            )

        # Method 1: XML modification to remove workbookProtection (OOXML)
        if not results["successful_bypass"] and self.file_path.suffix.lower() in EXCEL_OOXML:
            self.logger.info(
                    "The opening password bypass attempt started through "
                    "direct modification of the workbook.xml file."
                )
            xml_result = self._try_remove_workbook_password_xml()
            
            
                

            results["attempted_methods"].append({
                "name": "XML_REMOVE_WORKBOOK_PASSWORD",
                "successful": xml_result["successful"],
                "file": xml_result.get("unlocked_file")
            })
            
            if xml_result["successful"]:
                results["successful_bypass"] = True
                results["effective_method"] = "XML_REMOVE_WORKBOOK_PASSWORD"
                results["unlocked_file"] = xml_result.get("unlocked_file")
                self.logger.info(
                    "The protection tags were removed from the workbook.xml file. "
                    "The recompiled file could be opened without requesting a password."
                )

                # Take screenshots immediately on the unlocked file
                # (sheet protections were also removed by XML, so
                # if we wait for test_sheet_protection_bypass there will be nothing left to unprotect)
                if xml_result.get("unlocked_file"):
                    
                    
                    file = Path(xml_result["unlocked_file"])
                    self.logger.info("Attempting to capture sheet evidence (marks) + unhide (COM) ")
                    
                    #Method 1: write_marks 
                    marks_result = self._write_marks_after_xml_bypass(
                        target_file=file
                    )
                    if marks_result.get("successful"):
                        self.logger.info(
                            "Marks and screenshots taken on %d sheet(s): %s",
                            len(marks_result.get("marked_sheets", [])),
                            marks_result.get("marked_sheets"),
                        )
                    else:
                       self.logger.warning("Write_marks failed → trying unhide fallback")
                       
                       unhide_result = self.unhide_very_hidden_sheets(file)
                       
                       if unhide_result.get("successful"):
                           
                            self.logger.warning(
                                        "Sheets exposed via fallback: %s",
                                        unhide_result.get("sheets_modified"))
                       else: 
                           self.logger.warning("Unhide fallback also failed")
        
                           

            else:
                self.logger.info(
                    "No removable protection tags were found in workbook.xml "
                    "or the modification did not allow bypassing the password."
                )

        
        # Method 2: Binary modification for .xlsb
        if not results["successful_bypass"] and self.file_path.suffix.lower() in EXCEL_BINARY:
            
            self.logger.info(     
                    "The opening password bypass attempt started on a .xlsb file, "
                )

            bin_result = self._try_remove_xlsb_password()
            results["attempted_methods"].append({
                "name": "BINARY_REMOVE_XLSB_PASSWORD",
                "successful": bin_result["successful"],
                "file": bin_result.get("unlocked_file")
            })
            
            if bin_result["successful"]:
                
                self.logger.info(
                            "The binary protection of the .xlsb file was successfully removed, "
                            "allowing access to the content without a password."
                        )

                results["successful_bypass"] = True
                results["effective_method"] = "BINARY_REMOVE_XLSB_PASSWORD"
                results["unlocked_file"] = bin_result.get("unlocked_file")
            
            else:
                self.logger.info(
                    "The binary bypass attempt for the .xlsb file was not successful."
                )

        
        # Method 3: Content extraction without password (last resort)
        # Method 4: AGGRESSIVE bypass (radical search without validating structure)
        if not results["successful_bypass"]:
            self.logger.info(
                "The AGGRESSIVE bypass attempt started: removing protection patterns "
                "without validating strict structure (last structural resort)."
            )
            aggressive_result = self._try_aggressive_protection_strip()
            results["attempted_methods"].append({
                "name": "AGGRESSIVE_PROTECTION_STRIP",
                "successful": aggressive_result["successful"],
                "file": aggressive_result.get("unlocked_file")
            })
            
            if aggressive_result["successful"]:
                results["successful_bypass"] = True
                results["effective_method"] = "AGGRESSIVE_PROTECTION_STRIP"
                results["unlocked_file"] = aggressive_result.get("unlocked_file")
                self.logger.warning(
                    "AGGRESSIVE bypass successful: protection patterns radically removed without validating structure"
                )

        if not results["successful_bypass"]:
            self.logger.info("Since the previous methods were not effective, extraction of the "
                            "internal content of the file was attempted without opening it.")

            extract_result = self._try_extract_content_without_password()
            results["attempted_methods"].append({
                "name": "EXTRACT_CONTENT_NO_PASSWORD",
                "successful": extract_result["successful"],
                "file": extract_result.get("file_extracted")
            })
            if extract_result["successful"]:
                
                results["successful_bypass"] = True
                results["effective_method"] = "EXTRACT_CONTENT_NO_PASSWORD"
                results["unlocked_file"] = extract_result.get("file_extracted")

        if not results["successful_bypass"] and self.password:
            self.logger.info(
                "Structural bypasses were not effective; access will be attempted with the known/found password."
            )
            password_result = self._try_open_with_known_password()
            results["attempted_methods"].append({
                "name": "KNOWN_PASSWORD_ACCESS",
                "successful": password_result["successful"],
                "file": password_result.get("unlocked_file")
            })

            if password_result["successful"]:
                results["successful_bypass"] = True
                results["effective_method"] = "KNOWN_PASSWORD_ACCESS"
                results["unlocked_file"] = password_result.get("unlocked_file")
                self.logger.info(
                    "The file was opened with the found password after ruling out effective structural bypasses."
                )
        
        if results["successful_bypass"]:
            self.logger.error(f"CRITICAL VULNERABILITY: Opening password bypassed via {results['effective_method']}")
            self.logger.error(f"     Unlocked file: {results['unlocked_file']}")
        else:
            self.logger.info("Opening password resists bypass attempts")
            


        self.logger.info("="*60 + "\n")
        return results

    def _try_open_with_known_password(self) -> Dict[str, Any]:
        """Attempts to open the file with a known password and save an unlocked copy."""
        if not self.password:
            return {"successful": False, "error": "No password available"}

        if not WIN32COM_AVAILABLE:
            return {"successful": False, "error": "pywin32 not available"}

        excel = None
        workbook = None

        try:
            import pythoncom
            pythoncom.CoInitialize()

            excel = create_excel_application()
            excel.Visible = False
            excel.DisplayAlerts = False
            excel.EnableEvents = False
            excel.AskToUpdateLinks = False

            workbook = excel.Workbooks.Open(
                str(self._working_file().absolute()),
                ReadOnly=False,
                Password=self.password,
                UpdateLinks = 0,
                IgnoreReadOnlyRecommended = True
            )

            output_name = f"{self.file_path.stem}_BYPASS_WITH_PASSWORD{self.file_path.suffix}"
            output_path = (self.backup_dir / output_name).absolute()

            workbook.SaveAs(
                Filename=str(output_path),
                FileFormat=int(workbook.FileFormat),
                Password="",
                WriteResPassword=""
            )

            self.evidence["generated_files"].append(str(output_path))

            return {
                "successful": True,
                "unlocked_file": str(output_path),
                "message": "File opened and saved without a password using the known password"
            }
        except Exception as e:
            self.logger.debug(f"Opening with the known password failed: {e}")
            return {"successful": False, "error": str(e)}
        finally:
            try:
                if workbook is not None:
                    workbook.Close(SaveChanges=False)
            except Exception:
                pass
            try:
                if excel is not None:
                    excel.Quit()
            except Exception:
                pass
            try:
                import pythoncom
                pythoncom.CoUninitialize()
            except Exception:
                pass
    
    def _try_trivial_password_decrypt(self) -> Dict[str, Any]:
        """
        Attempts to decrypt the file with empty or trivial passwords using msoffcrypto.
        Ultra-fast (< 1 s). Covers files where the 'encryption' uses an empty password,
        spaces or trivial values that Excel accepts as valid.
        Only applies when the file is encrypted (CFB), not when it is an unencrypted ZIP.
        """
        try:
            import io
            import msoffcrypto
        except ImportError:
            return {"successful": False, "error": "msoffcrypto-tool not available"}

        TRIVIAL = ["", " ", "0", "00", "000", "1", "a", "x"]

        try:
            encrypted_bytes = self._working_file().read_bytes()
        except OSError as exc:
            return {"successful": False, "error": str(exc)}

        # If the file opens as a valid ZIP it is not CFB-encrypted → this method does not apply
        try:
            import io as _io
            with zipfile.ZipFile(_io.BytesIO(encrypted_bytes)):
                pass
            return {"successful": False, "error": "File not CFB-encrypted (it is a valid ZIP)"}
        except zipfile.BadZipFile:
            pass  # Encryption confirmed, continue

        for pwd in TRIVIAL:
            try:
                of = msoffcrypto.OfficeFile(io.BytesIO(encrypted_bytes))
                of.load_key(password=pwd, verify_password=True)
                decrypted = io.BytesIO()
                of.decrypt(decrypted)

                out_name = (
                    f"{self.file_path.stem}_BYPASS_TRIVIAL"
                    f"{self.file_path.suffix}"
                )
                out_path = self.backup_dir / out_name
                out_path.write_bytes(decrypted.getvalue())

                self.logger.warning(
                    "Encryption broken with trivial password %r → %s", pwd, out_path.name
                )
                return {
                    "successful": True,
                    "unlocked_file": str(out_path),
                    "trivial_password": repr(pwd),
                    "message": (
                        f"The file was encrypted with the trivial password {repr(pwd)}. "
                        "This protection is effectively null."
                    ),
                }
            except Exception:
                continue

        return {"successful": False, "error": "No trivial password was effective"}

    def _try_remove_workbook_password_xml(self) -> Dict[str, Any]:
        """
        Removes structural protections by modifying the internal XML files of the workbook.
        Applies to .xlsx/.xlsm NOT encrypted with a real opening password.
        Removes workbookProtection, fileSharing (workbook) and sheetProtection (each sheet).
        """
        import re
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)

                try:
                    with zipfile.ZipFile(self._working_file(), 'r') as zip_ref:
                        zip_ref.extractall(temp_path)
                except zipfile.BadZipFile:
                    return {
                        "successful": False,
                        "error": "File encrypted with a real password (not a valid ZIP)",
                    }

                modified = False

                # ── workbook.xml ───────────────────────────────────────────
                workbook_xml = temp_path / "xl" / "workbook.xml"
                if workbook_xml.exists():
                    content = workbook_xml.read_text(encoding="utf-8", errors="replace")
                    original = content

                    for tag in ("workbookProtection", "fileSharing"):
                        # self-closing: <tag ... />
                        content = re.sub(rf"<{tag}[^>]*/\s*>", "", content)
                        # paired: <tag ...>...</tag>
                        content = re.sub(
                            rf"<{tag}[^>]*>.*?</{tag}>", "", content, flags=re.DOTALL
                        )
                        # opening tag without an explicit closing tag (malformed)
                        content = re.sub(rf"<{tag}[^>]*>", "", content)

                    if content != original:
                        workbook_xml.write_text(content, encoding="utf-8")
                        modified = True
                        self.logger.info("    • Protections removed from workbook.xml")

                # ── Each worksheet sheet ──────────────────────────────
                worksheets_dir = temp_path / "xl" / "worksheets"
                if worksheets_dir.exists():
                    for sheet_file in sorted(worksheets_dir.glob("*.xml")):
                        content = sheet_file.read_text(encoding="utf-8", errors="replace")
                        original = content
                        content = re.sub(r"<sheetProtection[^>]*/\s*>", "", content)
                        content = re.sub(
                            r"<sheetProtection[^>]*>.*?</sheetProtection>",
                            "",
                            content,
                            flags=re.DOTALL,
                        )
                        content = re.sub(r"<sheetProtection[^>]*>", "", content)
                        if content != original:
                            sheet_file.write_text(content, encoding="utf-8")
                            modified = True
                            self.logger.info(
                                f"    • sheetProtection removed from {sheet_file.name}"
                            )

                if not modified:
                    return {
                        "successful": False,
                        "error": "No protection tags were found in the internal XML files",
                    }

                # Recompress
                output_name = (
                    f"{self.file_path.stem}_BYPASS{self.file_path.suffix}"
                )
                output_path = self.backup_dir / output_name

                with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zip_out:
                    for fp in temp_path.rglob("*"):
                        if fp.is_file():
                            zip_out.write(fp, fp.relative_to(temp_path))

                return {
                    "successful": True,
                    "unlocked_file": str(output_path),
                    "message": "XML protections removed (workbook + sheets)",
                }

        except Exception as e:
            self.logger.debug(f"XML bypass failed: {e}")
            return {"successful": False, "error": str(e)}
    
    def _try_remove_xlsb_password(self) -> Dict[str, Any]:
        """
        Removes structural protections from .xlsb files by deleting BIFF12
        records in workbook.bin (and sheet .bin files).

        Neutralized records:
          BrtBeginBookProtection  = 153  (0x0099) → bytes [0x99, 0x01]
          BrtBeginSheetProtection = 588  (0x024C) → bytes [0xCC, 0x04]

        Only works when the .xlsb is NOT encrypted with a real opening password
        (i.e. it is still a valid ZIP internally).
        """

        def _read_vlen(buf: bytes, pos: int):
            """Reads a variable-length BIFF12 integer (1-4 bytes). Returns (value, bytes_read)."""
            val, shift = 0, 0
            for consumed in range(1, 5):
                if pos >= len(buf):
                    return 0, consumed
                b = buf[pos]
                pos += 1
                val |= (b & 0x7F) << shift
                shift += 7
                if not (b & 0x80):
                    return val, consumed
            return val, 4

        def _nullify_records(data: bytearray, type_bytes: bytes, label: str) -> bool:
            """Zeroes out the payload of every record of the given type."""
            found = False
            idx = 0
            while True:
                idx = bytes(data).find(type_bytes, idx)
                if idx == -1:
                    break
                size_pos = idx + len(type_bytes)
                rec_size, size_len = _read_vlen(bytes(data), size_pos)
                data_start = size_pos + size_len
                data_end = data_start + rec_size
                if 0 < rec_size <= 4096 and data_end <= len(data):
                    for j in range(data_start, data_end):
                        data[j] = 0
                    found = True
                    self.logger.info(
                        f"    • {label} neutralized ({rec_size} bytes → 0x00)"
                    )
                idx += len(type_bytes)
            return found

        # BIFF12 type encodings  (first_byte = (type & 0x7F) | 0x80 ; second_byte = type >> 7)
        WB_RECORDS = [
            (bytes([0x99, 0x01]), "BrtBeginBookProtection"),     # 153
        ]
        SHEET_RECORDS = [
            (bytes([0xCC, 0x04]), "BrtBeginSheetProtection"),    # 588
        ]

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)

                try:
                    with zipfile.ZipFile(self._working_file(), "r") as zip_ref:
                        zip_ref.extractall(temp_path)
                except zipfile.BadZipFile:
                    return {
                        "successful": False,
                        "error": "xlsb file encrypted with a real password (not a valid ZIP)",
                    }

                workbook_bin = temp_path / "xl" / "workbook.bin"
                if not workbook_bin.exists():
                    return {"successful": False, "error": "workbook.bin not found"}

                modified = False

                # workbook.bin
                wb_data = bytearray(workbook_bin.read_bytes())
                for type_bytes, label in WB_RECORDS:
                    if _nullify_records(wb_data, type_bytes, label):
                        modified = True
                workbook_bin.write_bytes(bytes(wb_data))

                # Sheets *.bin
                xl_path = temp_path / "xl"
                for bin_file in sorted(xl_path.rglob("*.bin")):
                    if bin_file.name == "workbook.bin":
                        continue
                    sheet_data = bytearray(bin_file.read_bytes())
                    sheet_mod = False
                    for type_bytes, label in SHEET_RECORDS:
                        if _nullify_records(
                            sheet_data, type_bytes, f"{label} ({bin_file.name})"
                        ):
                            sheet_mod = True
                    if sheet_mod:
                        bin_file.write_bytes(bytes(sheet_data))
                        modified = True

                if not modified:
                    return {
                        "successful": False,
                        "error": "No BIFF12 protection records were found in the .bin files",
                    }

                output_name = (
                    f"{self.file_path.stem}_BYPASS{self.file_path.suffix}"
                )
                output_path = self.backup_dir / output_name

                with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zip_out:
                    for fp in temp_path.rglob("*"):
                        if fp.is_file():
                            zip_out.write(fp, fp.relative_to(temp_path))

                return {
                    "successful": True,
                    "unlocked_file": str(output_path),
                    "message": "BIFF12 protection records neutralized (workbook + sheets)",
                }

        except Exception as e:
            self.logger.debug(f"xlsb BIFF12 bypass failed: {e}")
            return {"successful": False, "error": str(e)}
    
    def _try_aggressive_protection_strip(self) -> Dict[str, Any]:
        
        # AGGRESSIVE method: neutralizes protections by searching for patterns without validating structure.
        
        # Strategy:
        # - ZIP (xlsx/xlsm): case-insensitive search of
        #     in XML; removes whole lines/attributes.
        # - XLSB: looks for characteristic byte patterns and replaces ranges with 0x00 without parsing varints.
        
        # More radical than the previous methods, but potentially more effective on files
        # with non-standard or malformed protections.
       

        import re
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)

                try:
                    with zipfile.ZipFile(self._working_file(), 'r') as zip_ref:
                        zip_ref.extractall(temp_path)
                except zipfile.BadZipFile:
                    return {
                        "successful": False,
                        "error": "File encrypted with a real password (not a valid ZIP)",
                    }

                modified = False

                # ────────────────────────────────────────────────────────────
                # STRATEGY 1: ZIP files (OOXML) - aggressive search in XML
                # ────────────────────────────────────────────────────────────
                if self.file_path.suffix.lower() in EXCEL_OOXML:
                    self.logger.info("AGGRESSIVE bypass: removing protection patterns in XML...")
                    
                    # Aggressive patterns to search for (case-insensitive)
                    AGGRESSIVE_PATTERNS = [
                        r'<workbookProtection[^>]*>.*?</workbookProtection>',  # paired
                        r'<workbookProtection[^>]*/\s*>',                      # self-closing
                        r'<sheetProtection[^>]*>.*?</sheetProtection>',        # paired
                        r'<sheetProtection[^>]*/\s*>',                         # self-closing
                        r'<fileSharing[^>]*>.*?</fileSharing>',               # paired
                        r'<fileSharing[^>]*/\s*>',                            # self-closing
                        r'<encryption[^>]*>.*?</encryption>',                 # paired
                        r'<encryption[^>]*/\s*>',                            # self-closing
                        r'hashValue\s*=\s*["\'][^"\']*["\']',                 # hash attribute
                        r'password\s*=\s*["\'][^"\']*["\']',                  # password attribute
                        r'spinCount\s*=\s*["\'][^"\']*["\']',                 # spinCount attribute
                    ]

                    for xml_file in temp_path.rglob("*.xml"):
                        content = xml_file.read_text(encoding="utf-8", errors="replace")
                        original = content

                        # Apply each aggressive pattern
                        for pattern in AGGRESSIVE_PATTERNS:
                            content = re.sub(pattern, "", content, flags=re.DOTALL | re.IGNORECASE)

                        if content != original:
                            xml_file.write_text(content, encoding="utf-8")
                            modified = True
                            self.logger.info(
                                f"    • Protection patterns removed from {xml_file.relative_to(temp_path)}"
                            )

                # ────────────────────────────────────────────────────────────
                # STRATEGY 2: XLSB - aggressive search for binary patterns
                # ────────────────────────────────────────────────────────────
                elif self.file_path.suffix.lower() in EXCEL_BINARY:
                    self.logger.info("AGGRESSIVE bypass: removing binary patterns in .xlsb...")

                    xl_path = temp_path / "xl"
                    
                    # Characteristic protection byte patterns (approximate)
                    # We search for and replace ranges without strictly parsing varints
                    BINARY_PATTERNS = [
                        (b'\x99\x01', "BrtBeginBookProtection"),     # 0x0099
                        (b'\xCC\x04', "BrtBeginSheetProtection"),    # 0x024C
                    ]

                    for bin_file in xl_path.rglob("*.bin"):
                        data = bytearray(bin_file.read_bytes())
                        file_mod = False

                        for pattern_bytes, label in BINARY_PATTERNS:
                            idx = 0
                            while True:
                                idx = bytes(data).find(pattern_bytes, idx)
                                if idx == -1:
                                    break

                                # Aggressive: replace the pattern + the next 16 bytes with 0x00
                                # (without parsing varints, we simply "erase" the area)
                                end_idx = min(idx + 18, len(data))  # pattern (2) + ~16 bytes of payload
                                for j in range(idx, end_idx):
                                    data[j] = 0x00

                                file_mod = True
                                self.logger.info(
                                    f"    • {label} aggressively neutralized in {bin_file.name}"
                                )
                                idx += 18  # Skip to the next search

                        if file_mod:
                            bin_file.write_bytes(bytes(data))
                            modified = True

                if not modified:
                    return {
                        "successful": False,
                        "error": "No protection patterns were found to remove aggressively",
                    }

                # Recompress
                output_name = (
                    f"{self.file_path.stem}_BYPASS_AGGRESSIVE{self.file_path.suffix}"
                )
                output_path = self.backup_dir / output_name

                with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zip_out:
                    for fp in temp_path.rglob("*"):
                        if fp.is_file():
                            zip_out.write(fp, fp.relative_to(temp_path))

                self.logger.warning(
                    "AGGRESSIVE BYPASS APPLIED: Protection patterns radically removed"
                )
                return {
                    "successful": True,
                    "unlocked_file": str(output_path),
                    "message": "Aggressive bypass: protection patterns removed without validating structure",
                }

        except Exception as e:
            self.logger.debug(f"Aggressive bypass failed: {e}")
            return {"successful": False, "error": str(e)}

    def _try_extract_content_without_password(self) -> Dict[str, Any]:
        """
        Attempts to extract content from the file without a password (data, not formulas)
        """
        try:
            # This method extracts the raw data from the XML without opening the workbook
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Extract ZIP
                with zipfile.ZipFile(self._working_file(), 'r') as zip_ref:
                    zip_ref.extractall(temp_path)
                
                # Verify that it was extracted correctly
                xl_path = temp_path / "xl"
                if not xl_path.exists():
                    return {"successful": False, "error": "Excel structure not found"}
                
                # Create the extracted content report
                report_name = f"{self.file_path.stem}_EXTRACTED.txt"
                report_path = self.backup_dir / report_name
                
                with open(report_path, 'w', encoding='utf-8') as report:
                    report.write(f"CONTENT EXTRACTED FROM: {self.file_path.name}\n")
                    report.write(f"DATE: {datetime.now()}\n")
                    report.write("="*60 + "\n\n")
                    report.write("WARNING: This file had password protection\n")
                    report.write("   but the XML content could be extracted.\n\n")
                    
                    # List the XML files found
                    report.write("Extracted XML files:\n")
                    for xml_file in xl_path.rglob('*.xml'):
                        rel_path = xml_file.relative_to(temp_path)
                        report.write(f"  • {rel_path}\n")
                
                return {
                    "successful": True,
                    "file_extracted": str(report_path),
                    "message": "XML content extracted (data without formulas)"
                }
                
        except Exception as e:
            self.logger.debug(f"Content extraction failed: {e}")
            return {"successful": False, "error": str(e)}
    
    def test_sheet_protection_bypass(self, sheet_name: str = None, write_marks: bool = False) -> Dict[str, Any]:
        """
        Tests multiple methods to bypass sheet protection.
        
        Args:
            sheet_name: Name of the sheet to test (None = all)
            write_marks: If True, writes visible marks on unprotected sheets
            
        Returns:
            Dict with the results of each tested method
        """
        results = {
            "attempted_methods": [],
            "successful_bypass": False,
            "effective_method": None,
            "unprotected_sheets": [],
            "vba_extracted": False
        }
        
        # Method 1: COM without a password (with the option of writing marks)
        if WIN32COM_AVAILABLE:
            self.logger.info("Testing COM bypass (without password)...")
            com_result = self._try_com_unprotect_no_password(sheet_name, write_marks=write_marks)
            results["attempted_methods"].append({
                "name": "COM_WITHOUT_PASSWORD",
                "successful": com_result["successful"],
                "sheets": com_result.get("unprotected_sheets", [])
            })
            
            if com_result["successful"]:
                results["successful_bypass"] = True
                results["effective_method"] = "COM_WITHOUT_PASSWORD"
                results["unprotected_sheets"].extend(com_result.get("unprotected_sheets", []))
                if write_marks and com_result.get("marks_written"):
                    results["marks_written"] = True
                    results["timestamp"] = com_result.get("timestamp")
        
        # Method 2: openpyxl bypass (OOXML only) - only if COM failed
        if not results["successful_bypass"] and OPENPYXL_AVAILABLE and self.file_path.suffix.lower() in EXCEL_OOXML:
            self.logger.info("Testing openpyxl bypass...")
            openpyxl_result = self._try_openpyxl_bypass(sheet_name)
            results["attempted_methods"].append({
                "name": "OPENPYXL_BYPASS",
                "successful": openpyxl_result["successful"],
                "sheets": openpyxl_result.get("unprotected_sheets", [])
            })
            
            if openpyxl_result["successful"]:
                results["successful_bypass"] = True
                results["effective_method"] = "OPENPYXL_BYPASS"
                results["unprotected_sheets"].extend(openpyxl_result.get("unprotected_sheets", []))
        
        # Method 3: Direct XML modification - only if the others failed (OOXML only)
        if not results["successful_bypass"] and self.file_path.suffix.lower() in EXCEL_OOXML:
            self.logger.info("Testing direct XML bypass...")
            xml_result = self._try_xml_modification_bypass(sheet_name)
            results["attempted_methods"].append({
                "name": "XML_DIRECT_MODIFICATION",
                "successful": xml_result["successful"],
                "sheets": xml_result.get("unprotected_sheets", [])
            })
            
            if xml_result["successful"]:
                results["successful_bypass"] = True
                results["effective_method"] = "XML_DIRECT_MODIFICATION"
                results["unprotected_sheets"].extend(xml_result.get("unprotected_sheets", []))
                
                # If write_marks=True, now write marks on the already unprotected file
                if write_marks and WIN32COM_AVAILABLE:
                    self.logger.info("Writing evidence marks on the unprotected file...")
                    marks_result = self._write_marks_after_xml_bypass(sheet_name)
                    if marks_result.get("successful"):
                        results["marks_written"] = True
                        results["timestamp"] = marks_result.get("timestamp")
                        self.logger.info(f"Marks written on {len(marks_result.get('marked_sheets', []))} sheets")
        
        return results
    
    def _try_com_unprotect_no_password(self, sheet_name: str = None, write_marks: bool = False) -> Dict[str, Any]:
        """Attempts to unprotect using COM without a password"""
        if not WIN32COM_AVAILABLE:
            return {"successful": False, "error": "pywin32 not available"}
        
        try:
            import pythoncom
            pythoncom.CoInitialize()
            
            excel = create_excel_application()
            excel.Visible = False
            excel.DisplayAlerts = False
            excel.EnableEvents = False
            excel.AskToUpdateLinks = False
            
            wb = excel.Workbooks.Open(str(self._working_file().absolute()), 
                                      ReadOnly=False,
                                       UpdateLinks = 0,
                                        IgnoreReadOnlyRecommended = True)
            
            unprotected_sheets = []
            sheets_accessible_without_bypass = []
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")           # For result metadata
            
            # Try to unprotect without a password
            for sheet in wb.Worksheets:
                if sheet_name and sheet.Name != sheet_name:
                    continue
                
                self.logger.debug(f"    • Evaluating sheet: {sheet.Name} (ProtectContents={sheet.ProtectContents})")
                sheet_accessible = False
                was_protected = bool(sheet.ProtectContents)

                if was_protected:
                    try:
                        sheet.Unprotect()  # Without password
                        unprotected_sheets.append(sheet.Name)
                        sheet_accessible = True
                        self.logger.warning(f"VULNERABILITY: Sheet '{sheet.Name}' unprotected without a password")
                    except Exception as e:
                        self.logger.debug(f"    • Sheet '{sheet.Name}' requires a password or error: {e}")
                else:
                    sheet_accessible = True
                    sheets_accessible_without_bypass.append(sheet.Name)
                    self.logger.info(
                        f"Sheet '{sheet.Name}' was already accessible; it will not be marked as bypass"
                    )

                # Only write bypass marks when the sheet was protected and was unprotected.
                if write_marks and was_protected and sheet_accessible:
                    try:
                        self.logger.info(f"    → Writing marks on '{sheet.Name}'...")

                        # Get the correct reference to the sheet
                        ws = wb.Worksheets(sheet.Name)

                        # Make the sheet visible if hidden
                        if ws.Visible != -1:  # -1 = xlSheetVisible
                            ws.Visible = -1
                            self.logger.info(f"    • Sheet '{sheet.Name}' made visible for writing")

                        # Insert 3 rows at the top (without overwriting data).
                        # If the sheet was already marked with an image (e.g. by excel_com),
                        # do not shift the content again.
                        if not self._sheet_already_marked(ws):
                            ws.Rows("1:3").Insert()

                        # Insert the evidence image (or fallback text if the image is missing)
                        self._mark_with_image_or_text(
                            ws, IMAGE_BYPASS,
                            '*** SUCCESSFUL BYPASS - TEST_WRITE_LEFIRU ***'
                        )

                        # The visible evidence is only the image inserted above.

                        # Capture the evidence BEFORE re-protecting. The Excel
                        # window stays parked off-screen: nothing is shown or
                        # brought to the foreground.
                        self._take_screenshot_bypass(sheet.Name, excel, ws)

                        if was_protected:
                            ws.Protect(
                                DrawingObjects=True,
                                Contents=True,
                                Scenarios=True,
                                AllowFormattingCells=False,
                                AllowFormattingColumns=False,
                                AllowFormattingRows=False
                            )
                            self.logger.warning(f"Sheet '{sheet.Name}' RE-PROTECTED without a password (VULNERABLE)")

                        excel.Visible = False
                        self.logger.info(f"Mark written on: {sheet.Name}")

                    except Exception as e:
                        self.logger.error(f"Error writing mark on '{sheet.Name}': {e}")
                        import traceback
                        self.logger.debug(traceback.format_exc())
                        excel.Visible = False  # Ensure it is hidden
            
            # Save only when there was a real protection bypass on some sheet.
            if unprotected_sheets:
                wb.Save()
            
            wb.Close()
            excel.Quit()
            pythoncom.CoUninitialize()
            
            result = {
                "successful": len(unprotected_sheets) > 0,
                "unprotected_sheets": unprotected_sheets,
                "sheets_accessible_without_bypass": sheets_accessible_without_bypass,
            }
            
            if write_marks and unprotected_sheets:
                result["marks_written"] = True
                result["timestamp"] = timestamp
            
            return result
            
        except Exception as e:
            self.logger.debug(f"COM bypass failed: {e}")
            return {"successful": False, "error": str(e)}
    
    def _try_openpyxl_bypass(self, sheet_name: str = None) -> Dict[str, Any]:
        """Attempts to unprotect by modifying attributes with openpyxl"""
        if not OPENPYXL_AVAILABLE:
            return {"successful": False, "error": "openpyxl not available"}
        
        try:
            wb = openpyxl.load_workbook(self._working_file())
            unprotected_sheets = []
            
            for sheet in wb.worksheets:
                if sheet_name and sheet.title != sheet_name:
                    continue
                
                if sheet.protection.sheet:
                    # Attempt a direct bypass
                    sheet.protection.sheet = False
                    sheet.protection.password = None
                    unprotected_sheets.append(sheet.title)
                    self.logger.warning(f"VULNERABILITY: Sheet '{sheet.title}' bypassed with openpyxl")
            
            if unprotected_sheets:
                wb.save(self._working_file())
            
            return {
                "successful": len(unprotected_sheets) > 0,
                "unprotected_sheets": unprotected_sheets
            }
            
        except Exception as e:
            self.logger.debug(f"openpyxl bypass failed: {e}")
            return {"successful": False, "error": str(e)}
    
    def _try_xml_modification_bypass(self, sheet_name: str = None) -> Dict[str, Any]:
        """Directly modifies XML files inside the .xlsx/.xlsm"""
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Extract ZIP
                with zipfile.ZipFile(self._working_file(), 'r') as zip_ref:
                    zip_ref.extractall(temp_path)
                
                # Look for sheet files
                worksheets_dir = temp_path / "xl" / "worksheets"
                if not worksheets_dir.exists():
                    return {"successful": False, "error": "Sheet directory not found"}
                
                sheets_modified = []
                
                for sheet_file in worksheets_dir.glob("sheet*.xml"):
                    with open(sheet_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # Look for and remove protection tags
                    if '<sheetProtection' in content:
                        # Remove the whole protection tag
                        import re
                        new_content = re.sub(r'<sheetProtection[^>]*>', '', content)
                        
                        with open(sheet_file, 'w', encoding='utf-8') as f:
                            f.write(new_content)
                        
                        sheets_modified.append(sheet_file.stem)
                        self.logger.warning(f"VULNERABILITY: {sheet_file.name} protection removed via XML")
                
                if sheets_modified:
                    # Repackage ZIP
                    with zipfile.ZipFile(self._working_file(), 'w', zipfile.ZIP_DEFLATED) as zip_out:
                        for file in temp_path.rglob('*'):
                            if file.is_file():
                                arcname = file.relative_to(temp_path)
                                zip_out.write(file, arcname)
                
                return {
                    "successful": len(sheets_modified) > 0,
                    "unprotected_sheets": sheets_modified
                }
                
        except Exception as e:
            self.logger.debug(f"XML bypass failed: {e}")
            return {"successful": False, "error": str(e)}
    
    def _try_binary_vba_bypass(self, sheet_name: str = None, write_marks: bool = False) -> Dict[str, Any]:
        """
        Protection bypass for .xlsb files by modifying binary VBA markers.
        This method modifies the DPB, CMG and GC markers in the binary to remove VBA protection.
        Creates a modified temporary file so the original is not corrupted.
        """
        if not WIN32COM_AVAILABLE:
            return {"successful": False, "error": "pywin32 not available"}
        
        import tempfile
        import shutil
        
        temp_file = None
        try:
            # Step 1: Read the original binary file
            with open(self._working_file(), 'rb') as f:
                data = f.read()
            
            # Step 2: Look for and replace VBA protection markers
            markers_modified = []
            original_data = data
            
            # DPB marker (0x44 0x50 0x42) → DPx (VBA protection)
            if b'DPB' in data:
                data = data.replace(b'DPB', b'DPx', 1)  # First occurrence only
                markers_modified.append('DPB')
                self.logger.debug("  • DPB marker modified (VBA unlock)")
            
            # CMG marker (password management)
            if b'CMG' in data:
                data = data.replace(b'CMG', b'CMx', 1)
                markers_modified.append('CMG')
                self.logger.debug("  • CMG marker modified (password manager)")
            
            # GC marker (garbage collection)
            if b'GC' in data:
                data = data.replace(b'GC', b'Gx', 1)
                markers_modified.append('GC')
                self.logger.debug("  • GC marker modified")
            
            if not markers_modified:
                return {
                    "successful": False,
                    "error": "No VBA protection markers were found in the file"
                }
            
            # Step 3: Create the modified temporary file (do not corrupt the original)
            temp_fd, temp_file = tempfile.mkstemp(suffix='.xlsb', prefix='bypass_')
            os.close(temp_fd)  # Close the descriptor
            
            with open(temp_file, 'wb') as f:
                f.write(data)
            
            self.logger.warning(f"VULNERABILITY: VBA protection removed via binary modification ({', '.join(markers_modified)})")
            self.logger.debug(f"  • Temporary file created: {temp_file}")
            
            # Step 4: Extract the VBA code from the temporary file
            self.logger.info("Extracting VBA code from the temporary file...")
            vba_extraction = self._extract_vba_after_bypass(temp_file)
            
            # Step 5: If write_marks=True, open with COM and write marks
            if write_marks:
                self.logger.info("Writing evidence marks on the unprotected sheets...")
                marks_result = self._write_marks_after_binary_bypass(temp_file, sheet_name)
                
                # If the marks were successful, replace the original file with the temporary one
                if marks_result.get("successful", False):
                    shutil.copy2(temp_file, self._working_file())
                    self.logger.info("Original file updated with marks")
                
                return {
                    "successful": True,
                    "method": "BINARY_VBA_MODIFICATION",
                    "markers_modified": markers_modified,
                    "unprotected_sheets": marks_result.get("marked_sheets", []),
                    "marks_written": marks_result.get("successful", False),
                    "timestamp": marks_result.get("timestamp"),
                    "vba_extracted": vba_extraction.get("successful", False),
                    "vba_modules": vba_extraction.get("modules", [])
                }
            else:
                # Without marks, just copy the modified file over the original
                shutil.copy2(temp_file, self._working_file())
                self.logger.info("Original file updated (without marks)")
                
                return {
                    "successful": True,
                    "method": "BINARY_VBA_MODIFICATION",
                    "markers_modified": markers_modified,
                    "vba_extracted": vba_extraction.get("successful", False),
                    "vba_modules": vba_extraction.get("modules", [])
                }
        
        except Exception as e:
            self.logger.error(f"Binary VBA bypass failed: {e}")
            import traceback
            self.logger.debug(traceback.format_exc())
            return {"successful": False, "error": str(e)}
        
        finally:
            # Clean up the temporary file
            if temp_file and os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                    self.logger.debug(f"  • Temporary file removed")
                except:
                    pass
    
    def _write_marks_after_binary_bypass(self, file_path: str, sheet_name: str = None) -> Dict[str, Any]:
        """
        Writes evidence marks after a binary VBA bypass on .xlsb.
        Similar to _write_marks_after_xml_bypass but for binary files.
        Uses the modified temporary file.
        """
        if not WIN32COM_AVAILABLE:
            return {"successful": False, "error": "pywin32 not available"}
        
        try:
            import pythoncom
            pythoncom.CoInitialize()
            
            excel = create_excel_application()
            excel.Visible = False
            excel.DisplayAlerts = False
            excel.EnableEvents = False
            excel.AskToUpdateLinks = False
            
            # Open the temporary file with the VBA bypass already applied
            wb = excel.Workbooks.Open(str(Path(file_path).absolute()), 
                                      ReadOnly=False,
                                      UpdateLinks = 0,
                                      IgnoreReadOnlyRecommended = True
                                      )
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            marked_sheets = []
            
            # Iterate all sheets
            for sheet in wb.Sheets:
                # If a sheet was specified, process only that one
                if sheet_name and sheet.Name != sheet_name:
                    continue
                
                try:
                    ws = wb.Worksheets(sheet.Name)
                    
                    # Make visible if hidden
                    if ws.Visible != -1:  # -1 = xlSheetVisible
                        ws.Visible = -1
                    
                    ws.Activate()
                    time.sleep(0.5)
                    
                    # Try to unprotect without a password (should work after the VBA bypass)
                    try:
                        ws.Unprotect()
                        self.logger.debug(f"Sheet '{sheet.Name}' unprotected without a password")
                    except:
                        # It is already unprotected or had no protection
                        pass
                    
                    self.logger.info(f"Writing marks on sheet '{sheet.Name}'...")
                    
                    # Insert 3 rows at the top (without overwriting data).
                    # If the sheet was already marked with an image (e.g. by excel_com),
                    # do not shift the content again.
                    if not self._sheet_already_marked(ws):
                        ws.Rows("1:3").Insert()
                    
                    # Insert the evidence image (or fallback text if the image is missing)
                    self._mark_with_image_or_text(
                        ws, IMAGE_BYPASS,
                        "*** SUCCESSFUL BYPASS - BINARY VBA (.xlsb) ***"
                    )
                    
                    marked_sheets.append(sheet.Name)
                    self.logger.info(f"Mark written on: {sheet.Name}")
                    
                    # Capture the evidence without showing Excel.
                    self._take_screenshot_bypass(sheet.Name, excel, ws)
                    
                    # Re-protect WITHOUT a password (to demonstrate the bypass)
                    ws.Protect(DrawingObjects=False, Contents=True, Scenarios=False)
                    self.logger.debug(f"RE-PROTECTED without password: {sheet.Name}")
                    
                except Exception as e:
                    self.logger.error(f"Error writing mark on '{sheet.Name}': {e}")
                    import traceback
                    self.logger.debug(traceback.format_exc())
            
            # Save changes
            wb.Save()
            wb.Close()
            excel.Quit()
            pythoncom.CoUninitialize()
            
            return {
                "successful": len(marked_sheets) > 0,
                "marked_sheets": marked_sheets,
                "timestamp": timestamp
            }
            
        except Exception as e:
            self.logger.error(f"Error writing post-binary marks: {e}")
            import traceback
            self.logger.debug(traceback.format_exc())
            return {"successful": False, "error": str(e)}
    
    def _extract_vba_after_bypass(self, file_path: str) -> Dict[str, Any]:
        """
        Extracts the VBA code after a successful bypass.
        Creates a folder with all the VBA modules of the project.
        Uses the modified temporary file.
        """
        if not WIN32COM_AVAILABLE:
            return {"successful": False, "error": "pywin32 not available"}
        
        try:
            import pythoncom
            pythoncom.CoInitialize()
            
            excel = create_excel_application()
            excel.Visible = False
            excel.DisplayAlerts = False
            excel.EnableEvents = False
            excel.AskToUpdateLinks = False
            
            wb = excel.Workbooks.Open(str(Path(file_path).absolute()),
                                      ReadOnly=True,
                                      UpdateLinks = 0,
                                      IgnoreReadOnlyRecommended = True)
            
            try:
                vba_project = wb.VBProject
                
                # Verify whether it is accessible now
                if vba_project.Protection == 1:
                    wb.Close()
                    excel.Quit()
                    pythoncom.CoUninitialize()
                    return {
                        "successful": False,
                        "error": "VBA still protected (bypass failed)"
                    }
                
                self.vba_output_dir.mkdir(parents=True, exist_ok=True)
                
                extracted_modules = []
                
                # Iterate all VBA components
                for component in vba_project.VBComponents:
                    try:
                        module_name = component.Name
                        module_type = component.Type
                        
                        # Types: 1=Module, 2=ClassModule, 3=MSForm, 100=DocumentModule
                        type_map = {
                            1: "Module",
                            2: "ClassModule",
                            3: "UserForm",
                            100: "DocumentModule"
                        }
                        
                        # Get the code
                        code_module = component.CodeModule
                        if code_module.CountOfLines > 0:
                            code = code_module.Lines(1, code_module.CountOfLines)
                            
                            # Save to a file
                            safe_name = "".join(c if c.isalnum() or c in ('_', '-') else '_' for c in module_name)
                            file_ext = ".bas" if module_type in [1, 2] else ".frm" if module_type == 3 else ".cls"
                            output_file = self.vba_output_dir / f"{safe_name}{file_ext}"
                            
                            with open(output_file, 'w', encoding='utf-8') as f:
                                f.write(f"' Module: {module_name}\n")
                                f.write(f"' Type: {type_map.get(module_type, 'Unknown')}\n")
                                f.write(f"' Lines: {code_module.CountOfLines}\n")
                                f.write(f"' Extracted: {datetime.now()}\n")
                                f.write("' " + "="*60 + "\n\n")
                                f.write(code)
                            
                            extracted_modules.append({
                                "name": module_name,
                                "type": type_map.get(module_type, "Unknown"),
                                "lines": code_module.CountOfLines,
                                "file": str(output_file)
                            })
                            
                            self.logger.info(f"Module extracted: {module_name} ({code_module.CountOfLines} lines)")
                    
                    except Exception as e:
                        self.logger.debug(f"  • Error extracting module {component.Name}: {e}")
                
                wb.Close()
                excel.Quit()
                pythoncom.CoUninitialize()
                
                if extracted_modules:
                    self.evidence["generated_files"].extend(
                        item["file"] for item in extracted_modules
                    )
                    self.logger.info(f"{len(extracted_modules)} VBA modules extracted to: {self.vba_output_dir}")
                    return {
                        "successful": True,
                        "modules": extracted_modules,
                        "output_dir": str(self.vba_output_dir)
                    }
                else:
                    return {
                        "successful": False,
                        "error": "No modules with code were found"
                    }
            
            except Exception as e:
                wb.Close()
                excel.Quit()
                pythoncom.CoUninitialize()
                raise e
                
        except Exception as e:
            self.logger.error(f"Error extracting VBA: {e}")
            import traceback
            self.logger.debug(traceback.format_exc())
            return {"successful": False, "error": str(e)}
    
    def test_vba_protection_bypass(self) -> Dict[str, Any]:
        """
        Attempts VBA protection bypass through binary modification.
        Based on VBA password recovery techniques.
        """
        if self.file_path.suffix.lower() not in EXCEL_WITH_MACROS | EXCEL_BINARY | EXCEL_LEGACY:
            return {"successful": False, "error": "File does not contain VBA"}
        
        self.logger.info("Testing VBA protection bypass...")
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # For OOXML with macros (it is a ZIP)
                if self.file_path.suffix.lower() in EXCEL_WITH_MACROS:
                    return self._bypass_vba_xlsm(temp_path)
                # For .xlsb/.xls (binary format)
                else:
                    return self._bypass_vba_binary()
                    
        except Exception as e:
            self.logger.error(f"Error in VBA bypass: {e}")
            return {"successful": False, "error": str(e)}
    
    def _bypass_vba_xlsm(self, temp_path: Path) -> Dict[str, Any]:
        """VBA bypass for .xlsm files"""
        try:
            # Extract ZIP
            with zipfile.ZipFile(self._working_file(), 'r') as zip_ref:
                zip_ref.extractall(temp_path)
            
            vba_project = temp_path / "xl" / "vbaProject.bin"
            if not vba_project.exists():
                return {"successful": False, "error": "No VBA project"}
            
            # Read binary
            with open(vba_project, 'rb') as f:
                data = f.read()
            
            # Look for and replace protection markers
            # DPB= (Document Protection Binary)
            # CMG= (Code Module GUID)
            # GC= (General Configuration)
            modified = False
            
            # Technique 1: Replace DPB with DPx
            if b'DPB=' in data:
                data = data.replace(b'DPB=', b'DPx=')
                modified = True
                self.logger.info("DPB marker modified")
            
            # Technique 2: Replace CMG
            if b'CMG=' in data:
                data = data.replace(b'CMG=', b'CMx=')
                modified = True
                self.logger.info("CMG marker modified")
            
            # Technique 3: Modify GC
            if b'GC=' in data:
                data = data.replace(b'GC=', b'Gx=')
                modified = True
                self.logger.info("GC marker modified")
            
            if modified:
                # Save the modified vbaProject.bin
                with open(vba_project, 'wb') as f:
                    f.write(data)
                
                # Repackage
                with zipfile.ZipFile(self._working_file(), 'w', zipfile.ZIP_DEFLATED) as zip_out:
                    for file in temp_path.rglob('*'):
                        if file.is_file():
                            arcname = file.relative_to(temp_path)
                            zip_out.write(file, arcname)
                
                self.logger.warning("VULNERABILITY: VBA protection bypassed through binary modification")
                return {
                    "successful": True,
                    "method": "BINARY_MODIFICATION",
                    "markers_modified": ["DPB", "CMG", "GC"]
                }
            
            return {"successful": False, "error": "No protection markers were found"}
            
        except Exception as e:
            return {"successful": False, "error": str(e)}
    
    def _bypass_vba_binary(self) -> Dict[str, Any]:
        """VBA bypass for binary files (.xlsb, .xls)"""
        try:
            with open(self._working_file(), 'rb') as f:
                data = f.read()
            
            modified = False
            original_size = len(data)
            
            # Look for and replace markers in the whole binary file
            if b'DPB=' in data:
                data = data.replace(b'DPB=', b'DPx=')
                modified = True
            
            if b'CMG=' in data:
                data = data.replace(b'CMG=', b'CMx=')
                modified = True
            
            if modified:
                # Save the modified file
                with open(self._working_file(), 'wb') as f:
                    f.write(data)
                
                self.logger.warning("VULNERABILITY: VBA protection bypassed in binary file")
                return {
                    "successful": True,
                    "method": "BINARY_FILE_MODIFICATION",
                    "size_original": original_size,
                    "size_modified": len(data)
                }
            
            return {"successful": False, "error": "No protection markers were found"}
            
        except Exception as e:
            return {"successful": False, "error": str(e)}
    
    def write_bypass_evidence_marks(self, unprotected_sheets: List[str]) -> Dict[str, Any]:
        """
        Writes visible marks on the sheets that were successfully unprotected.
        This serves as visual evidence of the bypass.
        
        Args:
            unprotected_sheets: List of names of the sheets that were unprotected
            
        Returns:
            Dict with the result of the operation
        """
        if not WIN32COM_AVAILABLE:
            return {"successful": False, "error": "pywin32 not available"}
        
        if not unprotected_sheets:
            return {"successful": False, "error": "There are no unprotected sheets"}
        
        try:
            import pythoncom
            pythoncom.CoInitialize()
            
            self.logger.info(f"\nWriting evidence marks on {len(unprotected_sheets)} sheets...")
            
            excel = create_excel_application()
            excel.Visible = False
            excel.DisplayAlerts = False
            excel.EnableEvents = False
            excel.AskToUpdateLinks = False
            
            wb = excel.Workbooks.Open(str(self._working_file().absolute()), 
                                      ReadOnly=False,
                                      UpdateLinks = 0,
                                      IgnoreReadOnlyRecommended = True)
            
            marks_written = []
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")           # For result metadata
            
            for sheet_name in unprotected_sheets:
                try:
                    ws = wb.Worksheets(sheet_name)
                    
                    # Step 1: Unprotect the sheet (if it is still protected)
                    was_protected = ws.ProtectContents
                    if was_protected:
                        try:
                            ws.Unprotect()  # Without a password (it was already bypassed)
                            self.logger.info(f"Sheet '{sheet_name}' unprotected")
                        except:
                            self.logger.warning(f"Could not unprotect '{sheet_name}' (it may already be unprotected)")
                    
                    # Step 2: Insert the evidence image (or fallback text if the image is missing)
                    self._mark_with_image_or_text(
                        ws, IMAGE_BYPASS,
                        '*** VVULNERABILITY***'
                    )
                    
                    # Step 3: Re-protect the sheet WITHOUT a password
                    # This demonstrates that protection without a password is useless
                    if was_protected:
                        ws.Protect(
                            DrawingObjects=True,
                            Contents=True,
                            Scenarios=True,
                            AllowFormattingCells=False,
                            AllowFormattingColumns=False,
                            AllowFormattingRows=False
                        )  # Without a Password parameter = without a password
                        self.logger.warning(f"Sheet '{sheet_name}' RE-PROTECTED without a password (VULNERABLE)")
                    
                    marks_written.append(sheet_name)
                    self.logger.info(f"Mark written on: {sheet_name}")
                    
                except Exception as e:
                    self.logger.warning(f"Error writing on '{sheet_name}': {e}")
            
            # Save the file with marks
            wb.Save()
            wb.Close()
            excel.Quit()
            pythoncom.CoUninitialize()
            
            if marks_written:
                self.logger.info(f"Evidence marks written on {len(marks_written)} sheets")
                self.logger.warning(f"IMPORTANT: Sheets RE-PROTECTED without a password (vulnerability demonstration)")
                return {
                    "successful": True,
                    "marked_sheets": marks_written,
                    "timestamp": timestamp,
                    "re_protected_without_password": True,
                    "note": "Sheets unprotected, marked and re-protected WITHOUT a password to evidence the vulnerability"
                }
            else:
                return {
                    "successful": False,
                    "error": "Marks could not be written on any sheet"
                }
        
        except Exception as e:
            self.logger.error(f"Error writing evidence marks: {e}")
            return {"successful": False, "error": str(e)}
        
    def get_evidence(self) -> Dict[str, Any]:
        """
        Returns the evidence generated during the bypass test
        """
        return {
            "bypass": {
                "screenshots": self.evidence.get("screenshots", []),
                "capture_methods": self.evidence.get("capture_methods", {}),
                "generated_files": self.evidence.get("generated_files", []),
                "backup_original": self.evidence.get("backup_original")
            }
        }

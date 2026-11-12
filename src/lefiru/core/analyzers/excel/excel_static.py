"""
Static analyzer for Excel files (cross-platform mode)

Uses openpyxl for OOXML formats (.xlsx, .xlsm, .xltx, .xltm, .xlam) and
pyxlsb for .xlsb.
"""

import logging
from pathlib import Path
from typing import Dict, List, Any
import zipfile
import re
import posixpath
import xml.etree.ElementTree as ET

try:
    import openpyxl
    from openpyxl.utils import get_column_letter
    from openpyxl.workbook.protection import WorkbookProtection
    OPENPYXL_AVAILABLE = True
except ImportError:
    OPENPYXL_AVAILABLE = False

from lefiru.core.analyzers.excel import evidence_capture as evidence

try:
    from pyxlsb import open_workbook as open_xlsb
    PYXLSB_AVAILABLE = True
except ImportError:
    PYXLSB_AVAILABLE = False

from lefiru.core.catalog import EXCEL_BINARY, EXCEL_WITH_MACROS, EXCEL_OOXML, EXCEL_WITHOUT_MACROS
from lefiru.core.analysis_support import is_critical_sheet


class StaticWorkbookInspector:
    """Static analyzer for Excel files"""

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
    
    def __init__(self, file_path: Path, output_root: Path,):
        self.file_path = file_path
        self.logger = logging.getLogger(__name__)
        self.file_type = file_path.suffix.lower()
        self.output_root = Path(output_root)
        self.evidence_dir = self.output_root / "reports" / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.vba_export_dir = self.evidence_dir / "vba"
        self.vba_export_dir.mkdir(parents=True, exist_ok=True)
        
        # Check library availability
        if self.file_type in EXCEL_OOXML and not OPENPYXL_AVAILABLE:
            raise ImportError("openpyxl is not installed. Run: pip install openpyxl")
        
        if self.file_type in EXCEL_BINARY and not PYXLSB_AVAILABLE:
            raise ImportError("pyxlsb is not installed. Run: pip install pyxlsb")
    
    def check_workbook_protection(self) -> Dict[str, Any]:
        """Check workbook and sheet protections"""
        self.logger.info("Analyzing workbook and worksheet protections...")
        
        if self.file_type in EXCEL_OOXML:
            return self._check_protection_openpyxl()
        elif self.file_type in EXCEL_BINARY:
            return self._check_protection_xlsb()
        else:
            return {"error": "Unsupported file type"}
    
    @staticmethod
    def _map_sheet_visibility(state: str) -> str:
        mapping = {
            "visible": "VISIBLE",
            "hidden": "HIDDEN",
            "veryHidden": "VERY_HIDDEN"
        }
        return mapping.get(state, f"UNKNOWN({state})")
    
    def _check_protection_openpyxl(self) -> Dict[str, Any]:
        """Check protections using openpyxl"""
        try:
            wb = openpyxl.load_workbook(self.file_path, read_only=False, keep_vba=True)
            
            # Workbook protection
            workbook_protected = wb.security is not None and wb.security.workbookPassword is not None
            
            # Sheet information
            sheets_info = []
            critical_sheets_without_protection = []
            total_sheets = len(wb.sheetnames)
            protected_sheets = 0
            
            for sheet_name in wb.sheetnames:
                ws = wb[sheet_name]
                is_protected = ws.protection.sheet
                is_critical = is_critical_sheet(sheet_name)
                
                sheets_info.append({
                    "name": sheet_name,
                    "protected": is_protected,
                    "critical": is_critical,
                    "visible": self._map_sheet_visibility(ws.sheet_state)
                })
                
                if is_protected:
                    protected_sheets += 1
                
                if is_critical and not is_protected:
                    critical_sheets_without_protection.append(sheet_name)
            
            wb.close()
            
            self.logger.info(f"Workbook protected: {workbook_protected}")
            self.logger.info(f"Protected sheets: {protected_sheets}/{total_sheets}")
            if critical_sheets_without_protection:
                self.logger.warning(f"Critical sheets without protection: {critical_sheets_without_protection}")
            
            return {
                "protected_workbook": workbook_protected,
                "total_sheets": total_sheets,
                "protected_sheets": protected_sheets,
                "critical_sheets_without_protection": critical_sheets_without_protection,
                "sheet_details": sheets_info,
                "method": "openpyxl"
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing protections: {str(e)}")
            return {
                "error": str(e),
                "method": "openpyxl"
            }
    
    def _check_protection_xlsb(self) -> Dict[str, Any]:
        """Check protections in .xlsb files"""
        try:
            sheets_info = []
            critical_sheets_without_protection = []
            
            with open_xlsb(self.file_path) as wb:
                sheet_names = wb.sheets
                total_sheets = len(sheet_names)
                protected_sheets = 0
                
                for sheet_name in sheet_names:
                    is_critical = is_critical_sheet(sheet_name)
                    # pyxlsb has limited support for detecting protection
                    # We assume that if we can read it, deeper analysis is needed
                    
                    sheets_info.append({
                        "name": sheet_name,
                        "protected": None,  # Not easily determinable with pyxlsb
                        "critical": is_critical,
                        "visible": True
                    })
                    
                    if is_critical:
                        critical_sheets_without_protection.append(sheet_name)
            
            self.logger.warning(".xlsb: Protection detection limited in static mode")
            self.logger.info(f"Total sheets: {total_sheets}")
            
            return {
                "protected_workbook": None,  # Not determinable
                "total_sheets": total_sheets,
                "protected_sheets": None,
                "critical_sheets_without_protection": critical_sheets_without_protection,
                "sheet_details": sheets_info,
                "method": "pyxlsb",
                "limitation": "Limited protection analysis in static .xlsb. Use COM mode."
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing .xlsb: {str(e)}")
            return {
                "error": str(e),
                "method": "pyxlsb"
            }
    
    def check_vba_protection(self) -> Dict[str, Any]:
        """Check protection and extract VBA metadata"""
        self.logger.info("Analyzing VBA project...")
        
        if self.file_type in EXCEL_WITHOUT_MACROS:
            self.logger.info("File %s: Contains no macros", self.file_type)
            return {
                "has_vba": False,
                "protected_project": None,
                "accessible_code": False,
                "status": "NOT_APPLICABLE"
            }
        
        # For the remaining macro-enabled formats, try to extract VBA information
        return self._check_vba_static()
    
    def _check_vba_static(self) -> Dict[str, Any]:
        """Static VBA analysis from the Excel ZIP"""
        try:
            # Macro-enabled OOXML workbooks are ZIPs containing vbaProject.bin
            if self.file_type not in EXCEL_WITH_MACROS:
                return {
                    "has_vba": None,
                    "protected_project": None,
                    "accessible_code": False,
                    "status": "MODE_STATIC_LIMITED",
                    "note": "Full VBA analysis requires COM mode"
                }
            
            with zipfile.ZipFile(self.file_path, 'r') as zip_ref:
                # Look for vbaProject.bin
                vba_files = [f for f in zip_ref.namelist() if 'vbaProject.bin' in f]
                
                if not vba_files:
                    self.logger.info("vbaProject.bin not found")
                    return {
                        "has_vba": False,
                        "protected_project": None,
                        "accessible_code": False,
                        "status": "WITHOUT_MACROS"
                    }
                
                # Extract basic information from vbaProject.bin
                vba_file = vba_files[0]
                vba_data = zip_ref.read(vba_file)
                vba_size = len(vba_data)
                
                # Look for protection signatures in the binary
                # Protected VBA projects contain specific patterns
                is_protected = self._detect_vba_protection_signature(vba_data)
                
                # Try to extract modules with oletools (if available)
                modules = self._extract_vba_modules_static(vba_data)
                
                self.logger.info(f"VBA detected: {vba_size} bytes")
                self.logger.info(f"Protection detected: {is_protected}")
                
                return {
                    "has_vba": True,
                    "protected_project": is_protected,
                    "accessible_code": not is_protected,
                    "vba_size_bytes": vba_size,
                    "modules": modules,
                    "method": "static_analysis",
                    "note": "Limited analysis. For full extraction use COM mode"
                }
                
        except Exception as e:
            self.logger.error(f"Error analyzing VBA: {str(e)}")
            return {
                "has_vba": None,
                "error": str(e),
                "status": "ERROR"
            }
    
    def _detect_vba_protection_signature(self, vba_data: bytes) -> bool:
        """
        Detects protection signatures in vbaProject.bin
        Protected projects have specific patterns in the binary
        """
        # Look for common VBA protection patterns
        protection_patterns = [
            b'DPB=',  # VBA protection signature
            b'CMG=',  # Protection pattern
            b'GC=',   # Another pattern
        ]
        
        for pattern in protection_patterns:
            if pattern in vba_data:
                return True
        
        return False
    
    def _export_vba_module(self, module_name: str, code: str) -> str:
        """Export a VBA module to a .bas file
        
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
            
            self.logger.info(f"VBA module exported: {filepath.name}")
            return str(filepath)
            
        except Exception as e:
            self.logger.warning(f"Could not export VBA module: {e}")
            return None
    
    def _create_code_screenshot(self, module_name: str, code: str) -> str:
        """Renders the extracted VBA source as a PNG.

        Uses the shared renderer: no Excel, no window and no VBA trust setting.
        The header states that the image is a rendering of the source and not a
        screen capture.
        """
        try:
            filepath = self.evidence_dir / f"{self.file_path.stem}_vba_{module_name}.png"
            return evidence.render_code_png(
                module_name,
                code,
                filepath,
                source_name=self.file_path.name,
            )
        except Exception as e:
            self.logger.warning(f"Could not create code image: {e}")
            return None

    def _extract_vba_modules_static(self, vba_data: bytes) -> Dict[str, Any]:
        """Try to extract VBA modules using oletools"""
        try:
            # Try to import oletools if available
            from oletools.olevba import VBA_Parser
            import io
            
            vba_file = io.BytesIO(vba_data)
            vba_parser = VBA_Parser(self.file_path)
            
            modules = {}
            if vba_parser.detect_vba_macros():
                self.logger.info("VBA code detected (protected project)")
                
                for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                    modules[vba_filename] = {
                        "name": vba_filename,
                        "lines": len(vba_code.split('\n')) if vba_code else 0,
                        "code": vba_code,
                        "stream": stream_path,
                        "file_exported": None,
                        "image_exported": None
                    }
                    
                    # Export the module to a .bas file and generate a visual capture
                    if vba_code and len(vba_code.strip()) > 0:
                        file_exported = self._export_vba_module(vba_filename, vba_code)
                        image_exported = self._create_code_screenshot(vba_filename, vba_code)
                        modules[vba_filename]["file_exported"] = file_exported
                        modules[vba_filename]["image_exported"] = image_exported
                        self.logger.info(f"Extracted: {vba_filename} ({modules[vba_filename]['lines']} lines)")
            
            vba_parser.close()
            
            return modules
            
        except ImportError:
            self.logger.warning("oletools not available. Install with: pip install oletools")
            return {}
        except Exception as e:
            self.logger.warning(f"Could not extract VBA modules: {str(e)}")
            return {}
    
    def check_external_connections(self) -> Dict[str, Any]:
        """Check external connections and links"""
        self.logger.info("Checking external connections...")
        
        if self.file_type in EXCEL_OOXML:
            return self._check_external_openpyxl()
        else:
            return {
                "external_links": [],
                "data_connections": [],
                "defined_names": [],
                "note": "Limited analysis in static .xlsb"
            }
    
    def _check_external_openpyxl(self) -> Dict[str, Any]:
        """Check external connections with openpyxl"""
        try:
            wb = openpyxl.load_workbook(self.file_path, read_only=True, keep_links=True)
            
            external_links = []
            defined_names = []
            locations = []
            
            # Defined names (may contain external references)
            if wb.defined_names:
                for name, defn in wb.defined_names.items():
                    if defn.value and ('[' in str(defn.value) or 'http' in str(defn.value).lower()):
                        record = {
                            "name": name,
                            "definition": str(defn.value)[:100]  # Truncate
                        }

                        match = re.search(r"(?:\[[^\]]+\])?([^!]+)!([\$A-Z]+\$?\d+(?::[\$A-Z]+\$?\d+)?)", str(defn.value))
                        if match:
                            sheet = match.group(1).strip("'")
                            cell = match.group(2)
                            record["sheet"] = sheet
                            record["cell"] = cell
                            record["code_line"] = f"{sheet}!{cell}"

                        defined_names.append(record)
                        locations.append(record)
            
            # Look for formulas with external references and locate sheet/cell.
            # Fast path: parse the internal XML (only cells with a formula)
            # Fallback: openpyxl iteration per sheet when coverage cannot be guaranteed.
            links_from_xml, fallback_sheets = self._scan_external_formulas_xml()
            for sheet_name in wb.sheetnames:
                xml_records = links_from_xml.get(sheet_name, [])
                if xml_records:
                    external_links.extend(xml_records)
                    locations.extend(xml_records)

            for sheet_name in fallback_sheets:
                if sheet_name not in wb.sheetnames:
                    continue
                ws = wb[sheet_name]
                fallback_records = self._scan_external_formulas_openpyxl_sheet(ws, sheet_name)
                external_links.extend(fallback_records)
                locations.extend(fallback_records)
            
            wb.close()
            
            self.logger.info(f"Defined names with external references: {len(defined_names)}")
            self.logger.info(f"Connection locations detected: {len(locations)}")
            
            return {
                "external_links": external_links,
                "data_connections": [],  # Requires internal XML analysis
                "defined_names": defined_names,
                "locations": locations,
                "total_external": len(external_links) + len(defined_names),
                "method": "openpyxl"
            }
            
        except Exception as e:
            self.logger.error(f"Error checking connections: {str(e)}")
            return {
                "error": str(e)
            }

    @classmethod
    def _is_external_reference(cls, value: str) -> bool:
        if not value:
            return False
        content = str(value).lower()
        return any(pattern in content for pattern in cls._EXTERNAL_CONN_PATTERNS)

    def _scan_external_formulas_openpyxl_sheet(self, ws: Any, sheet_name: str) -> List[Dict[str, Any]]:
        """Conservative fallback: openpyxl scan for a single sheet."""
        records: List[Dict[str, Any]] = []
        max_row = ws.max_row or 0
        max_col = ws.max_column or 0
        if max_row <= 0 or max_col <= 0:
            return records

        for row_idx, row in enumerate(
            ws.iter_rows(
                min_row=1,
                max_row=max_row,
                min_col=1,
                max_col=max_col,
                values_only=True,
            ),
            start=1,
        ):
            for col_idx, formula in enumerate(row, start=1):
                if not isinstance(formula, str):
                    continue
                if not formula.startswith("="):
                    continue
                if not self._is_external_reference(formula):
                    continue

                cell = f"{get_column_letter(col_idx)}{row_idx}"
                records.append(
                    {
                        "type": "FormulaExternalRef",
                        "sheet": sheet_name,
                        "cell": cell,
                        "formula": formula[:180],
                        "code_line": f"{sheet_name}!{cell}: {formula[:140]}",
                    }
                )

        return records

    def _scan_external_formulas_xml(self) -> (Dict[str, List[Dict[str, Any]]], List[str]):
        """
        Fast scan of the workbook's internal XML.
        Returns:
          - records by sheet
          - sheets that require the openpyxl fallback to keep coverage
        """
        records_by_sheet: Dict[str, List[Dict[str, Any]]] = {}
        fallback_sheets: List[str] = []

        try:
            with zipfile.ZipFile(self.file_path, "r") as zf:
                sheet_paths = self._map_sheet_name_to_xml_path(zf)
                for sheet_name, xml_path in sheet_paths.items():
                    try:
                        sheet_records, needs_fallback = self._scan_sheet_xml_for_external_formulas(zf, xml_path, sheet_name)
                        records_by_sheet[sheet_name] = sheet_records
                        if needs_fallback:
                            fallback_sheets.append(sheet_name)
                    except Exception:
                        fallback_sheets.append(sheet_name)
        except Exception:
            return {}, []

        return records_by_sheet, fallback_sheets

    def _map_sheet_name_to_xml_path(self, zf: zipfile.ZipFile) -> Dict[str, str]:
        """Map a sheet name to its internal XML path (xl/worksheets/sheetN.xml)."""
        mapping: Dict[str, str] = {}

        workbook_xml = ET.fromstring(zf.read("xl/workbook.xml"))
        rels_xml = ET.fromstring(zf.read("xl/_rels/workbook.xml.rels"))

        rel_by_id: Dict[str, str] = {}
        for rel in rels_xml.iter():
            if not rel.tag.endswith("Relationship"):
                continue
            rel_id = rel.attrib.get("Id")
            target = rel.attrib.get("Target")
            if not rel_id or not target:
                continue
            rel_by_id[rel_id] = target

        for sheet in workbook_xml.iter():
            if not sheet.tag.endswith("sheet"):
                continue
            sheet_name = sheet.attrib.get("name")
            rel_id = sheet.attrib.get("{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id")
            if not sheet_name or not rel_id:
                continue

            target = rel_by_id.get(rel_id)
            if not target:
                continue
            xml_path = posixpath.normpath(posixpath.join("xl", target))
            mapping[sheet_name] = xml_path

        return mapping

    def _scan_sheet_xml_for_external_formulas(
        self,
        zf: zipfile.ZipFile,
        xml_path: str,
        sheet_name: str,
    ) -> (List[Dict[str, Any]], bool):
        """Scan a sheet's XML and detect external references in formulas."""
        records: List[Dict[str, Any]] = []
        shared_formulas: Dict[str, str] = {}
        needs_fallback = False

        if xml_path not in zf.namelist():
            return records, True

        root = ET.fromstring(zf.read(xml_path))
        for cell in root.iter():
            if not cell.tag.endswith("c"):
                continue
            cell_ref = cell.attrib.get("r", "")
            if not cell_ref:
                continue

            formula_node = None
            for child in cell:
                if child.tag.endswith("f"):
                    formula_node = child
                    break
            if formula_node is None:
                continue

            formula_type = formula_node.attrib.get("t")
            shared_index = formula_node.attrib.get("yes")
            formula_text = (formula_node.text or "").strip()

            if formula_type == "shared":
                if formula_text:
                    if shared_index is not None:
                        shared_formulas[shared_index] = formula_text
                else:
                    if shared_index is None or shared_index not in shared_formulas:
                        needs_fallback = True
                        continue
                    formula_text = shared_formulas[shared_index]

            if not formula_text:
                continue

            formula_full = f"={formula_text}"
            if not self._is_external_reference(formula_full):
                continue

            records.append(
                {
                    "type": "FormulaExternalRef",
                    "sheet": sheet_name,
                    "cell": cell_ref,
                    "formula": formula_full[:180],
                    "code_line": f"{sheet_name}!{cell_ref}: {formula_full[:140]}",
                }
            )

        return records, needs_fallback
    
    def close(self):
        """Release resources (not necessary in static mode)"""
        pass

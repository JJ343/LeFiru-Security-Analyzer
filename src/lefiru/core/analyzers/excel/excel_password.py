"""
Detector of password protections in Excel files
"""

import logging
from pathlib import Path
from typing import Dict, Any, Optional
import struct
import zipfile

from lefiru.core.catalog import EXCEL_BINARY, EXCEL_LEGACY, EXCEL_OOXML

try:
    import olefile
except ImportError:
    olefile = None


class OpenPasswordDetector:
    """Detects whether an Excel file is protected with an opening password"""
    
    def __init__(self, file_path: Path):
        self.file_path = Path(file_path)
        self.logger = logging.getLogger(__name__)
    
    def detect_password_protection(self) -> Dict[str, Any]:
        """
        Detects whether the file has an opening password
        
        Returns:
            Dict with protection information
        """
        result = {
            "has_password": False,
            "protection_type": None,
            "detection_method": None,
            "encrypted": False,
            "message": None
        }
        
        suffix = self.file_path.suffix.lower()

        if suffix in EXCEL_OOXML:
            return self._detect_ooxml_password(result)
        elif suffix in EXCEL_BINARY:
            return self._detect_xlsb_password(result)
        elif suffix in EXCEL_LEGACY:
            return self._detect_xls_password(result)
        else:
            result["message"] = f"Format {suffix} not supported for detection"
            return result

    def _is_ole2_container(self) -> bool:
        """Detects the OLE2 signature (Compound File Binary)."""
        try:
            with open(self.file_path, 'rb') as f:
                header = f.read(8)
            return header == b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'
        except Exception:
            return False

    def _has_ooxml_encryption_markers(self) -> bool:
        """Detects OOXML encryption inside an OLE2 container via streams or binary markers."""
        if olefile is not None:
            try:
                with olefile.OleFileIO(str(self.file_path)) as ole:
                    if ole.exists("EncryptedPackage") or ole.exists("EncryptionInfo"):
                        return True
            except Exception:
                pass

        try:
            with open(self.file_path, 'rb') as f:
                head = f.read(32768)
            return (b'EncryptedPackage' in head) or (b'EncryptionInfo' in head)
        except Exception:
            return False
    
    def _detect_ooxml_password(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Detects a password in OOXML files (.xlsx/.xlsm/.xltx/.xltm/.xlam)"""
        try:
            # Try to open it as a ZIP
            with zipfile.ZipFile(self.file_path, 'r') as zip_ref:
                # If we get here, it does NOT have opening encryption
                # workbookProtection is INTERNAL protection, it does not block opening the file
                result["message"] = "No opening encryption detected"
                result["has_password"] = False
                result["encrypted"] = False
                
                return result
                
        except zipfile.BadZipFile:
            # Not a valid ZIP. It may be an encrypted OOXML (OLE+EncryptedPackage)
            # or a legacy / mislabeled file.
            if self._is_ole2_container():
                if self._has_ooxml_encryption_markers():
                    result["has_password"] = True
                    result["protection_type"] = "file_encryption"
                    result["detection_method"] = "ole_encrypted_package"
                    result["encrypted"] = True
                    result["message"] = "OOXML file encrypted with an opening password"
                    return result

                result["has_password"] = False
                result["protection_type"] = None
                result["detection_method"] = "ole_legacy_container"
                result["encrypted"] = False
                result["message"] = "OLE container detected without OOXML encryption markers"
                return result

            result["has_password"] = True
            result["protection_type"] = "file_encryption"
            result["detection_method"] = "zip_failure"
            result["encrypted"] = True
            result["message"] = "File is not a ZIP; possible opening encryption"
            return result
        except Exception as e:
            result["message"] = f"Error detecting protection: {str(e)}"
            return result
    
    def _detect_xlsb_password(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Detects a password in .xlsb files"""
        try:
            # .xlsb is also a ZIP, but with binary content
            with zipfile.ZipFile(self.file_path, 'r') as zip_ref:
                # If it can be opened as a ZIP, it has no opening encryption
                # workbookProtection is INTERNAL protection, it does not block opening the file
                result["message"] = "No opening encryption detected"
                result["has_password"] = False
                result["encrypted"] = False
                
                return result
                
        except zipfile.BadZipFile:
            if self._is_ole2_container() and self._has_ooxml_encryption_markers():
                result["has_password"] = True
                result["protection_type"] = "file_encryption"
                result["detection_method"] = "ole_encrypted_package"
                result["encrypted"] = True
                result["message"] = "OOXML file encrypted with an opening password"
                return result

            # If there is no OOXML encryption marker, do not flag it as encrypted at opening.
            result["has_password"] = False
            result["protection_type"] = None
            result["detection_method"] = "zip_failure_non_encrypted"
            result["encrypted"] = False
            result["message"] = "File is not a ZIP and has no OOXML encryption markers"
            return result
        except Exception as e:
            result["message"] = f"Error detecting protection: {str(e)}"
            return result
    
    def _detect_xls_password(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Detects a password in .xls files (old binary format)"""
        try:
            with open(self.file_path, 'rb') as f:
                # Read the first bytes
                header = f.read(8)
                
                # XLS files start with a specific signature
                # If the file is encrypted, the signature is different
                if header[:2] == b'\xD0\xCF':  # OLE2 compound document
                    # Look for the protection record
                    f.seek(0)
                    content = f.read(2048)  # Read the first 2KB
                    
                    # FilePass record = 0x002F
                    if b'\x2F\x00' in content:
                        result["has_password"] = True
                        result["protection_type"] = "file_encryption"
                        result["detection_method"] = "ole2_filepass_record"
                        result["encrypted"] = True
                        result["message"] = "File encrypted with an opening password (XLS)"
                    else:
                        result["message"] = "No opening encryption detected (XLS)"
                else:
                    result["message"] = "Unrecognized XLS format"
                
                return result
                
        except Exception as e:
            result["message"] = f"Error detecting XLS protection: {str(e)}"
            return result


def test_detector():
    """Test function"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python password_detector.py <file.xlsx>")
        sys.exit(1)
    
    file_path = Path(sys.argv[1])
    detector = OpenPasswordDetector(file_path)
    result = detector.detect_password_protection()
    
    print("\n=== PASSWORD DETECTION ===")
    print(f"File: {file_path.name}")
    print(f"Has password: {result['has_password']}")
    print(f"Type: {result['protection_type']}")
    print(f"Encrypted: {result['encrypted']}")
    print(f"Method: {result['detection_method']}")
    print(f"Message: {result['message']}")


if __name__ == "__main__":
    test_detector()

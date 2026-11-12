"""
Security pattern detector for VBA code
Looks for insecure patterns: credentials, connections, dangerous commands
"""

import re
import logging
from typing import Dict, List, Any
from lefiru.core.analysis_support import anonymize_credential, sanitize_string


class UnsafePatternScanner:
    """Security pattern detector for VBA code"""
    
    # Insecure patterns to detect
    PATTERNS = {
        "credentials": [
            (r'password\s*=\s*["\']([^"\']+)["\']', "Hardcoded password"),
            (r'pwd\s*=\s*["\']([^"\']+)["\']', "Hardcoded password"),
            (r'passwd\s*=\s*["\']([^"\']+)["\']', "Hardcoded password"),
            (r'user\s*=\s*["\']([^"\']+)["\']', "Hardcoded user"),
            (r'username\s*=\s*["\']([^"\']+)["\']', "Hardcoded user"),
            (r'uid\s*=\s*["\']([^"\']+)["\']', "Hardcoded user ID"),
        ],
        "secrets": [
            (r'token\s*=\s*["\']([^"\']+)["\']', "Hardcoded token"),
            (r'api[_-]?key\s*=\s*["\']([^"\']+)["\']', "Hardcoded API key"),
            (r'secret\s*=\s*["\']([^"\']+)["\']', "Hardcoded secret"),
            (r'key\s*=\s*["\']([^"\']+)["\']', "Hardcoded key"),
        ],
        "connections": [
            (r'server\s*=\s*["\']([^"\']+)["\']', "Hardcoded server"),
            (r'data\s+source\s*=\s*["\']([^"\']+)["\']', "Hardcoded data source"),
            (r'initial\s+catalog\s*=\s*["\']([^"\']+)["\']', "Hardcoded database"),
            (r'connection\s+string\s*=\s*["\']([^"\']+)["\']', "Full connection string"),
            (r'Provider\s*=\s*["\']?([^;"\'\s]+)', "OLEDB/ODBC provider"),
        ],
        "dangerous_commands": [
            (r'Shell\s*\(', "Use of Shell()"),
            (r'CreateObject\s*\(\s*["\']WScript\.Shell["\']', "WScript.Shell"),
            (r'CreateObject\s*\(\s*["\']Shell\.Application["\']', "Shell.Application"),
            (r'Environ\s*\(', "Environment variable access"),
            (r'GetObject\s*\(', "GetObject (COM risk)"),
        ],
        "sql_injection": [
            (r'SELECT\s+.*\s+&\s+\w+', "Possible SQL injection (concatenation)"),
            (r'INSERT\s+INTO\s+.*\s+&\s+\w+', "Possible SQL injection (concatenation)"),
            (r'UPDATE\s+.*SET\s+.*\s+&\s+\w+', "Possible SQL injection (concatenation)"),
            (r'DELETE\s+FROM\s+.*\s+&\s+\w+', "Possible SQL injection (concatenation)"),
        ],
        "evasion": [
            (r'On\s+Error\s+Resume\s+Next', "Error suppression (risk)"),
            (r'Application\.EnableEvents\s*=\s*False', "Event disabling"),
            (r'Application\.ScreenUpdating\s*=\s*False', "Refresh disabling (normal, but review)"),
        ],
        "authentication": [
            (r'(?:Sub|Function)\s+(?:Login|Autenticar|Authenticate|ValidateUser|CheckPassword)\s*\(', "Login/authentication function"),
            (r'InputBox\s*\([^)]*(?:password|contraseña|pwd|clave)', "Password request via InputBox"),
            (r'Environ\s*\(\s*["\'](?:USERNAME|USERDOMAIN|USER)["\']', "System user retrieval"),
            (r'Application\.UserName', "Excel user name retrieval"),
            (r'CreateObject\s*\(\s*["\']WinHttp\.WinHttpRequest["\']', "Possible web authentication"),
        ],
        "access_control": [
            (r'(?:If|ElseIf)\s+.*(?:UserName|Usuario|User)\s*[=<>]', "User-based access control"),
            (r'(?:If|ElseIf)\s+.*(?:Role|Rol)\s*[=<>]', "Role-based access control"),
            (r'(?:Select\s+Case|Case)\s+.*(?:UserName|Usuario)', "User permission evaluation"),
            (r'(?:Array|Dim)\s*\([^)]*\)\s*As.*\bString.*=.*(?:Array|{).*(?:admin|user|guest)', "User/role list"),
        ],
        "traceability": [
            (r'(?:Sub|Function)\s+(?:Log|Registrar|WriteLog)\s*\(', "Logging function"),
            (r'Open\s+[^F]+For\s+(?:Append|Output)', "File write (possible log)"),
            (r'Debug\.Print.*(?:User|Accion|Action|Evento)', "User action debug output"),
            (r'Application\.(?:OnTime|OnKey)', "Timed/key event registration"),
            (r'Workbook_(?:Open|BeforeClose|BeforeSave)', "Event handlers (open/close)"),
        ],
        "missing_authentication": [
            (r'Workbook_Open\s*\(\s*\)', "Workbook_Open without user validation"),
            (r'Auto_Open\s*\(\s*\)', "Auto_Open without validation"),
        ]
    }
    
    def __init__(self, modules: Dict[str, Any]):
        """
        Initializes the detector
        
        Args:
            modules: Dictionary with the extracted VBA modules
        """
        self.modules = modules
        self.logger = logging.getLogger(__name__)
    
    def scan_patterns(self) -> Dict[str, Any]:
        """
        Scans all modules for insecure patterns
        
        Returns:
            Dictionary with findings by category
        """
        self.logger.info("Scanning security patterns in VBA code...")
        
        results = {
            "total_modules": len(self.modules),
            "modules_analyzed": 0,
            "findings_by_category": {},
            "findings_by_module": {},
            "found_secrets": 0,
            "critical": 0,
            "warnings": 0,
            "summary": []
        }
        
        
        if not self.modules:
            self.logger.warning("No modules to analyze")
            return results
        
        # Scan each module
        for module_name, module_data in self.modules.items():
            code = module_data.get("code")
            
            if not code:
                continue
            
            results["modules_analyzed"] += 1
            module_findings = self._scan_module(module_name, code)
            
            if module_findings["total"] > 0:
                results["findings_by_module"][module_name] = module_findings
        
        # Consolidate findings by category
        for module_name, findings in results["findings_by_module"].items():
            for category, items in findings["categories"].items():
                if category not in results["findings_by_category"]:
                    results["findings_by_category"][category] = []
                
                results["findings_by_category"][category].extend(items)
        
        # Count severities
        for category, items in results["findings_by_category"].items():
            if category in ["credentials", "secrets"]:
                    results["critical"] += len(items)
                    results["found_secrets"] += len(items)

            elif category in ["connections", "sql_injection"]:
                results["critical"] += len(items)

            else:
                results["warnings"] += len(items)
        
        # Check for security mechanisms present
        results["mechanisms_security"] = self._check_security_mechanisms(results)
        
        # Generate summary
        self._generate_summary(results)
        
        return results
    
    def _scan_module(self, module_name: str, code: str) -> Dict[str, Any]:
        """
        Scans one specific module
        
        Args:
            module_name: Module name
            code: Module source code
        
        Returns:
            Module findings
        """
        findings = {
            "name": module_name,
            "code_lines": len(code.split('\n')),
            "categories": {},
            "total": 0
        }
        
        # Split into lines for numbering
        lines = code.split('\n')
        
        # Scan each pattern category
        for category, patterns in self.PATTERNS.items():
            findings["categories"][category] = []
            
            for pattern, description in patterns:
                regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                
                # Search within each line
                for i, line in enumerate(lines, start=1):
                    matches = regex.finditer(line)
                    
                    for match in matches:
                        # Anonymize the captured value if present
                        value_anonymized = None
                        if match.groups():
                            value_original = match.group(1)
                            value_anonymized = anonymize_credential(value_original)
                        
                        finding = {
                            "line": i,
                            "description": description,
                            "context": sanitize_string(line.strip(), 80),
                            "value_anonymized": value_anonymized
                        }
                        
                        findings["categories"][category].append(finding)
                        findings["total"] += 1
        
        if findings["total"] > 0:
            self.logger.warning(
                f"{module_name}: {findings['total']} finding(s) detected"
            )
        else:
            self.logger.info(f"{module_name}: No findings")
        
        return findings
    
    def _check_security_mechanisms(self, results: Dict[str, Any]) -> Dict[str, bool]:
        """
        Checks for the presence of security mechanisms
        
        Args:
            results: Scan results
            
        Returns:
            Dict indicating which mechanisms are present
        """
        findings_cat = results.get("findings_by_category", {})
        
        mechanisms = {
            "has_authentication": len(findings_cat.get("authentication", [])) > 0,
            "has_control_access": len(findings_cat.get("access_control", [])) > 0,
            "has_traceability": len(findings_cat.get("traceability", [])) > 0,
        }
        
        # Log the mechanisms found
        if mechanisms["has_authentication"]:
            self.logger.info("Authentication mechanism detected")
        else:
            self.logger.warning("NO authentication mechanism detected")
        
        if mechanisms["has_control_access"]:
            self.logger.info("User/role access control detected")
        else:
            self.logger.warning("NO access control detected")
        
        if mechanisms["has_traceability"]:
            self.logger.info("Traceability/logging system detected")
        else:
            self.logger.warning("NO traceability system detected")
        
        return mechanisms
    
    def _generate_summary(self, results: Dict[str, Any]):
        """Generates a summary of findings"""
        summary = []
        CATEGORIES_NO_CRITICAL = {
            "dangerous_commands",
            "evasion",
            "authentication",
            "access_control",
            "traceability",
            "missing_authentication",
        }

        
        CRITICAL_CATEGORIES = {
            "credentials",
            "secrets",
            "connections",
            "sql_injection",
        }
        
                
        total_findings = sum(
            len(items) for items in results["findings_by_category"].values()
        )
        
        # No findings
        
        if total_findings == 0:
            
            summary.append("No insecure patterns were detected in the VBA code")
            self.logger.info(
                "Analysis completed: No insecure patterns were detected in the VBA code"
            )
            results["summary"] = summary
            return
        
        # Summary by category
        self.logger.warning(f"TOTAL FINDINGS DETECTED: {total_findings}")
        for category, items in results["findings_by_category"].items():
            if items:
                count = len(items)
                summary.append(f"• {category.upper()}: {count} finding(s)")
                self.logger.warning(f"    - {category}: {count}")
        
        if results.get("critical", 0) > 0:
            self.logger.warning(
                f"CRITICAL: {results['critical']} "
                "critical security findings were detected in the VBA code:"
            )
            summary.append(
                f"CRITICAL: {results['found_secrets']} "
                "possible hardcoded credential(s) or secret(s)"
            )

            for module, module_data in results.get("findings_by_module", {}).items():
                for category in CRITICAL_CATEGORIES:
                    for h in module_data.get("categories", {}).get(category, []):
                        self.logger.warning(
                            f"  - [{module} | {category} | line {h['line']}] "
                            f"{h['description']} "
                            f"→ {h.get('value_anonymized', '')}"
                        )
                        self.logger.warning(
                            f"    Context: {h.get('context', 'N/A')}"
                        )
           



        if results.get("warnings", 0) > 0:  # Parentheses and comparison fixed
            # Header of the informational block
            self.logger.info(
                f"INFO: {results['warnings']} "
                "non-critical security findings were detected in the VBA code:"
            )

            # Individual detail for each non-critical finding
            for module, module_data in results.get("findings_by_module", {}).items():
                # Safely access the module's categories
                categories_module = module_data.get("categories", {})
                
                for category in CATEGORIES_NO_CRITICAL:
                    # Use .get() to avoid errors if the category does not exist in this module
                    for h in categories_module.get(category, []):
                        self.logger.info(
                            f"  - [{module} | {category} | line {h['line']}] "
                            f"{h['description']}"
                        )
                        self.logger.info(
                            f"    Context: {h.get('context', 'N/A').strip()}"
                        )



    
    @staticmethod
    def get_recommendations(results: Dict[str, Any]) -> List[str]:
        """
        Generates recommendations based on findings
        
        Args:
            results: Scan results
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        findings_cat = results.get("findings_by_category", {})
        
        if findings_cat.get("credentials") or findings_cat.get("secrets"):
            recommendations.append(
                "CRITICAL: Remove all hardcoded credentials and secrets. "
                "Use Windows Credential Manager or encrypted external configuration files."
            )
        
        if findings_cat.get("connections"):
            recommendations.append(
                "Externalize connection strings into configuration files. "
                "Do not include credentials in connection strings."
            )
        
        if findings_cat.get("dangerous_commands"):
            recommendations.append(
                "Review the use of Shell() and CreateObject. "
                "Validate all inputs before executing external commands."
            )
        
        if findings_cat.get("sql_injection"):
            recommendations.append(
                "HIGH RISK: Use parameterized queries (ADODB.Command with Parameters). "
                "Do not concatenate values directly into SQL."
            )
        
        if findings_cat.get("evasion"):
            recommendations.append(
                "Review the use of 'On Error Resume Next'. "
                "Implement explicit error handling."
            )
        
        # Check for missing security mechanisms
        mechanisms = results.get("mechanisms_security", {})
        
        if not mechanisms.get("has_authentication", False):
            recommendations.append(
                "RECOMMENDED: Implement an authentication mechanism to validate the user when opening the file. "
                "Consider Workbook_Open with InputBox or integration with Active Directory."
            )
        
        if not mechanisms.get("has_control_access", False):
            recommendations.append(
                "RECOMMENDED: Implement role/user-based access control. "
                "Different permissions for executors vs. developers."
            )
        
        if not mechanisms.get("has_traceability", False):
            recommendations.append(
                "RECOMMENDED: Implement a traceability system to record critical actions. "
                "Log changes with user, date and action performed."
            )
        
        if findings_cat.get("authentication"):
            recommendations.append(
                "INFO: Authentication code was detected. Verify that it uses secure methods "
                "(no hardcoded passwords, hashed passwords)."
            )
        
        if findings_cat.get("access_control"):
            recommendations.append(
                "INFO: Access control was detected. Verify that the validations are robust "
                "and cannot be easily bypassed."
            )
        
        if findings_cat.get("traceability"):
            recommendations.append(
                "INFO: A traceability system was detected. Verify that the logs are complete "
                "and immutable (append-only)."
            )
        
        if not recommendations:
            recommendations.append("No critical security patterns were detected.")
        
        return recommendations


# Helper function for testing
def test_patterns():
    """Test function to validate the patterns"""
    test_code = """
    Sub ConectarBD()
        Dim conn As Object
        Set conn = CreateObject("ADODB.Connection")
        
        ' Hardcoded credentials (BAD)
        Dim password As String
        password = "MiPassword123"
        
        Dim user As String
        user = "admin"
        
        ' Connection string with credentials (BAD)
        conn.ConnectionString = "Provider=SQLOLEDB;Data Source=servidor;Initial Catalog=BD;User ID=" & user & ";Password=" & password
        
        ' SQL with concatenation (INJECTION RISK)
        Dim sql As String
        sql = "SELECT * FROM Users WHERE Name = '" & userName & "'"
        
        ' Dangerous Shell
        Shell "cmd.exe /c dir"
        
        On Error Resume Next
    End Sub
    """
    
    modules = {
        "Module1": {
            "name": "Module1",
            "code": test_code,
            "lines": len(test_code.split('\n'))
        }
    }
    
    detector = UnsafePatternScanner(modules)
    results = detector.scan_patterns()
    
    print("\n=== TEST RESULTS ===")
    print(f"Total findings: {sum(len(items) for items in results['findings_by_category'].values())}")
    print(f"Critical: {results['critical']}")
    print(f"Warnings: {results['warnings']}")
    
    for category, items in results['findings_by_category'].items():
        if items:
            print(f"\n{category.upper()}: {len(items)}")
            for item in items[:3]:  # First 3
                print(f"  - Line {item['line']}: {item['description']}")


if __name__ == "__main__":
    test_patterns()

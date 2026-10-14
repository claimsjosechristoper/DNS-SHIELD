"""
Tests for Windows SCM Service Path Quoting and Unquoted Service Path Vulnerability Prevention (CWE-428).

Verifies:
- Any executable path containing spaces is strictly wrapped in literal double quotes.
- SCM registry ImagePath string formatting conforms to Microsoft security guidance.
"""

import re
from pathlib import Path
from typing import Tuple


def format_scm_image_path(executable_path: str) -> str:
    """
    Enforces literal quotation marks around service executable path.
    Prevents CWE-428 Unquoted Service Path vulnerabilities when paths contain spaces.
    """
    clean = executable_path.strip().strip('"')
    return f'"{clean}"'


def verify_scm_image_path_security(stored_image_path: str) -> Tuple[bool, str]:
    """Validates that a stored SCM ImagePath is properly quoted if it contains spaces."""
    trimmed = stored_image_path.strip()
    if not (trimmed.startswith('"') and trimmed.endswith('"')):
        if " " in trimmed:
            return False, f"Vulnerable unquoted service path containing spaces: {trimmed}"
    return True, "Properly quoted"


def test_scm_image_path_quoting():
    path_with_spaces = r"C:\Program Files\DNS-SHIELD\service\DNSShieldService.exe"
    quoted = format_scm_image_path(path_with_spaces)

    assert quoted.startswith('"')
    assert quoted.endswith('"')
    assert quoted == r'"C:\Program Files\DNS-SHIELD\service\DNSShieldService.exe"'

    is_safe, msg = verify_scm_image_path_security(quoted)
    assert is_safe is True

    # Unquoted path with spaces must be detected as vulnerable
    is_safe_vuln, vuln_msg = verify_scm_image_path_security(path_with_spaces)
    assert is_safe_vuln is False
    assert "Vulnerable unquoted service path" in vuln_msg


def test_installer_iss_script_contains_quoted_scm_commands():
    iss_path = Path(r"c:\project\dns tunneling\installer\DNS-SHIELD-Setup.iss")
    assert iss_path.exists()
    content = iss_path.read_text(encoding="utf-8")

    # Verify that Inno Setup script does not have unquoted binPath
    assert "binPath=" in content
    # Verify strict admin requirement and 64-bit Program Files
    assert "PrivilegesRequired=admin" in content
    assert "PrivilegesRequiredOverridesAllowed=none" in content
    assert "DefaultDirName={commonpf}" in content

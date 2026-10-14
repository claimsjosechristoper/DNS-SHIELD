"""
DNS-SHIELD Automated Build & Packaging Automation Script.

Compiles the background Windows SCM service and native Desktop application
into standalone Windows x64 executables using PyInstaller.
Executes test suite, records JUnit XML and raw pytest output, records git revision,
working tree status, execution logs, exit codes, and artifact hashes.
Attempts Inno Setup compilation if the compiler is present; otherwise documents the exact blocker.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

BASE_DIR = Path(__file__).resolve().parent
DIST_DIR = BASE_DIR / "dist"
BUILD_DIR = BASE_DIR / "build"
PYTHON_EXE = sys.executable
ISCC_DEFAULT_PATH = Path(r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe")


def compute_sha256(file_path: Path) -> str:
    """Computes the SHA-256 hexadecimal digest of a file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def get_git_revision() -> str:
    """Retrieves current git commit hash, or 'UNKNOWN' if not in git."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            check=True
        )
        return res.stdout.strip()
    except Exception:
        return "UNKNOWN"


def get_working_tree_status() -> str:
    """Retrieves working tree status via git status --porcelain."""
    try:
        res = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            check=True
        )
        return res.stdout.strip()
    except Exception:
        return "UNKNOWN"


def run_cmd(cmd: List[str]) -> Dict[str, Any]:
    print(f"[*] Running: {' '.join(cmd)}")
    start = time.time()
    res = subprocess.run(cmd, cwd=str(BASE_DIR), capture_output=True, text=True)
    duration = round(time.time() - start, 2)
    return {
        "command": cmd,
        "exit_code": res.returncode,
        "duration_seconds": duration,
        "stdout": res.stdout,
        "stderr": res.stderr,
    }


def build():
    print("==========================================================")
    print("  DNS-SHIELD REPRODUCIBLE PACKAGING PIPELINE")
    print("==========================================================")

    DIST_DIR.mkdir(parents=True, exist_ok=True)
    git_rev = get_git_revision()
    git_status = get_working_tree_status()
    build_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print(f"[*] Source Revision: {git_rev}")
    print(f"[*] Working Tree Modified: {'Yes' if git_status else 'Clean'}")
    print(f"[*] Build Timestamp: {build_time}")

    manifest: Dict[str, Any] = {
        "source_revision": git_rev,
        "working_tree_status": git_status,
        "build_timestamp": build_time,
        "python_version": sys.version,
        "automated_tests": {},
        "build_steps": [],
        "artifacts": {},
        "installer": {
            "status": "NOT_COMPILED",
            "blocker": None,
            "path": None,
            "sha256": None
        }
    }

    # 1. Execute Automated Test Suite & Record Evidence
    print("\n[1/4] Executing Automated Test Suite (JUnit XML & Raw Logs)...")
    junit_xml = DIST_DIR / "pytest_results.xml"
    raw_log = DIST_DIR / "pytest_raw_output.txt"
    test_cmd = [
        PYTHON_EXE, "-m", "pytest",
        "-v",
        f"--junitxml={junit_xml}"
    ]
    test_res = run_cmd(test_cmd)
    raw_log.write_text(test_res["stdout"] + "\n" + test_res["stderr"], encoding="utf-8")
    print(f"[+] Raw pytest output saved: {raw_log}")
    print(f"[+] JUnit XML results saved: {junit_xml}")

    manifest["automated_tests"] = {
        "exit_code": test_res["exit_code"],
        "duration_seconds": test_res["duration_seconds"],
        "junit_xml_path": str(junit_xml),
        "raw_output_path": str(raw_log),
        "passed": test_res["exit_code"] == 0,
    }

    if test_res["exit_code"] != 0:
        print(f"[-] Automated tests failed with exit code {test_res['exit_code']}!")
        print(test_res["stderr"][:1000])
        sys.exit(test_res["exit_code"])

    # 2. Compile Windows SCM Service
    print("\n[2/4] Compiling Windows SCM Service: DNSShieldService.exe...")
    service_cmd = [
        PYTHON_EXE, "-m", "PyInstaller",
        "--name", "DNSShieldService",
        "--onedir",
        "--noconfirm",
        "--clean",
        "--distpath", str(DIST_DIR),
        "--workpath", str(BUILD_DIR / "service"),
        "--hidden-import", "win32timezone",
        "--hidden-import", "win32service",
        "--hidden-import", "win32serviceutil",
        "--hidden-import", "win32event",
        "--hidden-import", "win32file",
        "--hidden-import", "win32pipe",
        "--hidden-import", "win32security",
        "--hidden-import", "cryptography",
        "--hidden-import", "hosted_management.policy_verifier",
        "--hidden-import", "wfp_manager",
        "--hidden-import", "network_manager",
        "--exclude-module", "pytest",
        "--exclude-module", "matplotlib",
        "--exclude-module", "scipy",
        "windows_service.py"
    ]
    step1 = run_cmd(service_cmd)
    manifest["build_steps"].append({
        "step": "compile_service",
        "command": " ".join(service_cmd),
        "exit_code": step1["exit_code"],
        "duration_seconds": step1["duration_seconds"]
    })
    if step1["exit_code"] != 0:
        print(f"[-] Service build failed with exit code {step1['exit_code']}!")
        print(step1["stderr"][:1000])
        sys.exit(step1["exit_code"])

    # 3. Compile Desktop Application
    print("\n[3/4] Compiling Desktop Control App: DNSShieldApp.exe...")
    app_cmd = [
        PYTHON_EXE, "-m", "PyInstaller",
        "--name", "DNSShieldApp",
        "--onedir",
        "--windowed",
        "--noconfirm",
        "--clean",
        "--distpath", str(DIST_DIR),
        "--workpath", str(BUILD_DIR / "app"),
        "--hidden-import", "tkinter",
        "--hidden-import", "tkinter.ttk",
        "--hidden-import", "network_manager",
        "--hidden-import", "local_ipc",
        "--hidden-import", "service_health",
        "--exclude-module", "pytest",
        "--exclude-module", "matplotlib",
        "desktop_app.py"
    ]
    step2 = run_cmd(app_cmd)
    manifest["build_steps"].append({
        "step": "compile_app",
        "command": " ".join(app_cmd),
        "exit_code": step2["exit_code"],
        "duration_seconds": step2["duration_seconds"]
    })
    if step2["exit_code"] != 0:
        print(f"[-] Desktop app build failed with exit code {step2['exit_code']}!")
        print(step2["stderr"][:1000])
        sys.exit(step2["exit_code"])

    # Copy blocklists into service dist
    service_dist = DIST_DIR / "DNSShieldService"
    data_dir = service_dist / "data" / "blocklists"
    data_dir.mkdir(parents=True, exist_ok=True)
    src_blocklists = BASE_DIR / "data" / "blocklists"
    if src_blocklists.exists():
        for f in src_blocklists.glob("*.txt"):
            shutil.copy(f, data_dir / f.name)

    # 4. Hash Executables
    print("\n[*] Calculating artifact hashes...")
    service_exe = service_dist / "DNSShieldService.exe"
    app_exe = DIST_DIR / "DNSShieldApp" / "DNSShieldApp.exe"

    if service_exe.exists():
        h_svc = compute_sha256(service_exe)
        manifest["artifacts"]["DNSShieldService.exe"] = {
            "path": str(service_exe),
            "size_bytes": service_exe.stat().st_size,
            "sha256": h_svc
        }
        print(f"    DNSShieldService.exe: {h_svc} ({service_exe.stat().st_size} bytes)")

    if app_exe.exists():
        h_app = compute_sha256(app_exe)
        manifest["artifacts"]["DNSShieldApp.exe"] = {
            "path": str(app_exe),
            "size_bytes": app_exe.stat().st_size,
            "sha256": h_app
        }
        print(f"    DNSShieldApp.exe:     {h_app} ({app_exe.stat().st_size} bytes)")

    # 5. Inno Setup Compilation Check
    print("\n[4/4] Checking for Inno Setup Compiler (ISCC.exe)...")
    iscc_path: Optional[Path] = None
    if ISCC_DEFAULT_PATH.exists():
        iscc_path = ISCC_DEFAULT_PATH
    else:
        sh_iscc = shutil.which("ISCC.exe")
        if sh_iscc:
            iscc_path = Path(sh_iscc)

    iss_file = BASE_DIR / "installer" / "DNS-SHIELD-Setup.iss"

    if iscc_path and iscc_path.exists():
        print(f"[*] Found Inno Setup compiler at: {iscc_path}")
        iscc_cmd = [str(iscc_path), str(iss_file)]
        step3 = run_cmd(iscc_cmd)
        manifest["build_steps"].append({
            "step": "compile_installer",
            "command": " ".join(iscc_cmd),
            "exit_code": step3["exit_code"],
            "duration_seconds": step3["duration_seconds"]
        })
        if step3["exit_code"] == 0:
            setup_exe = DIST_DIR / "DNS-SHIELD-Setup-x64.exe"
            if setup_exe.exists():
                h_setup = compute_sha256(setup_exe)
                manifest["installer"] = {
                    "status": "COMPILED",
                    "path": str(setup_exe),
                    "size_bytes": setup_exe.stat().st_size,
                    "sha256": h_setup
                }
                print(f"[+] Installer created: {setup_exe} (SHA-256: {h_setup})")
        else:
            manifest["installer"] = {
                "status": "COMPILATION_FAILED",
                "blocker": f"ISCC exited with code {step3['exit_code']}: {step3['stderr']}"
            }
            print(f"[-] Inno Setup compilation failed: {step3['stderr']}")
    else:
        blocker_msg = f"Inno Setup compiler (ISCC.exe) not found at '{ISCC_DEFAULT_PATH}' or in PATH."
        manifest["installer"] = {
            "status": "COMPILER_UNAVAILABLE",
            "blocker": blocker_msg,
            "required_command": f'& "{ISCC_DEFAULT_PATH}" "installer\\DNS-SHIELD-Setup.iss"'
        }
        print(f"[-] {blocker_msg}")
        print("    Installer compilation skipped. PyInstaller binaries are ready in dist/.")

    # Save Build Manifest
    manifest_path = DIST_DIR / "build_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"\n[+] Build manifest recorded: {manifest_path}")

    print("\n==========================================================")
    print("  PACKAGING PIPELINE SUMMARY")
    print(f"  Source Revision:    {git_rev}")
    print(f"  Working Tree State: {'Modified' if git_status else 'Clean'}")
    print(f"  Tests Passed:       {manifest['automated_tests'].get('passed')}")
    print(f"  Service Executable: {service_exe if service_exe.exists() else 'N/A'}")
    print(f"  App Executable:     {app_exe if app_exe.exists() else 'N/A'}")
    print(f"  Installer Status:   {manifest['installer']['status']}")
    if manifest['installer']['blocker']:
        print(f"  Installer Blocker:  {manifest['installer']['blocker']}")
    print("==========================================================")


if __name__ == "__main__":
    build()

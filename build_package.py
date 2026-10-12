"""
DNS-SHIELD Automated Build & Packaging Automation Script.

Compiles the background Windows SCM service and native Desktop application
into standalone Windows x64 executables using PyInstaller.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DIST_DIR = BASE_DIR / "dist"
BUILD_DIR = BASE_DIR / "build"

PYTHON_EXE = sys.executable


def run_cmd(cmd: list):
    print(f"[*] Running: {' '.join(cmd)}")
    res = subprocess.run(cmd, check=True)
    return res


def build():
    print("==========================================================")
    print("  DNS-SHIELD REPRODUCIBLE PACKAGING PIPELINE")
    print("==========================================================")

    # 1. Build Service Executable (Console / SCM service)
    print("\n[1/2] Compiling Windows SCM Service: DNSShieldService.exe...")
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
        "--exclude-module", "pytest",
        "--exclude-module", "matplotlib",
        "--exclude-module", "scipy",
        "windows_service.py"
    ]
    run_cmd(service_cmd)

    # 2. Build Desktop Application (Windowed GUI)
    print("\n[2/2] Compiling Desktop Control App: DNSShieldApp.exe...")
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
        "--exclude-module", "pytest",
        "--exclude-module", "matplotlib",
        "desktop_app.py"
    ]
    run_cmd(app_cmd)

    # Copy blocklists and recovery tools into service dist
    service_dist = DIST_DIR / "DNSShieldService"
    data_dir = service_dist / "data" / "blocklists"
    data_dir.mkdir(parents=True, exist_ok=True)

    src_blocklists = BASE_DIR / "data" / "blocklists"
    if src_blocklists.exists():
        for f in src_blocklists.glob("*.txt"):
            shutil.copy(f, data_dir / f.name)

    print("\n==========================================================")
    print("  BUILD COMPLETED SUCCESSFULLY")
    print(f"  Service Output: {DIST_DIR / 'DNSShieldService'}")
    print(f"  App Output:     {DIST_DIR / 'DNSShieldApp'}")
    print("==========================================================")


if __name__ == "__main__":
    build()

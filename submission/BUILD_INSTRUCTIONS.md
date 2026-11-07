# DNS-SHIELD: BUILD & COMPILATION INSTRUCTIONS

This document details the exact process for building DNS-SHIELD from the frozen source repository (Commit `2739e82d7a37dce2baf72f522d1a7368ceeb7de0`).

---

## 1. PREREQUISITES
- Windows 10/11 64-bit Workstation
- Python 3.12.10 (64-bit) installed and added to PATH
- Inno Setup 6.7.3 installed (Default: `C:\Users\claim\AppData\Local\Programs\Inno Setup 6\ISCC.exe`)
- Git for Windows

---

## 2. ENVIRONMENT SETUP
```powershell
# Clone or navigate to repository root
cd "c:\project\dns tunneling"

# Create and activate Python virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install required dependencies
pip install -r requirements.txt
pip install pyinstaller pytest python-docx
```

---

## 3. EXECUTE AUTOMATED REGRESSION TESTS
Before compiling release binaries, execute the full regression test suite:

```powershell
pytest --junitxml=dist/pytest_results.xml -v
```
Expected result: **95 passed** in ~11 seconds.

---

## 4. COMPILE STANDALONE EXECUTABLES (PyInstaller)

### 4.1 Compile Windows Service Binary (`DNSShieldService.exe`)
```powershell
pyinstaller --name DNSShieldService `
  --onedir --noconfirm --clean `
  --distpath dist --workpath build/service `
  --hidden-import win32timezone `
  --hidden-import win32service `
  --hidden-import win32serviceutil `
  --hidden-import win32event `
  --hidden-import win32file `
  --hidden-import win32pipe `
  --hidden-import win32security `
  --hidden-import cryptography `
  --hidden-import hosted_management.policy_verifier `
  --hidden-import wfp_manager `
  --hidden-import network_manager `
  --exclude-module pytest `
  --exclude-module matplotlib `
  --exclude-module scipy `
  windows_service.py
```

### 4.2 Compile Desktop GUI Application (`DNSShieldApp.exe`)
```powershell
pyinstaller --name DNSShieldApp `
  --onedir --windowed --noconfirm --clean `
  --distpath dist --workpath build/app `
  --hidden-import tkinter `
  --hidden-import tkinter.ttk `
  --hidden-import network_manager `
  --hidden-import local_ipc `
  --hidden-import service_health `
  --exclude-module pytest `
  --exclude-module matplotlib `
  desktop_app.py
```

---

## 5. COMPILE WINDOWS INSTALLER (Inno Setup)
Compile the enterprise installer using Inno Setup 6.7.3:

```powershell
& "C:\Users\claim\AppData\Local\Programs\Inno Setup 6\ISCC.exe" installer\DNS-SHIELD-Setup.iss
```
Output: `dist\DNS-SHIELD-Setup-x64.exe` (15,155,114 bytes).

---

## 6. GENERATE BUILD MANIFEST & CHECKSUMS
To verify package integrity and generate cryptographic hashes:

```powershell
python build_package.py
```
This produces `dist\build_manifest.json` and updates package metadata.

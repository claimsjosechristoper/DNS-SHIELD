"""
Assembles the complete verified submission package for DNS-SHIELD.
Copies binaries, runtimes, docs, test results, creates source snapshot archive,
computes SHA-256 checksums, and builds DNS_SHIELD_FINAL_SUBMISSION.zip.
"""

import os
import sys
import shutil
import hashlib
import zipfile
import subprocess
from pathlib import Path

ROOT = Path(r"c:\project\dns tunneling")
SUBMISSION = ROOT / "submission"
DIST = ROOT / "dist"

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def assemble():
    print("=" * 70)
    print("  ASSEMBLING DNS-SHIELD FINAL SUBMISSION PACKAGE")
    print("=" * 70)

    # 1. Ensure target directories exist
    dirs = [
        SUBMISSION / "installer",
        SUBMISSION / "runtime",
        SUBMISSION / "runtime" / "scripts",
        SUBMISSION / "source",
        SUBMISSION / "test_results",
        SUBMISSION / "demo",
        SUBMISSION / "docs",
        SUBMISSION / "report",
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)

    # 2. Copy Installer
    installer_src = DIST / "DNS-SHIELD-Setup-x64.exe"
    installer_dst = SUBMISSION / "installer" / "DNS-SHIELD-Setup-x64.exe"
    print(f"[+] Copying installer: {installer_src.name} ({installer_src.stat().st_size:,} bytes)...")
    shutil.copy2(installer_src, installer_dst)

    # 3. Copy Portable Runtimes
    service_src = DIST / "DNSShieldService"
    service_dst = SUBMISSION / "runtime" / "DNSShieldService"
    if service_dst.exists():
        shutil.rmtree(service_dst)
    print(f"[+] Copying portable Service runtime directory...")
    shutil.copytree(service_src, service_dst)

    app_src = DIST / "DNSShieldApp"
    app_dst = SUBMISSION / "runtime" / "DNSShieldApp"
    if app_dst.exists():
        shutil.rmtree(app_dst)
    print(f"[+] Copying portable GUI Desktop runtime directory...")
    shutil.copytree(app_src, app_dst)

    # 4. Copy Scripts to runtime/scripts
    shutil.copy2(ROOT / "scripts" / "recovery.ps1", SUBMISSION / "runtime" / "scripts" / "recovery.ps1")
    shutil.copy2(ROOT / "scripts" / "diagnose_service.ps1", SUBMISSION / "runtime" / "scripts" / "diagnose_service.ps1")
    shutil.copy2(ROOT / "scripts" / "controlled_demo.py", SUBMISSION / "runtime" / "scripts" / "controlled_demo.py")
    print("[+] Copied runtime scripts.")

    # 5. Create Source Snapshot from Git commit 2739e82d7a37dce2baf72f522d1a7368ceeb7de0
    source_zip = SUBMISSION / "source" / "source_snapshot.zip"
    print(f"[+] Generating clean source snapshot from git commit 2739e82d7a37dce2baf72f522d1a7368ceeb7de0...")
    cmd = ["git", "archive", "--format=zip", "-o", str(source_zip), "2739e82d7a37dce2baf72f522d1a7368ceeb7de0"]
    subprocess.run(cmd, cwd=str(ROOT), check=True)
    print(f"    Source snapshot created: {source_zip.name} ({source_zip.stat().st_size:,} bytes)")

    # 6. Copy Test Results & Demo Output
    shutil.copy2(DIST / "pytest_results.xml", SUBMISSION / "test_results" / "pytest_results.xml")
    shutil.copy2(DIST / "pytest_raw_output.txt", SUBMISSION / "test_results" / "pytest_raw_output.txt")
    shutil.copy2(DIST / "demo_results.txt", SUBMISSION / "test_results" / "demo_results.txt")
    shutil.copy2(DIST / "demo_results.txt", SUBMISSION / "demo" / "demo_results.txt")
    print("[+] Copied test results and demo output logs.")

    # 7. Copy Requirements and Build Manifest
    shutil.copy2(ROOT / "requirements.txt", SUBMISSION / "requirements.txt")
    shutil.copy2(DIST / "build_manifest.json", SUBMISSION / "build_manifest.json")

    # 8. Copy Documentation Runbooks
    shutil.copy2(ROOT / "docs" / "DISPOSABLE_VM_TEST_PROCEDURE.md", SUBMISSION / "docs" / "DISPOSABLE_VM_TEST_PROCEDURE.md")
    if (ROOT / "docs" / "RECOVERY_INSTRUCTIONS.md").exists():
        shutil.copy2(ROOT / "docs" / "RECOVERY_INSTRUCTIONS.md", SUBMISSION / "docs" / "RECOVERY_INSTRUCTIONS.md")
    print("[+] Copied runbooks and requirements.")

    # 9. Compute SHA-256 Checksums for all top-level files in submission
    print("[+] Computing SHA-256 checksums across submission package...")
    checksum_lines = []
    
    # We will record key deliverable files in CHECKSUMS.sha256
    files_to_hash = [
        SUBMISSION / "installer" / "DNS-SHIELD-Setup-x64.exe",
        SUBMISSION / "runtime" / "DNSShieldService" / "DNSShieldService.exe",
        SUBMISSION / "runtime" / "DNSShieldApp" / "DNSShieldApp.exe",
        SUBMISSION / "runtime" / "scripts" / "recovery.ps1",
        SUBMISSION / "runtime" / "scripts" / "controlled_demo.py",
        SUBMISSION / "source" / "source_snapshot.zip",
        SUBMISSION / "build_manifest.json",
        SUBMISSION / "requirements.txt",
        SUBMISSION / "README_FIRST.md",
        SUBMISSION / "PROJECT_SUMMARY.md",
        SUBMISSION / "PRESENTATION_SCRIPT.md",
        SUBMISSION / "VIVA_QUESTIONS_AND_ANSWERS.md",
        SUBMISSION / "BUILD_INSTRUCTIONS.md",
        SUBMISSION / "report" / "PROJECT_REPORT.docx",
        SUBMISSION / "report" / "PROJECT_REPORT.md",
        SUBMISSION / "test_results" / "pytest_results.xml",
        SUBMISSION / "test_results" / "pytest_raw_output.txt",
        SUBMISSION / "test_results" / "demo_results.txt",
        SUBMISSION / "demo" / "demo_results.txt",
        SUBMISSION / "docs" / "ARCHITECTURE_DIAGRAM.md",
        SUBMISSION / "docs" / "DISPOSABLE_VM_TEST_PROCEDURE.md"
    ]

    for fpath in files_to_hash:
        if fpath.exists() and fpath.is_file():
            rel = fpath.relative_to(SUBMISSION)
            h = sha256_file(fpath)
            checksum_lines.append(f"{h}  {rel.as_posix()}")

    checksum_file = SUBMISSION / "CHECKSUMS.sha256"
    with open(checksum_file, "w", encoding="utf-8") as f:
        f.write("\n".join(checksum_lines) + "\n")
    print(f"[+] Written CHECKSUMS.sha256 with {len(checksum_lines)} verified records.")

    # 10. Create Master Zip Archive: DNS_SHIELD_FINAL_SUBMISSION.zip
    final_zip = ROOT / "dist" / "DNS_SHIELD_FINAL_SUBMISSION.zip"
    final_zip_sub = SUBMISSION / "DNS_SHIELD_FINAL_SUBMISSION.zip"
    print(f"\n[+] Building master submission archive: {final_zip.name}...")
    
    with zipfile.ZipFile(final_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for root_dir, _, filenames in os.walk(SUBMISSION):
            for filename in filenames:
                # Do not recurse if zip already exists
                if filename.endswith(".zip") and "FINAL_SUBMISSION" in filename:
                    continue
                file_full = Path(root_dir) / filename
                arcname = file_full.relative_to(SUBMISSION)
                zf.write(file_full, arcname)

    shutil.copy2(final_zip, final_zip_sub)
    print(f"[+] Master archive created successfully:")
    print(f"    Path: {final_zip} ({final_zip.stat().st_size:,} bytes)")
    print(f"    SHA-256: {sha256_file(final_zip)}")
    print("=" * 70)
    print("  ASSEMBLY COMPLETE - ALL DELIVERABLES PREPARED")
    print("=" * 70)

if __name__ == "__main__":
    assemble()

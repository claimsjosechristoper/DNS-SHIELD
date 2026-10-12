# DNS-SHIELD: Packaging, Code Signing & Updates Specification

**Target Platform:** Windows 11 x64 / Windows 10 x64  
**Packaging Frameworks:** PyInstaller (Binary Compilation) + Inno Setup (MSI/EXE Setup Wizard)

---

## 1. Reproducible Build Instructions

To compile the service and desktop application on Windows 11 x64:

```powershell
# 1. Activate virtual environment
.\.venv\Scripts\Activate.ps1

# 2. Run automated packaging pipeline
python build_package.py
```

Output Artifacts:
- `dist/DNSShieldService/DNSShieldService.exe` — Background SCM service binary.
- `dist/DNSShieldApp/DNSShieldApp.exe` — Native Windows desktop application.

---

## 2. Inno Setup Compilation

If Inno Setup 6+ is installed on the build machine:

```powershell
iscc.exe installer/DNS-SHIELD-Setup.iss
```

This compiles:  
`dist/DNS-SHIELD-Setup-x64.exe`

---

## 3. Authenticode Code Signing Requirements

### Commercial Production Deployment
Windows SmartScreen and Defender Application Control require valid Authenticode digital signatures.

1. **Required Certificate:**
   - Standard Code Signing Certificate or Extended Validation (EV) Code Signing Hardware Token.
   - Issued by a trusted Microsoft Root CA (e.g., DigiCert, Sectigo).

2. **Signing Command:**
   ```powershell
   signtool.exe sign /v /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a "dist\DNSShieldService\DNSShieldService.exe"
   signtool.exe sign /v /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a "dist\DNSShieldApp\DNSShieldApp.exe"
   signtool.exe sign /v /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a "dist\DNS-SHIELD-Setup-x64.exe"
   ```

### Current Development Status: Unsigned Build
- **Current Build Identity:** **`Unsigned Development Build`**.
- Because no commercial EV Code Signing Certificate private key is embedded in this repository (in strict compliance with security secret protection rules), Windows SmartScreen will display an "Unknown Publisher" warning upon launching the executable until signed with an enterprise or commercial certificate.
- Do not attempt to bypass operating system signature warnings.

---

## 4. Automatic Update Policy

- **Status:** **`Pending Infrastructure`**
- Automatic updates must ONLY be implemented when backed by an authenticated, cryptographic signature verification mechanism (e.g. verifying Ed25519/RSA-4096 signatures and HTTPS certificates prior to executing installer binaries).
- Arbitrary unverified self-updates are intentionally prohibited to avoid creating remote code execution vulnerabilities.

; Inno Setup Script for DNS-SHIELD Windows x64 Installer
; Target Platform: Windows 11 x64 / Windows 10 x64 (1809+)
; Enforces administrator privilege, Program Files ACLs, quoted SCM paths, and upgrade/uninstall recovery.

#define MyAppName "DNS-SHIELD"
#define MyAppVersion "2.0.0"
#define MyAppPublisher "DNS-SHIELD Security"
#define MyAppURL "https://github.com/example/dns-shield"
#define MyAppExeName "DNSShieldApp.exe"
#define MyServiceExeName "DNSShieldService.exe"

[Setup]
AppId={{8B5C5E78-2B72-4B69-9D64-325A84F81712}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
; Strictly install into 64-bit Program Files (ordinary users have read-only access)
DefaultDirName={commonpf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=dist
OutputBaseFilename=DNS-SHIELD-Setup-x64
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
; Strict elevation: installer must run elevated
PrivilegesRequired=admin
; PrivilegesRequiredOverridesAllowed=none (Inno Setup directive below enforces no overrides)
PrivilegesRequiredOverridesAllowed=
SourceDir=..

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "autostart"; Description: "Start DNS Protection Service automatically on boot"; GroupDescription: "Service Setup:"; Flags: checkedonce

[Dirs]
; Explicit NTFS ACLs: SYSTEM and Administrators have Full Control; standard Users have Read & Execute only
Name: "{app}"; Permissions: admins-full system-full users-readexec
Name: "{app}\service"; Permissions: admins-full system-full users-readexec
Name: "{app}\app"; Permissions: admins-full system-full users-readexec
Name: "{app}\scripts"; Permissions: admins-full system-full users-readexec
Name: "{commonappdata}\{#MyAppName}"; Permissions: admins-full system-full

[Files]
; Binaries produced by PyInstaller
Source: "dist\DNSShieldService\*"; DestDir: "{app}\service"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "dist\DNSShieldApp\*"; DestDir: "{app}\app"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "scripts\recovery.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName} Control Center"; Filename: "{app}\app\{#MyAppExeName}"
Name: "{group}\Emergency Network Restore"; Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -File ""{app}\scripts\recovery.ps1"""
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\app\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; Upgrade & Installation: Stop existing service if running, configure quoted binPath, set recovery actions, and start
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""$bin = '""""{app}\service\{#MyServiceExeName}""""'; $svc = Get-Service -Name DNSShield -ErrorAction SilentlyContinue; if ($svc) {{{{ Stop-Service DNSShield -Force -ErrorAction SilentlyContinue; sc.exe config DNSShield binPath= $bin start= auto DisplayName= 'DNS-SHIELD DNS Protection' }}}} else {{{{ sc.exe create DNSShield binPath= $bin start= auto DisplayName= 'DNS-SHIELD DNS Protection' }}}}; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\DNSShield' -Name ImagePath -Value $bin -Force"""; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "description DNSShield ""Local deterministic DNS filtering background service."""; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "failure DNSShield reset= 86400 actions= restart/60000/restart/60000/restart/60000"; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "start DNSShield"; Flags: runhidden
Filename: "{app}\app\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Transactionally restore network adapter DNS and remove firewall rules before deleting service
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\scripts\recovery.ps1"""; Flags: runhidden
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""Remove-NetFirewallRule -Name 'DNSShield*' -ErrorAction SilentlyContinue"""; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "stop DNSShield"; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "delete DNSShield"; Flags: runhidden

[Code]
// Pre-installation hook: stop running service before file overwrite on upgrade
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Exec('sc.exe', 'stop DNSShield', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := '';
end;

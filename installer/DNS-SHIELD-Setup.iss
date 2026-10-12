; Inno Setup Script for DNS-SHIELD Windows x64 Installer
; Target Platform: Windows 11 x64 / Windows 10 x64 (1809+)

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
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=dist
OutputBaseFilename=DNS-SHIELD-Setup-x64
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "autostart"; Description: "Start DNS Protection Service automatically on boot"; GroupDescription: "Service Setup:"; Flags: checkedonce

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
; Register and start Windows SCM Service
Filename: "{sys}\sc.exe"; Parameters: "create DNSShield binPath= ""{app}\service\{#MyServiceExeName}"" start= auto DisplayName= ""DNS-SHIELD DNS Protection"""; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "description DNSShield ""Local deterministic DNS filtering background service."""; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "failure DNSShield reset= 86400 actions= restart/60000/restart/60000/restart/60000"; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "start DNSShield"; Flags: runhidden
Filename: "{app}\app\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Transactionally restore network DNS before stopping service
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\scripts\recovery.ps1"""; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "stop DNSShield"; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "delete DNSShield"; Flags: runhidden

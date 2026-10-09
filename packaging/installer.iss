; Inno Setup script - wraps the PyInstaller output into Dynascan-Setup.exe
; Build:  iscc packaging\installer.iss   (after pyinstaller has produced dist\Dynascan)
#define AppName "Dynascan"
#define AppVersion "0.1.0"

[Setup]
AppId={{B6F6E0C2-3D7A-4B55-9A41-DA57C0DE0001}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=Your Company
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
OutputDir=..\installer-out
OutputBaseFilename=Dynascan-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog

[Files]
Source: "..\dist\Dynascan\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\Dynascan.exe"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\Dynascan.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"

[Run]
Filename: "{app}\Dynascan.exe"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent

; Inno Setup script for Wazowski — a per-user Windows installer.
;
; Per-user (no admin): installs into %LOCALAPPDATA%\Programs\Wazowski, which is
; writable, so the in-app updater can replace the exe without elevation.
;
; The version is passed in at build time: ISCC.exe /DMyAppVersion=2.0.6 wazowski.iss
; and the payload (wazowski.exe, icon.ico) is expected in the same directory.

#ifndef MyAppVersion
  #define MyAppVersion "0.0.0"
#endif

#define MyAppName "Wazowski"
#define MyAppExeName "wazowski.exe"
#define MyAppPublisher "HoleInTheSeat"
#define MyAppURL "https://github.com/HoleInTheSeat/Wazowski"

[Setup]
; A stable AppId so upgrades replace the previous install in place.
AppId={{8F3A6C1E-4B7D-4E2A-9C55-2A1D9E4F77B1}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={localappdata}\Programs\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputBaseFilename=Wazowski-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupIconFile=icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"

[Files]
Source: "wazowski.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "icon.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"
Name: "{userdesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Wazowski"; Flags: nowait postinstall skipifsilent

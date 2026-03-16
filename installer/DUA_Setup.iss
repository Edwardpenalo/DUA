; DUA Windows Installer (Inno Setup)
#define AppName "DUA Scanner"
#define AppVersion "1.0.0"
#define AppPublisher "DUA"
#define AppExeName "DUA.exe"

[Setup]
AppId={{E5B30041-4E78-49A8-8FA4-DF6AB20D1CD1}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\DUA Scanner
DefaultGroupName=DUA Scanner
DisableProgramGroupPage=yes
OutputDir=output
OutputBaseFilename=DUA-Setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#AppExeName}
PrivilegesRequired=admin

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Tasks]
Name: "desktopicon"; Description: "Crear acceso directo en el escritorio"; GroupDescription: "Accesos directos:"; Flags: unchecked

[Files]
Source: "..\backend\DUA.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\DUA Scanner"; Filename: "{app}\{#AppExeName}"
Name: "{autodesktop}\DUA Scanner"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Ejecutar DUA Scanner ahora"; Flags: nowait postinstall skipifsilent

; Inno Setup 6 Script for RustUninstaller
#define MyAppName "RustUninstaller"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "RustUninstaller Contributors"
#define MyAppURL "https://github.com/BCUninstaller/Bulk-Crap-Uninstaller"
#define MyAppExeName "rust-uninstaller.exe"

[Setup]
AppId={{D37D3C6F-931A-4835-B5E3-A33BC8949821}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\RustUninstaller
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
LicenseFile=..\dist\Licence.txt
OutputDir=..\dist\installer
OutputBaseFilename=RustUninstaller_Setup_v{#MyAppVersion}
SetupIconFile=..\rust\crates\bcu-gui\assets\icon.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "contextmenu"; Description: "Add 'Find Leftovers with RustUninstaller' to Explorer context menu"; GroupDescription: "System Integration:"

[Files]
Source: "..\dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\bcu-cli.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\bcu_ffi.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\README.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\Licence.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\RustUninstaller CLI"; Filename: "{app}\bcu-cli.exe"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Registry]
Root: HKLM; Subkey: "Software\Classes\Directory\shell\RustUninstaller"; ValueType: string; ValueData: "Find Leftovers with RustUninstaller"; Tasks: contextmenu; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\Directory\shell\RustUninstaller"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\{#MyAppExeName}"""; Tasks: contextmenu
Root: HKLM; Subkey: "Software\Classes\Directory\shell\RustUninstaller\command"; ValueType: string; ValueData: """{app}\{#MyAppExeName}"" --scan-dir ""%1"""; Tasks: contextmenu
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: NeedsAddPath(ExpandConstant('{app}'))

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[Code]
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', OrigPath)
  then begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Param + ';', ';' + OrigPath + ';') = 0;
end;

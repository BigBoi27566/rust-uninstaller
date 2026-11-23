; Inno Setup 6 Script for Bulk Crap Uninstaller (Rust Edition)
#define MyAppName "Bulk Crap Uninstaller"
#define MyAppVersion "0.2.0"
#define MyAppPublisher "BCU Contributors"
#define MyAppURL "https://github.com/BCUninstaller/Bulk-Crap-Uninstaller"
#define MyAppExeName "bcu-gui.exe"

[Setup]
AppId={{D37D3C6F-931A-4835-B5E3-A33BC8949821}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\Bulk Crap Uninstaller
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
LicenseFile=..\dist\Licence.txt
OutputDir=..\dist\installer
OutputBaseFilename=BCU_Rust_Setup_v{#MyAppVersion}
SetupIconFile=..\rust\crates\bcu-gui\assets\logo.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "contextmenu"; Description: "Add 'Find Leftovers with BCU' to Windows Explorer folder context menu"; GroupDescription: "System Integration:"

[Files]
Source: "..\dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\bcu-cli.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\bcu_ffi.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\README.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\Licence.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\BCU Command Line Tool"; Filename: "{app}\bcu-cli.exe"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Registry]
; Windows Explorer Directory Context Menu Integration
Root: HKLM; Subkey: "Software\Classes\Directory\shell\BCU"; ValueType: string; ValueData: "Find Leftovers with BCU"; Tasks: contextmenu; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\Directory\shell\BCU"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\{#MyAppExeName}"""; Tasks: contextmenu
Root: HKLM; Subkey: "Software\Classes\Directory\shell\BCU\command"; ValueType: string; ValueData: """{app}\{#MyAppExeName}"" --scan-dir ""%1"""; Tasks: contextmenu

; Add installation directory to system PATH for easy CLI usage
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
  Result := Pos(';' + UpperCase(Param) + ';', ';' + UpperCase(OrigPath) + ';') = 0;
end;

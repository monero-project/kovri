; Kovri Installer for Windows, 32 bit variant
; Copyright (c) 2013-2017, The Kovri I2P Router Project
; See LICENSE

[Setup]
AppName=Kovri I2P Router
AppVersion=Latest
DefaultDirName={pf}\Kovri
DefaultGroupName=Kovri I2P Router
UninstallDisplayIcon={app}\Kovri.ico
PrivilegesRequired=admin
; ArchitecturesInstallIn64BitMode=x64
; ArchitecturesAllowed=x64
WizardSmallImageFile=WizardSmallImage.bmp
WizardImageFile=WizardImage.bmp
DisableWelcomePage=no
LicenseFile=LICENSE
OutputBaseFilename=KovriSetup32


[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"


[Files]
Source: "bin32\build\kovri.exe";      DestDir: "{app}"; Flags: comparetimestamp
Source: "bin32\build\kovri-util.exe"; DestDir: "{app}"; Flags: comparetimestamp
Source: "Kovri.ico";                  DestDir: "{app}"; Flags: comparetimestamp
Source: "ReadMe.htm";                 DestDir: "{app}"; Flags: comparetimestamp

; Install any new versions of "hosts.txt" and "publishers" in "\client\address_book"
Source: "bin32\pkg\client\*"; DestDir: "{userappdata}\Kovri\client"; Flags: recursesubdirs comparetimestamp

; Backup any existing user config files, as we will overwrite "kovri.conf" and "tunnels.conf" unconditionally
; Note that Inno Setup goes through the "[Files]" entries strictly in the order given here,
; therefore the old files are backed-up correctly BEFORE the new ones overwrite them
Source: "{userappdata}\Kovri\config\kovri.conf";   DestDir: "{userappdata}\Kovri\config"; DestName: "kovri.conf.bak";   Flags: external skipifsourcedoesntexist 
Source: "{userappdata}\Kovri\config\tunnels.conf"; DestDir: "{userappdata}\Kovri\config"; DestName: "tunnels.conf.bak"; Flags: external skipifsourcedoesntexist

Source: "bin32\pkg\config\*"; DestDir: "{userappdata}\Kovri\config"; Flags: recursesubdirs ignoreversion



[InstallDelete]
; Delete .exe files that the "old" install batch file copied directly to the desktop,
; as this installer works with another, user-selectable location for those files
Type: files; Name: "{userdesktop}\kovri.exe"
Type: files; Name: "{userdesktop}\kovri-util.exe"

; For every update delete all files and directories with transient data;
; with the following statements, in the "client" sub-directory currently only "hosts.txt" and "publishers.txt" are not deleted
Type: filesandordirs; Name: "{userappdata}\Kovri\client\address_book\addresses"
Type: files;          Name: "{userappdata}\Kovri\client\address_book\addresses.csv"
Type: filesandordirs; Name: "{userappdata}\Kovri\client\certificates"
Type: filesandordirs; Name: "{userappdata}\Kovri\core"


[UninstallDelete]
; Per default the uninstaller will only delete files it installed; to get rid of the whole "Kovri"
; directory with all the additional data that was created at runtime this special delete statement is needed
Type: filesandordirs; Name: "{userappdata}\Kovri"


[Tasks]
Name: desktopicon; Description: "Create a &desktop icon"; GroupDescription: "Additional icons:";


[Run]
Filename: "{app}\ReadMe.htm"; Description: "Show ReadMe"; Flags: postinstall shellexec skipifsilent


[Code]
(* So far nothing to do programmatically by using Pascal procedures *)


[Icons]
; Icons in the "Kovri I2P Router" program group
; Windows will almost always display icons in alphabetical order, per level, so specify the text accordingly
Name: "{group}\Kovri Daemon";         Filename: "{app}\kovri.exe";      IconFilename: "{app}\Kovri.ico"
Name: "{group}\Kovri Utility";        Filename: "{app}\kovri-util.exe"; IconFilename: "{app}\Kovri.ico"
Name: "{group}\Read Me";              Filename: "{app}\ReadMe.htm"
Name: "{group}\Show Config Folder";   Filename: "{win}\Explorer.exe";   Parameters: "{userappdata}\Kovri\config"
Name: "{group}\Uninstall Kovri";      Filename: "{uninstallexe}"

; Desktop icon, optional with the help of the "Task" section
Name: "{userdesktop}\Kovri Daemon"; Filename: "{app}\kovri.exe"; IconFilename: "{app}\Kovri.ico"; Tasks: desktopicon


[Registry]
; So far Kovri does not use the Windows registry

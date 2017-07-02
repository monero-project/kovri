# Kovri I2P Router Windows Installers #

Copyright (c) 2015-2017, The Kovri Project

## Introduction ##

This is a pair of *Inno Setup* scripts `Kovri64.iss` and
`Kovri32.iss` plus some related files that allow you to build
standalone Windows installers (.exe) for the
Kovri I2P Router software.

This turns Kovri into a more or less standard Windows program,
by default installed into a subdirectory of `C:\Program Files`,
a program group with some icons in the *Start* menu, and automatic
uninstall support.

The Inno Setup scripts have to refer to files and directories of the
software to install by name; therefore the addition of files and/or
directories in the future may require modifications of the scripts. 

## License ##

See [LICENSE](LICENSE).

## Building ##

You can only build on Windows, and the results are always
Windows .exe files that can act as standalone installers for Kovri.

The build steps in detail:

1. Install *Inno Setup*. You can get it from [here](http://www.jrsoftware.org/isdl.php)
2. Get the Inno Setup scripts plus related files by cloning the whole [kovri](https://github.com/monero-project/kovri) repository; you will only need the files in the installer directory  `pkg\installers\windows` however
3. The setup scripts are written to take the Kovri files from subdirectories named `bin64` and `bin32`; so create `pkg\installers\windows\bin64` and `pkg\installers\windows\bin32`
4. Get the zip files with the Kovri files you want to install [here](https://github.com/monero-project/kovri), unpack them somewhere, and copy all the files and subdirectories in the `kovri-...` directories to the `bin64` and `bin32` directories 
4. Start Inno Setup, load and compile `Kovri64.iss` and `Kovri32.iss`
5. The results i.e. the finished installers will be the files `KovriSetup64.exe` and `KovriSetup32.exe` in the `pkg\installers\windows\Output` subdirectory 


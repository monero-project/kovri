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

1. Ensure that [Kovri](https://github.com/monero-project/kovri) is cloned and built (see building instructions for details)
2. Install *Inno Setup*. You can get it from [here](http://www.jrsoftware.org/isdl.php)
3. Start Inno Setup then load and compile either `Kovri64.iss` or `Kovri32.iss` (depending on your architecture) in the `pkg\installers\windows` directory (Inno Setup scripts plus related files are all in this directory). Optional: for a command-line build, run `ISCC.exe` in the Inno Setup Program Files directory
4. The results i.e. the finished installers will be `KovriSetup64.exe` or `KovriSetup32.exe` in the repo's root `build` directory

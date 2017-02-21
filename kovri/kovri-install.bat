@ECHO OFF

REM Copyright (c) 2015-2017, The Kovri I2P Router Project
REM
REM All rights reserved.
REM
REM Redistribution and use in source and binary forms, with or without modification, are
REM permitted provided that the following conditions are met:
REM
REM 1. Redistributions of source code must retain the above copyright notice, this list of
REM    conditions and the following disclaimer.
REM
REM 2. Redistributions in binary form must reproduce the above copyright notice, this list
REM    of conditions and the following disclaimer in the documentation and/or other
REM    materials provided with the distribution.
REM
REM 3. Neither the name of the copyright holder nor the names of its contributors may be
REM    used to endorse or promote products derived from this software without specific
REM    prior written permission.
REM
REM THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
REM EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
REM MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
REM THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
REM SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
REM PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
REM INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
REM STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
REM THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

SET _banner=The Kovri I2P Router Project (c) 2015-2017
SET _data=%APPDATA%\Kovri

REM
REM Backup existing installation
REM

SET _config=%_data%\config
SET _kovri_conf=%_config%\kovri.conf
SET _tunnels_conf=%_config%\tunnels.conf

IF EXIST "%_config%%" (
  ECHO Begin configuration backup...
  IF EXIST "%_kovri_conf%" (
    ECHO Backing up "%_kovri_conf%"
    COPY /Y "%_kovri_conf%" "%_kovri_conf%".bak
  )
  IF EXIST "%_tunnels_conf%" (
    ECHO Backing up "%_tunnels_conf%"
    COPY /Y "%_tunnels_conf%" "%_tunnels_conf%".bak
  )
  CALL :catch could not backup configuration
)

REM
REM Remove existing install
REM

SET _core=%_data%\core
SET _client=%_data%\client
SET _installed[0]=%_core%
SET _installed[1]=%_client%\address_book\addresses
SET _installed[2]=%_client%\address_book\addresses.csv
SET _installed[3]=%_client%\certificates
FOR /F "tokens=2 delims==" %%s IN ('set _installed[') DO (
  IF EXIST %%s\* (
    REM Remove directory
    ECHO Removing %%s
    RMDIR /S /Q %%s
  )
  IF EXIST %%s (
    REM Remove file
    ECHO Removing %%s
    DEL /F /S /Q %%s
  )
)
CALL :catch could not remove existing install

REM
REM Create new install
REM
REM TODO(anonimal): Install to Program Files?

SET _path=%USERPROFILE%\Desktop

IF NOT EXIST "%_data%%" (
  ECHO Creating "%_data%"
  MKDIR "%_data%"
  CALL :catch could not create "%_data%"
)

IF NOT EXIST "%_path%%" (
  ECHO Creating "%_path%"
  MKDIR "%_path%"
  CALL :catch could not create "%_path%"
)

SET _resources[0]=client
SET _resources[1]=config
SET _resources[2]=kovri.exe
SET _resources[3]=kovri-util.exe

FOR /F "tokens=2 delims==" %%s IN ('set _resources[') DO (
  IF EXIST %%s\* (
    XCOPY /F /S /E /Y %%s\* "%_data%"\%%s\*
  ) ELSE (
    COPY /Y %%s "%_path%"
  )
)
CALL :catch could not install resources

ECHO Data directory is "%_data%"
ECHO Binaries are located in "%_path%"
ECHO Installation success!
IF %0 == "%~0" PAUSE

:catch
IF %ERRORLEVEL% NEQ 0 (
  ECHO " [ERROR] Failed to install: '%*'"
  EXIT /B 1
)
GOTO :EOF

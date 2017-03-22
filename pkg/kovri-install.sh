#!/usr/bin/env bash

# Copyright (c) 2015-2017, The Kovri I2P Router Project
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#
# Kovri installer script: installs or packages binary/resources for nightly/branch-tip builds
#

usage() {
  echo "Usage: $0 [-r \"<resources to install>\"] [-p (creates package)] [-c (creates package checksum file)] [-f <package output file>] [-u (uninstall)]"
  echo ""
  echo "Examples"
  echo "========"
  echo ""
  echo -e "End-users:\n\n$0\n\n"
  echo -e "Uninstall existing installation:\n\n$0 -u\n\n"
  echo -e "Specify resources:\n\n$0 -r \"client config kovri kovri-util\"\n\n"
  echo -e "Create package with default output file path:\n\n$0 [-r \"client config kovri kovri-util\"] -p\n\n"
  echo -e "Create package with specified file path:\n\n$0 [-r \"client config kovri kovri-util\"] -p -f /tmp/kovri-package.tar.bz2\n\n"
  echo -e "Create package with accompanying checksum file:\n\n$0 [-r \"client config kovri kovri-util\"] -p -c [-f /tmp/kovri-package.tar.bz2]\n\n"
}

while getopts ":r:f:cpu" _opt; do
  case $_opt in
    r) _resources="$OPTARG"
      ;;
    f) _package_file="$OPTARG"
      ;;
    c) _create_checksum_file=true
      ;;
    p) _create_package=true
      ;;
    u) _uninstall=true
      ;;
    *) usage && exit 1
      ;;
  esac
done
shift "$(($OPTIND -1))"

PrepareOptions() {
  # Get platform
  case $OSTYPE in
    linux*)
      _data="$HOME/.kovri"
      _is_linux=true
      ;;
    openbsd* | freebsd* | dragonfly*)
      _data="$HOME/.kovri"
      _is_bsd=true
      ;;
    darwin*)
      _data="$HOME/Library/Application Support/Kovri"
      _is_osx=true
      ;;
    msys)
      _data="$APPDATA/Kovri"
      _is_windows=true
      ;;
    *)
      false
      catch "unsupported platform"
      ;;
  esac
  # Ensure we're top-level if packaging from git repo
  _git="git rev-parse --show-toplevel"
  $_git &>/dev/null
  if [[ $? -eq 0 ]]; then
    cd $($_git)
    local _is_git=true
  else
    cd $(dirname "$0")
  fi
  # Path for binaries
  _path=$HOME/bin
  _binaries=(kovri kovri-util)
  # Set default resources if needed
  if [[ -z $_resources ]]; then
    _resources="pkg/client pkg/config build/${_binaries[0]} build/${_binaries[1]} "
  fi
  # Test if resources are available
  for _i in ${_resources[@]}; do
    if [[ ! -e $_i ]]; then
      false
      catch "$_i is unavailable, did you build Kovri?"
    fi
  done
  # Package preparation
  if [[ $_create_package == true ]]; then
    # Set defaults
    if [[ $_is_git == true ]]; then
      local _rev="-"$(git rev-parse --short HEAD 2>/dev/null)
    fi
    _package_path="kovri${_rev}-$(uname -s)-$(uname -m)-$(date +%Y.%m.%d)"
    # Set package file path if none supplied
    if [[ -z $_package_file ]]; then
      if [[ $_is_windows == true ]]; then
        local _ext=".zip"
      else
        local _ext=".tar.bz2"
      fi
      _package_file="build/${_package_path}${_ext}"
    fi
  else
    # Ensure proper command line
    if [[ ! -z $_package_file || $_create_checksum_file == false ]]; then
      usage ; false ; catch "set the package option to build a package"
    fi
  fi
}

LocalUninstall() {
  # Backup existing installation
  _config=${_data}/config
  _kovri_conf=${_config}/kovri.conf
  _tunnels_conf=${_config}/tunnels.conf
  if [[ -d $_data ]]; then
    echo -n "Backing up existing configuration files"
    if [[ -f $_kovri_conf ]]; then
      mv "$_kovri_conf" "${_kovri_conf}.bak" 2>/dev/null
    fi
    if [[ -f $_tunnels_conf ]]; then
      mv "$_tunnels_conf" "${_tunnels_conf}.bak" 2>/dev/null
    fi
    catch "could not backup configuration files"
  fi
  # Remove existing install
  _core=${_data}/core
  _client=${_data}/client
  _installed=($_core $_client/address_book/addresses $_client/address_book/addresses.csv $_client/certificates)
  for _i in ${_installed[@]}; do
    if [[ -e $_i ]]; then
      echo -n "Removing $_i"
      rm -fr $_i 2>/dev/null
      catch "could not remove $_i"
    fi
  done
  # Remove binaries
  for _i in ${_binaries[@]}; do
    local _bin=${_path}/${_i}
    if [[ -e $_bin ]]; then
      echo -n "Removing $_bin"
      rm -f $_bin 2>/dev/null
      catch "could not remove $_bin"
    fi
  done
  # Cleanup bin dir
  if [[ ! $(ls -A $_path 2>/dev/null) ]]; then
    rm -fr $_path
  fi
}

LocalInstall() {
  # Ensure paths for new install
  if [[ ! -d $_data ]]; then
    echo -n "Creating $_data"
    mkdir "$_data" 2>/dev/null
    catch "could not create $_data"
  fi
  if [[ ! -d $_path ]]; then
    echo -n "Creating $_path"
    mkdir "$_path" 2>/dev/null
    catch "could not create $_path"
  fi
  # Install resources
  for _i in ${_resources[@]}; do
    if [[ -d $_i ]]; then
      echo -n "Copying $_i to $_data"
      cp -fR $_i "$_data" 2>/dev/null
    else  # Implies binaries
      echo -n "Copying $_i to $_path"
      cp -f $_i "$_path" 2>/dev/null
    fi
    catch "could not copy resource"
  done
}

CreatePackage() {
  # Test access
  if [[ ! -x $_package_file ]]; then
    echo -n "Testing write access"
    catch "we can't write to $_package_file"
  fi
  echo -n "Creating staging path"
  mkdir $_package_path
  catch "could not create staging directory"
  echo -n "Copying resources"
  if [[ $_is_osx == true || $_is_bsd == true ]]; then
    # TODO(anonimal): using rsync is a hack to preserve parent path
    hash rsync 2>/dev/null
    if [[ $? -ne 0 ]]; then
      false
      catch "rsync not installed. Install rsync for $OSTYPE"
    fi
    for _i in ${_resources[@]}; do
      rsync -avR $_i $_package_path 1>/dev/null
    done
  else
    cp -R --parents $_resources $_package_path
  fi
  catch "could not copy resources for packaging"
  # Add ourself to the package
  echo -n "Copying installer"
  if [[ $_is_windows == true ]]; then
    cp pkg/kovri-install.bat $_package_path
  else
    cp pkg/kovri-install.sh $_package_path
  fi
  catch "could not copy installer"
  # Add the install guide
  echo -n "Copying guide"
  cp pkg/INSTALL.txt $_package_path
  catch "could not copy install guide"
  # Compress package
  echo -n "Compressing package $_package_file (please wait)..."
  if [[ $_is_windows == true ]]; then
    hash zip 2>/dev/null
    if [[ $? -ne 0 ]]; then
      false
      catch "zip not installed. Install zip for MSYS2"
    fi
    zip $_package_file -r $_package_path
  else
    tar cjf $_package_file $_package_path
  fi
  catch "could not create package file"
  echo -n "Cleaning staging path"
  rm -fr $_package_path
  catch "could not clean staging path"
  if [[ $_create_checksum_file == true ]]; then
    local _output_size=256
    local _shasum_file=${_package_file}.sha${_output_size}sum.txt
    echo -n "Creating shasum $_shasum_file"
    shasum -a $_output_size $_package_file 1> $_shasum_file ; catch "could not create shasum"
    echo -n "Verifying $_package_file"
    shasum -c $_shasum_file 1>/dev/null ; catch "could not verify shasum"
  fi
}

# Test if terminal is color capable
if [[ $(tput colors) ]]; then
  _red="$(tput setaf 1)"
  _green="$(tput setaf 2)"
  _yellow="$(tput setaf 3)"
  _normal="$(tput sgr0)"
fi

# Error handler
catch() {
  if [[ $? -ne 0 ]]; then
    echo " ${_red}[ERROR] Failed to install: '$1' ${_normal}" >&2
    exit 1
  fi
  echo " ${_green}[OK]${_normal}"
}

_banner="${_yellow}The Kovri I2P Router Project (c) 2015-2017${_normal}" && echo $_banner
PrepareOptions
if [[ $_create_package == true ]]; then
  CreatePackage
  echo "${_green}Package creation success!${_normal}"
elif [[ $_uninstall == true ]]; then
  LocalUninstall
  echo "${_green}Un-installation success!${_normal}"
else
  LocalUninstall
  LocalInstall
  echo "Data directory is $_data"
  echo "Binaries are located in $_path"
  echo "${_green}Installation success!${_normal}"
fi

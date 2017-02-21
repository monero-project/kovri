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
# Kovri installer script: installs binary/resources for nightly/branch-tip builds
#

# Test if terminal is color capable
if [[ $(tput colors) ]]; then
  _red="$(tput setaf 1)"
  _green="$(tput setaf 2)"
  _yellow="$(tput setaf 3)"
  _normal="$(tput sgr0)"
fi

_banner="${_yellow}The Kovri I2P Router Project (c) 2015-2017${_normal}"
echo $_banner

# Error handler
catch() {
  if [[ $? -ne 0 ]]; then
    echo " ${_red}[ERROR] Failed to install: '$1' ${_normal}"
    exit 1
  fi
  echo " ${_green}[OK]${_normal}"
}

# Get platform
case $OSTYPE in
  linux* | freebsd* | dragonfly*)
    _data="$HOME/.kovri"
    ;;
  darwin*)
    _data="$HOME/Library/Application Support/Kovri"
    ;;
  msys)
    _data="$APPDATA/Kovri"
    ;;
  *)
    false
    catch "unsupported platform"
    ;;
esac

# Backup existing installation
_config=${_data}/config
_kovri_conf=${_config}/kovri.conf
_tunnels_conf=${_config}/tunnels.conf

if [[ -d $_data ]]; then
  echo -n "Begin configuration backup..."
  if [[ -f $_kovri_conf ]]; then
    mv "$_kovri_conf" "${_kovri_conf}.bak"
  fi
  if [[ -f $_tunnels_conf ]]; then
    mv "$_tunnels_conf" "${_tunnels_conf}.bak"
  fi
  catch "could not backup configuration"
fi

# Remove existing install
_core=${_data}/core
_client=${_data}/client
_installed=($_core $_client/address_book/addresses $_client/address_book/addresses.csv $_client/certificates)
for _i in ${_installed[@]}; do
  if [[ -e $_i ]]; then
    echo -n "Removing $_i"
    rm -fr $_i
    catch "could not remove $_i"
  fi
done

# Create new install
_path=$HOME/bin

if [[ ! -d $_data ]]; then
  echo -n "Creating ${_data}"
  mkdir "$_data"
  catch "could not create $_data"
fi

if [[ ! -d $_path ]]; then
  echo -n "Creating ${_path}"
  mkdir "$_path"
  catch "could not create $_path"
fi

_resources=(client config kovri kovri-util)
for _i in ${_resources[@]}; do
  if [[ -d $_i ]]; then
    echo -n "Copying $_i to $_data"
    cp -fR $_i "$_data"
  else
    echo -n "Copying $_i to $_path"
    cp -f $_i "$_path"
  fi
  catch "could not copy resource"
done

echo "${_green}Installation success!${_normal}"

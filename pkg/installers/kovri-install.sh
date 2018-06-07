#!/usr/bin/env bash

# Copyright (c) 2015-2018, The Kovri I2P Router Project
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

PrintUsage()
{
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

# Error handler
catch()
{
  if [[ $? -ne 0 ]]; then
    echo " ${red}[ERROR] Failed to install: '$1' ${normal}" >&2
    exit 1
  fi
  echo " ${green}[OK]${normal}"
}

# Get platform
case $OSTYPE in
  linux*)
    kovri_data_dir="$HOME/.kovri"
    is_linux=true
    ;;
  freebsd* | dragonfly*)
    kovri_data_dir="$HOME/.kovri"
    is_bsd=true
    ;;
  openbsd*)
    kovri_data_dir="$HOME/.kovri"
    is_bsd=true
    is_openbsd=true
    ;;
  darwin*)
    kovri_data_dir="$HOME/Library/Application Support/Kovri"
    is_osx=true
    ;;
  msys)
    is_windows=true
    if [[ $MSYSTEM_CARCH == x86_64 ]]; then
      bitness=64
    elif [[ $MSYSTEM_CARCH == i686 ]]; then
      bitness=32
    else
      false
      catch "unsupported architecture"
    fi
    ;;
  *)
    false
    catch "unsupported platform"
    ;;
esac

while getopts ":r:f:cpu" _opt; do
  case $_opt in
    r) resources="$OPTARG"
      ;;
    f) package_file="$OPTARG"
      ;;
    c) checksum_option=true
      ;;
    p) package_option=true
      ;;
    u) uninstall_option=true
      ;;
    *) PrintUsage && exit 1
      ;;
  esac
done
shift "$(($OPTIND -1))"

# Path for binaries/scripts
bin_path=$HOME/bin
bin_path_files=(kovri-bash.sh kovri kovri-util)

# Set default resources if needed
if [[ -z $resources ]]; then
  # TODO: brittle, relies on appropriately placed index
  resources=("pkg/client" "pkg/config" \
             "contrib/utils/${bin_path_files[0]}" \
             "build/${bin_path_files[1]}" \
             "build/${bin_path_files[2]}")
fi

# Test if resources are available
for _resource in ${resources[@]}; do
  if [[ ! -e $_resource ]]; then
    # If kovri-util is unavailable, don't fail
    if [[ "$_resource" == "${resources[-1]}" ]]; then
      # Remove unavailable resource to avoid later attempt at install
      unset 'resources[${#resources[@]}-1]'
      true
    else
      false
    fi
    catch "$_resource is unavailable, did you build Kovri?"
  fi
done

Uninstall()
{
  # MSYS users should use our Inno Setup scripts/instructions
  if [[ $is_windows == true ]]; then
    echo "Warning: uninstall from Windows Control Panel"
    return
  fi

  # Backup existing installation
  local _config=${kovri_data_dir}/config
  local _kovri_conf=${_config}/kovri.conf
  local _tunnels_conf=${_config}/tunnels.conf
  if [[ -d $kovri_data_dir ]]; then
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
  local _core=${kovri_data_dir}/core
  local _client=${kovri_data_dir}/client
  local _resources=($_core $_client/address_book/addresses $_client/address_book/addresses.csv $_client/certificates)
  for _resource in ${_resources[@]}; do
    if [[ -e $_resource ]]; then
      echo -n "Removing $_resource"
      rm -fr $_resource 2>/dev/null
      catch "could not remove $_resource"
    fi
  done

  # Remove binaries/scripts
  for _bin in ${bin_path_files[@]}; do
    local _binary=${bin_path}/${_bin}
    if [[ -e $_binary ]]; then
      echo -n "Removing $_binary"
      rm -f $_binary 2>/dev/null
      catch "could not remove $_binary"
    fi
  done

  # Cleanup bin dir
  if [[ ! $(ls -A $bin_path 2>/dev/null) ]]; then
    rm -fr $bin_path
  fi
}

Install()
{
  # Build then run InnoSetup installer on windows
  if [[ $is_windows == true ]]; then
    package_option=true
    CreatePackage
    exec "$package_file"
    return
  fi

  # Ensure paths for new install
  if [[ ! -d $kovri_data_dir ]]; then
    echo -n "Creating $kovri_data_dir"
    mkdir "$kovri_data_dir" 2>/dev/null
    catch "could not create $kovri_data_dir"
  fi
  if [[ ! -d $bin_path ]]; then
    echo -n "Creating $bin_path"
    mkdir "$bin_path" 2>/dev/null
    catch "could not create $bin_path"
  fi

  # Install resources
  for _resource in ${resources[@]}; do
    if [[ -d $_resource ]]; then
      echo -n "Copying $_resource to $kovri_data_dir"
      cp -fR $_resource "$kovri_data_dir" 2>/dev/null
    else  # Implies binaries
      echo -n "Copying $_resource to $bin_path"
      cp -f $_resource "$bin_path" 2>/dev/null
    fi
    catch "could not copy resource"
  done
}

CreatePackage()
{
  # Ensure we're top-level if packaging from git repo
  local _git="git rev-parse --show-toplevel"
  $_git &>/dev/null
  if [[ $? -eq 0 ]]; then
    cd $($_git)
    local _is_git=true
  else
    cd $(dirname "$0")
  fi

  # Package preparation
  if [[ $package_option == true ]]; then
    # Set defaults
    if [[ $_is_git == true ]]; then
      local _rev="-"$(git rev-parse --short HEAD 2>/dev/null)
    fi
    staging_path="kovri${_rev}-$(uname -s)-$(uname -m)-$(date +%Y.%m.%d)"
    # Set package file if none supplied
    if [[ -z $package_file ]]; then
      local _ext=".tar.bz2"
      if [[ $is_windows == true ]]; then
        local _ext=".exe"
      fi
      package_file="build/${staging_path}${_ext}"
    fi
  else
    # Ensure proper command line
    if [[ ! -z $package_file || $checksum_option == true ]]; then
      PrintUsage ; false ; catch "set the package option to build a package"
    fi
  fi

  # Test access
  if [[ ! -x $package_file ]]; then
    echo -n "Testing write access"
    catch "we can't write to $package_file"
  fi

  # Create package
  if [[ $is_windows == true ]]; then
    # Inno Setup
    local _program_files="$PROGRAMFILES"
    if [[ $bitness == 64 ]]; then
      _program_files="$PROGRAMFILES (x86)"
    fi
    "${_program_files}"/Inno\ Setup\ 5/ISCC.exe pkg/installers/windows/Kovri${bitness}.iss
    catch "could not create Inno Setup installer"
    local _setup_bin="build/KovriSetup${bitness}.exe"
    echo -n "Moving $_setup_bin to $package_file"
    mv $_setup_bin $package_file
    catch "could not move package file"
  else
    echo -n "Creating staging path"
    mkdir $staging_path
    catch "could not create staging directory"

    # Copy resources
    echo -n "Copying resources"
    if [[ $is_osx == true || $is_bsd == true ]]; then
      # TODO(anonimal): using rsync is a hack to preserve parent path
      hash rsync 2>/dev/null
      if [[ $? -ne 0 ]]; then
        false
        catch "rsync not installed. Install rsync for $OSTYPE"
      fi
      for _resource in ${resources[@]}; do
        rsync -avR $_resource $staging_path 1>/dev/null
      done
    else
      cp -R --parents $resources $staging_path
    fi
    catch "could not copy resources for packaging"

    # Add ourself to the package
    echo -n "Copying installer"
    cp pkg/installers/kovri-install.sh $staging_path
    catch "could not copy installer"

    # Add the install guide
    echo -n "Copying guide"
    cp pkg/installers/INSTALL.txt $staging_path
    catch "could not copy install guide"

    # Compress package
    echo -n "Compressing package $package_file (please wait)..."
    tar cjf $package_file $staging_path
    catch "could not create package file"
    echo -n "Cleaning staging path"

    # Cleanup
    rm -fr $staging_path
    catch "could not clean staging path"
  fi

  # Create checksum
  if [[ $checksum_option == true ]]; then
    local _output_size=256
    local _shasum_file=${package_file}.sha${_output_size}sum.txt
    # Use available check command
    if [[ $is_openbsd == true ]]; then
      local _shasum_cmd="sha256"
    else
      local _shasum_cmd="shasum"
    fi
    # Calculate sum
    echo -n "Creating shasum $_shasum_file"
    if [[ $is_openbsd == true ]]; then
      $_shasum_cmd $package_file 1> $_shasum_file
    else
      $_shasum_cmd -a $_output_size $package_file 1> $_shasum_file
    fi
    catch "could not create checksum file"
    # Verify produced checksum
    echo -n "Verifying $package_file"
    $_shasum_cmd -c $_shasum_file 1>/dev/null ; catch "could not verify checksum"
  fi
}

# Test if terminal is color capable
if [[ $(tput colors) ]]; then
  red="$(tput setaf 1)"
  green="$(tput setaf 2)"
  yellow="$(tput setaf 3)"
  normal="$(tput sgr0)"
fi

echo "${yellow}The Kovri I2P Router Project (c) 2015-2018${normal}"

if [[ $package_option == true ]]; then
  CreatePackage
  echo "${green}Package creation success!${normal}"
elif [[ $uninstall_option == true ]]; then
  Uninstall
  echo "${green}Un-installation success!${normal}"
else
  Uninstall
  Install
  if [[ $is_windows != true ]]; then
    echo "Data directory is $kovri_data_dir"
    echo "Binaries are located in $bin_path"
    echo "${green}Installation success!${normal}"
  fi
fi

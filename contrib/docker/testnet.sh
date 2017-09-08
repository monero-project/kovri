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

#!/bin/bash

# Set constants

docker_base_name="kovri_testnet"

pid=$(id -u)
gid="docker" # Assumes user is in docker group

# TODO(unassigned): better sequencing impl
#Note: sequence limit [2:254]
seq_start=10  # Not 0 because of port assignments, not 1 because we can't use IP ending in .1 (assigned to gateway)
seq_base_nb=${KOVRI_NB_BASE:-20}  # TODO(unassigned): arbitrary end amount
seq_base_end=$((${seq_start} + ${seq_base_nb} - 1))
sequence="seq -f "%03g" ${seq_start} ${seq_base_end}"

reseed_file="reseed.zip"

PrintUsage()
{
  echo "Usage: $ $0 {create|start|stop|destroy|exec}" >&2
}

if [[ $# -lt 1 ]]
then
  PrintUsage
  exit 1
fi

Prepare()
{
  # Ensure we have proper binaries installed
  hash docker 2>/dev/null
  catch "docker not installed, please install"

  hash zip 2>/dev/null
  catch "zip not installed, please install"

  # Cleanup for new testnet
  if [[ $KOVRI_WORKSPACE || $KOVRI_NETWORK ]]; then
    read_bool_input "Kovri testnet environment detected. Attempt to destroy previous testnet?" KOVRI_CLEANUP cleanup_testnet
  fi

  # Set environment
  set_repo
  set_image
  set_bins
  set_workspace
  set_args
  set_network
}

cleanup_testnet()
{
  Destroy
  if [[ $? -ne 0 ]]; then
    echo "Previous testnet not found, continuing creation"
  fi
}

set_repo()
{
  # Set Kovri repo location
  if [[ -z $KOVRI_REPO ]]; then
    KOVRI_REPO="/tmp/kovri"
    read_input "Change location of Kovri repo? [KOVRI_REPO=${KOVRI_REPO}]" KOVRI_REPO
  fi

  # Ensure repo
  if [[ ! -d $KOVRI_REPO ]]; then
    false
    catch "Kovri not found. See building instructions."
  fi
}

set_bins()
{
  read_bool_input "Use binaries from repo?" KOVRI_USE_REPO_BINS ""

  if [[ $KOVRI_USE_REPO_BINS = true ]];then
    echo "Using binaries in ${KOVRI_REPO}/build"
    mount_repo_bins="-v ${KOVRI_REPO}/build/kovri:/usr/bin/kovri \
      -v ${KOVRI_REPO}/build/kovri-util:/usr/bin/kovri-util"

    read_bool_input "Build repo binaries?" KOVRI_BUILD_REPO_BINS "Exec make release-static"
    if [[ $KOVRI_BUILD_REPO_BINS = false ]];then
      echo "Please ensure that the binaries are built statically if not built within a container"
    fi
  fi
}

set_image()
{
  # Build Kovri image if applicable
  pushd $KOVRI_REPO
  catch "Could not access $KOVRI_REPO"

  # Set tag
  hash git 2>/dev/null
  if [[ $? -ne 0 ]]; then
    echo "git is not installed, using default tag"
    local _docker_tag=":latest"
  else
    local _docker_tag=":$(git rev-parse --short HEAD)"
  fi

  # If image name not set, provide name options + build options
  local _default_image="geti2p/kovri${_docker_tag}"
  if [[ -z $KOVRI_IMAGE ]]; then
    KOVRI_IMAGE=${_default_image}
    read_input "Change image name?: [KOVRI_IMAGE=${KOVRI_IMAGE}]" KOVRI_IMAGE
  fi

  # If input was null
  if [[ -z $KOVRI_IMAGE ]]; then
    KOVRI_IMAGE=${_default_image}
  fi

  # Select Dockerfile
  local _default_dockerfile="Dockerfile_dev"
  if [[ -z $KOVRI_DOCKERFILE ]]; then
    KOVRI_DOCKERFILE=${_default_dockerfile}
    read_input "Change Dockerfile?: [KOVRI_DOCKERFILE=${KOVRI_DOCKERFILE}]" KOVRI_DOCKERFILE
  fi

  local _dockerfile_path="${KOVRI_REPO}/contrib/docker/${KOVRI_DOCKERFILE}"

  read_bool_input "Build Kovri Docker image? [$KOVRI_IMAGE]" KOVRI_BUILD_IMAGE "docker build -t $KOVRI_IMAGE -f $_dockerfile_path $KOVRI_REPO"
  popd
}

set_workspace()
{
  # Set testnet workspace
  if [[ -z $KOVRI_WORKSPACE ]]; then
    KOVRI_WORKSPACE="${KOVRI_REPO}/build/testnet"
    read_input "Change workspace for testnet output? [KOVRI_WORKSPACE=${KOVRI_WORKSPACE}]" KOVRI_WORKSPACE
  fi

  # Ensure workspace
  if [[ ! -d $KOVRI_WORKSPACE ]]; then
    echo "$KOVRI_WORKSPACE does not exist, creating"
    mkdir -p $KOVRI_WORKSPACE 2>/dev/null
    catch "Could not create workspace"
  fi
}

set_args()
{
  # TODO(unassigned): *all* arguments (including sequence count, etc.)
  # Set utility binary arguments
  if [[ -z $KOVRI_UTIL_ARGS ]]; then
    KOVRI_UTIL_ARGS="--floodfill 1 --bandwidth P"
    read_input "Change utility binary arguments? [KOVRI_UTIL_ARGS=\"${KOVRI_UTIL_ARGS}\"]" KOVRI_UTIL_ARGS
  fi

  # Set daemon binary arguments
  if [[ -z $KOVRI_BIN_ARGS ]]; then
    KOVRI_BIN_ARGS="--floodfill 1 --disable-su3-verification 1"
    read_input "Change kovri binary arguments? [KOVRI_BIN_ARGS=\"${KOVRI_BIN_ARGS}\"]" KOVRI_BIN_ARGS
  fi
}

set_network()
{
  # Create network
  # TODO(anonimal): we splitup octet segments as a hack for later setting RI addresses
  if [[ -z $KOVRI_NETWORK ]]; then
    KOVRI_NETWORK="kovri-testnet"
  fi
  if [[ -z $network_octets ]]; then
    network_octets="172.18.0"
  fi
  network_subnet="${network_octets}.0/16"
}

create_network()
{
  echo "Creating $KOVRI_NETWORK"
  docker network create --subnet=${network_subnet} $KOVRI_NETWORK

  if [[ $? -ne 0 ]]; then
    read -r -p "Create a new network? [Y/n] " REPLY
    case $REPLY in
      [nN])
        echo "Could not finish testnet creation"
        exit 1
        ;;
      *)
        read -r -p "Set network name: " REPLY
        KOVRI_NETWORK=${REPLY}
        read -r -p "Set first 3 octets: " REPLY
        network_octets=${REPLY}
        set_network
        ;;
    esac

    # Fool me once, shame on you. Fool me twice, ...
    docker network create --subnet=${network_subnet} $KOVRI_NETWORK
    catch "Docker could not create network"
  fi

  echo "Created network: $KOVRI_NETWORK"
}

# Create data directory
# $1 - sequence id
create_data_dir()
{
  # Setup router dir
  local _dir="router_$1"

  # Create data dir
  local _data_dir="${_dir}/.kovri"
  mkdir -p $_data_dir
  catch "Could not create $_data_dir"

  # Set permissions
  chown -R ${pid}:${gid} ${KOVRI_WORKSPACE}/${_dir}
  catch "Could not set ownership ${pid}:${gid}"

  # Create data-dir + copy only what's needed from pkg
  mkdir -p kovri_${_seq}/core && cp -r ${KOVRI_REPO}/pkg/{client,config,*.sh} kovri_${_seq}
  catch "Could not copy package resources / create data-dir"

  ## Default with 1 server tunnel
  echo "\
[MyServer]
type = server
address = 127.0.0.1
port = 2222
in_port = 2222
keys = server-keys.dat
;white_list =
;black_list =
" > kovri_${_seq}/config/tunnels.conf
  catch "Could not create server tunnel"
}

# Create data directory
# $1 - sequence id
# $2 - Extra docker options
# $3 - Binary arguments
create_instance()
{
  local _seq=$1

  local _dir="router_${_seq}"
  local _data_dir="${_dir}/.kovri"
  local _host="${network_octets}.$((10#${_seq}))"
  local _port="${seq_start}${_seq}"
  local _mount="/home/kovri"
  local _volume="${KOVRI_WORKSPACE}/${_dir}:${_mount}"
  local _container_name="${docker_base_name}_${_seq}"

  docker create -w /home/kovri \
    --name $_container_name \
    --hostname $_container_name \
    --net $KOVRI_NETWORK \
    --ip $_host \
    -p ${_port}:${_port} \
    -v ${KOVRI_WORKSPACE}:/home/kovri/testnet \
    $mount_repo_bins \
    $2 \
    $KOVRI_IMAGE /usr/bin/kovri \
    --data-dir /home/kovri/testnet/kovri_${_seq} \
    --reseed-from /home/kovri/testnet/${reseed_file} \
    --host $_host \
    --port $_port \
    $3

  catch "Docker could not create container"
}

Create()
{
  # Create network
  create_network

  # Create workspace
  pushd $KOVRI_WORKSPACE

  for _seq in $($sequence); do
    create_data_dir ${_seq}

    # Create RI's
    local _dir="router_${_seq}"
    local _data_dir="${_dir}/.kovri"
    local _host="${network_octets}.$((10#${_seq}))"
    local _port="${seq_start}${_seq}"
    local _mount="/home/kovri"
    local _volume="${KOVRI_WORKSPACE}/${_dir}:${_mount}"
    docker run -w $_mount -it --rm \
      -v $_volume \
      $mount_repo_bins \
      $KOVRI_IMAGE /usr/bin/kovri-util routerinfo --create \
        --host $_host \
        --port $_port \
        $KOVRI_UTIL_ARGS
    catch "Docker could not run"
    echo "Created RI | host: $_host | port: $_port | args: $KOVRI_UTIL_ARGS | volume: $_volume"

    # Create container
    create_instance $_seq "" "${KOVRI_BIN_ARGS}"
  done

  ## ZIP RIs to create unsigned reseed file
  zip -j ${KOVRI_WORKSPACE}/${reseed_file} $(ls router_*/routerInfo* | grep -v key)
  catch "Could not ZIP RI's"

  for _seq in $($sequence); do
    ## Put RI + key in correct location
    cp $(ls router_${_seq}/routerInfo*.dat) kovri_${_seq}/core/router.info
    cp $(ls router_${_seq}/routerInfo*.key) kovri_${_seq}/core/router.keys
    catch "Could not copy RI and key"

    chown -R ${pid}:${gid} kovri_${_seq}
    catch "Could not set ownership ${pid}:${gid}"
  done
  popd
}

Start()
{
  for _seq in $($sequence); do
    local _container_name="${docker_base_name}_${_seq}"
    echo -n "Starting... " && docker start $_container_name
    catch "Could not start docker: $_seq"
  done
}

Stop()
{
  for _seq in $($sequence); do
    local _container_name="${docker_base_name}_${_seq}"
    echo -n "Stopping... " && docker stop $_container_name
    catch "Could not stop docker: $_seq"
  done
}

Destroy()
{
  echo "Destroying... [Workspace: $KOVRI_WORKSPACE | Network: $KOVRI_NETWORK]"

  # TODO(unassigned): error handling?
  if [[ -z $KOVRI_WORKSPACE ]]; then
    read -r -p "Enter workspace to remove: " REPLY
    KOVRI_WORKSPACE=${REPLY}
  fi

  Stop

  for _seq in $($sequence); do
    local _container_name="${docker_base_name}_${_seq}"
    echo -n "Removing... " && docker rm -v $_container_name
    rm -rf ${KOVRI_WORKSPACE}/router_${_seq}
    rm -rf ${KOVRI_WORKSPACE}/kovri_${_seq}
  done

  rm ${KOVRI_WORKSPACE}/${reseed_file}

  if [[ -z $KOVRI_NETWORK ]]; then
    read -r -p "Enter network name to remove: " REPLY
    KOVRI_NETWORK=${REPLY}
  fi

  docker network rm $KOVRI_NETWORK && echo "Removed network: $KOVRI_NETWORK"
}

Exec()
{
  docker run -i -t \
    --rm \
    -v $KOVRI_REPO:/home/kovri/kovri \
    -w /home/kovri/kovri \
    $KOVRI_IMAGE \
    $@
  catch "Docker: run failed"
}

# Error handler
catch()
{
  if [[ $? -ne 0 ]]; then
    echo "$1" >&2
    exit 1
  fi
}

# Read handler
# $1 - message
# $2 - varname to set
# $3 - function or string to execute
read_input()
{
  read -r -p "$1 [Y/n] " REPLY
  case $REPLY in
    [nN])
      ;;
    *)
      if [[ $2 != "NULL" ]]; then  # hack to ensure 2nd arg is unused
        read -r -p "Set new: " REPLY
        eval ${2}=\"${REPLY}\"
      fi
      $3
      ;;
  esac
}

# Read boolean handler
# $1 - message
# $2 - varname to set
# $3 - function or string to execute if var true
read_bool_input()
{
  if [[ ! ${!2} ]]; then
    read -r -p "$1 [Y/n] " REPLY
    case $REPLY in
      [nN])
        eval ${2}=false
        ;;
      *)
        eval ${2}=true
        ;;
    esac
  fi

  if [[ ${!2} = true ]];then
    $3
  fi
}

_args=($@)
case "$1" in
  create)
    Prepare && Create && echo "Kovri testnet created"
    ;;
  start)
    Start && echo "Kovri testnet started"
    ;;
  stop)
    Stop && echo "Kovri testnet stopped"
    ;;
  destroy)
    Destroy && echo "Kovri testnet destroyed"
    ;;
  exec)
    set_repo && set_image && Exec "${_args[@]:1}"
    ;;
  *)
    PrintUsage
    exit 1
esac

#!/bin/bash

# Set constants

docker_base_name="kovri_testnet"

pid=$(id -u)
gid="docker" # Assumes user is in docker group

# TODO(unassigned): better sequencing impl
#Note: sequence limit [2:254]
seq_start=10  # Not 0 because of port assignments, not 1 because we can't use IP ending in .1 (assigned to gateway)
seq_end=$((${seq_start} + 19))  # TODO(unassigned): arbitrary end amount
sequence="seq -f "%03g" ${seq_start} ${seq_end}"

#Note: this can avoid to rebuild the docker image
#custom_build_dir="-v /home/user/kovri/build/kovri:/usr/bin/kovri -v /home/user/kovri/build/kovri-util:/usr/bin/kovri-util"

reseed_file="reseed.zip"

PrintUsage()
{
  echo "Usage: $ $0 {create|start|stop|destroy}" >&2
}

if [ "$#" -ne 1 ]
then
  PrintUsage
  exit 1
fi

# TODO(anonimal): refactor out preparation
Create()
{
  # Cleanup for new testnet
  if [[ $KOVRI_WORKSPACE || $KOVRI_NETWORK ]]; then
    read -r -p "Kovri testnet environment detected. Attempt to destroy previous testnet? [Y/n] " REPLY
    case $REPLY in
      [nN])
        ;;
      *)
        Destroy
        if [[ $? -ne 0 ]]; then
          echo "Previous testnet not found, continuing creation"
        fi
        ;;
    esac
  fi

  # Set Kovri repo location
  local _repo=$KOVRI_REPO
  if [[ -z $_repo ]]; then
    _repo="/tmp/kovri"
    read -r -p "Change location of Kovri repo? [KOVRI_REPO=${_repo}] [Y/n] " REPLY
    case $REPLY in
      [nN])
        echo "Using default: $_repo"
        ;;
      *)
        read -r -p "Set new location: " REPLY
        _repo=$REPLY
        ;;
    esac
  fi

  # Ensure repo
  if [[ ! -d $_repo ]]; then
    false
    catch "Kovri not found. See building instructions."
  fi

  # Build Kovri image if applicable
  pushd $_repo
  catch "Could not access $_repo"

  # Set tag
  hash git 2>/dev/null
  if [[ $? -ne 0 ]]; then
    echo "git is not installed, using default tag"
    local _docker_tag=":latest"
  else
    local _docker_tag=":$(git rev-parse --short HEAD)"
  fi

  # If image name not set, provide name options + build options
  local _image=$KOVRI_IMAGE
  if [[ -z $_image ]]; then
    _default_image="geti2p/kovri${_docker_tag}"
    read -r -p "Change image name?: [KOVRI_IMAGE=${_default_image}] [Y/n] " REPLY
    case $REPLY in
      [nN])
        echo "Using default: $_default_image"
        ;;
      *)
        read -r -p "Set new name: " REPLY
        _image=$REPLY
        if [[ -z $_image ]]; then
          _image="$_default_image"
        fi
        ;;
    esac
  fi

  read -r -p "Build Kovri Docker image? [$_image] [Y/n] " REPLY
  case $REPLY in
    [nN])
      echo "Using built image: $_image"
      ;;
    *)
      echo "Building image: [$_image]"
      docker build -t $_image $_repo
      catch "Could not build image"
      ;;
  esac
  popd

  # Set testnet workspace
  local _workspace=$KOVRI_WORKSPACE
  if [[ -z $_workspace ]]; then
    _workspace="${_repo}/build/testnet"
    read -r -p "Change workspace for testnet output? [KOVRI_WORKSPACE=${_workspace}] [Y/n] " REPLY
    case $REPLY in
      [nN])
        echo "Using default: $_workspace"
        ;;
      *)
        read -r -p "Set new workspace: " REPLY
        _workspace=$REPLY
        ;;
    esac
  fi

  # Ensure workspace
  if [[ ! -d $_workspace ]]; then
    echo "$_workspace does not exist, creating"
    mkdir -p $_workspace 2>/dev/null
    catch "Could not create workspace"
  fi

  # TODO(unassigned): *all* arguments (including sequence count, etc.)
  # Set utility binary arguments
  local _util_args=$KOVRI_UTIL_ARGS
  if [[ -z $_util_args ]]; then
    _util_args="--floodfill 1 --bandwidth P"
    read -r -p "Change utility binary arguments? [KOVRI_UTIL_ARGS=\"${_util_args}\"] [Y/n] " REPLY
    case $REPLY in
      [nN])
        echo "Using default: $_util_args"
        ;;
      *)
        read -r -p "Set util args: " REPLY
        _util_args=$REPLY
        ;;
    esac
  fi

  # TODO(unassigned): *all* arguments (including sequence count, etc.)
  # Set daemon binary arguments
  local _bin_args=$KOVRI_BIN_ARGS
  if [[ -z $_bin_args ]]; then
    _bin_args="--log-level 5 --floodfill 1 --enable-ntcp 0 --disable-su3-verification 1"
    read -r -p "Change kovri binary arguments? [KOVRI_BIN_ARGS=\"${_bin_args}\"] [Y/n] " REPLY
    case $REPLY in
      [nN])
        echo "Using default: $_bin_args"
        ;;
      *)
        read -r -p "Set bin args: " REPLY
        _bin_args=$REPLY
        ;;
    esac
  fi

  # Create network
  # TODO(anonimal): we splitup octet segments as a hack for later setting RI addresses
  local _network_name=${KOVRI_NETWORK}
  if [[ -z $_network_name ]]; then
    _network_name="kovri-testnet"
  fi

  local _network_octets="172.18.0"
  local _network_subnet="${_network_octets}.0/16"

  echo "Creating $_network_name"
  docker network create --subnet=${_network_subnet} $_network_name

  if [[ $? -ne 0 ]]; then
    read -r -p "Create a new network? [Y/n] " REPLY
    case $REPLY in
      [nN])
        echo "Could not finish testnet creation"
        exit 1
        ;;
      *)
        read -r -p "Set network name: " REPLY
        _network_name=${REPLY}
        read -r -p "Set first 3 octets: " REPLY
        _network_octets=${REPLY}
        _network_subnet="${_network_octets}.0/16"
        ;;
    esac
    # Fool me once, shame on you. Fool me twice, ...
    docker network create --subnet=${_network_subnet} $_network_name
    catch "Docker could not create network"
  fi

  echo "Created network: $_network_name"

  # Create workspace
  pushd $_workspace

  for _seq in $($sequence); do
    # Setup router dir
    local _dir="router_${_seq}"

    # Create data dir
    local _data_dir="${_dir}/.kovri"
    mkdir -p $_data_dir
    catch "Could not create $_data_dir"

    # Set permissions
    chown -R ${pid}:${gid} ${_workspace}/${_dir}
    catch "Could not set ownership ${pid}:${gid}"

    # Create RI's
    local _host="${_network_octets}.$((10#${_seq}))"
    local _port="${seq_start}${_seq}"
    local _mount="/home/kovri"
    local _volume="${_workspace}/${_dir}:${_mount}"
    docker run -w $_mount -it --rm \
      -v $_volume \
      $custom_build_dir \
      $_image  /usr/bin/kovri-util routerinfo --create \
        --host $_host \
        --port $_port \
        $_util_args
    catch "Docker could not run"
    echo "Created RI | host: $_host | port: $_port | args: $_util_args | volume: $_volume"

    # Create container
    local _container_name="${docker_base_name}_${_seq}"
    docker create -w /home/kovri \
      --name $_container_name \
      --hostname $_container_name \
      --net $_network_name \
      --ip $_host \
      -p ${_port}:${_port} \
      -v ${_workspace}:/home/kovri/testnet \
      $custom_build_dir \
      $_image /usr/bin/kovri \
      --data-dir /home/kovri/testnet/kovri_${_seq} \
      --reseed-from /home/kovri/testnet/${reseed_file} \
      --host $_host \
      --port $_port \
      $_bin_args
    catch "Docker could not create container"
  done

  ## ZIP RIs to create unsigned reseed file
  # TODO(unassigned): ensure the zip binary is available
  local _tmp="tmp"
  mkdir $_tmp \
    && cp $(ls router_*/routerInfo* | grep -v key) $_tmp \
    && cd $_tmp \
    && zip $reseed_file * \
    && mv $reseed_file $_workspace \
    && cd .. \
    && rm -rf ${_workspace}/${_tmp}
  catch "Could not ZIP RI's"

  for _seq in $($sequence); do
    # Create data-dir + copy only what's needed from pkg
    mkdir -p kovri_${_seq}/core && cp -r ${_repo}/pkg/{client,config,*.sh} kovri_${_seq}
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
  local _workspace=${KOVRI_WORKSPACE}
  local _network=${KOVRI_NETWORK}

  echo "Destroying... [Workspace: $_workspace | Network: $_network]"

  # TODO(unassigned): error handling?
  if [[ -z $_workspace ]]; then
    read -r -p "Enter workspace to remove: " REPLY
    _workspace=${REPLY}
  fi

  Stop

  for _seq in $($sequence); do
    local _container_name="${docker_base_name}_${_seq}"
    echo -n "Removing... " && docker rm -v $_container_name
    rm -rf ${_workspace}/router_${_seq}
    rm -rf ${_workspace}/kovri_${_seq}
  done

  rm ${_workspace}/${reseed_file}

  if [[ -z $_network ]]; then
    read -r -p "Enter network name to remove: " REPLY
    _network=${REPLY}
  fi

  docker network rm $_network && echo "Removed network: $_network"
}

# Error handler
catch()
{
  if [[ $? -ne 0 ]]; then
    echo "$1" >&2
    exit 1
  fi
}

case "$1" in
  create)
    Create && echo "Kovri testnet created"
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
  *)
    PrintUsage
    exit 1
esac

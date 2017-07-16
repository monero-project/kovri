#!/bin/bash

# Set constants

docker_base_name="kovri_testnet"

pid=$(id -u)
gid="docker" # Assumes user is in docker group

#Note: sequence limit [2:254]
sequence="seq -f "%03g" 10 29"

#Note: this can avoid to rebuild the docker image
#custom_build_dir="-v /home/user/kovri:/kovri"

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

Create()
{
  # Set Kovri repo location
  local _repo=$KOVRI_REPO
  if [[ -z $_repo ]]; then
    _repo="/tmp/kovri"
    read -r -p "Set location of Kovri repo? [$_repo] [Y/n] " REPLY
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

  # If image name not set, provide options + build
  local _image=$KOVRI_IMAGE
  if [[ -z $_image ]]; then
    _image="geti2p/kovri${_docker_tag}"
    read -r -p "Build Kovri Docker image? [$_image] [Y/n] " REPLY
    case $REPLY in
      [nN])
        echo "Using built image: $_image"
        ;;
      *)
        read -r -p "Set new image name?: [$_image] [Y/n] " REPLY
        case $REPLY in
          [nN])
            echo "Using default: $_image"
            ;;
          *)
            read -r -p "Set new name: " REPLY
            _image=$REPLY
            ;;
        esac
        echo "Building image: [$_image]"
        docker build -t $_image $_repo
        catch "Could not build image"
        ;;
    esac
  fi
  popd

  # Set testnet workspace
  local _workspace=$KOVRI_WORKSPACE
  if [[ -z $_workspace ]]; then
    _workspace="${_repo}/build/testnet"
    read -r -p "Set workspace for testnet output? [$_workspace] [Y/n] " REPLY
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
    read -r -p "Set utility binary arguments? [$_util_args] [Y/n] " REPLY
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
    read -r -p "Set kovri binary arguments? [$_bin_args] [Y/n] " REPLY
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

  ## Create RIs
  pushd $_workspace

  for _seq in $($sequence); do
    # Setup router dir
    local _dir="router_${_seq}"

    # Create data dir
    mkdir -p ${_dir}/.kovri
    catch "Could not create data dir"

    # Set permissions
    chown -R ${pid}:${gid} ${_workspace}/${_dir}
    catch "Could not set ownership ${pid}:${gid}"

    # Run Docker
    docker run -w /home/kovri -it --rm \
      -v ${_workspace}/${_dir}:/home/kovri \
      $custom_build_dir \
      $_image  /kovri/build/kovri-util routerinfo --create \
        --host=172.18.0.$((10#${_seq})) \
        --port 10${_seq} \
        $_util_args
    catch "Docker could not run"
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

  ## Create docker private network
  docker network create --subnet=172.18.0.0/16 privatenet
  catch "Docker could not create network"

  for _seq in $($sequence)
  do
    ## Create data-dir
    cp -r ${_repo}/pkg kovri_${_seq} && mkdir kovri_${_seq}/core
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

    ## Create container
    docker create -w /home/kovri \
      --name ${docker_base_name}_${_seq} \
      --hostname ${docker_base_name}_${_seq} \
      --net privatenet \
      --ip 172.18.0.$((10#${_seq})) \
      -p 10${_seq}:10${_seq} \
      -v ${_workspace}:/home/kovri/testnet \
      $custom_build_dir \
      $_image /kovri/build/kovri \
      --data-dir /home/kovri/testnet/kovri_${_seq} \
      --reseed-from /home/kovri/testnet/${reseed_file} \
      --host 172.18.0.$((10#${_seq})) \
      --port 10${_seq} \
      $_bin_args
    catch "Docker could not create container"
  done
  popd
}

Start()
{
  for _seq in $($sequence); do
    docker start ${docker_base_name}_${_seq}
    catch "Could not start docker: $_seq"
  done
}

Stop()
{
  for _seq in $($sequence); do
    docker stop ${docker_base_name}_${_seq}
    catch "Could not stop docker: $_seq"
  done
}

Destroy()
{
  # TODO(unassigned): error handling?
  if [[ -z $KOVRI_WORKSPACE ]]; then
    read -r -p "Enter workspace to destroy: " REPLY
    KOVRI_WORKSPACE=$REPLY
  fi
  for _seq in $($sequence); do
    docker stop ${docker_base_name}_${_seq}
    docker rm -v ${docker_base_name}_${_seq}
    rm -rf ${KOVRI_WORKSPACE}/router_${_seq}
    rm -rf ${KOVRI_WORKSPACE}/kovri_${_seq}
  done
  rm ${KOVRI_WORKSPACE}/${reseed_file}
  docker network rm privatenet
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
    Create;;
  start)
    Start;;
  stop)
    Stop;;
  destroy)
    Destroy;;
  *)
    PrintUsage
    exit 1
esac

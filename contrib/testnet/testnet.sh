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

#!/bin/bash

# Set constants

docker_base_name="kovri_testnet_"
router_base_name="router_"
kovri_base_name="kovri_"
pipe_base_name="log_pipe"

# Monitoring Database
db_image="influxdb:latest"
db_container_name="kovri-influxdb"
db_host_octet=".3"
db_name="kovri"

# Monitoring: Container stats collector
stats_container_image="google/cadvisor:latest"
stats_container_name="kovri-cadvisor"
stats_container_host_octet=".4"

# Monitoring: Kovri stats collector
stats_kovri_name="kovri-collector"
stats_kovri_host_octet=".5"

# Monitoring UI
grafana_image="grafana/grafana"
grafana_base_name="kovri-grafana"
grafana_host_octet=".6"
grafana_host_port="3030"
grafana_password="kovri"

# Docker mount
mount="/home/kovri"
mount_testnet="${mount}/testnet"

kovri_data_dir=".kovri"

docker_dir="contrib/testnet"

# TODO(unassigned): only useful if we don't use Apache
web_name="kovri-webserver"
web_system_dir="/usr/local/apache2"
web_conf="httpd.conf"
web_dir="httpd"
web_conf_dir="conf"
web_root_dir="htdocs"
web_host_octet=".2"

pid=$(id -u)
gid="docker" # Assumes user is in docker group
docker_uid=$pid

# TODO(unassigned): better sequencing impl
#Note: sequence limit [2:254]
# Sequence for base instances (included in reseed)
seq_start=10  # Not 0 because of port assignments, not 1 because we can't use IP ending in .1 (assigned to gateway)
seq_base_nb=${KOVRI_NB_BASE:-20}  # TODO(unassigned): arbitrary end amount
seq_base_end=$((${seq_start} + ${seq_base_nb} - 1))
base_sequence="seq -f "%03g" $seq_start $seq_base_end"

# Sequence for firewalled instances (not include in reseed and firewalled)
seq_fw_nb=${KOVRI_NB_FW:-0}
seq_fw_start=$((${seq_base_end} + 1))
seq_fw_end=$((${seq_fw_start} + ${seq_fw_nb} - 1))
fw_sequence="seq -f "%03g" $seq_fw_start $seq_fw_end"

# Combined sequence (base + firewalled)
sequence="seq -f "%03g" ${seq_start} ${seq_fw_end}"

reseed_file="reseed.zip"

web_entrypoint="webserver.sh"
fw_entrypoint="firewall.sh"

PrintUsage()
{

  echo ""
  echo "Testnet environment variables"
  echo "-----------------------------"
  echo ""
  echo "strings:"
  echo ""
  echo "KOVRI_WORKSPACE         = testnet output directory"
  echo "KOVRI_NETWORK           = docker network name"
  echo "KOVRI_REPO              = kovri source repository (location of binaries)"
  echo "KOVRI_IMAGE             = kovri docker image repository:tag"
  echo "KOVRI_WEB_IMAGE         = kovri docker webserver image repository:tag"
  echo "KOVRI_DOCKERFILE        = Dockerfile to build kovri image"
  echo "KOVRI_WEB_DOCKERFILE    = Dockerfile to build kovri image"
  echo "KOVRI_BIN_ARGS          = daemon binary arguments"
  echo "KOVRI_FW_BIN_ARGS       = firewalled daemon binary arguments"
  echo "KOVRI_UTIL_ARGS         = utility binary arguments"
  echo ""
  echo "integrals:"
  echo ""
  echo "KOVRI_NB_BASE           = number of kovri instances to run"
  echo "KOVRI_NB_FW             = number of firewalled kovri instances"
  echo "KOVRI_STOP_TIMEOUT      = interval in seconds to stop container (0 for immediate)"
  echo ""
  echo "booleans:"
  echo ""
  echo "KOVRI_BUILD_IMAGE       = build kovri image"
  echo "KOVRI_BUILD_WEB_IMAGE   = build kovri webserver image"
  echo "KOVRI_USE_REPO_BINS     = use repo-built binaries"
  echo "KOVRI_BUILD_REPO_BINS   = build repo binaries from *within* the container"
  echo "KOVRI_CLEANUP           = cleanup/destroy previous testnet"
  echo "KOVRI_USE_NAMED_PIPES   = use named pipes for logging"
  echo "KOVRI_ENABLE_MONITORING = enable logging"
  echo ""
  echo "Log monitoring"
  echo "--------------"
  echo ""
  echo "Every kovri instance will provide real-time logging via named pipes (unless disabled)."
  echo "These pipes are located in their respective directories."
  echo ""
  echo "  Example: /tmp/testnet/kovri_010/log_pipe"
  echo ""
  echo "You can \"poll\" this output by simply cat'ing the pipe:"
  echo ""
  echo "  $ cat /tmp/testnet/kovri_010/log_pipe"
  echo ""
  echo "Usage: $ $0 {create|start|stop|destroy|exec|help}" >&2
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
  set_images
  set_bins
  set_workspace
  set_args
  set_network
  read_bool_input "Use named pipes for logging?" KOVRI_USE_NAMED_PIPES ""
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

set_images()
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
  local _default_image="monero-project/kovri${_docker_tag}"
  if [[ -z $KOVRI_IMAGE ]]; then
    KOVRI_IMAGE=${_default_image}
    read_input "Change kovri image name?: [KOVRI_IMAGE=\"${KOVRI_IMAGE}\"]" KOVRI_IMAGE
    # If input was null
    if [[ -z $KOVRI_IMAGE ]]; then
      KOVRI_IMAGE=${_default_image}
    fi
  fi

  # Web server image
  local _default_web_image="httpd:2.4"
  if [[ -z $KOVRI_WEB_IMAGE ]]; then
    KOVRI_WEB_IMAGE=${_default_web_image}
    read_input "Change kovri web image name?: [KOVRI_WEB_IMAGE=\"${KOVRI_WEB_IMAGE}\"]" KOVRI_WEB_IMAGE
    # If input was null
    if [[ -z $KOVRI_WEB_IMAGE ]]; then
      KOVRI_WEB_IMAGE=${_default_web_image}
    fi
  fi

  # Select Kovri Dockerfile
  local _default_dockerfile="Dockerfile.alpine"
  if [[ -z $KOVRI_DOCKERFILE ]]; then
    KOVRI_DOCKERFILE=${_default_dockerfile}
    read_input "Change Dockerfile?: [KOVRI_DOCKERFILE=${KOVRI_DOCKERFILE}]" KOVRI_DOCKERFILE
  fi
  local _kovri_dockerfile_path="${KOVRI_REPO}/${docker_dir}/Dockerfiles/${KOVRI_DOCKERFILE}"
  read_bool_input "Build Kovri Docker image? [$KOVRI_IMAGE]" KOVRI_BUILD_IMAGE "docker build --build-arg userid=$docker_uid -t $KOVRI_IMAGE -f $_kovri_dockerfile_path $KOVRI_REPO"

  # Select Kovri Webserver Dockerfile
  local _default_web_dockerfile="Dockerfile.apache"
  if [[ -z $KOVRI_WEB_DOCKERFILE ]]; then
    KOVRI_WEB_DOCKERFILE=${_default_web_dockerfile}
    read_input "Change Dockerfile?: [KOVRI_WEB_DOCKERFILE=${KOVRI_WEB_DOCKERFILE}]" KOVRI_WEB_DOCKERFILE
  fi
  local _web_dockerfile_path="${KOVRI_REPO}/${docker_dir}/Dockerfiles/${KOVRI_WEB_DOCKERFILE}"
  read_bool_input "Build Web Docker image? [$KOVRI_WEB_IMAGE]" KOVRI_BUILD_WEB_IMAGE "docker build -t $KOVRI_WEB_IMAGE -f $_web_dockerfile_path $KOVRI_REPO"

  popd
}

set_bins()
{
  read_bool_input "Use binaries from repo?" KOVRI_USE_REPO_BINS ""

  if [[ $KOVRI_USE_REPO_BINS = true ]]; then
    echo "Using binaries in ${KOVRI_REPO}/build"

    mount_repo_bins="-v ${KOVRI_REPO}/build/kovri:/usr/bin/kovri \
      -v ${KOVRI_REPO}/build/kovri-util:/usr/bin/kovri-util"

    build_cmd="make clean"
    if [[ $KOVRI_DOCKERFILE = "Dockerfile.arch" ]]; then
      build_cmd="${build_cmd} release" # Arch doesn't support static OpenSSL builds
    else
      build_cmd="${build_cmd} release-static"
    fi

    read_bool_input "Build repo binaries from within the container?" KOVRI_BUILD_REPO_BINS "Exec $build_cmd"

    if [[ $KOVRI_BUILD_REPO_BINS = false ]]; then
      echo "Please ensure that the binaries are built statically if not built within a container"
    fi
  fi
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
    KOVRI_UTIL_ARGS="--enable-floodfill --bandwidth P"
    read_input "Change utility binary arguments? [KOVRI_UTIL_ARGS=\"${KOVRI_UTIL_ARGS}\"]" KOVRI_UTIL_ARGS
  fi

  # Set daemon binary arguments
  if [[ -z $KOVRI_BIN_ARGS ]]; then
    KOVRI_BIN_ARGS="--enable-floodfill --disable-su3-verification --disable-https --enable-auto-flush-log --i2pcontroladdress 0.0.0.0 --i2pcontrolport 7650"
    read_input "Change kovri binary arguments? [KOVRI_BIN_ARGS=\"${KOVRI_BIN_ARGS}\"]" KOVRI_BIN_ARGS
  fi

  # Set firewalled daemon binary arguments
  if [[ $KOVRI_NB_FW -gt 0 && -z $KOVRI_FW_BIN_ARGS ]]; then
    KOVRI_FW_BIN_ARGS="--enable-floodfill --disable-su3-verification --enable-auto-flush-log --i2pcontroladdress 0.0.0.0 --i2pcontrolport 7650"
    read_input "Change firewalled kovri binary arguments? [KOVRI_FW_BIN_ARGS=\"${KOVRI_FW_BIN_ARGS}\"]" KOVRI_FW_BIN_ARGS
  fi
}

set_network()
{
  # Create network
  # TODO(anonimal): we splitup octet segments as a hack for later setting RI addresses
  if [[ -z $KOVRI_NETWORK ]]; then
    # TODO(anonimal): read input
    KOVRI_NETWORK="kovri-testnet"
  fi
  if [[ -z $network_octets ]]; then
    network_octets="172.18.0"
  fi
  network_subnet="${network_octets}.0/16"
}

Create()
{
  # Create network
  create_network

  # Create workspace
  pushd $KOVRI_WORKSPACE

  # Create unfirewalled testnet
  for _seq in $($base_sequence); do
    # Create data dir
    create_data_dir $_seq

    # Create RI
    create_ri $_seq

    # Create instance
    create_instance $_seq "" "$KOVRI_BIN_ARGS"

    # Create publisher webserver instance for first kovri instance only
    # TODO(unassigned): we create the instance with the first instance in mind
    #   because we want to "reserve" that instance as the eventual in-net publisher.
    if [[ $((10#${_seq})) -eq $seq_start ]]; then
      # TODO(unassigned): we run here instead of when starting testnet because
      #   we need to ensure we have set ENV vars without needing to re-read input.
      create_webserver_instance $_seq
    fi
  done

  if [[ $KOVRI_NB_FW -gt 0 ]]; then
    # Create instances that are not in reseed file and not directly accessible
    echo "Create $KOVRI_NB_FW firewalled instances"

    local _extra_opts="-v ${KOVRI_REPO}/${docker_dir}/entrypoints/${fw_entrypoint}:/${fw_entrypoint} \
      --entrypoint /${fw_entrypoint} \
      --user 0 --cap-add=NET_ADMIN"

    for _seq in $($fw_sequence); do
      create_data_dir $_seq
      create_instance $_seq "$_extra_opts" "$KOVRI_FW_BIN_ARGS"
    done
  fi

  ## ZIP RIs to create unsigned reseed file
  zip -j ${KOVRI_WORKSPACE}/${reseed_file} $(ls router_*/routerInfo* | grep -v key)
  catch "Could not ZIP RI's"

  for _seq in $($base_sequence); do
    local _base_dir="${kovri_base_name}${_seq}"

    ## Put RI + key in correct location
    cp $(ls ${router_base_name}${_seq}/routerInfo*.dat) "${_base_dir}/core/router.info"
    cp $(ls ${router_base_name}${_seq}/routerInfo*.key) "${_base_dir}/core/router.key"
    catch "Could not copy RI and key"

    chown -R ${pid}:${gid} ${_base_dir}
    catch "Could not set ownership ${pid}:${gid}"
  done

  create_monitoring
  popd
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
  local _host_router_dir="${router_base_name}${1}"
  local _host_data_dir="${kovri_base_name}${1}"

  # Create data dir
  local _data_dir="${_host_router_dir}/${kovri_data_dir}"
  mkdir -p $_data_dir
  catch "Could not create $_data_dir"

  # Set permissions
  chown -R ${pid}:${gid} "${KOVRI_WORKSPACE}/${_host_router_dir}"
  catch "Could not set ownership ${pid}:${gid}"

  # Create data-dir + copy only what's needed from pkg
  mkdir -p ${_host_data_dir}/core && cp -r ${KOVRI_REPO}/{pkg/client,pkg/config,contrib/utils/kovri-bash.sh} "$_host_data_dir"

  # Set webserver IP
  local _web_host="${network_octets}${web_host_octet}"

  # Create publisher data on *single* instance (note: requires webserver)
  # TODO(unassigned): create server tunnel + persistent keys for in-net publishing.
  #   If we continue to keep a webserver in a separate container,
  #   we would need to forward the traffic from the kovri instance to the webserver.
  if [[ $((10#${_seq})) -eq $seq_start ]]; then
    local _dest_dir="${KOVRI_WORKSPACE}/${_host_data_dir}/${web_dir}"

    # TODO(unassigned): enable TLS/SSL + key copy

    # Create servable subscription
    # TODO(unassigned): run-time generated testnet subscription file

    mkdir -p ${_dest_dir}/${web_root_dir} \
      && cp "${_host_data_dir}/client/address_book/hosts.txt" "${_dest_dir}/${web_root_dir}"
  fi
  catch "Could not copy package resources / create data-dir"

  # Set publisher to testnet publisher
  echo "http://${_web_host}/hosts.txt" > "${_host_data_dir}/client/address_book/publishers.txt"

  ## Default with 1 server tunnel
  # TODO(unassigned): client tunnel for in-net publisher
  echo "\
[MyServer]
type = server
address = 127.0.0.1
port = 2222
in_port = 2222
keys = server-keys.dat
;white_list =
;black_list =
" > ${_host_data_dir}/config/tunnels.conf
  catch "Could not create server tunnel"
}

# Create router info
# $1 - sequence ID
create_ri()
{
  local _seq=${1}

  local _host_dir="${KOVRI_WORKSPACE}/${router_base_name}${_seq}"
  local _volume="${_host_dir}:${mount}"

  local _host="${network_octets}.$((10#${_seq}))"
  local _port="${seq_start}${_seq}"

  docker run -w $mount -it --rm \
    -v $_volume \
    -u $docker_uid \
    $mount_repo_bins \
    $KOVRI_IMAGE /usr/bin/kovri-util routerinfo --create \
      --host $_host \
      --port $_port \
      $KOVRI_UTIL_ARGS
  catch "Docker could not run"

  echo "Created RI | host: $_host | port: $_port | args: $KOVRI_UTIL_ARGS | volume: $_volume"
}

# Create kovri container instance
# $1 - sequence id
# $2 - Extra docker options
# $3 - Binary arguments
create_instance()
{
  local _seq=${1}
  local _docker_opts=${2}

  # Create named pipe for logging
  local _pipe="${KOVRI_WORKSPACE}/${kovri_base_name}${_seq}/${pipe_base_name}"

  if [[ $KOVRI_USE_NAMED_PIPES = false ]]; then
    touch "$_pipe"
    catch "Could not create file $_pipe"
  else
    mkfifo "$_pipe"
    catch "Could not create named pipe $_pipe"
  fi

  # Set container options
  local _container_name="${docker_base_name}${_seq}"

  local _data_dir="${mount_testnet}/${kovri_base_name}${_seq}"
  local _container_pipe="${_data_dir}/${pipe_base_name}"

  local _host="${network_octets}.$((10#${_seq}))"
  local _port="${seq_start}${_seq}"

  local _volume="${KOVRI_WORKSPACE}:${mount_testnet}"

  local _bin_args="
    --data-dir $_data_dir
    --reseed-from ${mount_testnet}/${reseed_file}
    --host $_host --port $_port
    --log-file-name $_container_pipe
    $3"

  # Create container
  docker create -w $mount \
    --name $_container_name \
    --hostname $_container_name \
    --net $KOVRI_NETWORK \
    --ip $_host \
    -p ${_port}:${_port} \
    -v $_volume \
    -u $docker_uid \
    $mount_repo_bins \
    $_docker_opts \
    $KOVRI_IMAGE \
    /usr/bin/kovri $_bin_args
  catch "Docker could not create container"

  echo "Created container | volume: $_volume | host: $_host | port: $_port | args: $_bin_args"
}

# Create webserver instance (subscription publishing)
# $1 - sequence id
create_webserver_instance()
{
  local _seq=${1}
  local _web_host="${network_octets}${web_host_octet}"
  local _dest_dir="${KOVRI_WORKSPACE}/${kovri_base_name}${_seq}/${web_dir}"

  local _entrypoint="-v ${KOVRI_REPO}/${docker_dir}/entrypoints/${web_entrypoint}:/${web_entrypoint} --entrypoint /${web_entrypoint}"

  # TODO(unassigned): this is Apache-specific
  local _cmd="sed -i -e 's/#ServerName .*/ServerName ${_web_host}:80/' ${web_system_dir}/${web_conf_dir}/${web_conf} && httpd-foreground"

  # Start publisher instance
  docker create -it --network=${KOVRI_NETWORK} --ip=${_web_host} --name $web_name \
    $_entrypoint \
    -u $docker_uid \
    -v ${_dest_dir}/${web_root_dir}/:${web_system_dir}/${web_root_dir}/ \
    $KOVRI_WEB_IMAGE \
    "$_cmd"

  catch "Docker could not run webserver"
}

create_monitoring()
{
  read_bool_input "Enable monitoring?" KOVRI_ENABLE_MONITORING ""
  if [[ $KOVRI_ENABLE_MONITORING = true ]]; then
    # Set db IP
    local _db_host="${network_octets}${db_host_octet}"
    local _db_uri="${_db_host}:8086"

    # Create DB container
    docker create -it --name ${db_container_name} --network=${KOVRI_NETWORK} --ip=${_db_host} \
      ${db_image}
    catch "Could not create $db_container_name"

    # Create database ${db_name}
    echo -n "Starting... " && docker start ${db_container_name}
    catch "Could not start $db_container_name"

    echo "Wait 3s for db to start... " && sleep 3
    echo "Create database kovri"
    curl -i -XPOST http://${_db_uri}/query --data-urlencode "q=CREATE DATABASE ${db_name}"
    catch "Could not create database ${db_name}"

    echo -n "Stopping... " && docker stop ${db_container_name}
    catch "Could not stop $db_container_name"

    # Create container stats collector
    local _stats_container_host="${network_octets}${stats_container_host_octet}"
    docker create --name ${stats_container_name} --network=${KOVRI_NETWORK} --ip=${_stats_container_host} \
      --volume=/:/rootfs:ro --volume=/var/run:/var/run:rw --volume=/sys:/sys:ro \
      --volume=/var/lib/docker/:/var/lib/docker:ro \
      --volume=/dev/disk/:/dev/disk:ro \
      ${stats_container_image} -storage_driver=influxdb -storage_driver_host=${_db_uri} -storage_driver_db=${db_name}
    catch "Could not create $stats_container_name"
    echo "Created container stats collector ${stats_container_name}"

    # Create kovri stats collector
    local _collector_host="${network_octets}${stats_kovri_host_octet}"
    docker create -it  --name ${stats_kovri_name} --network=${KOVRI_NETWORK} --ip=${_collector_host} \
      -v ${KOVRI_REPO}/${docker_dir}/monitoring/collect.sh:/collect.sh \
      $mount_repo_bins \
      $KOVRI_IMAGE \
      /collect.sh "${sequence}" "${network_octets}" "${_db_uri}" "${db_name}" "${docker_base_name}"
    catch "Could not create $stats_kovri_name"
    echo "Created kovri stats collector ${stats_kovri_name}"

    # Create UI container
    local _grafana_host="${network_octets}${grafana_host_octet}"
    local _grafana_uri="http://admin:${grafana_password}@${_grafana_host}:3000"
    docker run -d --name ${grafana_base_name} --network=${KOVRI_NETWORK} --ip=${_grafana_host} \
      -p ${grafana_host_port}:3000 -e "GF_SECURITY_ADMIN_PASSWORD=${grafana_password}" ${grafana_image}
    catch "Could not create ${grafana_base_name}"
    echo "Created monitoring UI ${stats_kovri_name}"

    # Grafana: add ${db_container_name} as a "data source"
    echo "Wait 10s for container to start... " && sleep 10

    curl "${_grafana_uri}/api/datasources" \
      -X POST -H 'Content-Type: application/json;charset=UTF-8' \
      --data-binary \
      '{"name":"InfluxDB","type":"influxdb","url":"http://'${_db_host}':8086","access":"proxy","isDefault":true,"database":"'${db_name}'"}'
    catch "Could not configure default datasource"
    echo "Grafana: Created datasource ${_db_host}:8086"

    # Grafana: Create API token
    local _apiKey=$(curl -X POST -H "Content-Type: application/json" -d '{"name":"apikeycurl", "role": "Admin"}' ${_grafana_uri}/api/auth/keys | python -c "import sys, json; print(json.load(sys.stdin)['key'])")
    catch "Grafana: Could not create API key"
    echo "Grafana: Created api key $_apiKey"

    # Grafana: add dashboards
    for dashboard in ${KOVRI_REPO}/contrib/testnet/monitoring/dashboards/*.json; do
      echo "Importing dashboard ${dashboard}... " && curl -X POST --insecure \
        -H "Authorization: Bearer $_apiKey" \
        -H "Content-Type: application/json" \
        -d @${dashboard} \
        ${_grafana_uri}/api/dashboards/db && echo ""
      catch "Grafana: failed to add dashboard $dashboard"
    done

    # Stop grafana
    echo -n "Stopping... " && docker stop ${grafana_base_name}
    catch "Could not stop ${grafana_base_name}"

    echo "Monitoring interface is accessibe at: http://127.0.0.1:${grafana_host_port} with credentials admin:${grafana_password}"
  fi
}

has_monitoring()
{
  HAS_MONITORING=false;
  local monitor_containers="${db_container_name}|${stats_container_name}|${stats_kovri_name}|${grafana_base_name}"
  docker container ls --all | grep -q -E "$monitor_containers"
  if [[ $? -eq 0 ]]; then
    HAS_MONITORING=true;
  fi
}

Start()
{
  echo -n "Starting web server... " && docker start $web_name
  # Start testnet
  for _seq in $($sequence); do
    local _container_name="${docker_base_name}${_seq}"
    echo -n "Starting... " && docker start $_container_name
    catch "Could not start docker: $_seq"
  done

  has_monitoring
  if [[ $HAS_MONITORING = true ]]; then
    echo -n "Starting monitoring database... " && docker start $db_container_name
    echo -n "Starting container stats collector... " && docker start $stats_container_name
    echo -n "Starting kovri stats collector... " && docker start $stats_kovri_name
    echo -n "Starting monitoring UI... " && docker start $grafana_base_name
  fi
}

Stop()
{
  # Set timeout
  if [[ -z $KOVRI_STOP_TIMEOUT ]]; then
    read_input "Set container timeout interval (in seconds)?" KOVRI_STOP_TIMEOUT
    if [[ -z $KOVRI_STOP_TIMEOUT ]]; then
      KOVRI_STOP_TIMEOUT=10  # Set to 0 for immediate timeout
    fi
  fi

  local _stop="docker stop -t $KOVRI_STOP_TIMEOUT"

  # Stop testnet
  has_monitoring
  if [[ $HAS_MONITORING = true ]]; then
    echo -n "Stopping monitoring collector " && $_stop $stats_kovri_name
    echo -n "Stopping container stats collector... " && $_stop $stats_container_name
    echo -n "Stopping monitoring database... " && $_stop $db_container_name
    echo -n "Stopping monitoring UI... " && $_stop $grafana_base_name
  fi

  echo -n "Stopping web server... " && $_stop $web_name
  for _seq in $($sequence); do
    local _container_name="${docker_base_name}${_seq}"
    echo -n "Stopping... " && $_stop $_container_name
    # Don't exit, attempt to stop all potential containers
    if [[ $? -ne 0 ]]; then
      echo "Could not stop docker: $_seq"
    fi
  done

  # Stop webserver subscription publishing
  $_stop $web_name
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

  has_monitoring
  if [[ $HAS_MONITORING = true ]]; then
    echo -n "Removing monitoring collector... " && docker rm -v $stats_kovri_name
    echo -n "Removing container stats collector... " && docker rm -v $stats_container_name
    echo -n "Removing monitoring database... " && docker rm -v $db_container_name
    echo -n "Removing monitoring UI... " && docker rm -v $grafana_base_name
  fi

  echo -n "Removing web server... " && docker rm -v $web_name
  for _seq in $($sequence); do
    local _container_name="${docker_base_name}${_seq}"
    echo -n "Removing... " && docker rm -v $_container_name
  done

  # Remove the entire the workspace
  rm -fr ${KOVRI_WORKSPACE}

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
    -u $docker_uid \
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
    set_repo && set_images && Exec "${_args[@]:1}"
    ;;
  help | *)
    PrintUsage
    exit 1
esac

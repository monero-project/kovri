#!/bin/bash

# Get/set environment
KOVRI_DIR=${KOVRI_DIR:-"/tmp/kovri"}

# Set constants
workspace=${KOVRI_DIR}/build/testnet

docker_image="kovrid"
docker_base_name="kovritestnet"

pid="1000"
gid="1000"

#Note: sequence limit [2:254]
sequence="seq -f "%03g" 10 29"

#Note: this can avoid to rebuild the docker image
#custom_build_dir="-v /home/user/kovri:/kovri"

PrintUsage()
{
  echo "Usage: $ export KOVRI_DIR=\"path to your kovri repo\" && $0 {create|start|stop|destroy}" >&2
}

if [ "$#" -ne 1 ]
then
  PrintUsage
  exit 1
fi

Create()
{
  # Ensure paths
  if [[ ! -d $KOVRI_DIR ]]; then
    echo "Kovri not found. See building instructions."
    exit 1
  fi

  if [[ ! -d $workspace ]]; then
    echo "$workspace does not exist, creating"
    mkdir -p $workspace 2>/dev/null
  fi

  pushd $workspace

  ## Create RIs
  for _seq in $($sequence)
  do
      mkdir -p router_${_seq}/.kovri
      chown -R ${pid}:${gid} ${workspace}/router_${_seq}
      docker run -w /home/kovri -it --rm \
        -v ${workspace}/router_${_seq}:/home/kovri \
        $custom_build_dir \
        $docker_image  /kovri/build/kovri-util routerinfo --create \
          --host=172.18.0.$((10#${_seq})) --port 10${_seq} --floodfill 1 --bandwidth P
  done

  ## ZIP RIs to create reseed.zip
  mkdir tmp \
    && cp $(ls router_*/routerInfo* | grep -v key) tmp \
    && cd tmp \
    && zip reseed.zip * \  # TODO(unassigned): ensure this binary is available
    && mv reseed.zip $workspace \
    && cd .. \
    && rm -rf ${workspace}/tmp

  ## Create docker private network
  docker network create --subnet=172.18.0.0/16 privatenet

  for _seq in $($sequence)
  do
    ## Create data-dir
    cp -r ${KOVRI_DIR}/pkg kovri_${_seq}
    mkdir kovri_${_seq}/core

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

    ## Put RI + key in correct location
    cp $(ls router_${_seq}/routerInfo*.dat) kovri_${_seq}/core/router.info
    cp $(ls router_${_seq}/routerInfo*.key) kovri_${_seq}/core/router.keys
    chown -R ${pid}:${gid} kovri_${_seq}

    ## Create container
    docker create -u 0 -w /home/kovri \
      --name ${docker_base_name}_${_seq} \
      --hostname ${docker_base_name}_${_seq} \
      --net privatenet \
      --ip 172.18.0.$((10#${_seq})) \
      -p 10${_seq}:10${_seq} \
      -v ${workspace}:/home/kovri/testnet \
      $custom_build_dir \
      $docker_image /kovri/build/kovri \
      --data-dir /home/kovri/testnet/kovri_${_seq} \
      --log-level 5 \
      --host 172.18.0.$((10#${_seq})) \
      --port 10${_seq} \
      --floodfill=1 \
      --enable-ntcp=0 \
      --disable-su3-verification=1 \
      --reseed-from /home/kovri/testnet/reseed.zip
  done
  popd
}

Start()
{
  for _seq in $($sequence)
  do
    docker start ${docker_base_name}_${_seq}
  done
}

Stop()
{
  for _seq in $($sequence)
  do
    docker stop ${docker_base_name}_${_seq}
  done
}

Destroy()
{
  for _seq in $($sequence)
  do
    docker stop ${docker_base_name}_${_seq}
    docker rm -v ${docker_base_name}_${_seq}
    rm -rf ${workspace}/router_${_seq}
    rm -rf ${workspace}/kovri_${_seq}
  done
  rm ${workspace}/reseed.zip
  docker network rm privatenet
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

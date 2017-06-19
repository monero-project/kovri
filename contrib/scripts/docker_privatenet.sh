#!/bin/bash

PrintUsage()
{
  echo "Usage: $0 {create|start|stop|destroy}" >&2
}

if [ "$#" -ne 1 ]
then
  PrintUsage
  exit 1
fi

Create()
{
  pushd ${WORKSPACE}
  ## Create RIs
  for var in `$SEQUENCE`
  do
      mkdir -p router_$var/.kovri
      chown -R $PID:$GID $WORKSPACE/router_$var
      docker run -w /home/kovri -it --rm \
        -v $WORKSPACE/router_$var:/home/kovri \
        $CUSTOM_BUILD_DIR \
        $DOCKER_IMAGE  /kovri/build/kovri-util routerinfo --create \
          --host=172.18.0.$((10#$var)) --port 10$var --floodfill 1 --bandwidth P
  done

  ## ZIP RIs to create reseed.zip
  mkdir tmp \
    && cp `ls router_*/routerInfo* | grep -v key` tmp \
    && cd tmp \
    && zip reseed.zip * \
    && mv reseed.zip $WORKSPACE \
    && cd .. \
    && rm -rf $WORKSPACE/tmp

  ## Create docker private network
  docker network create --subnet=172.18.0.0/16 privatenet

  for var in `$SEQUENCE`
  do
    ## Create data-dir
    cp -r ${KOVRI_SRC}/pkg kovri_$var
    mkdir kovri_$var/core
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
" > kovri_$var/config/tunnels.conf

    ## Put RI + key in correct location
    cp `ls router_$var/routerInfo*.dat` kovri_$var/core/router.info
    cp `ls router_$var/routerInfo*.key` kovri_$var/core/router.keys
    chown -R $PID:$GID kovri_$var

    ## Create container
    docker create -u 0 -w /home/kovri \
      --name ${DOCKER_BASE_NAME}_$var \
      --hostname ${DOCKER_BASE_NAME}_$var \
      --net privatenet \
      --ip 172.18.0.$((10#$var)) \
      -p 10$var:10$var \
      -v $WORKSPACE:/home/kovri/testnet \
      $CUSTOM_BUILD_DIR \
      $DOCKER_IMAGE /kovri/build/kovri \
      --data-dir /home/kovri/testnet/kovri_$var \
      --log-level 5 \
      --host 172.18.0.$((10#$var)) \
      --port 10$var \
      --floodfill=1 \
      --enable-ntcp=0 \
      --disable-su3-verification=1 \
      --reseed-from /home/kovri/testnet/reseed.zip
  done
  popd
}

Start()
{
  for var in `$SEQUENCE`
  do
    docker start ${DOCKER_BASE_NAME}_$var
  done
}

Stop()
{
  for var in `$SEQUENCE`
  do
    docker stop ${DOCKER_BASE_NAME}_$var
  done
}

Destroy()
{
  for var in `$SEQUENCE`
  do
    docker stop ${DOCKER_BASE_NAME}_$var
    docker rm -v ${DOCKER_BASE_NAME}_$var
    rm -rf $WORKSPACE/router_$var
    rm -rf $WORKSPACE/kovri_$var
  done
  rm $WORKSPACE/reseed.zip
  docker network rm privatenet
}

## Variables
KOVRI_SRC="/opt/kovri"
WORKSPACE="/opt/testnet"
DOCKER_IMAGE="kovrid"
DOCKER_BASE_NAME="kovritestnet"
PID="1000"
GID="1000"
#Note: sequence limit [2:254]
SEQUENCE="seq -f "%03g" 10 29"

#Note: this can avoid to rebuild the docker image
#CUSTOM_BUILD_DIR="-v /home/user/kovri:/kovri"

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


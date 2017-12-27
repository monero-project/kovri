#!/bin/bash

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

sequence=$1
network_octets=$2
db_uri=$3
db_name=$4
docker_base_name=$5

while true; do
  sleep 15
  data=""
  for _seq in $($sequence); do
    _host="${network_octets}.$((10#${_seq}))"
    _container_name="${docker_base_name}${_seq}"
    IFS=$'\n'

    # Get statistics from kovri instances
    stats=$(/usr/bin/kovri-util control stats --host $_host --log-to-console 0)
    if [[ $? -ne 0 ]]; then
        echo "Instance $_seq is not accessible"
        continue
    fi

    # Format results
    for stat in $stats;do
      IFS=$' '
      stat=($stat)
      data=${data}$'\n'${stat[4]}",instance="${_container_name}" value="${stat[6]}
    done
    unset IFS

    # Persist data in database
    curl -s -i -XPOST http://${db_uri}/write?db=${db_name} --data-binary "$data" > /dev/null
  done
done

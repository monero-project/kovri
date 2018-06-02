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

# Example:
# $ docker build -t monero-project/kovri .
# $ export KOVRI_PORT=$((9111 + RANDOM & 30777))
# $ docker run -p ${KOVRI_PORT}:${KOVRI_PORT} --env KOVRI_PORT=${KOVRI_PORT} monero-project/kovri

FROM alpine:3.7
ENV KOVRI_HOST 0.0.0.0
ENV KOVRI_PORT 24085
ADD . kovri/
RUN apk add --update --no-cache \
      binutils \
      boost \
      boost-date_time \
      boost-dev \
      boost-program_options \
      boost-system \
      boost-unit_test_framework \
      cmake \
      g++ \
      libressl-dev \
      make \
      bash \
    && \
    cd kovri && \
    make all tests && \
    adduser -D kovri && \
    mkdir /home/kovri/.kovri && \
    cp -r /kovri/pkg/* /home/kovri/.kovri && \
    strip /kovri/build/kovri && \
    strip /kovri/build/kovri-util && \
    strip /kovri/build/kovri-tests && \
    install /kovri/build/kovri /usr/bin/kovri && \
    install /kovri/build/kovri-util /usr/bin/kovri-util && \
    install /kovri/build/kovri-tests /usr/bin/kovri-tests && \
    cd .. && \
    rm -rf ~/kovri && \
    chown -R kovri:kovri /home/kovri && \
    apk del \
      binutils \
      boost-dev \
      cmake \
      g++ \
      make \
      bash \
    && \
    rm -rf /kovri && \
    rm -rf /var/cache/*
USER kovri
RUN /usr/bin/kovri-tests
CMD /usr/bin/kovri --host ${KOVRI_HOST} --port ${KOVRI_PORT}

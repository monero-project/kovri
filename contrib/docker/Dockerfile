# kovri - I2P but in CPP
# Copyright (c) 2015-2017, The Kovri I2P Router Project (see LICENSE.md)
# docker build -t geti2p/kovri .
# KOVRI_PORT=42085 && sudo docker run -p $KOVRI_PORT --env KOVRI_PORT=$KOVRI_PORT geti2p/kovri

FROM alpine:3.6
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
    && \
    cd kovri && \
    make all tests && \
    adduser -D kovri && \
    mkdir /home/kovri/.kovri && \
    cp -r /kovri/pkg/* /home/kovri/.kovri && \
    strip /kovri/build/kovri && \
    strip /kovri/build/kovri-tests && \
    install /kovri/build/kovri-tests /usr/bin/kovri-tests && \
    install /kovri/build/kovri /usr/bin/kovri && \
    cd .. && \
    rm -rf ~/kovri && \
    chown -R kovri:kovri /home/kovri && \
    apk del \
      binutils \
      boost-dev \
      cmake \
      g++ \
      make \
    && \
    rm -rf /kovri && \
    rm -rf /var/cache/*
USER kovri
RUN /usr/bin/kovri-tests
CMD /usr/bin/kovri --host ${KOVRI_HOST} --port ${KOVRI_PORT}

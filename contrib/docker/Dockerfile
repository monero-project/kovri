# kovri - I2P but in CPP
# Copyright (c) 2015-2017, The Kovri I2P Router Project (see LICENSE.md)
# docker build -t geti2p/kovri .
# KOVRI_PORT=42085 && sudo docker run -p $KOVRI_PORT --env KOVRI_PORT=$KOVRI_PORT geti2p/kovri

FROM alpine:3.5
RUN apk add --update --no-cache -t .kovri-dev g++ make cmake binutils boost-dev libressl-dev
ENV KOVRI_HOST 0.0.0.0
ENV KOVRI_PORT 24085
ADD . kovri/
RUN cd kovri && \
    make all tests
RUN adduser -D kovri && \
    mkdir /home/kovri/.kovri && \
    /kovri/build/kovri-tests && \
    cp -r /kovri/pkg/* /home/kovri/.kovri
RUN install /kovri/build/kovri-tests /usr/bin/kovri-tests && \
    install /kovri/build/kovri /usr/bin/kovri && \
    cd .. && \
    rm -rf ~/kovri && \
    chown -R kovri:kovri /home/kovri
    # TODO[lazygravy]:
    #apk del -t .kovri-dev
USER kovri
CMD /usr/bin/kovri --host ${KOVRI_HOST} --port ${KOVRI_PORT}

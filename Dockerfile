FROM docker/for-desktop-kernel:5.10.25-6594e668feec68f102a58011bb42bd5dc07a7a9b AS ksrc

FROM ubuntu:latest

WORKDIR /
COPY --from=ksrc /kernel-dev.tar /
RUN tar xf kernel-dev.tar && rm kernel-dev.tar

RUN apt-get update
RUN apt install -y kmod python3-bpfcc
RUN apt install -y make
RUN apt install -y git curl 
ENV VERSION="1.23.0" 
ENV ARCH="amd64"
RUN curl -O -L "https://golang.org/dl/go${VERSION}.linux-${ARCH}.tar.gz"

RUN tar -C /usr/local -xzf "go${VERSION}.linux-${ARCH}.tar.gz" && \
    rm "go${VERSION}.linux-${ARCH}.tar.gz"
# set go environment
ENV PATH=$PATH:/usr/local/go/bin

WORKDIR /root
CMD mount -t debugfs debugfs /sys/kernel/debug && /bin/bash

WORKDIR /usr/src 
COPY . .
# RUN cd app 
# CMD make docker
 


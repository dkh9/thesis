FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive

# basic deps 
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    python3 python3-pip \
    && apt-get clean && rm -rf /var/lib/apt/lists/* 

# direct BigMAC dependencies
RUN apt-get update && apt-get install -y \
    build-essential flex bison swig python-dev graphviz libgraphviz-dev pkg-config libaudit-dev 

# build patches
RUN apt-get install -y software-properties-common libpcre3-dev \
    libbz2-dev xmlto gettext libcap-dev libdbus-1-dev libdbus-glib-1-dev 

# java build 
RUN apt-get install -y android-tools-fsutils default-jdk maven wget

# filesystem dependencies
RUN apt-get install -y sudo f2fs-tools autotools-dev automake libtool uuid-dev liblz4-tool cpio \ 
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --upgrade pip setuptools virtualenv

RUN useradd -m -s /bin/bash hexhive && \
    echo "hexhive ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

USER hexhive 
WORKDIR /home/hexhive

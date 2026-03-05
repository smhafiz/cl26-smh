FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /project

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        libgmp-dev \
        libssl-dev \
        wget \
    && wget -q https://github.com/Kitware/CMake/releases/download/v3.29.6/cmake-3.29.6-linux-x86_64.sh \
    && sh cmake-3.29.6-linux-x86_64.sh --skip-license --prefix=/usr/local \
    && rm -f cmake-3.29.6-linux-x86_64.sh \
    && rm -rf /var/lib/apt/lists/* \
    && echo "/usr/lib/x86_64-linux-gnu" >> /etc/ld.so.conf.d/local.conf \
    && ldconfig

COPY ./build.sh /

ENV DOCKER=on

CMD ["bash", "/build.sh"]

FROM mcr.microsoft.com/dotnet/sdk:6.0-focal

RUN apt-get update && apt-get install -y git gcc g++ nasm curl make nano

WORKDIR /cipherfix
RUN curl -H "User-Agent: Firefox" https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.23-98579-gb15ab7903-gcc-linux.tar.gz --output pin.tar.gz
RUN mkdir -p pin && tar -xf pin.tar.gz -C pin --strip-components 1 && rm pin.tar.gz
ENV PIN_ROOT=/cipherfix/pin

ENV OPENSSL_VERSION="3.0.2"
RUN set -x \
 && mkdir -p openssl-install \
 && wget --no-check-certificate -O /tmp/openssl-${OPENSSL_VERSION}.tar.gz "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz" \
 && tar -xvf /tmp/openssl-${OPENSSL_VERSION}.tar.gz -C /tmp/ \
 && rm -rf /tmp/openssl-${OPENSSL_VERSION}.tar.gz \ 
 && cd /tmp/openssl-${OPENSSL_VERSION} \
 && ./Configure --prefix=/cipherfix/openssl-install --openssldir=/cipherfix/openssl-install linux-x86_64 shared\
 && make -j \
 && make install \
 && cd .. \
 && rm -rf openssl-${OPENSSL_VERSION} 

COPY ./scripts/ .

ENTRYPOINT "/bin/bash"

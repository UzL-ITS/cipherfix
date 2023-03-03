# Build with:
#   docker build . -t cipherfix-base:latest

FROM mcr.microsoft.com/dotnet/sdk:6.0-focal

RUN apt-get update && apt-get install -y git gcc g++ nasm curl make nano python3 autoconf automake libtool

WORKDIR /cipherfix
RUN curl -H "User-Agent: Firefox" https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.26-98690-g1fc9d60e6-gcc-linux.tar.gz --output pin.tar.gz
RUN mkdir -p pin && tar -xf pin.tar.gz -C pin --strip-components 1 && rm pin.tar.gz
ENV PIN_ROOT=/cipherfix/pin
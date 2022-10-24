FROM mcr.microsoft.com/dotnet/sdk:6.0-focal

RUN apt-get update && apt-get install -y git gcc g++ nasm curl make libssl-dev nano

WORKDIR /cipherfix
RUN curl -H "User-Agent: Firefox" https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.23-98579-gb15ab7903-gcc-linux.tar.gz --output pin.tar.gz
RUN mkdir -p pin && tar -xf pin.tar.gz -C pin --strip-components 1 && rm pin.tar.gz
ENV PIN_ROOT=/cipherfix/pin

COPY ./scripts/ .

ENTRYPOINT "/bin/bash"

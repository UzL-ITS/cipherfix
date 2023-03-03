# Build with:
#   docker build . -t ghcr.io/uzl-its/cipherfix-examples:latest

FROM cipherfix-base:latest AS build-libs

# Build libraries

RUN set -x \
 && mkdir -p libsodium-install \
 && wget --no-check-certificate -O /tmp/libsodium.tar.gz "https://download.libsodium.org/libsodium/releases/libsodium-1.0.18-stable.tar.gz" \
 && tar -xvf /tmp/libsodium.tar.gz -C /tmp/ \
 && rm -rf /tmp/libsodium.tar.gz \ 
 && cd /tmp/libsodium-stable \
 && ./configure CFLAGS="-O2 -fstack-reuse=none -fno-optimize-sibling-calls -mno-push-args" --prefix=/cipherfix/libsodium-install --without-pthreads --disable-ssp \
 && make -j \
 && make install

RUN set -x \
 && wget --no-check-certificate -O /tmp/mbedtls.tar.gz "https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.3.0.tar.gz" \
 && tar -xvf /tmp/mbedtls.tar.gz -C /tmp/ \
 && mv /tmp/mbedtls-3.3.0 /tmp/mbedtls \
 && rm -rf /tmp/mbedtls.tar.gz \ 
 && cd /tmp/mbedtls \
 && ./scripts/config.py full_no_deprecated \
 && sed -i -E 's/(#define MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS)/\/\/\1/' include/mbedtls/mbedtls_config.h \
 && sed -i -E 's/(#define MBEDTLS_THREADING.*)/\/\/\1/' include/mbedtls/mbedtls_config.h \
 && make -j CFLAGS="-O2 -fstack-reuse=none -fno-optimize-sibling-calls -mno-push-args" lib

ENV OPENSSL_VERSION="3.0.2"
RUN set -x \
 && mkdir -p openssl-install \
 && wget --no-check-certificate -O /tmp/openssl-${OPENSSL_VERSION}.tar.gz "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz" \
 && tar -xvf /tmp/openssl-${OPENSSL_VERSION}.tar.gz -C /tmp/ \
 && rm -rf /tmp/openssl-${OPENSSL_VERSION}.tar.gz \ 
 && cd /tmp/openssl-${OPENSSL_VERSION} \
 && ./Configure --prefix=/cipherfix/openssl-install --openssldir=/cipherfix/openssl-install no-threads linux-x86_64 shared -g -O2 -fno-optimize-sibling-calls -ffixed-xmm13 -ffixed-xmm14 -ffixed-xmm15 \
 && make -j \
 && make install

RUN set -x \
 && mkdir -p wolfssl-install \
 && wget --no-check-certificate -O /tmp/wolfssl.tar.gz "https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.3.0-stable.tar.gz" \
 && tar -xvf /tmp/wolfssl.tar.gz -C /tmp/ \
 && rm -rf /tmp/wolfssl.tar.gz \ 
 && cd /tmp/wolfssl-5.3.0-stable \
 && ./autogen.sh \
 && ./configure --build=x86_64-linux-gnu --prefix=/cipherfix/wolfssl-install --disable-examples --enable-curve25519 --enable-ed25519 --disable-hashdrbg --enable-singlethreaded CFLAGS="-g -O2 -fstack-reuse=none -fno-optimize-sibling-calls -mno-push-args -DCUSTOM_RAND_GENERATE_BLOCK=custom_rand_generate_block" \
 && sed -i -E 's/\/\* If building for old FIPS\. \*\//extern int custom_rand_generate_block(unsigned char* output, unsigned int sz); word64 custom_rng_counter = 0x1122334455667788; extern int custom_rand_generate_block(unsigned char* output, unsigned int sz) { int ctr = custom_rng_counter; for(unsigned int i = 0; i < sz; ++i) { if(i % 8 == 0) { ctr = custom_rng_counter; } output[i] = (unsigned char)(ctr); ctr >>= 8; } custom_rng_counter = custom_rng_counter * 13 + 7; return 0; }/' wolfcrypt/src/random.c \
 && make -j \
 && make install

#################################################

FROM cipherfix-base:latest AS final

# Copy libraries
COPY --from=build-libs /cipherfix/libsodium-install /cipherfix/libsodium-install
COPY --from=build-libs /tmp/mbedtls /cipherfix/mbedtls
COPY --from=build-libs /cipherfix/openssl-install /cipherfix/openssl-install
COPY --from=build-libs /cipherfix/wolfssl-install /cipherfix/wolfssl-install

ENV CF_LIBSODIUM_DIR="/cipherfix/libsodium-install"
ENV CF_MBEDTLS_DIR="/cipherfix/mbedtls"
ENV CF_OPENSSL_DIR="/cipherfix/openssl-install"
ENV CF_WOLFSSL_DIR="/cipherfix/wolfssl-install"

COPY ./scripts/ .

ENTRYPOINT "/bin/bash"

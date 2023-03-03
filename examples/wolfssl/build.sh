#!/bin/bash

CC="${CC:-gcc}"
INSTALL_DIR="${CF_WOLFSSL_DIR:-$CF_WOLFSSL_DIR}"

mkdir -p chacha20 ecdsa eddsa aes rsa ecdh aes-multiround chacha20-multiround
${CC} chacha20.c -O2 -fstack-reuse=none -fno-optimize-sibling-calls -mno-push-args -fPIE -pie -I$CF_WOLFSSL_DIR/include -L$CF_WOLFSSL_DIR/lib -lwolfssl -o chacha20/app
${CC} ecdsa.c -O2 -fstack-reuse=none -fno-optimize-sibling-calls -mno-push-args -fPIE -pie -I$CF_WOLFSSL_DIR/include -L$CF_WOLFSSL_DIR/lib -lwolfssl -o ecdsa/app
${CC} eddsa.c -O2 -fstack-reuse=none -fno-optimize-sibling-calls -mno-push-args -fPIE -pie -I$CF_WOLFSSL_DIR/include -L$CF_WOLFSSL_DIR/lib -lwolfssl -o eddsa/app
${CC} aes.c -O2 -fstack-reuse=none -fno-optimize-sibling-calls -mno-push-args -fPIE -pie -I$CF_WOLFSSL_DIR/include -L$CF_WOLFSSL_DIR/lib -lwolfssl -o aes/app
${CC} rsa.c -O2 -fstack-reuse=none -fno-optimize-sibling-calls -mno-push-args -fPIE -pie -I$CF_WOLFSSL_DIR/include -L$CF_WOLFSSL_DIR/lib -lwolfssl -o rsa/app
${CC} ecdh.c -O2 -fstack-reuse=none -fno-optimize-sibling-calls -mno-push-args -fPIE -pie -I$CF_WOLFSSL_DIR/include -L$CF_WOLFSSL_DIR/lib -lwolfssl -o ecdh/app
${CC} aes-multiround.c -O2 -fstack-reuse=none -fno-optimize-sibling-calls -mno-push-args -fPIE -pie -I$CF_WOLFSSL_DIR/include -L$CF_WOLFSSL_DIR/lib -lwolfssl -o aes-multiround/app
${CC} chacha20-multiround.c -O2 -fstack-reuse=none -fno-optimize-sibling-calls -mno-push-args -fPIE -pie -I$CF_WOLFSSL_DIR/include -L$CF_WOLFSSL_DIR/lib -lwolfssl -o chacha20-multiround/app
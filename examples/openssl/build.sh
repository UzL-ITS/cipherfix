#!/bin/bash

CC="${CC:-gcc}"
INSTALL_DIR="${CF_OPENSSL_DIR:-./lib-install}"

mkdir -p ecdsa ecdh rsa
${CC} ecdsa.c -fstack-reuse=none -Wno-deprecated-declarations -fPIE -pie -I$INSTALL_DIR/include -L$INSTALL_DIR/lib64 -lcrypto -o ecdsa/app
${CC} ecdh.c -fstack-reuse=none -Wno-deprecated-declarations -fPIE -pie -I$INSTALL_DIR/include -L$INSTALL_DIR/lib64 -lcrypto -o ecdh/app
${CC} rsa.c -fstack-reuse=none -Wno-deprecated-declarations -fPIE -pie -I$INSTALL_DIR/include -L$INSTALL_DIR/lib64 -lcrypto -o rsa/app
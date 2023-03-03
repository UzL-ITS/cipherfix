#!/bin/bash

CC="${CC:-gcc}"
INSTALL_DIR="${CF_LIBSODIUM_DIR:-./lib-install}"

mkdir -p eddsa sha512
${CC} eddsa.c -fstack-reuse=none -fPIE -pie -I$INSTALL_DIR/include -L$INSTALL_DIR/lib -lsodium -o eddsa/app
${CC} sha512.c -fstack-reuse=none -fPIE -pie -I$INSTALL_DIR/include -L$INSTALL_DIR/lib -lsodium -o sha512/app
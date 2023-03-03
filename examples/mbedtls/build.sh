#!/bin/bash

CC="${CC:-gcc}"
INSTALL_DIR="${CF_MBEDTLS_DIR:-$INSTALL_DIR}"

mkdir -p rsa aes aes-multiround chacha20 chacha20-multiround ecdh base64 ecdsa
${CC} rsa.c -O2 -fstack-reuse=none -fno-optimize-sibling-calls -mno-push-args -fPIE -pie -I$INSTALL_DIR/include -L$INSTALL_DIR/library $INSTALL_DIR/library/libmbedtls.a $INSTALL_DIR/library/libmbedx509.a $INSTALL_DIR/library/libmbedcrypto.a -o rsa/app
${CC} aes.c -O2 -fstack-reuse=none -fno-optimize-sibling-calls -mno-push-args -fPIE -pie -I$INSTALL_DIR/include -L$INSTALL_DIR/library $INSTALL_DIR/library/libmbedtls.a $INSTALL_DIR/library/libmbedx509.a $INSTALL_DIR/library/libmbedcrypto.a -o aes/app
${CC} chacha20.c -O2 -fstack-reuse=none -fno-optimize-sibling-calls -mno-push-args -fPIE -pie -I$INSTALL_DIR/include -L$INSTALL_DIR/library $INSTALL_DIR/library/libmbedtls.a $INSTALL_DIR/library/libmbedx509.a $INSTALL_DIR/library/libmbedcrypto.a -o chacha20/app
${CC} ecdh.c -O2 -fstack-reuse=none -fno-optimize-sibling-calls -mno-push-args -fPIE -pie -I$INSTALL_DIR/include -L$INSTALL_DIR/library $INSTALL_DIR/library/libmbedtls.a $INSTALL_DIR/library/libmbedx509.a $INSTALL_DIR/library/libmbedcrypto.a -o ecdh/app
${CC} base64.c -O2 -fstack-reuse=none -fno-optimize-sibling-calls -mno-push-args -fPIE -pie -I$INSTALL_DIR/include -L$INSTALL_DIR/library $INSTALL_DIR/library/libmbedtls.a $INSTALL_DIR/library/libmbedx509.a $INSTALL_DIR/library/libmbedcrypto.a -o base64/app
${CC} ecdsa.c -O2 -fstack-reuse=none -fno-optimize-sibling-calls -mno-push-args -fPIE -pie -I$INSTALL_DIR/include -L$INSTALL_DIR/library $INSTALL_DIR/library/libmbedtls.a $INSTALL_DIR/library/libmbedx509.a $INSTALL_DIR/library/libmbedcrypto.a -o ecdsa/app
${CC} aes-multiround.c -O2 -fstack-reuse=none -fno-optimize-sibling-calls -mno-push-args -fPIE -pie -I$INSTALL_DIR/include -L$INSTALL_DIR/library $INSTALL_DIR/library/libmbedtls.a $INSTALL_DIR/library/libmbedx509.a $INSTALL_DIR/library/libmbedcrypto.a -o aes-multiround/app
${CC} chacha20-multiround.c -O2 -fstack-reuse=none -fno-optimize-sibling-calls -mno-push-args -fPIE -pie -I$INSTALL_DIR/include -L$INSTALL_DIR/library $INSTALL_DIR/library/libmbedtls.a $INSTALL_DIR/library/libmbedx509.a $INSTALL_DIR/library/libmbedcrypto.a -o chacha20-multiround/app
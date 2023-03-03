#!/bin/bash

cd cipherfix
./analyze.sh $(pwd)/examples/mbedtls/aes-multiround $CF_MBEDTLS_DIR "1;4" app 10 perf
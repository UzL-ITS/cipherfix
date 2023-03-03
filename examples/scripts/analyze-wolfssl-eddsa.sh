#!/bin/bash

cd cipherfix
./analyze.sh $(pwd)/examples/wolfssl/eddsa $CF_WOLFSSL_DIR/lib "1;4;5;6" app 10 perf
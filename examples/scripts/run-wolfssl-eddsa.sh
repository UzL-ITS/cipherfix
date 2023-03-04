#!/bin/bash

cd cipherfix

cd examples/wolfssl/eddsa
echo "-- Original: --"
LD_LIBRARY_PATH=$CF_WOLFSSL_DIR/lib ./app 3

echo ""
echo "-- Instrumented: --"
cd instr-fast-aesrng
chmod +x app.instr
./app.instr 3
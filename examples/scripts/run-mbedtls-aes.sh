#!/bin/bash

cd cipherfix

cd examples/mbedtls/aes-multiround
echo "-- Original: --"
./app 3

echo ""
echo "-- Instrumented: --"
cd instr-fast-aesrng
chmod +x app.instr
./app.instr 3
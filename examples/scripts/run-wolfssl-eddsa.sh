#!/bin/bash

cd cipherfix

cd examples/wolfssl/eddsa
echo "-- Original: --"
./app 3

echo ""
echo "-- Instrumented: --"
cd instr-fast-aesrng
chmod +x app.instr
./app.instr 3
#!/bin/bash

cd cipherfix/examples/openssl-ecdsa
echo "-- Original: --"
LD_LIBRARY_PATH=/cipherfix/openssl-install/lib64 ./app 3

echo ""
echo "-- Instrumented: --"
cd instr-base
chmod +x app.instr
./app.instr 3
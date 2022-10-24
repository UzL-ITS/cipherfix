#!/bin/bash

cd cipherfix/examples/openssl-ecdsa
echo "-- Original: --"
./app 3

echo ""
echo "-- Instrumented: --"
cd instr-base
chmod +x app.instr
./app.instr 3
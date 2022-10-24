#!/bin/bash

cd cipherfix/examples/tweetnacl-eddsa
echo "-- Original: --"
LD_LIBRARY_PATH=. ./app 3

echo ""
echo "-- Instrumented: --"
cd instr-base
chmod +x app.instr
./app.instr 3
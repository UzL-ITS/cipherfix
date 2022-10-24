#!/bin/bash

git clone --recurse-submodules https://github.com/UzL-ITS/cipherfix.git
cd cipherfix
./build-all.sh
cd examples/tweetnacl-eddsa
./build.sh
cd ../openssl-ecdsa
./build.sh
cd ../..

echo "Setup complete"
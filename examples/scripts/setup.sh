#!/bin/bash

git clone --recurse-submodules https://github.com/UzL-ITS/cipherfix.git

cd cipherfix
./build-all.sh

cd examples/libsodium
./build.sh
cd ../mbedtls
./build.sh
cd ../openssl
./build.sh
cd ../wolfssl
./build.sh

echo "Setup complete"
#!/bin/bash

git clone --recurse-submodules https://github.com/UzL-ITS/cipherfix.git

cd cipherfix
./build-all.sh

cd examples/libsodium
./build.sh
cd ../examples/mbedtls
./build.sh
cd ../examples/openssl
./build.sh
cd ../examples/wolfssl
./build.sh

echo "Setup complete"
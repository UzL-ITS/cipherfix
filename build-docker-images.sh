#!/bin/bash

# The base image contains all necessary dependencies and the build toolchain.
cd examples/base-image
docker build . -t cipherfix-base:latest

# The main image contains the library binaries.
cd ../
docker build . -t cipherfix-examples:latest

# The full image also contains the pre-built Cipherfix framework, and the compiled examples (allows reproducibility even on some non-Zen3 systems).
cd full-image
docker build . -t cipherfix-examples-precompiled:latest

echo "Done."
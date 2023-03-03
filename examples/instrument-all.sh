#!/bin/bash

# Utility script for comparison of different Cipherfix variants.
# Generates all variants for a given target.

set -e

library=$1
target=$2

if [ "$#" -ne 2 ]; then
    echo "Usage: <library> <target>"
    exit
fi

instrument() {
    variant=$1
    flags=$2

    ./instrument.sh $(pwd)/examples/$library/$target $variant $flags
    pushd $(pwd)/examples/$library/$target/instr-$variant-$flags
    chmod +x app.instr
    popd
}

cd ..
instrument base rdrand
instrument base aesrng
instrument base gf61rng
instrument base xsprng
instrument fast rdrand
instrument fast aesrng
instrument fast gf61rng
instrument fast xsprng
instrument enhanced rdrand
instrument enhanced aesrng
instrument enhanced gf61rng
instrument enhanced xsprng

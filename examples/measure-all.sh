#!/bin/bash

# Utility script for comparison of different Cipherfix variants.
# Runs all variants for a given target.

set -e

library=$1
target=$2
ldPath=$3

if [ "$#" -ne 3 ]; then
    echo "Usage: <library> <target> <ld path>"
    exit
fi

cpu=21

measure() {
    mode=$1

    echo "###################################################### $mode ######################################################"

    cd instr-$mode
    chmod +x app.instr

    # Run command multiple times 
    for i in {1..10}; do
        taskset -c $cpu ./app.instr 1000 perf
    done

    cd ..
}

echo "###################################################### ORIGINAL ######################################################"
cd $(pwd)/$library/$target

export LD_LIBRARY_PATH=$ldPath
for i in {1..10}; do
    taskset -c $cpu ./app 1000 perf
done

measure "base-rdrand"
measure "base-aesrng"
measure "base-xsprng"
measure "fast-rdrand"
measure "fast-aesrng"
measure "fast-xsprng"
measure "enhanced-rdrand"
measure "enhanced-aesrng"
measure "enhanced-xsprng"

#!/bin/bash

# Traces all memory (interesting) writes
# Arguments:
# - Path to instrumented files
# - List of interesting image-offset-ranges to be traced, e.g., "5.afc3.afe4;5.b05a.b07b"
# - Name of original binary
# - ...further arguments for the original binary

# Example usage: ./run.sh /path/to/instrDir "5.afc3.afe4;5.b05a.b07b" app.instr 3

instrDir=$1
interesting=$2
mainBinary=$3

thisDir=$(pwd)

cd $instrDir
LD_LIBRARY_PATH=$instrDir $PIN_ROOT/pin -t $thisDir/obj-intel64/pintool.so -o $instrDir/memtrace.out -offsets "$interesting" -- ./$mainBinary ${@:4}

#!/bin/bash

# Detects basic blocks and tracks register and flag usage per instruction.
# Arguments:
# - Path to working directory (contains the original binary)
# - Path to needed shared libraries (for LD_LIBRARY_PATH)
# - Output file path
# - Name of original binary
# ...further arguments for the original binary

# Example usage: ./run.sh /path/to/workdir /path/to/libs /path/to/structure.out app --app-arg1 --app-arg2

workDir=$1
libPath=$2
outFilePath=$3
mainBinary=$4

thisDir=$(pwd)

cd $workDir
LD_LIBRARY_PATH=$libPath $PIN_ROOT/pin -t $thisDir/obj-intel64/pintool.so -o $outFilePath -- ./$mainBinary ${@:5}
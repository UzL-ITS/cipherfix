#!/bin/bash

# Tracks secrets and outputs results for static instrumentation.
# Arguments:
# - Path to working directory (contains the original binary)
# - Path to needed shared libraries (for LD_LIBRARY_PATH)
# - Path to static variables analysis result
# - Output file path
# - Name of original binary
# ...further arguments for the original binary

# Example usage: ./run.sh /path/to/workdir /path/to/libs /path/to/static-vars.out /path/to/taint.out app --app-arg1 --app-arg2

workDir=$1
libPath=$2
staticVarsPath=$3
outFilePath=$4
mainBinary=$5

thisDir=$(pwd)

cd $workDir
LD_LIBRARY_PATH=$libPath $PIN_ROOT/pin -t $thisDir/tools/obj-intel64/cipherfix-dta.so -in $staticVarsPath -o $outFilePath -- ./$mainBinary ${@:6}
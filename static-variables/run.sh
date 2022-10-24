#!/bin/bash

# Detects static variables.
# Arguments:
# - Path to working directory (contains the original binary)
# - Path to needed shared libraries (for LD_LIBRARY_PATH)
# - List of image IDs which should be marked as interesting in Pin, e.g., "1;4"
# - Output file path
# - Name of original binary
# ...further arguments for the original binary

# Example usage: ./run.sh /path/to/workdir /path/to/libs "1;4" /path/to/static-vars.out app --app-arg1 --app-arg2

workDir=$1
libPath=$2
interestingImages=$3
outFilePath=$4
mainBinary=$5

thisDir=$(pwd)

cd $workDir
LD_LIBRARY_PATH=$libPath $PIN_ROOT/pin -t $thisDir/obj-intel64/pintool.so -i $interestingImages -o $outFilePath -- ./$mainBinary ${@:6}
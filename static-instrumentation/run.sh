#!/bin/bash

# Instruments the binaries.
# Arguments:
# - Path to directory with original binaries, including structure.out (from structure-analysis) and taint.out (from taint-tracking).
# - Instrumentation mode.
# - Flags.

# Example usage: ./run.sh /path/to/workdir base

workDir=$1
mode=$2
flags=$3

pushd StaticInstrumentation
dotnet run --no-build -c Release -- $workDir $mode $flags
popd

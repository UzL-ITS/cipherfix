#!/bin/bash

# Applies the static instrumentation to the analyzed binaries.
# Arguments:
# - Path to working directory (contains the original binary and analysis results)
# - Instrumentation mode (base, fast, enhanced)
# - Optional instrumentation flags (only for debugging/evaluation)

# Example usage: ./instrument.sh /path/to/workdir base

workDir=$1
mode=$2
flags=$3

echo -e "\e[1;94mRunning static instrumentation\e[0m"
pushd static-instrumentation
bash run.sh $workDir $mode $flags
popd

echo -e "\e[1;94mInstrumentation completed\e[0m"
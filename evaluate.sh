#!/bin/bash

# Runs the leakage evaluation.
# Takes the memory write trace output of the uninstrumented binary from taint-tracking (taint.out.memtrace)
# and generates the trace for the hardened binary with the memwrite-tracer.
# The C# MemtraceComparer is run to check the resulting traces for uniqueness of memory writes.

# Arguments:
# - Path to working directory (contains the original binary)
# - Path to instrumented files
# - List of interesting image-offset-ranges to be traced, e.g., "5.afc3.afe4;5.b05a.b07b"
# - Name of original binary
# ...further arguments for the original binary

# Example usage: ./evaluate.sh /path/to/workDir /path/to/instrDir "5.afc3.afe4;5.b05a.b07b" main 3

workDir=$1
instrDir=$2
interesting=$3
mainBinary=$4

echo -e "\e[1;94mRunning memory write tracer\e[0m"
pushd memwrite-tracer
bash run.sh $instrDir $mainBinary.instr $interesting ${@:5}
popd


echo -e "\e[1;94mRunning memory trace comparison\e[0m"
pushd evaluation/MemtraceComparer
dotnet run --no-build -c Release -- $workDir/taint.out.memtrace $instrDir/memtrace.out $instrDir/map.txt $instrDir/ignore.txt >$workDir/eval-result.txt
popd
#!/bin/bash

# Runs the leakage evaluation.
# Takes the memory write trace output of the uninstrumented binary from taint-tracking (taint.out.memtrace)
# and the trace for the hardened binary from the memwrite-tracer.
# The C# MemtraceComparer is run to check the resulting traces for uniqueness of memory writes.

# Arguments:
# - Path to working directory (contains the original binary)
# - Path to instrumented files

# Example usage: ./run.sh /path/to/workDir /path/to/instrDir 

workDir=$1
instrDir=$2

cd MemtraceComparer
dotnet run --no-build -c Release -- $workDir/taint.out.memtrace $instrDir/memtrace.out $instrDir/map.txt $instrDir/ignore.txt >$workDir/eval-result.txt

#!/bin/bash

# Runs the dynamic analysis.
# Arguments:
# - Path to working directory (contains the original binary)
# - Path to needed shared libraries (for LD_LIBRARY_PATH)
# - List of image IDs which should be marked as interesting in Pin, e.g., "1;4"
# - Name of original binary
# ...further arguments for the original binary

# Example usage: ./run.sh /path/to/workdir /path/to/libs "1;4" app --app-arg1 --app-arg2

workDir=$1
libPath=$2
interestingImages=$3
mainBinary=$4

echo -e "\e[1;94mRunning structure analysis\e[0m"
pushd structure-analysis
bash run.sh $workDir $libPath $workDir/structure.out $mainBinary ${@:5}
popd

echo -e "\e[1;94mRunning static variable detection\e[0m"
pushd static-variables
bash run.sh $workDir $libPath $interestingImages $workDir/static-vars.out $mainBinary ${@:5}
popd

echo -e "\e[1;94mRunning taint tracking\e[0m"
pushd taint-tracking
bash run.sh $workDir $libPath $workDir/static-vars.out $workDir/taint.out $mainBinary ${@:5}
popd

echo -e "\e[1;94mAnalysis completed\e[0m"
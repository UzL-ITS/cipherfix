#!/bin/bash

# Builds all dependencies.

echo -e "\e[1;94mBuilding structure analysis\e[0m"
pushd structure-analysis
bash build.sh
popd

echo -e "\e[1;94mBuilding static variables analysis\e[0m"
pushd static-variables
bash build.sh
popd

echo -e "\e[1;94mBuilding taint tracking\e[0m"
pushd taint-tracking
bash build.sh
popd

echo -e "\e[1;94mBuilding static instrumentation\e[0m"
pushd static-instrumentation
bash build.sh
popd

echo -e "\e[1;94mBuilding memory write tracer\e[0m"
pushd memwrite-tracer
bash build.sh
popd

echo -e "\e[1;94mBuilding evaluation tool\e[0m"
pushd evaluation
bash build.sh
popd

echo -e "\e[1;94mBuild completed\e[0m"
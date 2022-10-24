#!/bin/bash

echo "Building memory trace comparison tool"
pushd MemtraceComparer
dotnet build -c Release
popd

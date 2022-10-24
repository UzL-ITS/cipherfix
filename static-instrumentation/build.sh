#!/bin/bash

echo "Building static instrumentation tool"
pushd StaticInstrumentation
dotnet build -c Release
popd

echo "Building instrumentation header"
pushd header
nasm -f elf64 -o instrument_header_base.o instrument_header_base.asm
nasm -f elf64 -o instrument_header_fast.o instrument_header_fast.asm
popd

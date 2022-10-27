#!/bin/bash

gcc randombytes.c tweetnacl.c -fstack-reuse=none -fPIC -shared -o libtnacl.so

gcc main.c -fstack-reuse=none -fPIE -pie -I. -L. -ltnacl -o app
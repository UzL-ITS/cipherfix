#!/bin/bash

gcc randombytes.c tweetnacl.c -fPIC -shared -o libtnacl.so

gcc main.c -fstack-reuse=none -I. -L. -ltnacl -o app
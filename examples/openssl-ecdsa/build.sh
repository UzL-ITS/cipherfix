#!/bin/bash

gcc main.c -fstack-reuse=none -Wno-deprecated-declarations -fPIE -pie -I/cipherfix/openssl-install/include -L/cipherfix/openssl-install/lib64 -lcrypto -o app
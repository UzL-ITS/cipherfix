#!/bin/bash

gcc main.c -fstack-reuse=none -Wno-deprecated-declarations -fPIE -pie  -lcrypto -o app
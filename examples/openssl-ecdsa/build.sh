#!/bin/bash

gcc main.c -fstack-reuse=none -Wno-deprecated-declarations -lcrypto -o app
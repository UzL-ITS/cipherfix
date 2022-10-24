#!/bin/bash

gcc main.c -fstack-reuse=none -lcrypto -o app
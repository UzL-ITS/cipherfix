/*
Utility functions for analysis with Cipherfix.
*/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// Marks data at the given address and with the given length as secret.
void __attribute__((noinline, optimize("O0"))) classify(void *ptr, int length) { asm (""); }

// Marks data at the given address and with the given length as public.
void __attribute__((noinline, optimize("O0"))) declassify(void *ptr, int length) { asm (""); }

// Deletes all taint, effectively stopping secret tracking.
void __attribute__((noinline, optimize("O0"))) drop_taint(void) { asm (""); }

// Dumps a secret array of the given length without tainting I/O functions.
// Optionally, a string can be prepended.
void dump_secret(uint8_t *data, int length, const char* prefix)
{
    uint8_t *buf = malloc(length);
    int *bufLen = malloc(sizeof(int));
    memcpy(buf, data, length);
    *bufLen = length;
    declassify(bufLen, sizeof(int));
    declassify(buf, *bufLen);

    if(prefix)
        printf("%s  ", prefix);

    for(int i = 0; i < *bufLen; ++i)
        printf("%02x ", buf[i]);

    printf("\n");

    free(buf);
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#define CLOCK CLOCK_MONOTONIC

#include <randombytes.h>
#include <tweetnacl.h>

void __attribute__((optimize("O0"))) foo()
{
    void *a = malloc(4);
    free(a);
}

void __attribute__((noinline, optimize("O0"))) classify(void *ptr, int length) { asm (""); }
void __attribute__((noinline, optimize("O0"))) declassify(void *ptr, int length) { asm (""); }
void __attribute__((noinline, optimize("O0"))) drop_taint(void) { asm (""); }

void dump_secret(uint8_t *data, int length, const char* prefix)
{
    uint8_t *buf = malloc(length);
    int *bufLen = malloc(sizeof(int));
    memcpy(buf, data, length);
    *bufLen = length;
    declassify(bufLen, sizeof(int));
    declassify(buf, *bufLen);

    printf("%s  ", prefix);
    for(int i = 0; i < *bufLen; ++i)
        printf("%02x ", buf[i]);

    printf("\n");

    free(buf);
}

int main(int argc, char *argv[])
{
    // Time measurement
    struct timespec timeStart, timeLoop, timeEnd;
    clock_gettime(CLOCK, &timeStart);

    foo();

    // Number of iterations
    int n = 1;
    if(argc >= 2)
    {
        n = atoi(argv[1]);
        printf("Running %d rounds\n", n);
    }

    // Performance evaluation mode?
    bool performanceMode = false;
    if(argc >= 3 && strcmp(argv[2], "perf") == 0)
    {
        printf("Performance mode\n");
        performanceMode = true;
    }
    
    // Secret key that is used for signature
    unsigned char alice_secretkey[crypto_box_SECRETKEYBYTES] = { 0x60, 0xea, 0x88, 0x4a, 0x8c, 0x32, 0x36, 0x0e, 0xfd, 0xa4, 0x58, 0x0b, 0x30, 0x36, 0x9e, 0xac, 0x4b, 0xd2, 0xc9, 0xbe, 0xfe, 0x43, 0xd9, 0x0f, 0xdb, 0x80, 0xbb, 0xd8, 0xae, 0xc4, 0xa8, 0x78 };
    dump_secret(alice_secretkey, sizeof(alice_secretkey), "sk");

    // Hash to sign
    unsigned char m[32] = { 0x0c, 0xb8, 0x64, 0x56, 0xa7, 0x3a, 0x55, 0xd1, 0x90, 0x1b, 0xbd, 0x0b, 0x4c, 0xff, 0x13, 0x6d, 0x84, 0x78, 0x33, 0x2d, 0xf3, 0x5e, 0xe7, 0xa1, 0x15, 0x63, 0x71, 0x0b, 0x48, 0xec, 0x06, 0x1c   };

    clock_gettime(CLOCK, &timeLoop);
    while(n --> 0)
    {
        // Classify secrets
        classify(alice_secretkey, sizeof(alice_secretkey));

        // Compute signature
        unsigned char *sm = malloc(32 * sizeof(m) + crypto_sign_BYTES);
        unsigned long long ssize;
        crypto_sign(sm, &ssize, m, sizeof(m), alice_secretkey);
        
        // Only output the last signature
        if(!performanceMode || n == 0)
            dump_secret(sm, ssize, "signature");

        // Cleanup
        free(sm);

        // Ensure that there is no leftover taint
        drop_taint();

        // Increment hash
        for(int i = 0; i < sizeof(m); ++i)
        {
            unsigned char tmp = m[i] + 1;
            m[i] = tmp;
            if(tmp != 0)
                break;
        }
    }
    
    clock_gettime(CLOCK, &timeEnd);
    int64_t durationInit = (timeLoop.tv_sec - timeStart.tv_sec) * 1000000 + (timeLoop.tv_nsec - timeStart.tv_nsec) / 1000;
    int64_t durationLoop = (timeEnd.tv_sec - timeLoop.tv_sec) * 1000000 + (timeEnd.tv_nsec - timeLoop.tv_nsec) / 1000;

    printf("\n");
    printf("Init time: %*ld us -> %*.3f ms\n", 9, durationInit, 9, durationInit / 1000.0);
    printf("Loop time: %*ld us -> %*.3f ms\n", 9, durationLoop, 9, durationLoop / 1000.0);

    return 0;
}

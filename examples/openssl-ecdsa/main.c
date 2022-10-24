#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#define CLOCK CLOCK_MONOTONIC
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

int rndCtr = 0;

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

// Our own really simple and non-random number generator
static uint8_t randState[32] = { 0 };

int DummyRandAdd(const void* buf, int num, double randomness)
{
    // Completely replace random state
    int count = num;
    if(count > sizeof(randState))
        count = sizeof(randState);

    memset(randState, 0, sizeof(randState));
    memcpy(randState, buf, count);

    return 1;
}

int DummyRandSeed(const void* buf, int num)
{
    return DummyRandAdd(buf, num, num);
}

int DummyRandBytes(uint8_t* buf, int num)
{
    // Generate chunks
    int chunkLen = sizeof(randState);
    SHA256_CTX sha256;
    int offset = 0;
    for(int i = 0; i < num / chunkLen; ++i)
    {
        // Update state and copy
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, randState, sizeof(randState));
        SHA256_Final(randState, &sha256);
        memcpy(buf + offset, randState, chunkLen);

        offset += chunkLen;
    }

    // Generate last chunk
    if(offset < num)
    {
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, randState, sizeof(randState));
        SHA256_Final(randState, &sha256);
        memcpy(buf + offset, randState, num - offset);
    }

    // Classify buffer receiving randomness on first call
    if (rndCtr == 0)
        classify(buf, num);
    rndCtr++;

    return 1;
}

int DummyRandStatus(void)
{
    return 1;
}

RAND_METHOD rand_meth = {
    DummyRandSeed,
    DummyRandBytes,
    NULL,
    DummyRandAdd,
    DummyRandBytes,
    DummyRandStatus
};

int main(int argc, char **argv)
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

    // Hash to sign
	unsigned char hash[] = "c0ffee11c0ffee11c0ffee11c0ffee11";

    // Private key
    unsigned char priv[] = { 0x66, 0x68, 0x7a, 0xad, 0xf8, 0x62, 0xbd, 0x77, 0x6c, 0x8f, 0xc1, 0x8b, 0x8e, 0x9f, 0x8e, 0x20, 0x08, 0x97, 0x14, 0x85, 0x6e, 0xe2, 0x33, 0xb3, 0x90, 0x2a, 0x59, 0x1d, 0x0d, 0x5f, 0x29, 0x25 };

    dump_secret(priv, sizeof(priv), "key");

    // Ensure that there is no external randomness
    RAND_set_rand_method(&rand_meth);

    // Allocate and initialize necessary data structures
    EC_KEY *eckey = EC_KEY_new();
    if (eckey == NULL)
        printf("eckey is null\n");
    EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (ecgroup == NULL)
        printf("ecgroup is null\n");
    if (!EC_KEY_set_group(eckey,ecgroup))
        printf("error setting group\n");

    clock_gettime(CLOCK, &timeLoop);
    while(n --> 0)
    {
        // Classify secrets
        classify(priv, sizeof(priv));

        // Load key
        if (!EC_KEY_oct2priv(eckey, priv, sizeof(priv)))
            printf("oct2priv error\n");

        // Compute signature
        int bufLen = ECDSA_size(eckey);
        unsigned char *buffer = OPENSSL_malloc(bufLen);
        if(!ECDSA_sign(0, hash, 32, buffer, &bufLen, eckey))
            printf("signature error\n");
        
        // Only output the last signature
        if(!performanceMode || n == 0)
            dump_secret(buffer, bufLen, "signature");

        // Cleanup
        OPENSSL_free(buffer);

        // Ensure that there is no leftover taint
        drop_taint();

        // Increment hash
        for(int i = 0; i < sizeof(hash); ++i)
        {
            unsigned char tmp = hash[i] + 1;
            hash[i] = tmp;
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
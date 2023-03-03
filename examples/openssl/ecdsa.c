#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "../cipherfix-main.h"

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


// Key
//*
    uint8_t key[32] = {
        0xb3, 0x21, 0xca, 0x3d, 0x67, 0xd6, 0x5b, 0xe3,
        0x9f, 0x8b, 0xdd, 0xdd, 0xb2, 0xea, 0x6b, 0xa0,
        0xab, 0x96, 0xd8, 0xac, 0x66, 0x03, 0x8d, 0x1e,
        0x5a, 0x8a, 0xbb, 0x50, 0xb6, 0x6b, 0x2d, 0x95
    };
//*/

// Message to sign.
unsigned char m[32] = { 0x0c, 0xb8, 0x64, 0x56, 0xa7, 0x3a, 0x55, 0xd1, 0x90, 0x1b, 0xbd, 0x0b, 0x4c, 0xff, 0x13, 0x6d, 0x84, 0x78, 0x33, 0x2d, 0xf3, 0x5e, 0xe7, 0xa1, 0x15, 0x63, 0x71, 0x0b, 0x48, 0xec, 0x06, 0x1c   };

EC_KEY *eckey;
EC_GROUP *ecgroup;

void cf_init_target(void)
{
    // Ensure that there is no external randomness
    RAND_set_rand_method(&rand_meth);

    // Allocate and initialize necessary data structures
    eckey = EC_KEY_new();
    if (eckey == NULL)
        printf("eckey is null\n");
    ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (ecgroup == NULL)
        printf("ecgroup is null\n");
    if (!EC_KEY_set_group(eckey,ecgroup))
        printf("error setting group\n");
}

void cf_run_target(bool dumpResult)
{
    classify(key, sizeof(key));

    if (!EC_KEY_oct2priv(eckey, key, sizeof(key)))
        printf("oct2priv error\n");

    int sigLen = ECDSA_size(eckey);
    unsigned char *sig = OPENSSL_malloc(sigLen);
    if(!ECDSA_sign(0, m, sizeof(m), sig, &sigLen, eckey))
        printf("signature error\n");

    if(dumpResult)
        dump_secret(sig, sigLen, "signature");

    OPENSSL_free(sig);
}

void cf_prepare_next(void)
{
    // Increment message
    for(int i = 0; i < sizeof(m); ++i)
    {
        unsigned char tmp = m[i] + 1;
        m[i] = tmp;
        if(tmp != 0)
            break;
    }
}
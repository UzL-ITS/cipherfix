#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

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

EVP_PKEY *theirKey = NULL;

uint8_t ecdhOurD[] = { 0x49, 0x6b, 0xd0, 0xa7, 0xd4, 0xc5, 0xda, 0x01, 0x54, 0xe3, 0xa9, 0x91, 0x5d, 0xda, 0x43, 0xfd, 0xd5, 0x87, 0x67, 0x05, 0xb1, 0x6c, 0xd8, 0x21, 0x19, 0xc2, 0x81, 0x2e, 0x83, 0x61, 0x15, 0xf8 };
uint8_t ecdhOurQ[] = { 0x59, 0xa5, 0xeb, 0x93, 0x5e, 0x89, 0xfa, 0xa7, 0x94, 0x9d, 0xf0, 0xfa, 0x75, 0xbd, 0x05, 0x39, 0xc0, 0x43, 0x05, 0x92, 0xdb, 0x56, 0xe4, 0x84, 0x76, 0xfb, 0x75, 0x80, 0x6b, 0xfe, 0x21, 0x7a };

void cf_init_target(void)
{
    // Ensure that there is no external randomness
    RAND_set_rand_method(&rand_meth);

    // Generate remote public key
    cf_prepare_next();
}

void cf_run_target(bool dumpResult)
{
    classify(ecdhOurD, sizeof(ecdhOurD));
    
    EVP_PKEY *ourKey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, ecdhOurD, sizeof(ecdhOurD));
    if(!ourKey)
        printf("our key alloc error\n");

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(ourKey, NULL);
    EVP_PKEY_derive_init(pctx);
    EVP_PKEY_derive_set_peer(pctx, theirKey);

    size_t len = 32;
    unsigned char *secret = OPENSSL_malloc(len);
    if(!EVP_PKEY_derive(pctx, secret, &len))
        printf("dh error\n");

    if(dumpResult)
        dump_secret(secret, len, "signature");

    OPENSSL_free(secret);
    EVP_PKEY_free(ourKey);
    EVP_PKEY_CTX_free(pctx);
}

void cf_prepare_next(void)
{
    if(theirKey)
        EVP_PKEY_free(theirKey);

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(NID_X25519, NULL);

    EVP_PKEY_keygen_init(pctx);

    theirKey = NULL;
    if(!EVP_PKEY_keygen(pctx, &theirKey))
        printf("their keygen error\n");
}
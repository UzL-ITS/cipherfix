#include <mbedtls/ecdsa.h>
#include <mbedtls/sha256.h>
#include "../cipherfix-main.h"

uint8_t rngState[256 / 8] = { 0 };
mbedtls_sha256_context rngCtx;

int myrng(void *context, uint8_t *buffer, size_t length)
{
    for(int i = 0; i < length; i += sizeof(rngState))
    {
        mbedtls_sha256_starts(&rngCtx, 0);
        mbedtls_sha256_update(&rngCtx, rngState, sizeof(rngState));
        mbedtls_sha256_finish(&rngCtx, rngState);

        for(int j = 0; i + j < length; ++j)
            buffer[i + j] = rngState[j];
    }

    return 0;
}

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


void cf_init_target(void)
{
    // Initialize RNG and run a few rounds
    mbedtls_sha256_init(&rngCtx);
    uint8_t *rngDummy = malloc(1024);
    myrng(NULL, rngDummy, 1024);
    free(rngDummy);
}

void cf_run_target(bool dumpResult)
{
    classify(key, sizeof(key));

    mbedtls_ecp_keypair kp;
    mbedtls_ecp_keypair_init(&kp);
    mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &kp, key, sizeof(key));

    mbedtls_ecdsa_context ecdsa;
    mbedtls_ecdsa_init(&ecdsa);
    if(mbedtls_ecdsa_from_keypair(&ecdsa, &kp))
        printf("could not load key\n");

    uint8_t *sig = malloc(512);
    size_t sigLen = 0;
    if(mbedtls_ecdsa_write_signature(&ecdsa, MBEDTLS_MD_SHA256, m, sizeof(m), sig, 512, &sigLen, myrng, NULL))
        printf("sign error\n");

    if(dumpResult)
        dump_secret(sig, sigLen, "signature");

    free(sig);
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

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include "../cipherfix-main.h"

uint8_t rngState[256 / 8] = { 0 };
wc_Sha256 rngCtx;

int myrng(void *context, uint8_t *buffer, size_t length)
{
    for(int i = 0; i < length; i += sizeof(rngState))
    {
        wc_InitSha256(&rngCtx);
        wc_Sha256Update(&rngCtx, rngState, sizeof(rngState));
        wc_Sha256Final(&rngCtx, rngState);

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
    uint8_t *rngDummy = malloc(1024);
    myrng(NULL, rngDummy, 1024);
    free(rngDummy);
}

void cf_run_target(bool dumpResult)
{
    classify(key, sizeof(key));

    struct ecc_key k;
    wc_ecc_init(&k);
    wc_ecc_import_private_key_ex(key, sizeof(key), NULL, 0, &k, ECC_SECP256R1);

    wc_ecc_make_pub(&k, NULL);

    WC_RNG rng;
    wc_InitRng(&rng);

	uint8_t *sig = malloc(512);
    int sigLen = 512;

    wc_ecc_sign_hash(m, sizeof(m), sig, &sigLen, &rng, &k);

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

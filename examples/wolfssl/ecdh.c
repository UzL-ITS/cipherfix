#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/curve25519.h>
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

WC_RNG keyRng;

uint8_t ecdhTheirD[32];
uint8_t ecdhTheirQ[32];

// Key
//*
    uint8_t ecdhOurD[] = { 0x49, 0x6b, 0xd0, 0xa7, 0xd4, 0xc5, 0xda, 0x01, 0x54, 0xe3, 0xa9, 0x91, 0x5d, 0xda, 0x43, 0xfd, 0xd5, 0x87, 0x67, 0x05, 0xb1, 0x6c, 0xd8, 0x21, 0x19, 0xc2, 0x81, 0x2e, 0x83, 0x61, 0x15, 0xf8 };
    uint8_t ecdhOurQ[] = { 0x59, 0xa5, 0xeb, 0x93, 0x5e, 0x89, 0xfa, 0xa7, 0x94, 0x9d, 0xf0, 0xfa, 0x75, 0xbd, 0x05, 0x39, 0xc0, 0x43, 0x05, 0x92, 0xdb, 0x56, 0xe4, 0x84, 0x76, 0xfb, 0x75, 0x80, 0x6b, 0xfe, 0x21, 0x7a };
//*/

void cf_init_target(void)
{
    // Initialize RNG and run a few rounds
    uint8_t *rngDummy = malloc(1024);
    myrng(NULL, rngDummy, 1024);
    free(rngDummy);

    wc_InitRng(&keyRng);

    // Generate remote key
    cf_prepare_next();
}

void cf_run_target(bool dumpResult)
{
    classify(ecdhOurD, sizeof(ecdhOurD));

    curve25519_key kOur;
    wc_curve25519_init(&kOur);
    wc_curve25519_import_private(ecdhOurD, sizeof(ecdhOurD), &kOur);

    curve25519_key kTheir;
    wc_curve25519_init(&kTheir);
    wc_curve25519_import_public(ecdhTheirQ, sizeof(ecdhTheirQ), &kTheir);

    int secretLen = 32;
    unsigned char *secretBuf = malloc(secretLen);
    wc_curve25519_shared_secret(&kOur, &kTheir, secretBuf, &secretLen);

    if(dumpResult)
        dump_secret(secretBuf, secretLen, "secret");

    free(secretBuf);
}

void cf_prepare_next(void)
{
    curve25519_key k;
    wc_curve25519_init(&k);
    wc_curve25519_make_key(&keyRng, 32, &k);

    int len = sizeof(ecdhTheirQ);
    wc_curve25519_export_public(&k, ecdhTheirQ, &len);
}

#include <mbedtls/base64.h>
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

unsigned char data[128];
unsigned char m[(sizeof(data) * 8) / 6 + 3 + 1];

void cf_init_target(void)
{
    // Initialize RNG and run a few rounds
    mbedtls_sha256_init(&rngCtx);
    uint8_t *rngDummy = malloc(1024);
    myrng(NULL, rngDummy, 1024);
    free(rngDummy);

    cf_prepare_next();
}

void cf_run_target(bool dumpResult)
{
    int err;

    classify(m, sizeof(m));
    
    size_t bufSize;
    if((err = mbedtls_base64_decode(NULL, 0, &bufSize, m, strlen(m))) && err != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
        printf("length error %d\n", err);

    unsigned char *buf = malloc(bufSize);
    if((err = mbedtls_base64_decode(buf, bufSize, &bufSize, m, strlen(m))))
        printf("decode error %d\n", err);

    if(dumpResult)
        dump_secret(buf, 32, "data");

    free(buf);
}

void cf_prepare_next(void)
{
    myrng(NULL, data, sizeof(data));

    size_t size;
    if(mbedtls_base64_encode(m, sizeof(m), &size, data, sizeof(data)))
        printf("update error\n");
}

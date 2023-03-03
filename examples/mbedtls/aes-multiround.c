#include <mbedtls/gcm.h>
#include "../cipherfix-main.h"

unsigned char key[16] = { 0 };
unsigned char iv[16] = { 0 };

// Message to encrypt.
unsigned char m[16] = { 0x0c, 0xb8, 0x64, 0x56, 0xa7, 0x3a, 0x55, 0xd1, 0x90, 0x1b, 0xbd, 0x0b, 0x4c, 0xff, 0x13, 0x6d  };

// AES-GCM context.
mbedtls_gcm_context aes;

void cf_init_target(void)
{
    mbedtls_gcm_init(&aes);
}

void cf_run_target(bool dumpResult)
{
    int pLen = 16 * 1000;
    unsigned char *p = malloc(pLen);
    for(int i = 0; i < pLen; i += 16)
        memcpy(p + i, m, 16);

    classify(key, sizeof(key));
    classify(p, pLen);

    if(mbedtls_gcm_setkey(&aes, MBEDTLS_CIPHER_ID_AES, key, sizeof(key) * 8))
        printf("could not set key\n");

    unsigned char *cipher = malloc(pLen);
    unsigned char *tag = malloc(16);
    if(mbedtls_gcm_crypt_and_tag(&aes, MBEDTLS_GCM_ENCRYPT, pLen, iv, sizeof(iv), NULL, 0, p, cipher, 16, tag))
        printf("could not encrypt\n");
    
    if(dumpResult)
    {
        dump_secret(cipher, 16, "ciphertext");
        dump_secret(tag, 16, "tag");
    }

    free(cipher);
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

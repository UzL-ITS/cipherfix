#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>

#include "../cipherfix-main.h"

unsigned char key[16] = { 0 };
unsigned char iv[16] = { 0 };

// Message to encrypt.
unsigned char m[16] = { 0x0c, 0xb8, 0x64, 0x56, 0xa7, 0x3a, 0x55, 0xd1, 0x90, 0x1b, 0xbd, 0x0b, 0x4c, 0xff, 0x13, 0x6d  };


void cf_init_target(void)
{
    
}

void cf_run_target(bool dumpResult)
{
    int pLen = 16 * 1000;
    unsigned char *p = malloc(pLen);
    for(int i = 0; i < pLen; i += 16)
        memcpy(p + i, m, 16);

    classify(key, sizeof(key));
    classify(p, pLen);

    unsigned char *cipher = malloc(pLen);
    unsigned char *tag = malloc(16);

    Aes aes;
    wc_AesGcmSetKey(&aes, key, sizeof(key));
    wc_AesGcmEncrypt(&aes, cipher, p, pLen, iv, sizeof(iv), tag, 16, NULL, 0);
    
    if(dumpResult)
    {
        dump_secret(cipher, sizeof(m), "ciphertext");
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

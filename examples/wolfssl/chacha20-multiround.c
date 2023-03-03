#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>

#include "../cipherfix-main.h"

unsigned char key[32] = { 0 };
unsigned char nonce[12] = { 0 };

// Message to encrypt.
unsigned char m[32] = { 0x0c, 0xb8, 0x64, 0x56, 0xa7, 0x3a, 0x55, 0xd1, 0x90, 0x1b, 0xbd, 0x0b, 0x4c, 0xff, 0x13, 0x6d,
                        0x0c, 0xb8, 0x64, 0x56, 0xa7, 0x3a, 0x55, 0xd1, 0x90, 0x1b, 0xbd, 0x0b, 0x4c, 0xff, 0x13, 0x6d  };


void cf_init_target(void)
{

}

void cf_run_target(bool dumpResult)
{
    int pLen = sizeof(m) * 1000;
    unsigned char *p = malloc(pLen);
    for(int i = 0; i < pLen; i += sizeof(m))
        memcpy(p + i, m, sizeof(m));
    
    classify(key, sizeof(key));
    classify(p, pLen);

    unsigned char *cipher = malloc(pLen);
    unsigned char *tag = malloc(16);

    wc_ChaCha20Poly1305_Encrypt(key, nonce, NULL, 0, p, pLen, cipher, tag);
    
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

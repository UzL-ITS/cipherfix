#include <mbedtls/chachapoly.h>
#include "../cipherfix-main.h"

unsigned char key[32] = { 0 };
unsigned char nonce[12] = { 0 };

// Message to encrypt.
unsigned char m[32] = { 0x0c, 0xb8, 0x64, 0x56, 0xa7, 0x3a, 0x55, 0xd1, 0x90, 0x1b, 0xbd, 0x0b, 0x4c, 0xff, 0x13, 0x6d,
                        0x0c, 0xb8, 0x64, 0x56, 0xa7, 0x3a, 0x55, 0xd1, 0x90, 0x1b, 0xbd, 0x0b, 0x4c, 0xff, 0x13, 0x6d  };

// ChaCha20-Poly1305 context.
mbedtls_chachapoly_context chacha;

void cf_init_target(void)
{
    mbedtls_chachapoly_init(&chacha);
}

void cf_run_target(bool dumpResult)
{
    classify(key, sizeof(key));
    classify(m, sizeof(m));

    if(mbedtls_chachapoly_setkey(&chacha, key))
        printf("could not set key\n");

    unsigned char *cipher = malloc(sizeof(m));
    unsigned char *tag = malloc(16);
    if(mbedtls_chachapoly_encrypt_and_tag(&chacha, sizeof(m), nonce, NULL, 0, m, cipher, tag))
        printf("could not encrypt\n");
    
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

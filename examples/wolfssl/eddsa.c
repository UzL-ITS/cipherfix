#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ed25519.h>

#include "../cipherfix-main.h"

// Secret key that is used for signature
unsigned char secretkey[32] = { 
    0x60, 0xea, 0x88, 0x4a, 0x8c, 0x32, 0x36, 0x0e,
    0xfd, 0xa4, 0x58, 0x0b, 0x30, 0x36, 0x9e, 0xac,
    0x4b, 0xd2, 0xc9, 0xbe, 0xfe, 0x43, 0xd9, 0x0f,
    0xdb, 0x80, 0xbb, 0xd8, 0xae, 0xc4, 0xa8, 0x78
};

// Hash to sign
unsigned char m[32] = {
    0x0c, 0xb8, 0x64, 0x56, 0xa7, 0x3a, 0x55, 0xd1,
    0x90, 0x1b, 0xbd, 0x0b, 0x4c, 0xff, 0x13, 0x6d,
    0x84, 0x78, 0x33, 0x2d, 0xf3, 0x5e, 0xe7, 0xa1,
    0x15, 0x63, 0x71, 0x0b, 0x48, 0xec, 0x06, 0x1c
};


void cf_init_target(void)
{
    
}

void cf_run_target(bool dumpResult)
{
    classify(secretkey, sizeof(secretkey));

    struct ed25519_key k;
    wc_ed25519_init(&k);
    wc_ed25519_import_private_only(secretkey, sizeof(secretkey), &k);

    uint8_t public[32] = { 0 };
    wc_ed25519_make_public(&k, public, sizeof(public));

    unsigned char *sm = malloc(64);
    word32 ssize;
    wc_ed25519_sign_msg(m, sizeof(m), sm, &ssize, &k);


    if(dumpResult)
        dump_secret(sm, ssize, "signature");

    free(sm);
}

void cf_prepare_next(void)
{
    // Increment hash
    for(int i = 0; i < sizeof(m); ++i)
    {
        unsigned char tmp = m[i] + 1;
        m[i] = tmp;
        if(tmp != 0)
            break;
    }
}
#include <sodium.h>
#include "../cipherfix-main.h"

// Plaintext to hash
int len = 3200;
unsigned char *m = 0;

void cf_init_target(void)
{
    m = malloc(len);
    memset(m, 'a', len);
}

void cf_run_target(bool dumpResult)
{
    classify(m, len);

    unsigned char *hash = malloc(len);
    crypto_hash_sha512(hash, m, len);

    if(dumpResult)
        dump_secret(hash, 512 / 8, "hash");

    free(hash);
}

void cf_prepare_next(void)
{
    // Increment plain text
    for(int i = 0; i < len; ++i)
    {
        unsigned char tmp = m[i] + 1;
        m[i] = tmp;
        if(tmp != 0)
            break;
    }
}
#include <mbedtls/ecdh.h>
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
    mbedtls_sha256_init(&rngCtx);
    uint8_t *rngDummy = malloc(1024);
    myrng(NULL, rngDummy, 1024);
    free(rngDummy);

    // Generate key
    /*
        mbedtls_ecp_group grp;
        mbedtls_ecp_group_init(&grp);
        printf("ecp load: %d\n", mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519));

        mbedtls_mpi ourD;
        mbedtls_ecp_point ourQ;
        mbedtls_mpi_init(&ourD);
        mbedtls_ecp_point_init(&ourQ);
        printf("gen ours: %d\n", mbedtls_ecdh_gen_public(&grp, &ourD, &ourQ, myrng, NULL));

        size_t len;
        uint8_t ecdhOurD[32];
        uint8_t ecdhOurQ[32];
        printf("save our D: %d\n", mbedtls_mpi_write_binary(&ourD, ecdhOurD, sizeof(ecdhOurD)));
        printf("save our Q: %d\n", mbedtls_ecp_point_write_binary(&grp, &ourQ, MBEDTLS_ECP_PF_COMPRESSED, &len, ecdhOurQ, sizeof(ecdhOurQ)));
        printf(" --> len (must be %ld): %ld\n", sizeof(ecdhOurQ), len);

        dump_secret(ecdhOurD, sizeof(ecdhOurD), "oD");
        dump_secret(ecdhOurQ, sizeof(ecdhOurQ), "oQ");
    */

    // Generate remote key
    cf_prepare_next();
}

void cf_run_target(bool dumpResult)
{
    classify(ecdhOurD, sizeof(ecdhOurD));

    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);

    mbedtls_ecp_point theirQ;
    mbedtls_ecp_point_init(&theirQ);
    mbedtls_ecp_point_read_binary(&grp, &theirQ, ecdhTheirQ, sizeof(ecdhTheirQ));
    
    mbedtls_mpi ourD;
    mbedtls_mpi_init(&ourD);
    mbedtls_mpi_read_binary(&ourD, ecdhOurD, sizeof(ecdhOurD));

    mbedtls_mpi secret;
    mbedtls_mpi_init(&secret);
    mbedtls_ecdh_compute_shared(&grp, &secret, &theirQ, &ourD, myrng, NULL);

    size_t secretLen = mbedtls_mpi_size(&secret);
    unsigned char *secretBuf = malloc(secretLen);
    mbedtls_mpi_write_binary(&secret, secretBuf, secretLen);

    if(dumpResult)
        dump_secret(secretBuf, secretLen, "secret");

    free(secretBuf);
}

void cf_prepare_next(void)
{
    // Generate new remote public key
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);

    mbedtls_mpi theirD;
    mbedtls_ecp_point theirQ;
    mbedtls_mpi_init(&theirD);
    mbedtls_ecp_point_init(&theirQ);
    mbedtls_ecdh_gen_public(&grp, &theirD, &theirQ, myrng, NULL);
    
    size_t len;
    mbedtls_mpi_write_binary(&theirD, ecdhTheirD, sizeof(ecdhTheirD));
    mbedtls_ecp_point_write_binary(&grp, &theirQ, MBEDTLS_ECP_PF_COMPRESSED, &len, ecdhTheirQ, sizeof(ecdhTheirQ));
}

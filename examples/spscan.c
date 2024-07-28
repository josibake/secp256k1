/*************************************************************************
 * To the extent possible under law, the author(s) have dedicated all    *
 * copyright and related and neighboring rights to the software in this  *
 * file to the public domain worldwide. This software is distributed     *
 * without any warranty. For the CC0 Public Domain Dedication, see       *
 * EXAMPLES_COPYING or https://creativecommons.org/publicdomain/zero/1.0 *
 *************************************************************************/

#include <stdio.h>
#include <assert.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_silentpayments.h>

#include <string.h>
#include "examples_util.h"

static unsigned char carol_address[2][33] = {
    {
        0x03, 0xbb, 0xc6, 0x3f, 0x12, 0x74, 0x5d, 0x3b,
        0x9e, 0x9d, 0x24, 0xc6, 0xcd, 0x7a, 0x1e, 0xfe,
        0xba, 0xd0, 0xa7, 0xf4, 0x69, 0x23, 0x2f, 0xbe,
        0xcf, 0x31, 0xfb, 0xa7, 0xb4, 0xf7, 0xdd, 0xed, 0xa8
    },
    {
        0x03, 0x81, 0xeb, 0x9a, 0x9a, 0x9e, 0xc7, 0x39,
        0xd5, 0x27, 0xc1, 0x63, 0x1b, 0x31, 0xb4, 0x21,
        0x56, 0x6f, 0x5c, 0x2a, 0x47, 0xb4, 0xab, 0x5b,
        0x1f, 0x6a, 0x68, 0x6d, 0xfb, 0x68, 0xea, 0xb7, 0x16
    }
};

int main(void) {
    unsigned char randomize[32];
    int ret;
    size_t i, j;
    unsigned char shared_secret[33];
    secp256k1_pubkey spend_pubkey;
    secp256k1_silentpayments_public_data public_data;
    unsigned char seckey[32];
    size_t k = 0;
    size_t N_CUSTOMERS = 1000000;
    secp256k1_xonly_pubkey potential_output;

    /* Before we can call actual API functions, we need to create a "context" */
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!fill_random(randomize, sizeof(randomize))) {
        printf("Failed to generate randomness\n");
        return 1;
    }
    /* Randomizing the context is recommended to protect against side-channel
     * leakage See `secp256k1_context_randomize` in secp256k1.h for more
     * information about it. This should never fail. */
    ret = secp256k1_context_randomize(ctx, randomize);
    assert(ret);

    if (!fill_random(seckey, sizeof(seckey))) {
        printf("Failed to generate randomness\n");
        return 1;
    }
    /* Load Carol's spend public key */
    ret = secp256k1_ec_pubkey_parse(ctx,
        &spend_pubkey,
        carol_address[1],
        33
    );
    assert(ret);

    /* Scan one output at a time, using the serialized `public_data`
     * created by Bob's full node
     */
    ret = secp256k1_silentpayments_recipient_public_data_parse(ctx,
        &public_data,
        carol_address[0]
    );
    assert(ret);
    for (i = 0; i < N_CUSTOMERS; i++) {
        for (j = 0; j < 32; j++) {
            seckey[j] = j + 1;
        }
        ret = secp256k1_silentpayments_recipient_create_shared_secret(ctx,
            shared_secret,
            seckey,
            &public_data
        );
        assert(ret);
        ret = secp256k1_silentpayments_recipient_create_output_pubkey(ctx,
            &potential_output,
            shared_secret,
            &spend_pubkey,
            k
        );
    }
    /* This will clear everything from the context and free the memory */
    secp256k1_context_destroy(ctx);
    return 0;
}

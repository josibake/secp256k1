/*************************************************************************
 * Written in 2024 by josibake                                           *
 * To the extent possible under law, the author(s) have dedicated all    *
 * copyright and related and neighboring rights to the software in this  *
 * file to the public domain worldwide. This software is distributed     *
 * without any warranty. For the CC0 Public Domain Dedication, see       *
 * EXAMPLES_COPYING or https://creativecommons.org/publicdomain/zero/1.0 *
 *************************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_silentpayments.h>

#include "examples_util.h"

/* Static data for Bob and Carol's silent payment addresses.
 * This consists of a scan key for each and the addresse data for each
 */
static unsigned char smallest_outpoint[36] = {
    0x16,0x9e,0x1e,0x83,0xe9,0x30,0x85,0x33,0x91,
    0xbc,0x6f,0x35,0xf6,0x05,0xc6,0x75,0x4c,0xfe,
    0xad,0x57,0xcf,0x83,0x87,0x63,0x9d,0x3b,0x40,
    0x96,0xc5,0x4f,0x18,0xf4,0x00,0x00,0x00,0x00
};
static unsigned char bob_scan_key[32] = {
    0xa8,0x90,0x54,0xc9,0x5b,0xe3,0xc3,0x01,
    0x56,0x65,0x74,0xf2,0xaa,0x93,0xad,0xe0,
    0x51,0x85,0x09,0x03,0xa6,0x9c,0xbd,0xd1,
    0xd4,0x7e,0xae,0x26,0x3d,0x7b,0xc0,0x31
};
static unsigned char bob_spend_pubkey[33] = {
    0x02,0xee,0x97,0xdf,0x83,0xb2,0x54,0x6a,
    0xf5,0xa7,0xd0,0x62,0x15,0xd9,0x8b,0xcb,
    0x63,0x7f,0xe0,0x5d,0xd0,0xfa,0x37,0x3b,
    0xd8,0x20,0xe6,0x64,0xd3,0x72,0xde,0x9a,0x01
};
static unsigned char bob_address[2][33] = {
    {
        0x02,0x15,0x40,0xae,0xa8,0x97,0x54,0x7a,
        0xd4,0x39,0xb4,0xe0,0xf6,0x09,0xe5,0xf0,
        0xfa,0x63,0xde,0x89,0xab,0x11,0xed,0xe3,
        0x1e,0x8c,0xde,0x4b,0xe2,0x19,0x42,0x5f,0x23
    },
    {
        0x02,0x3e,0xff,0xf8,0x18,0x51,0x65,0xea,
        0x63,0xa9,0x92,0xb3,0x9f,0x31,0xd8,0xfd,
        0x8e,0x0e,0x64,0xae,0xf9,0xd3,0x88,0x07,
        0x34,0x97,0x37,0x14,0xa5,0x3d,0x83,0x11,0x8d
    }
};
static unsigned char carol_scan_key[32] = {
    0x04,0xb2,0xa4,0x11,0x63,0x5c,0x09,0x77,
    0x59,0xaa,0xcd,0x0f,0x00,0x5a,0x4c,0x82,
    0xc8,0xc9,0x28,0x62,0xc6,0xfc,0x28,0x4b,
    0x80,0xb8,0xef,0xeb,0xc2,0x0c,0x3d,0x17
};
static unsigned char carol_address[2][33] = {
    {
        0x03,0xbb,0xc6,0x3f,0x12,0x74,0x5d,0x3b,
        0x9e,0x9d,0x24,0xc6,0xcd,0x7a,0x1e,0xfe,
        0xba,0xd0,0xa7,0xf4,0x69,0x23,0x2f,0xbe,
        0xcf,0x31,0xfb,0xa7,0xb4,0xf7,0xdd,0xed,0xa8
    },
    {
        0x03,0x81,0xeb,0x9a,0x9a,0x9e,0xc7,0x39,
        0xd5,0x27,0xc1,0x63,0x1b,0x31,0xb4,0x21,
        0x56,0x6f,0x5c,0x2a,0x47,0xb4,0xab,0x5b,
        0x1f,0x6a,0x68,0x6d,0xfb,0x68,0xea,0xb7,0x16
    }
};

/* Labels
 * The structs and call back function are for demonstration only and not optimized.
 * In a production usecase, it is expected that the caller will be using a much more performant
 * method for storing and querying labels.
 */

struct label_cache_entry {
    secp256k1_pubkey label;
    unsigned char label_tweak[32];
};

struct labels_cache {
    const secp256k1_context *ctx;
    size_t entries_used;
    struct label_cache_entry entries[5];
};

const unsigned char* label_lookup(const secp256k1_pubkey* key, const void* cache_ptr) {
    const struct labels_cache* cache = (const struct labels_cache*)cache_ptr;
    size_t i;
    for (i = 0; i < cache->entries_used; i++) {
        if (secp256k1_ec_pubkey_cmp(cache->ctx, &cache->entries[i].label, key) == 0) {
            return cache->entries[i].label_tweak;
        }
    }
    return NULL;
}

int main(void) {
    enum { N_TX_INPUTS = 2, N_TX_OUTPUTS = 3 };
    unsigned char randomize[32];
    unsigned char xonly_print[32];
    secp256k1_xonly_pubkey tx_inputs[N_TX_INPUTS];
    secp256k1_xonly_pubkey tx_outputs[N_TX_OUTPUTS];
    int ret;
    size_t i;
    /* Before we can call actual API functions, we need to create a "context". */
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

    /*** Sending ***/
    {
        secp256k1_keypair sender_seckeys[N_TX_INPUTS];
        const secp256k1_keypair *sender_seckey_ptrs[N_TX_INPUTS];
        secp256k1_silentpayments_recipient recipients[N_TX_OUTPUTS];
        const secp256k1_silentpayments_recipient *recipient_ptrs[N_TX_OUTPUTS];
        secp256k1_xonly_pubkey *generated_output_ptrs[N_TX_OUTPUTS];
        unsigned char (*sp_addresses[N_TX_OUTPUTS])[2][33] = {&carol_address, &bob_address, &carol_address};

        /*** Generate private keys for the sender ***/

        /* In practice, the private keys would come from the eligible UTXOs being spent in the transaction.
         * The recipient would extract the corresponding public keys from the transaction inputs.
         *
         * In this example, only taproot inputs are used but the function can be called with
         * a mix of taproot seckeys and plain seckeys. Taproot seckeys are passed as keypairs
         * to allow the sending function to check if the private keys need to be negated without needing
         * to do an expensive pubkey generation. This is not needed for plain seckeys since there is no need
         * for negation. For normal usage, use `secp256k1_keypair_load` instead of `secp256k1_keypair_create` since
         * the wallet will likely already have the taproot pubkey.
         *
         * The pubkey from each input keypair is saved in the `tx_inputs` array. This array will be used
         * later in the example to represent the public keys the recipient would have extracted from the
         * transaction inputs.
         */

        for (i = 0; i < 2; i++) {
            /* If the secret key is zero or out of range (bigger than secp256k1's
             * order), we try to sample a new key. Note that the probability of this
             * happening is negligible. */
            while (1) {
                unsigned char seckey[32];
                if (!fill_random(seckey, sizeof(seckey))) {
                    printf("Failed to generate randomness\n");
                    return 1;
                }
                /* Try to create a keypair with a valid context, it should only fail if
                 * the secret key is zero or out of range. */
                if (secp256k1_keypair_create(ctx, &sender_seckeys[i], seckey)) {
                    sender_seckey_ptrs[i] = &sender_seckeys[i];
                    ret = secp256k1_keypair_xonly_pub(ctx, &tx_inputs[i], NULL, &sender_seckeys[i]);
                    assert(ret);
                    break;
                } else {
                    printf("Failed to create keypair\n");
                    return 1;
                }
            }
        }
        /*** Create the recipient objects ***/

        /* Alice is sending to Bob and Carol in this transaction. Afte decoding their silent payment addresses,
         * she creates the recipient struct to hold their scan and spend public keys. Alice wants to create two
         * outputs for Carol, so she passes Carol's address twice. Note that the index is added to the struct - this
         * is because `_sender_create_outputs` will sort the recipients in place as part of creating the
         * outputs, but the index is used to return the generated outputs in the original order (i.e. the order
         * in `sp_addresses`). This allows the caller to easily match up the generated output with the original
         * silent payment address.
         */

        for (i = 0; i < N_TX_OUTPUTS; i++) {
            ret = secp256k1_ec_pubkey_parse(ctx, &recipients[i].scan_pubkey, (*(sp_addresses[i]))[0], 33);
            assert(ret);
            ret = secp256k1_ec_pubkey_parse(ctx, &recipients[i].spend_pubkey, (*(sp_addresses[i]))[1], 33);
            assert(ret);
            recipients[i].index = i;
            recipient_ptrs[i] = &recipients[i];
        }

        for (i = 0; i < N_TX_OUTPUTS; i++) {
            generated_output_ptrs[i] = &tx_outputs[i];
        }
        ret = secp256k1_silentpayments_sender_create_outputs(ctx,
            generated_output_ptrs,
            recipient_ptrs, N_TX_OUTPUTS,
            smallest_outpoint,
            sender_seckey_ptrs, N_TX_INPUTS,
            NULL, 0
        );
        assert(ret);
        printf("Alice created the following outputs for Bob and Carol: \n");
        for (i = 0; i < N_TX_OUTPUTS; i++) {
            printf("    Output %lu: ", i);
            secp256k1_xonly_pubkey_serialize(ctx, xonly_print, &tx_outputs[i]);
            print_hex(xonly_print, sizeof(xonly_print));
        }

    }

    /*** Receiving ***/

    {
        /* Common variables
         * For receiving, there are two examples to demonstrate:
         * 1. Bob - simple scan with labels
         * 3. Carol - scanning as a light client
         *
         * To keep the example simple, the shared variables between these examples are defined at the top level
         */
        const secp256k1_xonly_pubkey *input_pubkey_ptrs[N_TX_INPUTS];
        const secp256k1_xonly_pubkey *tx_output_ptrs[N_TX_OUTPUTS];
        secp256k1_pubkey input_pubkey_sum;
        size_t n_found_outputs;
        secp256k1_pubkey spend_pubkey;

        for (i = 0; i < N_TX_INPUTS; i++) {
            input_pubkey_ptrs[i] = &tx_inputs[i];
        }
        for (i = 0; i < N_TX_OUTPUTS; i++) {
            tx_output_ptrs[i] = &tx_outputs[i];
        }

        /* Bob - scanning with the full transaction (e.g. a full node)
         * Bob first collects the eligible inputs from the transaction, extracts the public key
         * and calls `_recipient_compute_public_data` to get the summed public key and the input_hash.
         * If Bob has multiple scanning keys, he can reuse the outputs from this function to scan
         * the transaction multiple times.
         *
         * Next, Bob calls `_recipient_create_shared_secret` with a scan key and then proceeds to scan the
         * transaction with `_scan_outputs`. Notice that the `found_outputs` array must be the same
         * size as the `tx_outputs`, since we don't know beforehand how many outputs belong to us.
         * If outputs are found (i.e. `n_found_outputs` > 0`), Bob can use `n_found_outputs` to
         * iterate over the `found_outputs` array.
         *
         * Since Bob has access to the full transaction outputs when scanning, its also easy for him
         * to scan with labels, as demonstrated below. For efficient scanning, Bob keeps a cache of
         * every label he has previously used and uses a callback to check if a potential label exists
         * in his database. Since the labels are created using an incremental integer `m`, if Bob ever
         * forgets how many labels he has previously used, he can pregenerate a large number of
         * labels (e.g. 0..100_000) and use that while scanning.
         */
        {
            secp256k1_silentpayments_found_output found_outputs[N_TX_OUTPUTS];
            secp256k1_silentpayments_found_output *found_output_ptrs[N_TX_OUTPUTS];
            unsigned char input_hash[32];
            unsigned int m = 1;
            struct labels_cache bob_labels;

            for (i = 0; i < N_TX_OUTPUTS; i++) {
                found_output_ptrs[i] = &found_outputs[i];
            }

            /* In this contrived example, our label context needs the secp256k1 context because our lookup function
             * is calling `secp256k1_ec_pubkey_cmp`. In practice, this context can be anything the lookup function needs.
             */
            bob_labels.ctx = ctx;
            ret = secp256k1_ec_pubkey_parse(ctx, &spend_pubkey, bob_spend_pubkey, 33);

            /* Add an entry to the cache. Presumably, Bob has previously called `_create_address_spend_pubkey`
             * and used the labeled spend pubkey to encode a labelled silent payments address.
             *
             * In this example, we create the label tweak and store it directly in our cache, but in practice
             * the caller would save the outputs as `secp256k1_pubkey` and `unsigned char tweak[32]`. These can
             * then be stored in whatever cache the caller is using (e.g. a map)
             */
            ret = secp256k1_silentpayments_recipient_create_label_tweak(ctx,
                &bob_labels.entries[0].label,
                bob_labels.entries[0].label_tweak,
                bob_scan_key,
                m
            );
            assert(ret);
            bob_labels.entries_used = 1;

            /*** Scanning ***/
            ret = secp256k1_silentpayments_recipient_compute_public_data(ctx,
                &input_pubkey_sum,
                input_hash,
                smallest_outpoint,
                input_pubkey_ptrs, N_TX_INPUTS,
                NULL, 0 /* null because no eligible plain pubkey inputs were found in the tx */
            );
            assert(ret);

            n_found_outputs = 0;
            ret = secp256k1_silentpayments_recipient_scan_outputs(ctx,
                found_output_ptrs, &n_found_outputs,
                tx_output_ptrs, N_TX_OUTPUTS,
                bob_scan_key,
                &input_pubkey_sum,
                &spend_pubkey,
                input_hash,
                label_lookup, &bob_labels
            );
            assert(n_found_outputs == 1);
            printf("\n");
            printf("Bob found the following outputs: \n");
            for (i = 0; i < n_found_outputs; i++) {
                printf("    Output %lu: ", i);
                secp256k1_xonly_pubkey_serialize(ctx, xonly_print, &found_outputs[i].output);
                print_hex(xonly_print, sizeof(xonly_print));
            }
        }

        /* Carol - scanning as a light client
         * Being a light client, Carol likely does not have access to the transaction outputs. This
         * means she will need to first generate an output, check if it exists in the UTXO (e.g.
         * BIP158 or some other means of querying) and only proceed to check the next output (by
         * incrementing `k`) if the first output exists.
         *
         * The light client usecase demonstates why we need a more granular API for receiving.
         */
        {
            unsigned char found_outputs_light[2][32];
            unsigned char shared_secret[33];
            secp256k1_pubkey pubkey_light_client;
            ret = secp256k1_ec_pubkey_parse(ctx, &spend_pubkey, carol_address[1], 33);
            assert(ret);
            /* Summing the public keys from the transaction is not done by Carol. This step would
             * likely be done by a full node running an index and then serving up the 33 byte public keys
             * to Carol's client. This is why we don't also send the `input_hash`: we can save Carol
             * 32 bytes by multiplying the public key sum and the `input_hash` scalar before sending
             * her the data.
             *
             * For a full node, we want them separate so we can multiply the `input_hash` and `scan_key`
             * scalars before doing ECDH, to save us from needing to do two ECDH. But in the light client
             * case, the server only needs to do one ECDH (`input_hash`*`A_sum`) to server the data to
             * any number of clients, so its better to save the 32 bytes.
             */
            ret = secp256k1_silentpayments_recipient_compute_public_data(ctx,
                &pubkey_light_client,
                NULL,    /* null because we want the `input_hash` multiplied in with the pubkey sum */
                smallest_outpoint,
                input_pubkey_ptrs, N_TX_INPUTS,
                NULL, 0 /* null because no eligible plain pubkey inputs were found in the tx */
            );
            assert(ret);

            ret = secp256k1_silentpayments_recipient_create_shared_secret(ctx,
                shared_secret,
                carol_scan_key,
                &pubkey_light_client
            );
            assert(ret);

            n_found_outputs = 0;
            /* Scanning */
            {
                int found = 0;
                size_t k = 0;
                secp256k1_xonly_pubkey potential_output;
                while(1) {

                    ret = secp256k1_silentpayments_recipient_create_output_pubkey(ctx,
                        &potential_output,
                        shared_secret,
                        &spend_pubkey,
                        k
                    );
                    assert(ret);
                    /* At this point, we check that the utxo exists with a light client protocol.
                     * For this example, we'll just iterate through the list of pubkeys */
                    found = 0;
                    for (i = 0; i < N_TX_OUTPUTS; i++) {
                        if (secp256k1_xonly_pubkey_cmp(ctx, &potential_output, &tx_outputs[i]) == 0) {
                            secp256k1_xonly_pubkey_serialize(ctx, found_outputs_light[n_found_outputs], &potential_output);
                            found = 1;
                            n_found_outputs++;
                            k++;
                            break;
                        }
                    }
                    if (!found) {
                        break;
                    }
                }
            }

            printf("\n");
            printf("Carol found the following outputs: \n");
            for (i = 0; i < n_found_outputs; i++) {
                printf("    Output %lu: ", i);
                print_hex(found_outputs_light[i], 32);
            }
        }
    }

    /* This will clear everything from the context and free the memory */
    secp256k1_context_destroy(ctx);

    /* It's best practice to try to clear secrets from memory after using them.
     * This is done because some bugs can allow an attacker to leak memory, for
     * example through "out of bounds" array access (see Heartbleed), Or the OS
     * swapping them to disk. Hence, we overwrite the secret key buffer with zeros.
     *
     * Here we are preventing these writes from being optimized out, as any good compiler
     * will remove any writes that aren't used. */

    /* do some cleanup here */
    return 0;
}

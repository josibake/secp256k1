/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_SILENTPAYMENTS_MAIN_H
#define SECP256K1_MODULE_SILENTPAYMENTS_MAIN_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_ecdh.h"
#include "../../../include/secp256k1_extrakeys.h"
#include "../../../include/secp256k1_silentpayments.h"
#include "../../hash.h"

/** Sort an array of silent payment recipients. This is used to group recipients by scan pubkey to
 *  ensure the correct values of k are used when creating multiple outputs for a recipient. */
static int secp256k1_silentpayments_recipient_cmp(const void* r1, const void* r2, void *cmp_data) {
    const secp256k1_silentpayments_recipient *first = r1;
    const secp256k1_silentpayments_recipient *second = r2;
    secp256k1_ec_pubkey_sort_cmp_data *cmpd = cmp_data;
    return secp256k1_ec_pubkey_cmp(cmpd->ctx, &first->scan_pubkey, &second->scan_pubkey);
}

int secp256k1_silentpayments_recipient_sort(const secp256k1_context* ctx, secp256k1_silentpayments_recipient **recipients, size_t n_recipients) {
    secp256k1_ec_pubkey_sort_cmp_data cmp_data;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(recipients != NULL);

    cmp_data.ctx = ctx;

    /* Suppress wrong warning (fixed in MSVC 19.33) */
    #if defined(_MSC_VER) && (_MSC_VER < 1933)
    #pragma warning(push)
    #pragma warning(disable: 4090)
    #endif

    secp256k1_hsort(recipients, n_recipients, sizeof(recipients), secp256k1_silentpayments_recipient_cmp, &cmp_data);

    #if defined(_MSC_VER) && (_MSC_VER < 1933)
    #pragma warning(pop)
    #endif

    return 1;
}

/** Set hash state to the BIP340 tagged hash midstate for "BIP0352/Inputs". */
static void secp256k1_silentpayments_sha256_init_inputs(secp256k1_sha256* hash) {
    secp256k1_sha256_initialize(hash);
    hash->s[0] = 0xd4143ffcul;
    hash->s[1] = 0x012ea4b5ul;
    hash->s[2] = 0x36e21c8ful;
    hash->s[3] = 0xf7ec7b54ul;
    hash->s[4] = 0x4dd4e2acul;
    hash->s[5] = 0x9bcaa0a4ul;
    hash->s[6] = 0xe244899bul;
    hash->s[7] = 0xcd06903eul;

    hash->bytes = 64;
}

static void secp256k1_silentpayments_calculate_input_hash(unsigned char *input_hash, const unsigned char *outpoint_smallest36, secp256k1_ge *pubkey_sum) {
    secp256k1_sha256 hash;
    unsigned char pubkey_sum_ser[33];
    size_t ser_size;
    int ser_ret;

    secp256k1_silentpayments_sha256_init_inputs(&hash);
    secp256k1_sha256_write(&hash, outpoint_smallest36, 36);
    ser_ret = secp256k1_eckey_pubkey_serialize(pubkey_sum, pubkey_sum_ser, &ser_size, 1);
    VERIFY_CHECK(ser_ret && ser_size == sizeof(pubkey_sum_ser));
    (void)ser_ret;
    secp256k1_sha256_write(&hash, pubkey_sum_ser, sizeof(pubkey_sum_ser));
    secp256k1_sha256_finalize(&hash, input_hash);
}

/* secp256k1_ecdh expects a hash function to be passed in or uses its default
 * hashing function. We don't want to hash the ECDH result, so we define a
 * custom function which simply returns the pubkey without hashing.
 */
static int secp256k1_silentpayments_ecdh_return_pubkey(unsigned char *output, const unsigned char *x32, const unsigned char *y32, void *data) {
    secp256k1_ge point;
    secp256k1_fe x, y;
    size_t ser_size;
    int ser_ret;

    (void)data;
    /* Parse point as group element */
    if (!secp256k1_fe_set_b32_limit(&x, x32) || !secp256k1_fe_set_b32_limit(&y, y32)) {
        return 0;
    }
    secp256k1_ge_set_xy(&point, &x, &y);

    /* Serialize as compressed pubkey */
    ser_ret = secp256k1_eckey_pubkey_serialize(&point, output, &ser_size, 1);
    VERIFY_CHECK(ser_ret && ser_size == 33);
    (void)ser_ret;

    return 1;
}

int secp256k1_silentpayments_create_shared_secret(const secp256k1_context *ctx, unsigned char *shared_secret33, const secp256k1_pubkey *public_component, const unsigned char *secret_component, const unsigned char *input_hash) {
    unsigned char tweaked_secret_component[32];

    /* Sanity check inputs */
    ARG_CHECK(shared_secret33 != NULL);
    memset(shared_secret33, 0, 33);
    ARG_CHECK(public_component != NULL);
    ARG_CHECK(secret_component != NULL);

    /* Tweak secret component with input hash, if available */
    memcpy(tweaked_secret_component, secret_component, 32);
    if (input_hash != NULL) {
        if (!secp256k1_ec_seckey_tweak_mul(ctx, tweaked_secret_component, input_hash)) {
            return 0;
        }
    }

    /* Compute shared_secret = tweaked_secret_component * Public_component */
    if (!secp256k1_ecdh(ctx, shared_secret33, public_component, tweaked_secret_component, secp256k1_silentpayments_ecdh_return_pubkey, NULL)) {
        return 0;
    }

    return 1;
}

/** Set hash state to the BIP340 tagged hash midstate for "BIP0352/SharedSecret". */
static void secp256k1_silentpayments_sha256_init_sharedsecret(secp256k1_sha256* hash) {
    secp256k1_sha256_initialize(hash);
    hash->s[0] = 0x88831537ul;
    hash->s[1] = 0x5127079bul;
    hash->s[2] = 0x69c2137bul;
    hash->s[3] = 0xab0303e6ul;
    hash->s[4] = 0x98fa21faul;
    hash->s[5] = 0x4a888523ul;
    hash->s[6] = 0xbd99daabul;
    hash->s[7] = 0xf25e5e0aul;

    hash->bytes = 64;
}

static void secp256k1_silentpayments_create_t_k(secp256k1_scalar *t_k_scalar, const unsigned char *shared_secret33, unsigned int k) {
    secp256k1_sha256 hash;
    unsigned char hash_ser[32];
    unsigned char k_serialized[4];

    /* Compute t_k = hash(shared_secret || ser_32(k))  [sha256 with tag "BIP0352/SharedSecret"] */
    secp256k1_silentpayments_sha256_init_sharedsecret(&hash);
    secp256k1_sha256_write(&hash, shared_secret33, 33);
    secp256k1_write_be32(k_serialized, k);
    secp256k1_sha256_write(&hash, k_serialized, sizeof(k_serialized));
    secp256k1_sha256_finalize(&hash, hash_ser);
    secp256k1_scalar_set_b32(t_k_scalar, hash_ser, NULL);
}

int secp256k1_silentpayments_create_output_pubkey(const secp256k1_context *ctx, secp256k1_xonly_pubkey *P_output_xonly, const unsigned char *shared_secret33, const secp256k1_pubkey *receiver_spend_pubkey, unsigned int k) {
    secp256k1_ge P_output_ge;
    secp256k1_scalar t_k_scalar;

    /* Sanity check inputs */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(P_output_xonly != NULL);
    ARG_CHECK(shared_secret33 != NULL);
    ARG_CHECK(receiver_spend_pubkey != NULL);

    /* Calculate and return P_output_xonly = B_spend + t_k * G */
    secp256k1_silentpayments_create_t_k(&t_k_scalar, shared_secret33, k);
    secp256k1_pubkey_load(ctx, &P_output_ge, receiver_spend_pubkey);
    if (!secp256k1_eckey_pubkey_tweak_add(&P_output_ge, &t_k_scalar)) {
        return 0;
    }
    secp256k1_xonly_pubkey_save(P_output_xonly, &P_output_ge);

    return 1;
}

int secp256k1_silentpayments_sender_create_outputs(const secp256k1_context *ctx, secp256k1_silentpayments_recipient **recipients, size_t n_recipients,
        const unsigned char *outpoint_smallest36, const unsigned char * const *plain_seckeys, size_t n_plain_seckeys, const unsigned char * const *taproot_seckeys, size_t n_taproot_seckeys
) {
    size_t i, k;
    secp256k1_scalar a_sum_scalar, addend;
    secp256k1_ge A_sum_ge;
    secp256k1_gej A_sum_gej;
    unsigned char input_hash[32];
    unsigned char a_sum[32];
    unsigned char shared_secret[33];
    secp256k1_silentpayments_recipient last_recipient;

    /* Sanity check inputs. */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(recipients != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(plain_seckeys == NULL || n_plain_seckeys >= 1);
    ARG_CHECK(taproot_seckeys == NULL || n_taproot_seckeys >= 1);
    ARG_CHECK((plain_seckeys != NULL) || (taproot_seckeys != NULL));
    ARG_CHECK((n_plain_seckeys + n_taproot_seckeys) >= 1);
    ARG_CHECK(outpoint_smallest36 != NULL);

    /* Compute input private keys sum: a_sum = a_1 + a_2 + ... + a_n */
    a_sum_scalar = secp256k1_scalar_zero;
    for (i = 0; i < n_plain_seckeys; i++) {
        int ret = secp256k1_scalar_set_b32_seckey(&addend, plain_seckeys[i]);
        VERIFY_CHECK(ret);
        (void)ret;

        secp256k1_scalar_add(&a_sum_scalar, &a_sum_scalar, &addend);
        VERIFY_CHECK(!secp256k1_scalar_is_zero(&a_sum_scalar));
    }
    /* private keys used for taproot outputs have to be negated if they resulted in an odd point */
    for (i = 0; i < n_taproot_seckeys; i++) {
        secp256k1_ge addend_point;
        int ret = secp256k1_ec_pubkey_create_helper(&ctx->ecmult_gen_ctx, &addend, &addend_point, taproot_seckeys[i]);
        VERIFY_CHECK(ret);
        (void)ret;
        /* declassify addend_point to allow using it as a branch point (this is fine because addend_point is not a secret) */
        secp256k1_declassify(ctx, &addend_point, sizeof(addend_point));
        secp256k1_fe_normalize_var(&addend_point.y);
        if (secp256k1_fe_is_odd(&addend_point.y)) {
            secp256k1_scalar_negate(&addend, &addend);
        }

        secp256k1_scalar_add(&a_sum_scalar, &a_sum_scalar, &addend);
        VERIFY_CHECK(!secp256k1_scalar_is_zero(&a_sum_scalar));
    }
    if (secp256k1_scalar_is_zero(&a_sum_scalar)) {
        /* TODO: do we need a special error return code for this case? */
        return 0;
    }
    secp256k1_scalar_get_b32(a_sum, &a_sum_scalar);

    /* Compute input_hash = hash(outpoint_L || (a_sum * G)) */
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &A_sum_gej, &a_sum_scalar);
    secp256k1_ge_set_gej(&A_sum_ge, &A_sum_gej);
    secp256k1_silentpayments_calculate_input_hash(input_hash, outpoint_smallest36, &A_sum_ge);
    secp256k1_silentpayments_recipient_sort(ctx, recipients, n_recipients);
    last_recipient = *recipients[0];
    k = 0;
    for (i = 0; i < n_recipients; i++) {
        if ((secp256k1_ec_pubkey_cmp(ctx, &last_recipient.scan_pubkey, &recipients[i]->scan_pubkey) != 0) || (i == 0)) {
            /* if we are on a different scan pubkey, its time to recreate the the shared secret and reset k to 0 */
            if (!secp256k1_silentpayments_create_shared_secret(ctx, shared_secret, &recipients[i]->scan_pubkey, a_sum, input_hash)) {
                return 0;
            }
            k = 0;
        }
        if (!secp256k1_silentpayments_create_output_pubkey(ctx, &recipients[i]->generated_output, shared_secret, &recipients[i]->spend_pubkey, k)) {
            return 0;
        }
        k++;
        last_recipient = *recipients[i];
    }
    return 1;
}

/* TODO: implement functions for receiver side. */

#endif

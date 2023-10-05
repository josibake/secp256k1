/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_SILENTPAYMENTS_MAIN_H
#define SECP256K1_MODULE_SILENTPAYMENTS_MAIN_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_ecdh.h"
#include "../../../include/secp256k1_silentpayments.h"

/** Sort an array of silent payment recipients. This is used to group recipients by scan pubkey to
 *  ensure the correct values of k are used when creating multiple outputs for a recipient. */
static int secp256k1_silentpayments_recipient_sort_cmp(const void* pk1, const void* pk2, void *ctx) {
    return secp256k1_ec_pubkey_cmp((secp256k1_context *)ctx,
        &(*(const secp256k1_silentpayments_recipient **)pk1)->scan_pubkey,
        &(*(const secp256k1_silentpayments_recipient **)pk2)->scan_pubkey
    );
}

int secp256k1_silentpayments_recipient_sort(const secp256k1_context* ctx, const secp256k1_silentpayments_recipient **recipients, size_t n_recipients) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(recipients != NULL);

    /* Suppress wrong warning (fixed in MSVC 19.33) */
    #if defined(_MSC_VER) && (_MSC_VER < 1933)
    #pragma warning(push)
    #pragma warning(disable: 4090)
    #endif

    secp256k1_hsort(recipients, n_recipients, sizeof(*recipients), secp256k1_silentpayments_recipient_sort_cmp, (void *)ctx);

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
 * hashing function. We don't want to hash the ECDH result yet (it will be
 * hashed later with a counter `k`), so we define a custom function which simply
 * returns the pubkey without hashing.
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

static int secp256k1_silentpayments_create_shared_secret(const secp256k1_context *ctx, unsigned char *shared_secret33, const unsigned char *secret_component, const secp256k1_pubkey *public_component, unsigned char *input_hash) {
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

#endif

/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_SILENTPAYMENTS_MAIN_H
#define SECP256K1_MODULE_SILENTPAYMENTS_MAIN_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_extrakeys.h"
#include "../../../include/secp256k1_silentpayments.h"

/** Sort an array of silent payment recipients. This is used to group recipients by scan pubkey to
 *  ensure the correct values of k are used when creating multiple outputs for a recipient. */
static int secp256k1_silentpayments_recipient_sort_cmp(const void* pk1, const void* pk2, void *ctx) {
    (void)ctx;
    return secp256k1_memcmp_var(
        (*(const secp256k1_silentpayments_recipient **)pk1)->scan_pubkey,
        (*(const secp256k1_silentpayments_recipient **)pk2)->scan_pubkey,
        32
    );
}

static void secp256k1_silentpayments_recipient_sort(const secp256k1_context* ctx, const secp256k1_silentpayments_recipient **recipients, size_t n_recipients) {

    /* Suppress wrong warning (fixed in MSVC 19.33) */
    #if defined(_MSC_VER) && (_MSC_VER < 1933)
    #pragma warning(push)
    #pragma warning(disable: 4090)
    #endif

    secp256k1_hsort(recipients, n_recipients, sizeof(*recipients), secp256k1_silentpayments_recipient_sort_cmp, (void *)ctx);

    #if defined(_MSC_VER) && (_MSC_VER < 1933)
    #pragma warning(pop)
    #endif
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
    size_t len;
    int ret;

    secp256k1_silentpayments_sha256_init_inputs(&hash);
    secp256k1_sha256_write(&hash, outpoint_smallest36, 36);
    ret = secp256k1_eckey_pubkey_serialize(pubkey_sum, pubkey_sum_ser, &len, 1);
    VERIFY_CHECK(ret && len == sizeof(pubkey_sum_ser));
    (void)ret;
    secp256k1_sha256_write(&hash, pubkey_sum_ser, sizeof(pubkey_sum_ser));
    secp256k1_sha256_finalize(&hash, input_hash);
}

static void secp256k1_silentpayments_create_shared_secret(const secp256k1_context *ctx, unsigned char *shared_secret33, const secp256k1_scalar *secret_component, const unsigned char *public_component) {
    secp256k1_fe result, x;

    (void)ctx;

    /* Compute shared_secret = tweaked_secret_component * Public_component */
    secp256k1_fe_set_b32_limit(&x, public_component);
    secp256k1_ecmult_const_xonly(&result, &x, NULL, secret_component, 1);
    /* This can only fail if the shared secret is the point at infinity, which should be
     * impossible at this point, considering we have already validated the public key and
     * the secret key being used
     */
    secp256k1_fe_normalize(&result);
    secp256k1_fe_get_b32(shared_secret33, &result);
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

static void secp256k1_silentpayments_create_t_k(secp256k1_scalar *t_k_scalar, const unsigned char *shared_secret33, uint32_t k) {
    secp256k1_sha256 hash;
    unsigned char hash_ser[32];
    unsigned char k_serialized[4];
    int overflow = 0;

    /* Compute t_k = hash(shared_secret || ser_32(k))  [sha256 with tag "BIP0352/SharedSecret"] */
    secp256k1_silentpayments_sha256_init_sharedsecret(&hash);
    secp256k1_sha256_write(&hash, shared_secret33, 32);
    secp256k1_write_be32(k_serialized, k);
    secp256k1_sha256_write(&hash, k_serialized, sizeof(k_serialized));
    secp256k1_sha256_finalize(&hash, hash_ser);
    secp256k1_scalar_set_b32(t_k_scalar, hash_ser, &overflow);
    VERIFY_CHECK(!overflow);
    VERIFY_CHECK(!secp256k1_scalar_is_zero(t_k_scalar));
    /* While not technically "secret" data, explicitly clear hash_ser since leaking this would allow an attacker
     * to identify the resulting transaction as a silent payments transaction and potentially link the transaction
     * back to the silent payment address
     */
    secp256k1_memclear(hash_ser, sizeof(hash_ser));
}

static int secp256k1_silentpayments_create_output_pubkey(const secp256k1_context *ctx, secp256k1_xonly_pubkey *P_output_xonly, const unsigned char *shared_secret33, const secp256k1_pubkey *recipient_spend_pubkey, uint32_t k) {
    secp256k1_ge P_output_ge;
    secp256k1_scalar t_k_scalar;
    int ret;

    /* Calculate and return P_output_xonly = B_spend + t_k * G
     * This will fail if B_spend is the point at infinity or if
     * B_spend + t_k*G is the point at infinity.
     */
    secp256k1_silentpayments_create_t_k(&t_k_scalar, shared_secret33, k);
    if (!secp256k1_pubkey_load(ctx, &P_output_ge, recipient_spend_pubkey)) {
        secp256k1_scalar_clear(&t_k_scalar);
        return 0;
    }
    ret = secp256k1_eckey_pubkey_tweak_add(&P_output_ge, &t_k_scalar);
    /* tweak add only fails if t_k_scalar is equal to the dlog of P_output_ge, but t_k_scalar is the output of a collision resistant hash function. */
    /* TODO: consider declassify ret */
    /* TODO: but we don't want to imply this can never happen */
    VERIFY_CHECK(ret);
#ifndef VERIFY
    (void) ret;
#endif
    secp256k1_xonly_pubkey_save(P_output_xonly, &P_output_ge);

    /* While not technically "secret" data, explicitly clear t_k since leaking this would allow an attacker
     * to identify the resulting transaction as a silent payments transaction and potentially link the transaction
     * back to the silent payment address
     */
    secp256k1_scalar_clear(&t_k_scalar);
    return 1;
}

int secp256k1_silentpayments_sender_create_outputs(
    const secp256k1_context *ctx,
    secp256k1_xonly_pubkey **generated_outputs,
    const secp256k1_silentpayments_recipient **recipients,
    size_t n_recipients,
    const unsigned char *outpoint_smallest36,
    const secp256k1_keypair * const *taproot_seckeys,
    size_t n_taproot_seckeys,
    const unsigned char * const *plain_seckeys,
    size_t n_plain_seckeys
) {
    size_t i, k;
    secp256k1_scalar a_sum_scalar, addend, input_hash_scalar;
    secp256k1_ge A_sum_ge;
    secp256k1_gej A_sum_gej;
    unsigned char input_hash[32];
    unsigned char shared_secret[32];
    secp256k1_silentpayments_recipient last_recipient;
    int overflow = 0;
    int ret;

    /* Sanity check inputs. */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(generated_outputs != NULL);
    ARG_CHECK(recipients != NULL);
    ARG_CHECK(n_recipients > 0);
    ARG_CHECK((plain_seckeys != NULL) || (taproot_seckeys != NULL));
    if (taproot_seckeys != NULL) {
        ARG_CHECK(n_taproot_seckeys > 0);
    } else {
        ARG_CHECK(n_taproot_seckeys == 0);
    }
    if (plain_seckeys != NULL) {
        ARG_CHECK(n_plain_seckeys > 0);
    } else {
        ARG_CHECK(n_plain_seckeys == 0);
    }
    ARG_CHECK(outpoint_smallest36 != NULL);
    /* ensure the index field is set correctly */
    for (i = 0; i < n_recipients; i++) {
        ARG_CHECK(recipients[i]->index == i);
    }

    /* Compute input private keys sum: a_sum = a_1 + a_2 + ... + a_n */
    a_sum_scalar = secp256k1_scalar_zero;
    for (i = 0; i < n_plain_seckeys; i++) {
        ret = secp256k1_scalar_set_b32_seckey(&addend, plain_seckeys[i]);
        /* TODO: We can declassify return value, because scalar set only fails if the seckey is invalid */
        secp256k1_declassify(ctx, &ret, sizeof(ret));
        if (!ret) {
            /* TODO: clear a_sum_scalar */
            return 0;
        }
        secp256k1_scalar_add(&a_sum_scalar, &a_sum_scalar, &addend);
    }
    /* private keys used for taproot outputs have to be negated if they resulted in an odd point */
    for (i = 0; i < n_taproot_seckeys; i++) {
        secp256k1_ge addend_point;
        ret = secp256k1_keypair_load(ctx, &addend, &addend_point, taproot_seckeys[i]);
        /* TODO: we can declassify return value */
        if (!ret) {
            /* TODO: clear a_sum_scalar */
            return 0;
        }
        secp256k1_declassify(ctx, &ret, sizeof(ret));
        if (secp256k1_fe_is_odd(&addend_point.y)) {
            secp256k1_scalar_negate(&addend, &addend);
        }
        secp256k1_scalar_add(&a_sum_scalar, &a_sum_scalar, &addend);
    }
    /* If there are any failures in loading/summing up the secret keys, fail early */
    /* TODO: can we declassify this? */
    /* Yes: We assume the adversary has access to a_sum_scalar*G */
    ret = secp256k1_scalar_is_zero(&a_sum_scalar);
    secp256k1_declassify(ctx, &ret, sizeof(ret));
    if (ret) {
        return 0;
    }
    /* Compute input_hash = hash(outpoint_L || (a_sum * G)) */
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &A_sum_gej, &a_sum_scalar);
    secp256k1_ge_set_gej(&A_sum_ge, &A_sum_gej);
    /* TODO: comment */
    secp256k1_declassify(ctx, &A_sum_ge, sizeof(A_sum_ge));

    /* Calculate the input hash and tweak a_sum, i.e., a_sum_tweaked = a_sum * input_hash */
    secp256k1_silentpayments_calculate_input_hash(input_hash, outpoint_smallest36, &A_sum_ge);
    secp256k1_scalar_set_b32(&input_hash_scalar, input_hash, &overflow);
    /* This should fail if input hash is greater than the curver order, but this is stastically improbable so
     * we only do a verify_check here.
     */
    VERIFY_CHECK(!overflow);
    secp256k1_scalar_mul(&a_sum_scalar, &a_sum_scalar, &input_hash_scalar);
    /* _recipient_sort sorts the array of recipients in place by their scan public keys (lexicographically).
     * This ensures that all recipients with the same scan public key are grouped together, as specified in BIP0352.
     *
     * More specifically, this ensures `k` is incremented from 0 to the number of requested outputs for each recipient group,
     * where a recipient group is all addresses with the same scan public key.
     */
    secp256k1_silentpayments_recipient_sort(ctx, recipients, n_recipients);
    last_recipient = *recipients[0];
    k = 0;
    for (i = 0; i < n_recipients; i++) {
        if ((i == 0) || (secp256k1_memcmp_var(&last_recipient.scan_pubkey, recipients[i]->scan_pubkey, 32) != 0)) {
            /* If we are on a different scan pubkey, its time to recreate the the shared secret and reset k to 0.
             * It's very unlikely the scan public key is invalid by this point, since this means the caller would
             * have created the _silentpayments_recipient object incorrectly, but just to be sure we still check that
             * the public key is valid.
             */
            secp256k1_silentpayments_create_shared_secret(ctx, shared_secret, &a_sum_scalar, recipients[i]->scan_pubkey);
            k = 0;
        }
        if (!secp256k1_silentpayments_create_output_pubkey(ctx, generated_outputs[recipients[i]->index], shared_secret, &recipients[i]->spend_pubkey, k)) {
            /* TODO: clean up */
            return 0;
        }
        k++;
        last_recipient = *recipients[i];
    }
    /* Explicitly clear variables containing secret data */
    secp256k1_scalar_clear(&addend);
    secp256k1_scalar_clear(&a_sum_scalar);

    /* While technically not "secret data," explicitly clear the shared secret since leaking this
     * could result in a third party being able to identify the transaction as a silent payments transaction
     * and potentially link the transaction back to a silent payment address
     */
    secp256k1_memclear(&shared_secret, sizeof(shared_secret));
    return 1;
}

/** Set hash state to the BIP340 tagged hash midstate for "BIP0352/Label". */
static void secp256k1_silentpayments_sha256_init_label(secp256k1_sha256* hash) {
    secp256k1_sha256_initialize(hash);
    hash->s[0] = 0x26b95d63ul;
    hash->s[1] = 0x8bf1b740ul;
    hash->s[2] = 0x10a5986ful;
    hash->s[3] = 0x06a387a5ul;
    hash->s[4] = 0x2d1c1c30ul;
    hash->s[5] = 0xd035951aul;
    hash->s[6] = 0x2d7f0f96ul;
    hash->s[7] = 0x29e3e0dbul;

    hash->bytes = 64;
}

int secp256k1_silentpayments_recipient_create_label(const secp256k1_context *ctx, secp256k1_pubkey *label, unsigned char *label_tweak32, const unsigned char *recipient_scan_key, uint32_t m) {
    secp256k1_sha256 hash;
    unsigned char m_serialized[4];

    /* Sanity check inputs. */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(label != NULL);
    ARG_CHECK(label_tweak32 != NULL);
    ARG_CHECK(recipient_scan_key != NULL);

    /* Compute label_tweak = hash(ser_256(b_scan) || ser_32(m))  [sha256 with tag "BIP0352/Label"] */
    secp256k1_silentpayments_sha256_init_label(&hash);
    secp256k1_sha256_write(&hash, recipient_scan_key, 32);
    secp256k1_write_be32(m_serialized, m);
    secp256k1_sha256_write(&hash, m_serialized, sizeof(m_serialized));
    secp256k1_sha256_finalize(&hash, label_tweak32);

    /* Compute label = label_tweak * G */
    return secp256k1_ec_pubkey_create(ctx, label, label_tweak32);
}

int secp256k1_silentpayments_recipient_create_labelled_spend_pubkey(const secp256k1_context *ctx, secp256k1_pubkey *labelled_spend_pubkey, const secp256k1_pubkey *recipient_spend_pubkey, const secp256k1_pubkey *label) {
    secp256k1_ge B_m, label_addend;
    secp256k1_gej result_gej;
    secp256k1_ge result_ge;
    int ret;

    /* Sanity check inputs. */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(labelled_spend_pubkey != NULL);
    ARG_CHECK(recipient_spend_pubkey != NULL);
    ARG_CHECK(label != NULL);

    /* Calculate B_m = B_spend + label
     * If either the label or spend public key is an invalid public key,
     * return early
     */
    ret = secp256k1_pubkey_load(ctx, &B_m, recipient_spend_pubkey);
    ret &= secp256k1_pubkey_load(ctx, &label_addend, label);
    if (!ret) {
        return ret;
    }
    secp256k1_gej_set_ge(&result_gej, &B_m);
    secp256k1_gej_add_ge_var(&result_gej, &result_gej, &label_addend, NULL);
    if (secp256k1_gej_is_infinity(&result_gej)) {
        return 0;
    }

    secp256k1_ge_set_gej(&result_ge, &result_gej);
    secp256k1_pubkey_save(labelled_spend_pubkey, &result_ge);

    return 1;
}

int secp256k1_silentpayments_recipient_public_data_create(
    const secp256k1_context *ctx,
    secp256k1_silentpayments_recipient_public_data *public_data,
    const unsigned char *outpoint_smallest36,
    const secp256k1_xonly_pubkey * const *xonly_pubkeys,
    size_t n_xonly_pubkeys,
    const secp256k1_pubkey * const *plain_pubkeys,
    size_t n_plain_pubkeys
) {
    size_t i;
    size_t pubkeylen = 32;
    secp256k1_ge A_sum_ge, addend;
    secp256k1_gej A_sum_gej;
    secp256k1_scalar input_hash_scalar;
    unsigned char input_hash_local[32];
    int overflow = 0;
    int ret = 1;

    /* Sanity check inputs */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(public_data != NULL);
    ARG_CHECK(outpoint_smallest36 != NULL);
    ARG_CHECK((plain_pubkeys != NULL) || (xonly_pubkeys != NULL));
    if (xonly_pubkeys != NULL) {
        ARG_CHECK(n_xonly_pubkeys > 0);
    } else {
        ARG_CHECK(n_xonly_pubkeys == 0);
    }
    if (plain_pubkeys != NULL) {
        ARG_CHECK(n_plain_pubkeys > 0);
    } else {
        ARG_CHECK(n_plain_pubkeys == 0);
    }
    secp256k1_memclear(input_hash_local, 32);

    /* Compute input public keys sum: A_sum = A_1 + A_2 + ... + A_n */
    secp256k1_gej_set_infinity(&A_sum_gej);
    for (i = 0; i < n_plain_pubkeys; i++) {
        ret &= secp256k1_pubkey_load(ctx, &addend, plain_pubkeys[i]);
        secp256k1_gej_add_ge_var(&A_sum_gej, &A_sum_gej, &addend, NULL);
    }
    for (i = 0; i < n_xonly_pubkeys; i++) {
        ret &= secp256k1_xonly_pubkey_load(ctx, &addend, xonly_pubkeys[i]);
        secp256k1_gej_add_ge_var(&A_sum_gej, &A_sum_gej, &addend, NULL);
    }
    /* Since an attacker can maliciously craft transactions where the public keys sum to zero, fail early here
     * to avoid making the caller do extra work, e.g., when building an index or scanning many malicious transactions
     *
     * This will also fail if any of the provided input public keys are malformed.
     */
    if (!ret || secp256k1_gej_is_infinity(&A_sum_gej)) {
        return 0;
    }
    /* Compute input_hash = hash(outpoint_L || A_sum) */
    secp256k1_ge_set_gej(&A_sum_ge, &A_sum_gej);
    secp256k1_silentpayments_calculate_input_hash(input_hash_local, outpoint_smallest36, &A_sum_ge);
    /* Convert input_hash to a scalar to ensure the value is less than the curve order.
     *
     * This can only fail if the output of the hash function is greater than the curve order, which
     * is statistically improbable.
     *
     * TODO: BIP0352 is currently underspecified with respect to input_hash, update to specify how to
     * handle the conversion of input_hash to a scalar.*/
    secp256k1_scalar_set_b32(&input_hash_scalar, input_hash_local, &overflow);
    VERIFY_CHECK(!overflow);
    /* serialize the public_data struct */
    memcpy(&public_data->data[0], secp256k1_silentpayments_public_data_magic, 4);
    public_data->data[4] = 0;
    secp256k1_fe_get_b32(&public_data->data[5], &A_sum_ge.x);
    memcpy(&public_data->data[5 + pubkeylen], input_hash_local, 32);
    return 1;
}

static int secp256k1_silentpayments_recipient_public_data_load_pubkey(const secp256k1_context* ctx, secp256k1_ge *ge, const secp256k1_silentpayments_recipient_public_data *public_data) {
    secp256k1_xonly_pubkey xonly;
    int ret;
    ARG_CHECK(secp256k1_memcmp_var(&public_data->data[0], secp256k1_silentpayments_public_data_magic, 4) == 0);
    ret = secp256k1_xonly_pubkey_parse(ctx, &xonly, &public_data->data[5]);
    ret &= secp256k1_xonly_pubkey_load(ctx, ge, &xonly);
    return ret;
}

static int secp256k1_silentpayments_recipient_public_data_load_input_hash(const secp256k1_context* ctx, secp256k1_scalar *input_hash_scalar, const secp256k1_silentpayments_recipient_public_data *public_data) {
    ARG_CHECK(secp256k1_memcmp_var(&public_data->data[0], secp256k1_silentpayments_public_data_magic, 4) == 0);
    secp256k1_scalar_set_b32(input_hash_scalar, &public_data->data[5 + 32], NULL);
    return 1;
}

int secp256k1_silentpayments_recipient_public_data_serialize(const secp256k1_context *ctx, unsigned char *output33, const secp256k1_silentpayments_recipient_public_data *public_data) {
    secp256k1_ge ge;
    secp256k1_scalar input_hash_scalar;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output33 != NULL);
    ARG_CHECK(public_data != NULL);
    ARG_CHECK(secp256k1_memcmp_var(&public_data->data[0], secp256k1_silentpayments_public_data_magic, 4) == 0);
    /* Only allow public_data to be serialized if it has the hash and the summed public key
     * This helps protect against accidentally serialiazing just a the summed public key A
     */
    ARG_CHECK(public_data->data[4] == 0);
    ret &= secp256k1_silentpayments_recipient_public_data_load_pubkey(ctx, &ge, public_data);
    ret &= secp256k1_silentpayments_recipient_public_data_load_input_hash(ctx, &input_hash_scalar, public_data);
    ret &= secp256k1_eckey_pubkey_tweak_mul(&ge, &input_hash_scalar);
    secp256k1_fe_get_b32(output33, &ge.x);
    return ret;
}

int secp256k1_silentpayments_recipient_public_data_parse(const secp256k1_context *ctx, secp256k1_silentpayments_recipient_public_data *public_data, const unsigned char *input33) {

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(public_data != NULL);
    ARG_CHECK(input33 != NULL);
    /* A serialized public data will always have have the input_hash multiplied in, so we set combined = true.
     * Additionally, we zero out the 32 bytes where the input_hash would be
     */
    memcpy(&public_data->data[0], secp256k1_silentpayments_public_data_magic, 4);
    public_data->data[4] = 1;
    memcpy(&public_data->data[5], input33, 32);
    memset(&public_data->data[5 + 32], 0, 32);
    return 1;
}

int secp256k1_silentpayments_recipient_scan_outputs(
    const secp256k1_context *ctx,
    secp256k1_silentpayments_found_output **found_outputs, size_t *n_found_outputs,
    const secp256k1_xonly_pubkey * const *tx_outputs, size_t n_tx_outputs,
    const unsigned char *recipient_scan_key,
    const secp256k1_silentpayments_recipient_public_data *public_data,
    const secp256k1_pubkey *recipient_spend_pubkey,
    const secp256k1_silentpayments_label_lookup label_lookup,
    const void *label_context
) {
    secp256k1_scalar t_k_scalar, rsk_scalar;
    secp256k1_ge label_ge, recipient_spend_pubkey_ge;
    secp256k1_xonly_pubkey P_output_xonly;
    unsigned char shared_secret[32];
    const unsigned char *label_tweak = NULL;
    size_t i, k, n_found, found_idx;
    int found, combined;
    int ret = 1;

    /* Sanity check inputs */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(found_outputs != NULL);
    ARG_CHECK(n_found_outputs != NULL);
    ARG_CHECK(tx_outputs != NULL);
    ARG_CHECK(n_tx_outputs > 0);
    ARG_CHECK(recipient_scan_key != NULL);
    ARG_CHECK(public_data != NULL);
    ARG_CHECK(recipient_spend_pubkey != NULL);
    /* Passing a context without a lookup function is non-sensical */
    if (label_context != NULL) {
        ARG_CHECK(label_lookup != NULL);
    }
    /* Recall: a scan key isnt really "secret" data in that leaking the scan key will only leak privacy.
     *
     * However, if there is something wrong with the recipient scan key, recipient spend pubkey, or the public data,
     * we fail early and make sure to clear the scan key from memory. */
    ret = secp256k1_scalar_set_b32_seckey(&rsk_scalar, recipient_scan_key);
    secp256k1_declassify(ctx, &ret, sizeof(ret));
    if (!ret) {
        secp256k1_scalar_clear(&rsk_scalar);
        return 0;
    }
    combined = (int)public_data->data[4];
    if (!combined) {
        secp256k1_scalar input_hash_scalar;
        ret &= secp256k1_silentpayments_recipient_public_data_load_input_hash(ctx, &input_hash_scalar, public_data);
        secp256k1_scalar_mul(&rsk_scalar, &rsk_scalar, &input_hash_scalar);
    }
    ret &= secp256k1_pubkey_load(ctx, &recipient_spend_pubkey_ge, recipient_spend_pubkey);
    if (!ret) {
        secp256k1_scalar_clear(&rsk_scalar);
        return 0;
    }
    secp256k1_silentpayments_create_shared_secret(ctx, shared_secret, &rsk_scalar, &public_data->data[5]);

    found_idx = 0;
    n_found = 0;
    k = 0;
    while (1) {
        secp256k1_ge P_output_ge = recipient_spend_pubkey_ge;
        /* Calculate t_k = hash(shared_secret || ser_32(k)) */
        secp256k1_silentpayments_create_t_k(&t_k_scalar, shared_secret, k);

        /* Calculate P_output = B_spend + t_k * G
         * This can fail if t_k is the negation of B_spend, but this is statistically
         * improbable as t_k is the output of a hash function. */
        ret = secp256k1_eckey_pubkey_tweak_add(&P_output_ge, &t_k_scalar);
        VERIFY_CHECK(ret);
        found = 0;
        secp256k1_xonly_pubkey_save(&P_output_xonly, &P_output_ge);
        for (i = 0; i < n_tx_outputs; i++) {
            if (secp256k1_xonly_pubkey_cmp(ctx, &P_output_xonly, tx_outputs[i]) == 0) {
                label_tweak = NULL;
                found = 1;
                found_idx = i;
                break;
            }

            /* If not found, proceed to check for labels (if the labels cache is present) */
            if (label_lookup != NULL) {
                secp256k1_ge P_output_negated_ge, tx_output_ge;
                secp256k1_gej tx_output_gej, label_gej;
                unsigned char label33[33];
                size_t len;

                secp256k1_xonly_pubkey_load(ctx, &tx_output_ge, tx_outputs[i]);
                secp256k1_gej_set_ge(&tx_output_gej, &tx_output_ge);
                secp256k1_ge_neg(&P_output_negated_ge, &P_output_ge);
                /* Negate the generated output and calculate first scan label candidate:
                 * label1 = tx_output - P_output */
                secp256k1_gej_add_ge_var(&label_gej, &tx_output_gej, &P_output_negated_ge, NULL);
                secp256k1_ge_set_gej(&label_ge, &label_gej);
                ret = secp256k1_eckey_pubkey_serialize(&label_ge, label33, &len, 1);
                /* serialize must succeed because the point was just loaded */
                VERIFY_CHECK(ret && len == 33);
                label_tweak = label_lookup(label33, label_context);
                if (label_tweak != NULL) {
                    found = 1;
                    found_idx = i;
                    break;
                }

                secp256k1_gej_neg(&label_gej, &tx_output_gej);
                /* If not found, negate the tx_output and calculate second scan label candidate:
                 * label2 = -tx_output - P_output */
                secp256k1_gej_add_ge_var(&label_gej, &label_gej, &P_output_negated_ge, NULL);
                secp256k1_ge_set_gej(&label_ge, &label_gej);
                ret = secp256k1_eckey_pubkey_serialize(&label_ge, label33, &len, 1);
                /* serialize must succeed because the point was just loaded */
                VERIFY_CHECK(ret && len == 33);
                label_tweak = label_lookup(label33, label_context);
                if (label_tweak != NULL) {
                    found = 1;
                    found_idx = i;
                    break;
                }
            }
        }
        if (found) {
            found_outputs[n_found]->output = *tx_outputs[found_idx];
            secp256k1_scalar_get_b32(found_outputs[n_found]->tweak, &t_k_scalar);
            if (label_tweak != NULL) {
                found_outputs[n_found]->found_with_label = 1;
                /* This is extremely unlikely to fail in that it can only really fail if label_tweak
                 * is the negation of the shared secret tweak. But since both tweak and label_tweak are
                 * created by hashing data, practically speaking this would only happen if an attacker
                 * tricked us into using a particular label_tweak (deviating from the protocol).
                 */
                ret = secp256k1_ec_seckey_tweak_add(ctx, found_outputs[n_found]->tweak, label_tweak);
                VERIFY_CHECK(ret);
                secp256k1_pubkey_save(&found_outputs[n_found]->label, &label_ge);
            } else {
                found_outputs[n_found]->found_with_label = 0;
                /* Set the label public key with an invalid public key value */
                secp256k1_memclear(&found_outputs[n_found]->label, sizeof(secp256k1_pubkey));
            }
            /* Set everything for the next round of scanning */
            label_tweak = NULL;
            n_found++;
            k++;
        } else {
            break;
        }
    }
    *n_found_outputs = n_found;
    /* Explicitly clear secrets. Recall that the scan key is not quite "secret" in that leaking the scan key
     * results in a loss of privacy, not a loss of funds
     */
    secp256k1_scalar_clear(&rsk_scalar);
    /* Explicitly clear the shared secret. While this isn't technically "secret data," any third party
     * with access to the shared secret could potentially identify and link the transaction back to the
     * recipient address
     */
    secp256k1_scalar_clear(&t_k_scalar);
    secp256k1_memclear(shared_secret, sizeof(shared_secret));
    return ret;
}

int secp256k1_silentpayments_recipient_create_shared_secret(const secp256k1_context *ctx, unsigned char *shared_secret33, const unsigned char *recipient_scan_key, const secp256k1_silentpayments_recipient_public_data *public_data) {
    secp256k1_scalar rsk;
    int ret = 1;
    /* Sanity check inputs */
    ARG_CHECK(shared_secret33 != NULL);
    ARG_CHECK(recipient_scan_key != NULL);
    ARG_CHECK(public_data != NULL);
    ARG_CHECK(public_data->data[4] == 1);
    /* TODO: do we need a _cmov operation here to avoid leaking information about the scan key?
     * Recall: a scan key is not really "secret" data, its functionally the same as an xpub
     */
    ret &= secp256k1_scalar_set_b32_seckey(&rsk, recipient_scan_key);
    /* If there are any issues with the recipient scan key or public data, return early */
    if (!ret) {
        return 0;
    }
    secp256k1_silentpayments_create_shared_secret(ctx, shared_secret33, &rsk, &public_data->data[5]);

    /* Explicitly clear secrets */
    secp256k1_scalar_clear(&rsk);
    return ret;
}

int secp256k1_silentpayments_recipient_create_output_pubkey(const secp256k1_context *ctx, secp256k1_xonly_pubkey *P_output_xonly, const unsigned char *shared_secret33, const secp256k1_pubkey *recipient_spend_pubkey, uint32_t k)
{
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(P_output_xonly != NULL);
    ARG_CHECK(shared_secret33 != NULL);
    ARG_CHECK(recipient_spend_pubkey != NULL);
    return secp256k1_silentpayments_create_output_pubkey(ctx, P_output_xonly, shared_secret33, recipient_spend_pubkey, k);
}


#endif

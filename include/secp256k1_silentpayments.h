#ifndef SECP256K1_SILENTPAYMENTS_H
#define SECP256K1_SILENTPAYMENTS_H

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"

#ifdef __cplusplus
extern "C" {
#endif

/* This module provides an implementation for Silent Payments, as specified in BIP352.
 * This particularly involves the creation of input tweak data by summing up private
 * or public keys and the derivation of a shared secret using Elliptic Curve Diffie-Hellman.
 * Combined are either:
 *   - spender's private keys and receiver's public key (a * B, sender side)
 *   - spender's public keys and receiver's private key (A * b, receiver side)
 * With this result, the necessary key material for ultimately creating/scanning
 * or spending Silent Payment outputs can be determined.
 *
 * Note that this module is _not_ a full implementation of BIP352, as it
 * inherently doesn't deal with higher-level concepts like addresses, output
 * script types or transactions. The intent is to provide a module for abstracting away
 * the elliptic-curve operations required for the protocol. For any wallet software already
 * using libsecp256k1, this API should provide all the functions needed for a Silent Payments
 * implementation without requiring any further elliptic-curve operations from the wallet.
 */

/* This struct serves as an In param for passing the silent payment address data.
 * The index field is for when more than one address is being sent to in a transaction. Index is
 * set based on the original ordering of the addresses and used to return the generated outputs
 * matching the original ordering. When more than one recipient is used the recipient array
 * will be sorted in place as part of generating the outputs, but the generated outputs will be
 * outputs will be returned original ordering specified by the index to ensure the caller is able
 * to match up the generated outputs to the correct silent payment address (e.g. to be able to
 * assign the correct amounts to the correct generatetd outputs in the final transaction).
 */
typedef struct {
    secp256k1_pubkey scan_pubkey;
    secp256k1_pubkey spend_pubkey;
    size_t index;
} secp256k1_silentpayments_recipient;

/** Create Silent Payment outputs for recipient(s).
 *
 * Given a list of n private keys a_1...a_n (one for each silent payment
 * eligible input to spend), a serialized outpoint, and a list of recipients,
 * create the taproot outputs:
 *
 * a_sum = a_1 + a_2 + ... + a_n
 * input_hash = hash(outpoint_smallest || (a_sum * G))
 * taproot_output = B_spend + hash(a_sum * input_hash * B_scan || k) * G
 *
 * If necessary, the private keys are negated to enforce the right y-parity.
 * For that reason, the private keys have to be passed in via two different parameter
 * pairs, depending on whether they seckeys correspond to x-only outputs or not.
 *
 *  Returns: 1 if shared secret creation was successful. 0 if an error occured.
 *   Args:                 ctx: pointer to a context object
 *    Out:   generated_outputs: pointer to an array of pointers to xonly pubkeys, one per recipient.
 *                              The order of outputs here matches the original ordering of the
 *                              recipients array.
 *     In:          recipients: pointer to an array of pointers to silent payment recipients,
 *                              where each recipient is a scan public key, a spend public key, and
 *                              an index indicating its position in the original ordering.
 *                              The recipient array will be sorted in place, but generated outputs
 *                              are saved in the `generated_outputs` array to match the ordering
 *                              from the index field. This ensures the caller is able to match the
 *                              generated outputs to the correct silent payment addresses. The same
 *                              recipient can be passed multiple times to create multiple
 *                              outputs for the same recipient.
 *                n_recipients: the number of recipients. This is equal to the total
 *                              number of outputs to be generated as each recipient may passed
 *                              multiple times to generate multiple outputs for the same recipient
 *         outpoint_smallest36: serialized smallest outpoint
 *             taproot_seckeys: pointer to an array of pointers to 32-byte private keys
 *                              of taproot inputs (can be NULL if no private keys of
 *                              taproot inputs are used)
 *           n_taproot_seckeys: the number of sender's taproot input private keys
 *               plain_seckeys: pointer to an array of pointers to 32-byte private keys
 *                              of non-taproot inputs (can be NULL if no private keys of
 *                              non-taproot inputs are used)
 *             n_plain_seckeys: the number of sender's non-taproot input private keys
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_silentpayments_sender_create_outputs(
    const secp256k1_context *ctx,
    secp256k1_xonly_pubkey **generated_outputs,
    const secp256k1_silentpayments_recipient **recipients,
    size_t n_recipients,
    const unsigned char *outpoint_smallest36,
    const secp256k1_keypair * const *taproot_seckeys,
    size_t n_taproot_seckeys,
    const unsigned char * const *plain_seckeys,
    size_t n_plain_seckeys
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(5);

/** Create Silent Payment label tweak and label.
 *
 *  Given a recipient's scan private key b_scan and a label integer m, calculate
 *  the corresponding label tweak and label:
 *
 *  label_tweak = hash(b_scan || m)
 *  label = label_tweak * G
 *
 *  Returns: 1 if label tweak and label creation was successful. 0 if an error occured.
 *  Args:                  ctx: pointer to a context object
 *  Out:           label_tweak: pointer to the resulting label tweak
 *   In:  receiver_scan_seckey: pointer to the receiver's scan private key
 *                           m: label integer (0 is used for change outputs)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_silentpayments_recipient_create_label_tweak(
    const secp256k1_context *ctx,
    secp256k1_pubkey *label,
    unsigned char *label_tweak32,
    const unsigned char *receiver_scan_seckey,
    unsigned int m
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Create Silent Payment labelled spend public key.
 *
 *  Given a recipient's spend public key B_spend and a label, calculate
 *  the corresponding serialized labelled spend public key:
 *
 *  B_m = B_spend + label
 *
 *  The result is used by the recipient to create a Silent Payment address, consisting
 *  of the serialized and concatenated scan public key and (labelled) spend public key each.
 *
 *  Returns: 1 if labelled spend public key creation was successful. 0 if an error occured.
 *  Args:                  ctx: pointer to a context object
 *  Out: l_addr_spend_pubkey33: pointer to the resulting labelled spend public key
 *   In: receiver_spend_pubkey: pointer to the receiver's spend pubkey
 *                       label: pointer to the the receiver's label
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_silentpayments_recipient_create_labelled_spend_pubkey(
    const secp256k1_context *ctx,
    secp256k1_pubkey *labeled_spend_pubkey,
    const secp256k1_pubkey *receiver_spend_pubkey,
    const secp256k1_pubkey *label
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_SILENTPAYMENTS_H */

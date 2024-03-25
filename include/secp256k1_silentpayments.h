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
 * The index field is for when more than address is being sent to in a transaction. Index is
 * set based on the original ordering of the addresses and used to return the generated outputs
 * matching the original ordering. This is necessary because when more than one recipient is used,
 * the array will be sorted in place as part of generating the outputs. Order of the generated
 * outputs matches the original ordering to ensure the caller is able to match up the generated
 * outputs to the correct recpient (e.g. to be able to assign the correct amounts to the correct
 * outputs in the final transaction).
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
 * pairs, depending on whether they were used for creating taproot outputs or not.
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
 *                              recipient can be passed multiple times to create multiple taproot
 *                              outputs for the same recipient.
 *                n_recipients: the number of recipients. This is not necessarily equal to the total
 *                              number of outputs to be generated as each recipient may request more
 *                              than one output be generated
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

/** Compute Silent Payment public data from input public keys and transaction inputs.
 *
 * Given a list of n public keys A_1...A_n (one for each silent payment
 * eligible input to spend) and a serialized outpoint_smallest, compute
 * the corresponding input public tweak data:
 *
 * A_sum = A_1 + A_2 + ... + A_n
 * input_hash = hash(outpoint_lowest || A_sum)
 *
 * The public keys have to be passed in via two different parameter pairs,
 * one for regular and one for x-only public keys, in order to avoid the need
 * of users converting to a common pubkey format before calling this function.
 * The resulting data is can be used for scanning on the recipient side, or stored
 * in an index for late use (e.g. wallet rescanning, vending data to light clients).
 *
 * If calling this function for scanning, the reciever must provide an output param
 * for the `input_hash`. If calling this function for simply aggregating the inputs
 * for later use, the caller should pass NULL for `input_hash` to have the `input_hash` scalar
 * multipled in with the return `A_sum` pubkey.
 *
 *  Returns: 1 if tweak data creation was successful. 0 if an error occured.
 *  Args:                  ctx: pointer to a context object
 *  Out:                 A_sum: pointer to the resulting public keys sum
 *                  input_hash: pointer to the resulting 32-byte input hash. If null, input_hash
 *                              is included with A_sum, i.e. A_sum_tweaked = A_sum * input_hash
 *  In:          plain_pubkeys: pointer to an array of pointers to non-taproot
 *                              public keys (can be NULL if no non-taproot inputs are used)
 *             n_plain_pubkeys: the number of non-taproot input public keys
 *               xonly_pubkeys: pointer to an array of pointers to taproot x-only
 *                              public keys (can be NULL if no taproot inputs are used)
 *             n_xonly_pubkeys: the number of taproot input public keys
 *         outpoint_smallest36: serialized smallest outpoint
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_silentpayments_recipient_compute_public_data(
    const secp256k1_context *ctx,
    secp256k1_pubkey *A_sum,
    unsigned char *input_hash,
    const unsigned char *outpoint_smallest36,
    const secp256k1_xonly_pubkey * const *xonly_pubkeys,
    size_t n_xonly_pubkeys,
    const secp256k1_pubkey * const *plain_pubkeys,
    size_t n_plain_pubkeys
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(4);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_SILENTPAYMENTS_H */

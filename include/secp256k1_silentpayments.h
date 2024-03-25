#ifndef SECP256K1_SILENTPAYMENTS_H
#define SECP256K1_SILENTPAYMENTS_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/* This module provides an implementation for Silent Payments, as specified in BIP352.
 * This particularly involves the creation of input tweak data by summing up private
 * or public keys and the derivation of a shared secret using Elliptic Curve Diffie-Hellman.
 * Combined are either:
 *   - spender's private keys and recipient's public key (a * B, sender side)
 *   - spender's public keys and recipient's private key (A * b, recipient side)
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

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_SILENTPAYMENTS_H */

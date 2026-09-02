/***********************************************************************
 * Copyright (c) 2026 The secp256k1 developers                         *
 * AVX-512 IFMA multi-buffer ECDSA verification configuration.         *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECDSA_IFMA_CONFIG_H
#define SECP256K1_ECDSA_IFMA_CONFIG_H

#define SECP256K1_ECDSA_IFMA_LANES 8
#define SECP256K1_ECDSA_IFMA_WINDOWS 33
#define SECP256K1_ECDSA_IFMA_Q_TABLE 8
#define SECP256K1_ECDSA_IFMA_JOINT_TABLE (2 * SECP256K1_ECDSA_IFMA_Q_TABLE * SECP256K1_ECDSA_IFMA_Q_TABLE)
#define SECP256K1_ECDSA_IFMA_TILE 128

#if (defined(__GNUC__) || defined(__clang__)) && defined(__x86_64__) \
    && defined(__AVX512F__) && defined(__AVX512DQ__) \
    && defined(__AVX512IFMA__) && defined(SECP256K1_WIDEMUL_INT128) \
    && !defined(EXHAUSTIVE_TEST_ORDER)
#define SECP256K1_ECDSA_VERIFY_MANY_IFMA 1
#endif

#endif /* SECP256K1_ECDSA_IFMA_CONFIG_H */

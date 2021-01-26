#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** An entropy source for generating a polynomial. */
typedef uint8_t blgc_seed_t[32];

/** A field element. */
typedef uint8_t blgc_fr_t[32];

/** A point on the small and fast curve. */
typedef uint8_t blgc_p1_t[48];

/** A point on the big and slow curve. */
typedef uint8_t blgc_p2_t[96];

/** Generate polynomial from seed. The seed must be an array of m field elements. */
bool blgc_polynomial_from_seed(blgc_fr_t* polynomial, const blgc_seed_t* seed, size_t m);

/** Generate n secret key shares from polynomial with threshold m. */
bool blgc_sk_shares_from_polynomial(blgc_fr_t* sk_shares, const blgc_fr_t* polynomial, size_t m, size_t n);

/** Generate public key share from a polynomial with threshold m. */
bool blgc_pk_share_from_polynomial(blgc_p1_t pk_share, const blgc_fr_t* polynomial, size_t m);

/** Combine secret key from n shares. */
bool blgc_sk_from_shares(blgc_fr_t sk, const blgc_fr_t* sk_shares, size_t n);

/** Combine public key from n shares. */
bool blgc_pk_from_shares(blgc_p1_t pk, const blgc_p1_t* pk_shares, size_t n);

/** Sign message with secret key. */
void blgc_sign(blgc_p2_t sig, const blgc_fr_t sk, const uint8_t* msg, size_t msg_len);

/** Combine signature from m shares. */
bool blgc_sig_from_shares(blgc_p2_t sig, const size_t* idx, const blgc_p2_t* shares, size_t m);

/** Verify signature of message. */
bool blgc_verify(const blgc_p2_t sig, const blgc_p1_t pk, const uint8_t* msg, size_t msg_len);

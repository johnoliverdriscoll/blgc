#include <blgc.h>
#include <blst.h>
#include <string.h>

/** Magic bytes used by the hash_to_curve standard function. */
const static char dst_label[] = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
const static size_t dst_label_len = 43;

/** A field element of value zero. */
const static uint64_t zero_fr_uint64[] = { 0llu, 0llu, 0llu, 0llu };

/** A field element of value one. */
const static uint64_t one_fr_uint64[] = { 1llu, 0llu, 0llu, 0llu };

/** A point element of value zero. */
const static uint64_t zero_fp_uint64[] = { 0llu, 0llu, 0llu, 0llu, 0llu, 0llu };

/** A point element of value one. */
const static uint64_t one_fp_uint64[] = { 1llu, 0llu, 0llu, 0llu, 0llu, 0llu };

/** Returns true if polynomial is valid. */
static bool is_polynomial_valid(const blgc_fr_t* polynomial, size_t m) {
  if (m < 2) {
    return false;
  }
  // As long as the last element is non-zero, the polynomial is valid.
  bool is_zero = true;
  for (int i = 0; i < sizeof(blgc_fr_t); i++) {
    if (polynomial[m - 1][i]) {
      is_zero = false;
      break;
    }
  }
  return !is_zero;
}

/** Get the value of a point in the polynomial. */
static void polynomial_value(blst_fr* value_fr, const blgc_fr_t* polynomial, size_t m, uint32_t point) {
  // value = 0;
  blst_fr pow_fr;
  blst_fr_from_uint64(value_fr, zero_fr_uint64);
  // pow = 1;
  blst_fr point_fr;
  blst_fr_from_uint64(&pow_fr, one_fr_uint64);
  // Create field element for point.
  uint64_t point_uint64[] = { point, 0llu, 0llu, 0llu };
  blst_fr_from_uint64(&point_fr, point_uint64);
  for (int i = 0; i < m; i++) {
    blst_scalar polyi_scalar;
    blst_fr polyi_fr;
    // Create scalar from polynomial[i].
    blst_scalar_from_bendian(&polyi_scalar, polynomial[i]);
    // Create field element from scalar of polynomial[i].
    blst_fr_from_scalar(&polyi_fr, &polyi_scalar);
    // value += polynomial[i] * pow;
    blst_fr_mul(&polyi_fr, &polyi_fr, &pow_fr);
    blst_fr_add(value_fr, value_fr, &polyi_fr);
    // pow *= point;
    blst_fr_mul(&pow_fr, &pow_fr, &point_fr);
  }
}

bool blgc_polynomial_from_seed(blgc_fr_t* polynomial, const blgc_seed_t* seed, size_t m) {
  if (m < 2) {
    return false;
  }
  for (int i = 0; i < m; i++) {
    // Use the blst keygen function to get a field element for each seed element.
    blst_scalar polyi_scalar;
    blst_keygen(&polyi_scalar, seed[i], sizeof(blgc_seed_t), NULL, 0);
    // Serialize the scalar as a big-endian byte array.
    blst_bendian_from_scalar(polynomial[i], &polyi_scalar);
  }
  return is_polynomial_valid(polynomial, m);
}

bool blgc_sk_shares_from_polynomial(blgc_fr_t* sk_shares, const blgc_fr_t* polynomial, size_t m, size_t n) {
  if (n < m) {
    return false;
  }
  if (!is_polynomial_valid(polynomial, m)) {
    return false;
  }
  for (int i = 0; i < n; i++) {
    // Get the polynomial value for each point.
    blst_fr value_fr;
    polynomial_value(&value_fr, polynomial, m, i + 1);
    // Convert the field element to a scalar type.
    blst_scalar value_scalar;
    blst_scalar_from_fr(&value_scalar, &value_fr);
    // Serialize the scalar as a big-endian byte array.
    blst_bendian_from_scalar(sk_shares[i], &value_scalar);
  }
  return true;
}

bool blgc_pk_share_from_polynomial(blgc_p1_t pk_share, const blgc_fr_t* polynomial, size_t m) {
  if (!is_polynomial_valid(polynomial, m)) {
    return false;
  }
  // Interpret polynomial[0] as big-endian scalar.
  blst_scalar poly0_scalar;
  blst_scalar_from_bendian(&poly0_scalar, polynomial[0]);
  // Treat scalar as a secret key and get its public key.
  blst_p1 pk_share_p1;
  blst_sk_to_pk_in_g1(&pk_share_p1, &poly0_scalar);
  // Compress the point.
  blst_p1_compress(pk_share, &pk_share_p1);
  return true;
}

bool blgc_sk_from_shares(blgc_fr_t sk, const blgc_fr_t* sk_shares, size_t n) {
  if (n < 2) {
    return false;
  }
  // sk = 0;
  blst_fr sk_fr;
  blst_fr_from_uint64(&sk_fr, zero_fr_uint64);
  for (int i = 0; i < n; i++) {
    // Interpret sk_shares[i] as big-endian scalar.
    blst_scalar sharei_scalar;
    blst_scalar_from_bendian(&sharei_scalar, sk_shares[i]);
    // Convert scalar to field element.
    blst_fr sharei_fr;
    blst_fr_from_scalar(&sharei_fr, &sharei_scalar);
    // sk += share[i];
    blst_fr_add(&sk_fr, &sk_fr, &sharei_fr);
  }
  // Convert field element to scalar.
  blst_scalar sk_scalar;
  blst_scalar_from_fr(&sk_scalar, &sk_fr);
  // Serialize the scalar as big-endian byte array.
  blst_bendian_from_scalar(sk, &sk_scalar);
  return true;
}

bool blgc_pk_from_shares(blgc_p1_t pk, const blgc_p1_t* pk_shares, size_t n) {
  if (n < 2) {
    return false;
  }
  // Uncompress pk_shares[0].
  blst_p1_affine pk_p1_affine;
  blst_p1_uncompress(&pk_p1_affine, pk_shares[0]);
  // Convert public key from affine point.
  blst_p1 pk_p1;
  blst_p1_from_affine(&pk_p1, &pk_p1_affine);
  for (int i = 1; i < n; i++) {
    // Uncompress pk_shares[i].
    blst_p1_affine pk_share_p1_affine;
    blst_p1_uncompress(&pk_share_p1_affine, pk_shares[i]);
    // pk += pk_shares[i];
    blst_p1_add_affine(&pk_p1, &pk_p1, &pk_share_p1_affine);
  }
  // Compress the point.
  blst_p1_compress(pk, &pk_p1);
  return true;
}

void blgc_sign(blgc_p2_t sig, const blgc_fr_t sk, const uint8_t* msg, size_t msg_len) {
  // Interpret sk as big-endian scalar.
  blst_scalar sk_scalar;
  blst_scalar_from_bendian(&sk_scalar, sk);
  // Map message to point on curve.
  blst_p2 msg_p2;
  blst_hash_to_g2(&msg_p2, msg, msg_len, (const uint8_t*)dst_label, dst_label_len, NULL, 0);
  // sig = msg * sk;
  blst_p2 sig_p2;
  blst_p2_mult(&sig_p2, &msg_p2, &sk_scalar, 256);
  // Compress the point.
  blst_p2_compress(sig, &sig_p2);
}

/** Get Lagrange coefficients for an array of m indicies. */
static void lagrange_coefficients(blst_scalar* coeffs_scalar, const size_t* idx, size_t m) {
  // Create field elements from each index.
  blst_fr idx_fr[m];
  for (int i = 0; i < m; i++) {
    uint64_t idx_uint64[] = { idx[i], 0llu, 0llu, 0llu };
    blst_fr_from_uint64(&idx_fr[i], idx_uint64);
  }
  // w = 1;
  blst_fr w_fr;
  blst_fr_from_uint64(&w_fr, one_fr_uint64);
  // Get product of all indices.
  for (int i = 0; i < m; i++) {
    // w *= idx[i];
    blst_fr_mul(&w_fr, &w_fr, &idx_fr[i]);
  }
  for (int i = 0; i < m; i++) {
    // v = idx[i];
    blst_fr v_fr;
    memcpy(&v_fr, &idx_fr[i], sizeof(blst_fr));
    for (int j = 0; j < m; j++) {
      if (j != i) {
        // v *= idx[j] - idx[i];
        blst_fr idxj_sub_idxi_fr;
        blst_fr_sub(&idxj_sub_idxi_fr, &idx_fr[j], &idx_fr[i]);
        blst_fr_mul(&v_fr, &v_fr, &idxj_sub_idxi_fr);
      }
    }
    // v = w * invert(v);
    blst_fr_eucl_inverse(&v_fr, &v_fr);
    blst_fr_mul(&v_fr, &v_fr, &w_fr);
    // Serialize the scalar as a big-endian byte array.
    blst_scalar_from_fr(&coeffs_scalar[i], &v_fr);
  }
}

bool blgc_sig_from_shares(blgc_p2_t sig, const size_t* idx, const blgc_p2_t* shares, size_t m) {
  if (m < 2) {
    return false;
  }
  // Create the zero and one points on the curve.
  blst_fp zero_fp;
  blst_fp_from_uint64(&zero_fp, zero_fp_uint64);
  blst_fp one_fp;
  blst_fp_from_uint64(&one_fp, one_fp_uint64);
  blst_fp2 zero_fp2 = {{ zero_fp, zero_fp }};
  blst_fp2 one_fp2 = {{ one_fp, zero_fp }};
  // sig = { 1, 1, 0 };
  blst_p2 sig_p2 = { one_fp2, one_fp2, zero_fp2 };
  // Get coefficients for the indicies.
  blst_scalar coeffs_scalar[m];
  lagrange_coefficients(coeffs_scalar, idx, m);
  for (int i = 0; i < m; i++) {
    // Uncompress shares[i].
    blst_p2_affine share_p2_affine;
    blst_p2_uncompress(&share_p2_affine, shares[i]);
    // Convert from affine point.
    blst_p2 share_p2;
    blst_p2_from_affine(&share_p2, &share_p2_affine);
    // sig += coeffs[i] * shares[i];
    blst_p2_mult(&share_p2, &share_p2, &coeffs_scalar[i], 256);
    blst_p2_add(&sig_p2, &sig_p2, &share_p2);
  }
  // Compress the point.
  blst_p2_compress(sig, &sig_p2);
  return true;
}

bool blgc_verify(const blgc_p2_t sig, const blgc_p1_t pk, const uint8_t* msg, size_t msg_len) {
  // Uncompress pk.
  blst_p1_affine pk_p1_affine;
  blst_p1_uncompress(&pk_p1_affine, pk);
  // Uncompress sig.
  blst_p2_affine sig_p2_affine;
  blst_p2_uncompress(&sig_p2_affine, sig);
  // Use the blst verify convenience function.
  return BLST_SUCCESS == blst_core_verify_pk_in_g1(
    &pk_p1_affine,
    &sig_p2_affine,
    true,
    msg,
    msg_len,
    (const uint8_t*)dst_label,
    dst_label_len,
    NULL,
    0
  );
}

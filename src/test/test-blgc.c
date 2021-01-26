#include <blgc.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static void fill_random(void* buf, size_t count) {
  for (int i = 0; i < count; i++) {
    *(uint8_t*)buf++ = rand() % 256;
  }
}

int main(int argc, const char* argv[]) {
  // Seed RNG.
  long rng_seed;
  if (argc > 1) {
    // Use seed from command line argument.
    rng_seed = atoi(argv[1]);
  } else {
    // Use current time as seed.
    time((time_t*)&rng_seed);
  }
  srand(rng_seed);
  // Threshold.
  size_t m = 2;
  // Number of signers.
  size_t n = 3;
  // Create some seed data for the polynomial.
  blgc_seed_t user_seed[m];
  blgc_seed_t backup_seed[m];
  blgc_seed_t wallet_seed[m];
  fill_random(user_seed, sizeof(user_seed));
  fill_random(backup_seed, sizeof(backup_seed));
  fill_random(wallet_seed, sizeof(wallet_seed));
  // Generate each participants polynomial.
  blgc_fr_t user_polynomial[m];
  blgc_fr_t backup_polynomial[m];
  blgc_fr_t wallet_polynomial[m];
  blgc_polynomial_from_seed(user_polynomial, user_seed, m);
  blgc_polynomial_from_seed(backup_polynomial, backup_seed, m);
  blgc_polynomial_from_seed(wallet_polynomial, wallet_seed, m);
  // Generate each participants secret key shares.
  blgc_fr_t user_sk_shares[n];
  blgc_fr_t backup_sk_shares[n];
  blgc_fr_t wallet_sk_shares[n];
  blgc_sk_shares_from_polynomial(user_sk_shares, user_polynomial, m, n);
  blgc_sk_shares_from_polynomial(backup_sk_shares, backup_polynomial, m, n);
  blgc_sk_shares_from_polynomial(wallet_sk_shares, wallet_polynomial, m, n);
  // Generate each participants public key shares.
  blgc_p1_t pk_shares[n];
  blgc_pk_share_from_polynomial(pk_shares[0], user_polynomial, m);
  blgc_pk_share_from_polynomial(pk_shares[1], backup_polynomial, m);
  blgc_pk_share_from_polynomial(pk_shares[2], wallet_polynomial, m);
  // Create an array of shares for each participant with the shares
  // they need to compute their signing key.
  blgc_fr_t sk_shares[n][n];
  for (int i = 0; i < n; i++) {
    memcpy(sk_shares[i][0], user_sk_shares[i], sizeof(blgc_fr_t));
    memcpy(sk_shares[i][1], backup_sk_shares[i], sizeof(blgc_fr_t));
    memcpy(sk_shares[i][2], wallet_sk_shares[i], sizeof(blgc_fr_t));
  }
  // Compute each participants signing key.
  blgc_fr_t user_sk;
  blgc_fr_t backup_sk;
  blgc_fr_t wallet_sk;
  blgc_sk_from_shares(user_sk, sk_shares[0], n);
  blgc_sk_from_shares(backup_sk, sk_shares[1], n);
  blgc_sk_from_shares(wallet_sk, sk_shares[2], n);
  // Compute the common public key.
  blgc_p1_t pk;
  blgc_pk_from_shares(pk, pk_shares, n);
  // Sign a message with each participants signing key.
  const char msg[] = "Hello";
  size_t msg_len = strlen(msg);
  blgc_p2_t user_sig;
  blgc_p2_t backup_sig;
  blgc_p2_t wallet_sig;
  blgc_sign(user_sig, user_sk, msg, msg_len);
  blgc_sign(backup_sig, backup_sk, msg, msg_len);
  blgc_sign(wallet_sig, wallet_sk, msg, msg_len);
  // Construct arrays for each combination of signature shares.
  size_t user_backup_idx[] = { 1, 2 };
  size_t user_wallet_idx[] = { 1, 3 };
  size_t backup_wallet_idx[] = { 2, 3 };
  blgc_p2_t user_backup_shares[m];
  blgc_p2_t user_wallet_shares[m];
  blgc_p2_t backup_wallet_shares[m];
  memcpy(user_backup_shares[0], user_sig, sizeof(blgc_p2_t));
  memcpy(user_backup_shares[1], backup_sig, sizeof(blgc_p2_t));
  memcpy(user_wallet_shares[0], user_sig, sizeof(blgc_p2_t));
  memcpy(user_wallet_shares[1], wallet_sig, sizeof(blgc_p2_t));
  memcpy(backup_wallet_shares[0], backup_sig, sizeof(blgc_p2_t));
  memcpy(backup_wallet_shares[1], wallet_sig, sizeof(blgc_p2_t));
  // Verify each combination of signatures.
  blgc_p2_t sig;
  blgc_sig_from_shares(sig, user_backup_idx, user_backup_shares, m);
  if (!blgc_verify(sig, pk, msg, msg_len)) {
    fprintf(stderr, "Could not verify user + backup sig\n");
    return 1;
  }
  blgc_sig_from_shares(sig, user_wallet_idx, user_wallet_shares, m);
  if (!blgc_verify(sig, pk, msg, msg_len)) {
    fprintf(stderr, "Could not verify user + wallet sig\n");
    return 1;
  }
  blgc_sig_from_shares(sig, backup_wallet_idx, backup_wallet_shares, m);
  if (!blgc_verify(sig, pk, msg, msg_len)) {
    fprintf(stderr, "Could not verify backup + wallet sig\n");
    return 1;
  }
  printf("Success\n");
  return 0;
}


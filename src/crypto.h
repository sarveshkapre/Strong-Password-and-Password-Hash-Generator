#pragma once

#include <stddef.h>
#include <stdint.h>

// Small portability layer:
// - macOS: CommonCrypto for digests + PBKDF2 + arc4random_buf RNG
// - other: OpenSSL libcrypto for digests + PBKDF2, with OS RNG best-effort

typedef enum {
  CRYPTO_ALGO_MD5 = 0,
  CRYPTO_ALGO_SHA1,
  CRYPTO_ALGO_SHA256,
  CRYPTO_ALGO_SHA512,
} crypto_algo_t;

const char *crypto_algo_name(crypto_algo_t algo);
int crypto_parse_algo(const char *s, crypto_algo_t *out_algo);

size_t crypto_digest_size(crypto_algo_t algo);

// Writes lowercase hex. out_hex_len must be at least digest_size*2 + 1.
int crypto_digest_hex(crypto_algo_t algo, const uint8_t *data, size_t len,
                      char *out_hex, size_t out_hex_len);

// PBKDF2-HMAC. dk_len bytes derived key. Writes hex (dk_len*2 + 1 required).
int crypto_pbkdf2_hex(crypto_algo_t prf_algo, const char *password,
                      const uint8_t *salt, size_t salt_len,
                      uint32_t iterations, size_t dk_len,
                      char *out_hex, size_t out_hex_len);

// Cryptographically secure random bytes. Returns 0 on success.
int crypto_random_bytes(uint8_t *out, size_t len);


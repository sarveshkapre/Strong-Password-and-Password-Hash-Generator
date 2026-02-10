#include "crypto.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#if defined(__APPLE__)
#include <CommonCrypto/CommonCrypto.h>
#include <stdlib.h>
#else
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdlib.h>

#if defined(__linux__)
#include <sys/random.h>
#endif
#endif

static void hex_encode_lower(const uint8_t *in, size_t in_len, char *out) {
  static const char *hex = "0123456789abcdef";
  for (size_t i = 0; i < in_len; i++) {
    out[i * 2] = hex[(in[i] >> 4) & 0xF];
    out[i * 2 + 1] = hex[in[i] & 0xF];
  }
  out[in_len * 2] = '\0';
}

const char *crypto_algo_name(crypto_algo_t algo) {
  switch (algo) {
  case CRYPTO_ALGO_MD5:
    return "md5";
  case CRYPTO_ALGO_SHA1:
    return "sha1";
  case CRYPTO_ALGO_SHA256:
    return "sha256";
  case CRYPTO_ALGO_SHA512:
    return "sha512";
  default:
    return "unknown";
  }
}

int crypto_parse_algo(const char *s, crypto_algo_t *out_algo) {
  if (!s || !out_algo)
    return -1;

  // normalize to lowercase without allocating
  char buf[16];
  size_t n = strlen(s);
  if (n >= sizeof(buf))
    return -1;
  for (size_t i = 0; i < n; i++)
    buf[i] = (char)tolower((unsigned char)s[i]);
  buf[n] = '\0';

  if (strcmp(buf, "md5") == 0) {
    *out_algo = CRYPTO_ALGO_MD5;
    return 0;
  }
  if (strcmp(buf, "sha1") == 0) {
    *out_algo = CRYPTO_ALGO_SHA1;
    return 0;
  }
  if (strcmp(buf, "sha256") == 0) {
    *out_algo = CRYPTO_ALGO_SHA256;
    return 0;
  }
  if (strcmp(buf, "sha512") == 0) {
    *out_algo = CRYPTO_ALGO_SHA512;
    return 0;
  }
  return -1;
}

size_t crypto_digest_size(crypto_algo_t algo) {
  switch (algo) {
  case CRYPTO_ALGO_MD5:
    return 16;
  case CRYPTO_ALGO_SHA1:
    return 20;
  case CRYPTO_ALGO_SHA256:
    return 32;
  case CRYPTO_ALGO_SHA512:
    return 64;
  default:
    return 0;
  }
}

int crypto_digest_hex(crypto_algo_t algo, const uint8_t *data, size_t len,
                      char *out_hex, size_t out_hex_len) {
  size_t dlen = crypto_digest_size(algo);
  if (dlen == 0 || !out_hex)
    return -1;
  if (out_hex_len < (dlen * 2 + 1))
    return -1;

  uint8_t digest[64];
  memset(digest, 0, sizeof(digest));

#if defined(__APPLE__)
  switch (algo) {
  case CRYPTO_ALGO_MD5:
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif
    CC_MD5(data, (CC_LONG)len, digest);
#if defined(__clang__)
#pragma clang diagnostic pop
#endif
    break;
  case CRYPTO_ALGO_SHA1:
    CC_SHA1(data, (CC_LONG)len, digest);
    break;
  case CRYPTO_ALGO_SHA256:
    CC_SHA256(data, (CC_LONG)len, digest);
    break;
  case CRYPTO_ALGO_SHA512:
    CC_SHA512(data, (CC_LONG)len, digest);
    break;
  default:
    return -1;
  }
#else
  const EVP_MD *md = NULL;
  switch (algo) {
  case CRYPTO_ALGO_MD5:
    md = EVP_md5();
    break;
  case CRYPTO_ALGO_SHA1:
    md = EVP_sha1();
    break;
  case CRYPTO_ALGO_SHA256:
    md = EVP_sha256();
    break;
  case CRYPTO_ALGO_SHA512:
    md = EVP_sha512();
    break;
  default:
    return -1;
  }

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx)
    return -1;
  unsigned int out_len = 0;
  int ok = EVP_DigestInit_ex(ctx, md, NULL) == 1 &&
           EVP_DigestUpdate(ctx, data, len) == 1 &&
           EVP_DigestFinal_ex(ctx, digest, &out_len) == 1;
  EVP_MD_CTX_free(ctx);
  if (!ok || out_len != dlen)
    return -1;
#endif

  hex_encode_lower(digest, dlen, out_hex);
  return 0;
}

int crypto_pbkdf2_hex(crypto_algo_t prf_algo, const char *password,
                      const uint8_t *salt, size_t salt_len,
                      uint32_t iterations, size_t dk_len,
                      char *out_hex, size_t out_hex_len) {
  if (!password || (!salt && salt_len > 0) || !out_hex)
    return -1;
  if (iterations == 0 || dk_len == 0)
    return -1;
  if (out_hex_len < (dk_len * 2 + 1))
    return -1;

  uint8_t *dk = (uint8_t *)calloc(1, dk_len);
  if (!dk)
    return -1;

  int rc = -1;

#if defined(__APPLE__)
  CCPseudoRandomAlgorithm prf = 0;
  switch (prf_algo) {
  case CRYPTO_ALGO_SHA1:
    prf = kCCPRFHmacAlgSHA1;
    break;
  case CRYPTO_ALGO_SHA256:
    prf = kCCPRFHmacAlgSHA256;
    break;
  case CRYPTO_ALGO_SHA512:
    prf = kCCPRFHmacAlgSHA512;
    break;
  // CommonCrypto supports MD5-HMAC, but we intentionally disallow it for PBKDF2.
  default:
    free(dk);
    return -1;
  }

  int ok = CCKeyDerivationPBKDF(
               kCCPBKDF2, password, (size_t)strlen(password), salt, salt_len,
               prf, iterations, dk, dk_len) == kCCSuccess;
  if (!ok) {
    free(dk);
    return -1;
  }
#else
  const EVP_MD *md = NULL;
  switch (prf_algo) {
  case CRYPTO_ALGO_SHA1:
    md = EVP_sha1();
    break;
  case CRYPTO_ALGO_SHA256:
    md = EVP_sha256();
    break;
  case CRYPTO_ALGO_SHA512:
    md = EVP_sha512();
    break;
  default:
    free(dk);
    return -1;
  }
  if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password), salt, (int)salt_len,
                        (int)iterations, md, (int)dk_len, dk) != 1) {
    free(dk);
    return -1;
  }
#endif

  hex_encode_lower(dk, dk_len, out_hex);
  rc = 0;
  free(dk);
  return rc;
}

int crypto_random_bytes(uint8_t *out, size_t len) {
  if (!out && len > 0)
    return -1;
  if (len == 0)
    return 0;

#if defined(__APPLE__)
  arc4random_buf(out, len);
  return 0;
#else
#if defined(__linux__)
  size_t off = 0;
  while (off < len) {
    ssize_t n = getrandom(out + off, len - off, 0);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    off += (size_t)n;
  }
  if (off == len)
    return 0;
#endif

  // Portable fallback: /dev/urandom
  FILE *fp = fopen("/dev/urandom", "rb");
  if (!fp)
    return -1;
  size_t nread = fread(out, 1, len, fp);
  fclose(fp);
  return nread == len ? 0 : -1;
#endif
}

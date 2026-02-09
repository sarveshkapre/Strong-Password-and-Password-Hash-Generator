#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"

typedef enum {
  MODE_DIGEST = 0,
  MODE_PBKDF2,
} hash_mode_t;

typedef enum {
  OUTFMT_V1 = 1, // password<TAB>algo<TAB>hash_hex<TAB>entropy_bits
  OUTFMT_V2 = 2, // v1 + salt/iterations/dk_len (empty for digest mode)
} output_format_t;

static void rstrip_newlines(char *s) {
  if (!s)
    return;
  size_t n = strlen(s);
  while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
    s[n - 1] = '\0';
    n--;
  }
}

static int hexval(int c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return 10 + (c - 'a');
  if (c >= 'A' && c <= 'F')
    return 10 + (c - 'A');
  return -1;
}

static int parse_hex(const char *hex, uint8_t **out, size_t *out_len) {
  if (!hex || !out || !out_len)
    return -1;
  size_t n = strlen(hex);
  if (n == 0 || (n % 2) != 0)
    return -1;
  size_t blen = n / 2;
  uint8_t *buf = (uint8_t *)calloc(1, blen);
  if (!buf)
    return -1;
  for (size_t i = 0; i < blen; i++) {
    int hi = hexval((unsigned char)hex[i * 2]);
    int lo = hexval((unsigned char)hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) {
      free(buf);
      return -1;
    }
    buf[i] = (uint8_t)((hi << 4) | lo);
  }
  *out = buf;
  *out_len = blen;
  return 0;
}

static int estimate_pool_size(const char *s) {
  int has_lower = 0, has_upper = 0, has_digit = 0, has_symbol = 0;
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    if (islower(*p))
      has_lower = 1;
    else if (isupper(*p))
      has_upper = 1;
    else if (isdigit(*p))
      has_digit = 1;
    else if (isprint(*p))
      has_symbol = 1;
  }

  int pool = 0;
  if (has_lower)
    pool += 26;
  if (has_upper)
    pool += 26;
  if (has_digit)
    pool += 10;
  if (has_symbol)
    pool += 32; // conservative-ish "common symbols" bucket
  return pool;
}

static double estimate_entropy_bits(const char *s) {
  size_t len = strlen(s);
  if (len == 0)
    return 0.0;
  int pool = estimate_pool_size(s);
  if (pool <= 1)
    return 0.0;
  return log2((double)pool) * (double)len;
}

static void usage(const char *argv0) {
  fprintf(stderr,
          "Usage: %s [-i input.txt] [-o output.txt] [--append]\n"
          "          [--algo md5|sha1|sha256|sha512|pbkdf2-sha1|pbkdf2-sha256|pbkdf2-sha512]\n"
          "          [--iterations N] [--dk-len N] [--salt-len N | --salt-hex HEX] [--format v1|v2]\n"
          "\n"
          "Reads one password per line.\n"
          "\n"
          "Output format v1 (default for digest algos):\n"
          "  password<TAB>algo<TAB>hash_hex<TAB>entropy_bits\n"
          "\n"
          "Output format v2 (automatic for PBKDF2 algos unless --format v1 is forced):\n"
          "  password<TAB>algo<TAB>hash_hex<TAB>entropy_bits<TAB>salt_hex<TAB>iterations<TAB>dk_len\n"
          "\n"
          "Defaults: -i GitHub-Brute-Force/passwordfile.txt, --algo sha256, output to stdout.\n"
          "PBKDF2 defaults: --iterations 310000, --dk-len 32, --salt-len 16.\n",
          argv0);
}

static int parse_algo_or_kdf(const char *s, hash_mode_t *out_mode,
                             crypto_algo_t *out_digest_algo,
                             crypto_algo_t *out_prf_algo,
                             const char **out_algo_name) {
  if (!s || !out_mode || !out_digest_algo || !out_prf_algo || !out_algo_name)
    return -1;

  // normalize to lowercase without allocating
  char buf[32];
  size_t n = strlen(s);
  if (n == 0 || n >= sizeof(buf))
    return -1;
  for (size_t i = 0; i < n; i++)
    buf[i] = (char)tolower((unsigned char)s[i]);
  buf[n] = '\0';

  if (strncmp(buf, "pbkdf2-", 7) == 0) {
    const char *prf = buf + 7;
    crypto_algo_t prf_algo;
    if (crypto_parse_algo(prf, &prf_algo) != 0)
      return -1;
    // Intentionally disallow PBKDF2-MD5 even if someone types it.
    if (prf_algo == CRYPTO_ALGO_MD5)
      return -1;

    *out_mode = MODE_PBKDF2;
    *out_prf_algo = prf_algo;
    switch (prf_algo) {
    case CRYPTO_ALGO_SHA1:
      *out_algo_name = "pbkdf2-sha1";
      break;
    case CRYPTO_ALGO_SHA256:
      *out_algo_name = "pbkdf2-sha256";
      break;
    case CRYPTO_ALGO_SHA512:
      *out_algo_name = "pbkdf2-sha512";
      break;
    default:
      return -1;
    }
    return 0;
  }

  crypto_algo_t d;
  if (crypto_parse_algo(buf, &d) != 0)
    return -1;
  *out_mode = MODE_DIGEST;
  *out_digest_algo = d;
  *out_algo_name = crypto_algo_name(d);
  return 0;
}

int main(int argc, char **argv)
{
  const char *input_path = "GitHub-Brute-Force/passwordfile.txt";
  const char *output_path = NULL;
  int append = 0;
  hash_mode_t mode = MODE_DIGEST;
  crypto_algo_t digest_algo = CRYPTO_ALGO_SHA256;
  crypto_algo_t pbkdf2_prf_algo = CRYPTO_ALGO_SHA256;
  const char *algo_name = "sha256";

  output_format_t outfmt = OUTFMT_V1;
  int format_set = 0;

  uint32_t pbkdf2_iterations = 310000;
  size_t pbkdf2_dk_len = 32;
  size_t pbkdf2_salt_len = 16;
  const char *salt_hex_arg = NULL;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
      input_path = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
      output_path = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--append") == 0) {
      append = 1;
      continue;
    }
    if (strcmp(argv[i], "--algo") == 0 && i + 1 < argc) {
      const char *val = argv[++i];
      if (parse_algo_or_kdf(val, &mode, &digest_algo, &pbkdf2_prf_algo,
                            &algo_name) != 0) {
        fprintf(stderr, "Unsupported --algo value.\n");
        usage(argv[0]);
        return 2;
      }
      continue;
    }
    if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
      errno = 0;
      unsigned long v = strtoul(argv[++i], NULL, 10);
      if (errno != 0 || v == 0 || v > 0xFFFFFFFFUL) {
        fprintf(stderr, "Invalid --iterations value.\n");
        return 2;
      }
      pbkdf2_iterations = (uint32_t)v;
      continue;
    }
    if (strcmp(argv[i], "--dk-len") == 0 && i + 1 < argc) {
      errno = 0;
      unsigned long v = strtoul(argv[++i], NULL, 10);
      if (errno != 0 || v == 0 || v > 1024) {
        fprintf(stderr, "Invalid --dk-len value (1..1024).\n");
        return 2;
      }
      pbkdf2_dk_len = (size_t)v;
      continue;
    }
    if (strcmp(argv[i], "--salt-len") == 0 && i + 1 < argc) {
      errno = 0;
      unsigned long v = strtoul(argv[++i], NULL, 10);
      if (errno != 0 || v == 0 || v > 1024) {
        fprintf(stderr, "Invalid --salt-len value (1..1024).\n");
        return 2;
      }
      pbkdf2_salt_len = (size_t)v;
      continue;
    }
    if (strcmp(argv[i], "--salt-hex") == 0 && i + 1 < argc) {
      salt_hex_arg = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--format") == 0 && i + 1 < argc) {
      const char *v = argv[++i];
      if (strcmp(v, "v1") == 0) {
        outfmt = OUTFMT_V1;
        format_set = 1;
        continue;
      }
      if (strcmp(v, "v2") == 0) {
        outfmt = OUTFMT_V2;
        format_set = 1;
        continue;
      }
      fprintf(stderr, "Invalid --format value (use v1 or v2).\n");
      return 2;
    }
    if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      usage(argv[0]);
      return 0;
    }

    fprintf(stderr, "Unknown argument: %s\n", argv[i]);
    usage(argv[0]);
    return 2;
  }

  if (mode == MODE_PBKDF2) {
    // PBKDF2 needs salt+params in output. Default to v2 unless user forced v1.
    if (format_set && outfmt == OUTFMT_V1) {
      fprintf(stderr, "PBKDF2 requires --format v2.\n");
      return 2;
    }
    if (!format_set)
      outfmt = OUTFMT_V2;
  }

  FILE *in = fopen(input_path, "r");
  if (!in) {
    perror("Error opening input file");
    return 1;
  }

  FILE *out = stdout;
  if (output_path) {
    out = fopen(output_path, append ? "a" : "w");
    if (!out) {
      perror("Error opening output file");
      fclose(in);
      return 1;
    }
  }

  uint8_t *fixed_salt = NULL;
  size_t fixed_salt_len = 0;
  if (salt_hex_arg) {
    if (parse_hex(salt_hex_arg, &fixed_salt, &fixed_salt_len) != 0) {
      fprintf(stderr, "Invalid --salt-hex value (must be even-length hex).\n");
      fclose(in);
      if (out != stdout)
        fclose(out);
      return 2;
    }
    if (fixed_salt_len == 0) {
      fprintf(stderr, "--salt-hex must not be empty.\n");
      free(fixed_salt);
      fclose(in);
      if (out != stdout)
        fclose(out);
      return 2;
    }
  }

  if (mode == MODE_DIGEST) {
    size_t digest_len = crypto_digest_size(digest_algo);
    if (digest_len == 0) {
      fprintf(stderr, "Internal error: unknown digest size.\n");
      fclose(in);
      if (out != stdout)
        fclose(out);
      return 1;
    }
  }

  char *line = NULL;
  size_t line_cap = 0;
  ssize_t nread;

  while ((nread = getline(&line, &line_cap, in)) != -1) {
    (void)nread;
    rstrip_newlines(line);
    if (line[0] == '\0')
      continue;

    double entropy = estimate_entropy_bits(line);

    if (mode == MODE_DIGEST) {
      char hash_hex[64 * 2 + 1];
      if (crypto_digest_hex(digest_algo, (const uint8_t *)line, strlen(line),
                            hash_hex, sizeof(hash_hex)) != 0) {
        fprintf(stderr, "Hashing failed for a line.\n");
        free(line);
        free(fixed_salt);
        fclose(in);
        if (out != stdout)
          fclose(out);
        return 1;
      }

      if (outfmt == OUTFMT_V1) {
        fprintf(out, "%s\t%s\t%s\t%.2f\n", line, crypto_algo_name(digest_algo),
                hash_hex, entropy);
      } else {
        fprintf(out, "%s\t%s\t%s\t%.2f\t\t\t\n", line,
                crypto_algo_name(digest_algo), hash_hex, entropy);
      }
      continue;
    }

    // MODE_PBKDF2
    uint8_t *salt = fixed_salt;
    size_t salt_len = fixed_salt_len;
    uint8_t *tmp_salt = NULL;
    if (!salt) {
      salt_len = pbkdf2_salt_len;
      tmp_salt = (uint8_t *)calloc(1, salt_len);
      if (!tmp_salt) {
        perror("calloc");
        free(line);
        fclose(in);
        if (out != stdout)
          fclose(out);
        return 1;
      }
      if (crypto_random_bytes(tmp_salt, salt_len) != 0) {
        fprintf(stderr, "Salt generation failed.\n");
        free(tmp_salt);
        free(line);
        fclose(in);
        if (out != stdout)
          fclose(out);
        return 1;
      }
      salt = tmp_salt;
    }

    char *hash_hex = (char *)calloc(1, pbkdf2_dk_len * 2 + 1);
    char *salt_hex = (char *)calloc(1, salt_len * 2 + 1);
    if (!hash_hex || !salt_hex) {
      perror("calloc");
      free(hash_hex);
      free(salt_hex);
      free(tmp_salt);
      free(line);
      free(fixed_salt);
      fclose(in);
      if (out != stdout)
        fclose(out);
      return 1;
    }

    // Use the digest helper to hex-encode via PBKDF2 module output; salt needs hex too.
    // crypto_pbkdf2_hex already writes lowercase hex for derived key.
    if (crypto_pbkdf2_hex(pbkdf2_prf_algo, line, salt, salt_len,
                          pbkdf2_iterations, pbkdf2_dk_len, hash_hex,
                          pbkdf2_dk_len * 2 + 1) != 0) {
      fprintf(stderr, "PBKDF2 failed for a line.\n");
      free(hash_hex);
      free(salt_hex);
      free(tmp_salt);
      free(line);
      free(fixed_salt);
      fclose(in);
      if (out != stdout)
        fclose(out);
      return 1;
    }

    // Local hex encoding for salt (keep output format self-contained).
    static const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < salt_len; i++) {
      salt_hex[i * 2] = hex[(salt[i] >> 4) & 0xF];
      salt_hex[i * 2 + 1] = hex[salt[i] & 0xF];
    }
    salt_hex[salt_len * 2] = '\0';

    fprintf(out, "%s\t%s\t%s\t%.2f\t%s\t%u\t%zu\n", line, algo_name, hash_hex,
            entropy, salt_hex, pbkdf2_iterations, pbkdf2_dk_len);

    free(hash_hex);
    free(salt_hex);
    free(tmp_salt);
  }

  free(line);
  free(fixed_salt);

  fclose(in);
  if (out != stdout)
    fclose(out);
  return 0;
}

#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"

static void usage(const char *argv0) {
  fprintf(stderr,
          "Educational brute-force demo (safe by default).\n"
          "\n"
          "Usage: %s --length N --max N [--charset alnum|lower|upper|digits|hex]\n"
          "          [--chars STR] [--algo md5|sha1|sha256|sha512]\n"
          "          [--target-hex HEX] [--print] [--log PATH] [--force]\n"
          "\n"
          "Required:\n"
          "  --length N   Candidate length (1..32)\n"
          "  --max N      Max candidates to try (1..1,000,000 unless --force)\n"
          "\n"
          "Behavior:\n"
          "  - If --target-hex is provided, stops on first match and exits 0; exits 3 if not found.\n"
          "  - If --target-hex is NOT provided, prints candidate<TAB>algo<TAB>hash_hex (like a demo).\n"
          "  - No files are written unless --log is provided.\n",
          argv0);
}

static int parse_u64_strict(const char *s, uint64_t *out) {
  if (!s || !*s || !out)
    return -1;
  errno = 0;
  char *end = NULL;
  unsigned long long v = strtoull(s, &end, 10);
  if (errno != 0 || !end || *end != '\0')
    return -1;
  *out = (uint64_t)v;
  return 0;
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

static int normalize_hex_lower(const char *in, char *out, size_t out_cap) {
  if (!in || !out || out_cap == 0)
    return -1;
  size_t n = strlen(in);
  if (n + 1 > out_cap)
    return -1;
  for (size_t i = 0; i < n; i++) {
    int v = hexval((unsigned char)in[i]);
    if (v < 0)
      return -1;
    out[i] = (char)tolower((unsigned char)in[i]);
  }
  out[n] = '\0';
  return 0;
}

static const char *charset_from_name(const char *name) {
  if (!name)
    return NULL;
  if (strcmp(name, "alnum") == 0)
    return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  if (strcmp(name, "lower") == 0)
    return "abcdefghijklmnopqrstuvwxyz";
  if (strcmp(name, "upper") == 0)
    return "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  if (strcmp(name, "digits") == 0)
    return "0123456789";
  if (strcmp(name, "hex") == 0)
    return "0123456789abcdef";
  return NULL;
}

int main(int argc, char **argv) {
  uint64_t length_u = 0;
  uint64_t max_u = 0;
  int have_length = 0;
  int have_max = 0;
  int force = 0;
  int print_each = 0;

  const char *charset_name = "alnum";
  const char *chars = NULL;

  crypto_algo_t algo = CRYPTO_ALGO_SHA256;
  const char *target_hex_arg = NULL;
  const char *log_path = NULL;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--length") == 0 && i + 1 < argc) {
      if (parse_u64_strict(argv[++i], &length_u) != 0) {
        fprintf(stderr, "Invalid --length value.\n");
        return 2;
      }
      have_length = 1;
      continue;
    }
    if (strcmp(argv[i], "--max") == 0 && i + 1 < argc) {
      if (parse_u64_strict(argv[++i], &max_u) != 0) {
        fprintf(stderr, "Invalid --max value.\n");
        return 2;
      }
      have_max = 1;
      continue;
    }
    if (strcmp(argv[i], "--charset") == 0 && i + 1 < argc) {
      charset_name = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--chars") == 0 && i + 1 < argc) {
      chars = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--algo") == 0 && i + 1 < argc) {
      crypto_algo_t a;
      if (crypto_parse_algo(argv[++i], &a) != 0) {
        fprintf(stderr, "Invalid --algo value.\n");
        return 2;
      }
      algo = a;
      continue;
    }
    if (strcmp(argv[i], "--target-hex") == 0 && i + 1 < argc) {
      target_hex_arg = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--print") == 0) {
      print_each = 1;
      continue;
    }
    if (strcmp(argv[i], "--log") == 0 && i + 1 < argc) {
      log_path = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--force") == 0) {
      force = 1;
      continue;
    }
    if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      usage(argv[0]);
      return 0;
    }

    fprintf(stderr, "Unknown argument: %s\n", argv[i]);
    usage(argv[0]);
    return 2;
  }

  if (!have_length || !have_max) {
    usage(argv[0]);
    return 2;
  }
  if (length_u == 0 || length_u > 32) {
    fprintf(stderr, "--length must be in 1..32.\n");
    return 2;
  }
  if (max_u == 0) {
    fprintf(stderr, "--max must be > 0.\n");
    return 2;
  }
  if (!force && max_u > 1000000ULL) {
    fprintf(stderr, "--max is capped at 1,000,000 unless --force is set.\n");
    return 2;
  }

  const char *charset = NULL;
  if (chars) {
    charset = chars;
  } else {
    charset = charset_from_name(charset_name);
  }
  if (!charset || charset[0] == '\0') {
    fprintf(stderr, "Empty charset.\n");
    return 2;
  }
  size_t charset_len = strlen(charset);

  size_t dlen = crypto_digest_size(algo);
  if (dlen == 0) {
    fprintf(stderr, "Internal error: unknown digest size.\n");
    return 1;
  }

  char target_hex[64 * 2 + 1];
  target_hex[0] = '\0';
  if (target_hex_arg) {
    if (normalize_hex_lower(target_hex_arg, target_hex, sizeof(target_hex)) != 0) {
      fprintf(stderr, "Invalid --target-hex value (must be hex).\n");
      return 2;
    }
    if (strlen(target_hex) != dlen * 2) {
      fprintf(stderr, "--target-hex length must match %zu-byte digest (%zu hex chars).\n",
              dlen, dlen * 2);
      return 2;
    }
  }

  FILE *log_fp = NULL;
  if (log_path) {
    log_fp = fopen(log_path, "a");
    if (!log_fp) {
      perror("fopen");
      return 1;
    }
  }

  // Default printing behavior: print each attempt only when not matching a target.
  if (!target_hex_arg)
    print_each = 1;

  size_t length = (size_t)length_u;
  uint64_t max = max_u;

  // Base-N counter over charset indices.
  size_t *idx = (size_t *)calloc(length, sizeof(size_t));
  char *candidate = (char *)calloc(length + 1, 1);
  if (!idx || !candidate) {
    perror("calloc");
    free(idx);
    free(candidate);
    if (log_fp)
      fclose(log_fp);
    return 1;
  }

  char hash_hex[64 * 2 + 1];

  for (uint64_t attempt = 0; attempt < max; attempt++) {
    for (size_t i = 0; i < length; i++)
      candidate[i] = charset[idx[i] % charset_len];
    candidate[length] = '\0';

    if (crypto_digest_hex(algo, (const uint8_t *)candidate, strlen(candidate),
                          hash_hex, sizeof(hash_hex)) != 0) {
      fprintf(stderr, "Hashing failed.\n");
      free(idx);
      free(candidate);
      if (log_fp)
        fclose(log_fp);
      return 1;
    }

    int is_match = 0;
    if (target_hex[0] != '\0' && strcmp(hash_hex, target_hex) == 0)
      is_match = 1;

    if (print_each || is_match) {
      fprintf(stdout, "%s\t%s\t%s\n", candidate, crypto_algo_name(algo), hash_hex);
      if (log_fp) {
        fprintf(log_fp, "%s\t%s\t%s\n", candidate, crypto_algo_name(algo), hash_hex);
        fflush(log_fp);
      }
    }

    if (is_match) {
      free(idx);
      free(candidate);
      if (log_fp)
        fclose(log_fp);
      return 0;
    }

    // Increment base-N counter.
    for (size_t p = 0; p < length; p++) {
      idx[p]++;
      if (idx[p] < charset_len)
        break;
      idx[p] = 0;
    }
  }

  free(idx);
  free(candidate);
  if (log_fp)
    fclose(log_fp);

  if (target_hex[0] != '\0') {
    fprintf(stderr, "Not found within max=%" PRIu64 " attempts.\n", max);
    return 3;
  }
  return 0;
}

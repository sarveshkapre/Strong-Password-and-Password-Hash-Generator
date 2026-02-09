#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#include "crypto.h"

static void rstrip_newlines(char *s) {
  if (!s)
    return;
  size_t n = strlen(s);
  while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
    s[n - 1] = '\0';
    n--;
  }
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
          "Usage: %s [-i input.txt] [-o output.txt] [--append] [--algo md5|sha1|sha256|sha512]\n"
          "\n"
          "Reads one password per line and prints: password<TAB>algo<TAB>hash_hex<TAB>entropy_bits\n"
          "Defaults: -i GitHub-Brute-Force/passwordfile.txt, --algo sha256, output to stdout.\n",
          argv0);
}


int main(int argc, char **argv)
{
  const char *input_path = "GitHub-Brute-Force/passwordfile.txt";
  const char *output_path = NULL;
  int append = 0;
  crypto_algo_t algo = CRYPTO_ALGO_SHA256;

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
      if (crypto_parse_algo(argv[++i], &algo) != 0) {
        fprintf(stderr, "Unsupported --algo value.\n");
        usage(argv[0]);
        return 2;
      }
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

  char line[256];
  size_t dlen = crypto_digest_size(algo);
  char hash_hex[64 * 2 + 1];
  if (dlen == 0) {
    fprintf(stderr, "Internal error: unknown digest size.\n");
    fclose(in);
    if (out != stdout)
      fclose(out);
    return 1;
  }

  while (fgets(line, sizeof(line), in)) {
    rstrip_newlines(line);
    if (line[0] == '\0')
      continue;

    if (crypto_digest_hex(algo, (const uint8_t *)line, strlen(line), hash_hex,
                          sizeof(hash_hex)) != 0) {
      fprintf(stderr, "Hashing failed for a line.\n");
      fclose(in);
      if (out != stdout)
        fclose(out);
      return 1;
    }

    double entropy = estimate_entropy_bits(line);
    fprintf(out, "%s\t%s\t%s\t%.2f\n", line, crypto_algo_name(algo), hash_hex,
            entropy);
  }

  fclose(in);
  if (out != stdout)
    fclose(out);
  return 0;
}

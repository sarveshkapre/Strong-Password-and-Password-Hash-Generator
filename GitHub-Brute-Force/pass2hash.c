#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
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

typedef enum {
  STREAM_TSV = 0,
  STREAM_JSONL = 1,
} stream_format_t;

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

static int sbuf_append(char **buf, size_t *cap, size_t *len, const void *src,
                       size_t src_len) {
  if (!buf || !cap || !len || (!src && src_len > 0))
    return -1;
  size_t need = *len + src_len + 1;
  if (*cap < need) {
    size_t new_cap = (*cap == 0) ? 128 : *cap;
    while (new_cap < need) {
      if (new_cap > (SIZE_MAX / 2))
        return -1;
      new_cap *= 2;
    }
    char *tmp = (char *)realloc(*buf, new_cap);
    if (!tmp)
      return -1;
    *buf = tmp;
    *cap = new_cap;
  }
  if (src_len > 0)
    memcpy(*buf + *len, src, src_len);
  *len += src_len;
  (*buf)[*len] = '\0';
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
          "          (use -i - for stdin; -o - for stdout)\n"
          "          [--output-format tsv|jsonl] [--header]\n"
          "          [--omit-password] [--escape-tsv]\n"
          "          [--iterations N] [--dk-len N] [--salt-len N | --salt-hex HEX] [--format v1|v2]\n"
          "       %s --verify [-i input.(tsv|jsonl)] [--input-format tsv|jsonl] [--escape-tsv]\n"
          "\n"
          "Reads one password per line.\n"
          "With --verify, reads TSV or JSONL output and recomputes hashes (fails fast on mismatch).\n"
          "\n"
          "Output format v1 (default for digest algos):\n"
          "  password<TAB>algo<TAB>hash_hex<TAB>entropy_bits\n"
          "  With --omit-password: algo<TAB>hash_hex<TAB>entropy_bits\n"
          "  With --escape-tsv: password field uses backslash-escapes (\\t, \\n, \\r, \\\\).\n"
          "\n"
          "Output format v2 (automatic for PBKDF2 algos unless --format v1 is forced):\n"
          "  password<TAB>algo<TAB>hash_hex<TAB>entropy_bits<TAB>salt_hex<TAB>iterations<TAB>dk_len\n"
          "  With --omit-password: algo<TAB>hash_hex<TAB>entropy_bits<TAB>salt_hex<TAB>iterations<TAB>dk_len\n"
          "\n"
          "Output format jsonl (with --output-format jsonl): one JSON object per line.\n"
          "\n"
          "Defaults: -i GitHub-Brute-Force/passwordfile.txt, --algo sha256, output to stdout.\n"
          "PBKDF2 defaults: --dk-len 32, --salt-len 16, and --iterations depends on PRF:\n"
          "  pbkdf2-sha1=1300000, pbkdf2-sha256=600000, pbkdf2-sha512=210000.\n",
          argv0, argv0);
}

static int parse_u32_strict(const char *s, uint32_t min, uint32_t max,
                            uint32_t *out) {
  if (!s || !*s || !out)
    return -1;
  errno = 0;
  char *end = NULL;
  unsigned long long v = strtoull(s, &end, 10);
  if (errno != 0 || !end || *end != '\0')
    return -1;
  if (v < (unsigned long long)min || v > (unsigned long long)max)
    return -1;
  *out = (uint32_t)v;
  return 0;
}

static int parse_size_strict(const char *s, size_t min, size_t max,
                             size_t *out) {
  if (!s || !*s || !out)
    return -1;
  errno = 0;
  char *end = NULL;
  unsigned long long v = strtoull(s, &end, 10);
  if (errno != 0 || !end || *end != '\0')
    return -1;
  if (v < (unsigned long long)min || v > (unsigned long long)max)
    return -1;
  *out = (size_t)v;
  return 0;
}

static char *tsv_escape_alloc(const char *s) {
  if (!s)
    return NULL;

  size_t n = 0;
  int needs = 0;
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    if (*p == '\t' || *p == '\n' || *p == '\r' || *p == '\\') {
      needs = 1;
      n += 2;
    } else {
      n += 1;
    }
  }
  if (!needs)
    return NULL;

  char *out = (char *)calloc(1, n + 1);
  if (!out)
    return NULL;
  size_t w = 0;
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    if (*p == '\\') {
      out[w++] = '\\';
      out[w++] = '\\';
      continue;
    }
    if (*p == '\t') {
      out[w++] = '\\';
      out[w++] = 't';
      continue;
    }
    if (*p == '\n') {
      out[w++] = '\\';
      out[w++] = 'n';
      continue;
    }
    if (*p == '\r') {
      out[w++] = '\\';
      out[w++] = 'r';
      continue;
    }
    out[w++] = (char)*p;
  }
  out[w] = '\0';
  return out;
}

static int tsv_unescape_inplace(char *s) {
  if (!s)
    return -1;
  size_t w = 0;
  for (size_t r = 0; s[r] != '\0'; r++) {
    if (s[r] != '\\') {
      s[w++] = s[r];
      continue;
    }
    r++;
    if (s[r] == '\0')
      return -1;
    switch (s[r]) {
    case '\\':
      s[w++] = '\\';
      break;
    case 't':
      s[w++] = '\t';
      break;
    case 'n':
      s[w++] = '\n';
      break;
    case 'r':
      s[w++] = '\r';
      break;
    default:
      return -1;
    }
  }
  s[w] = '\0';
  return 0;
}

static int normalize_hex_lower_inplace(char *s) {
  if (!s)
    return -1;
  for (size_t i = 0; s[i] != '\0'; i++) {
    int v = hexval((unsigned char)s[i]);
    if (v < 0)
      return -1;
    s[i] = (char)tolower((unsigned char)s[i]);
  }
  return 0;
}

static size_t tsv_split_fields_inplace(char *line, char **fields,
                                       size_t max_fields) {
  if (!line || !fields || max_fields == 0)
    return 0;
  size_t n = 0;
  fields[n++] = line;
  for (char *p = line; *p != '\0'; p++) {
    if (*p != '\t')
      continue;
    *p = '\0';
    if (n >= max_fields)
      break;
    fields[n++] = p + 1;
  }
  return n;
}

static int verify_tsv_stream(FILE *in, int escaped_input) {
  if (!in)
    return 1;

  char *line = NULL;
  size_t cap = 0;
  ssize_t nread;
  uint64_t lineno = 0;

  while ((nread = getline(&line, &cap, in)) != -1) {
    (void)nread;
    lineno++;
    rstrip_newlines(line);
    if (line[0] == '\0')
      continue;
    if (line[0] == '#')
      continue;

    char *fields[8];
    size_t nf = tsv_split_fields_inplace(line, fields, 8);
    if (nf == 3 || nf == 6) {
      fprintf(stderr, "Verify error on line %" PRIu64 ": password is omitted.\n",
              lineno);
      free(line);
      return 2;
    }
    if (nf != 4 && nf != 7) {
      fprintf(stderr,
              "Verify error on line %" PRIu64 ": expected v1 (4 cols) or v2 (7 cols), got %zu.\n",
              lineno, nf);
      free(line);
      return 2;
    }

    char *pw = fields[0];
    char *algo = fields[1];
    char *hash_hex = fields[2];

    if (escaped_input) {
      if (tsv_unescape_inplace(pw) != 0) {
        fprintf(stderr, "Verify error on line %" PRIu64 ": invalid escapes.\n",
                lineno);
        free(line);
        return 2;
      }
    }

    if (normalize_hex_lower_inplace(hash_hex) != 0) {
      fprintf(stderr, "Verify error on line %" PRIu64 ": invalid hash hex.\n",
              lineno);
      free(line);
      return 2;
    }

    // PBKDF2 v2: pw\tpbkdf2-...\thash\tentropy\tsalt_hex\titerations\tdk_len
    if (strncmp(algo, "pbkdf2-", 7) == 0) {
      if (nf != 7) {
        fprintf(stderr,
                "Verify error on line %" PRIu64 ": PBKDF2 requires v2 format.\n",
                lineno);
        free(line);
        return 2;
      }
      const char *prf_name = algo + 7;
      crypto_algo_t prf_algo;
      if (crypto_parse_algo(prf_name, &prf_algo) != 0 ||
          prf_algo == CRYPTO_ALGO_MD5) {
        fprintf(stderr, "Verify error on line %" PRIu64 ": invalid PBKDF2 algo.\n",
                lineno);
        free(line);
        return 2;
      }

      char *salt_hex = fields[4];
      char *iters_s = fields[5];
      char *dklen_s = fields[6];
      if (!salt_hex || salt_hex[0] == '\0' || !iters_s || iters_s[0] == '\0' ||
          !dklen_s || dklen_s[0] == '\0') {
        fprintf(stderr,
                "Verify error on line %" PRIu64 ": missing PBKDF2 parameters.\n",
                lineno);
        free(line);
        return 2;
      }

      uint32_t iters = 0;
      if (parse_u32_strict(iters_s, 1, 0xFFFFFFFFu, &iters) != 0) {
        fprintf(stderr, "Verify error on line %" PRIu64 ": bad iterations.\n",
                lineno);
        free(line);
        return 2;
      }
      size_t dk_len = 0;
      if (parse_size_strict(dklen_s, 1, 1024, &dk_len) != 0) {
        fprintf(stderr, "Verify error on line %" PRIu64 ": bad dk_len.\n", lineno);
        free(line);
        return 2;
      }

      if (strlen(hash_hex) != dk_len * 2) {
        fprintf(stderr,
                "Verify error on line %" PRIu64 ": hash length mismatch for dk_len.\n",
                lineno);
        free(line);
        return 2;
      }

      uint8_t *salt = NULL;
      size_t salt_len = 0;
      if (parse_hex(salt_hex, &salt, &salt_len) != 0 || salt_len == 0 ||
          salt_len > 1024) {
        fprintf(stderr, "Verify error on line %" PRIu64 ": bad salt hex.\n",
                lineno);
        free(salt);
        free(line);
        return 2;
      }

      char *computed = (char *)calloc(1, dk_len * 2 + 1);
      if (!computed) {
        perror("calloc");
        free(salt);
        free(line);
        return 1;
      }
      if (crypto_pbkdf2_hex(prf_algo, pw, salt, salt_len, iters, dk_len,
                            computed, dk_len * 2 + 1) != 0) {
        fprintf(stderr, "Verify error on line %" PRIu64 ": PBKDF2 failed.\n",
                lineno);
        free(computed);
        free(salt);
        free(line);
        return 1;
      }
      if (strcmp(computed, hash_hex) != 0) {
        fprintf(stderr, "Verify mismatch on line %" PRIu64 ".\n", lineno);
        free(computed);
        free(salt);
        free(line);
        return 4;
      }
      free(computed);
      free(salt);
      continue;
    }

    crypto_algo_t d_algo;
    if (crypto_parse_algo(algo, &d_algo) != 0) {
      fprintf(stderr, "Verify error on line %" PRIu64 ": invalid algo.\n", lineno);
      free(line);
      return 2;
    }
    size_t dlen = crypto_digest_size(d_algo);
    if (dlen == 0) {
      fprintf(stderr, "Verify error on line %" PRIu64 ": invalid digest.\n",
              lineno);
      free(line);
      return 2;
    }
    if (strlen(hash_hex) != dlen * 2) {
      fprintf(stderr,
              "Verify error on line %" PRIu64 ": digest length mismatch.\n",
              lineno);
      free(line);
      return 2;
    }

    char computed[64 * 2 + 1];
    if (crypto_digest_hex(d_algo, (const uint8_t *)pw, strlen(pw), computed,
                          sizeof(computed)) != 0) {
      fprintf(stderr, "Verify error on line %" PRIu64 ": digest failed.\n",
              lineno);
      free(line);
      return 1;
    }
    if (strcmp(computed, hash_hex) != 0) {
      fprintf(stderr, "Verify mismatch on line %" PRIu64 ".\n", lineno);
      free(line);
      return 4;
    }
  }

  free(line);
  if (ferror(in)) {
    fprintf(stderr, "Verify error: failed reading input.\n");
    return 1;
  }
  return 0;
}

static const char *json_skip_ws(const char *p) {
  while (p && *p && isspace((unsigned char)*p))
    p++;
  return p;
}

static int json_hex4(const char *p, uint32_t *out_cp) {
  if (!p || !out_cp)
    return -1;
  uint32_t v = 0;
  for (int i = 0; i < 4; i++) {
    int h = hexval((unsigned char)p[i]);
    if (h < 0)
      return -1;
    v = (v << 4) | (uint32_t)h;
  }
  *out_cp = v;
  return 0;
}

static int append_utf8(char **buf, size_t *cap, size_t *len, uint32_t cp) {
  if (!buf || !cap || !len)
    return -1;

  uint8_t tmp[4];
  size_t n = 0;
  if (cp <= 0x7Fu) {
    tmp[0] = (uint8_t)cp;
    n = 1;
  } else if (cp <= 0x7FFu) {
    tmp[0] = (uint8_t)(0xC0u | ((cp >> 6) & 0x1Fu));
    tmp[1] = (uint8_t)(0x80u | (cp & 0x3Fu));
    n = 2;
  } else if (cp <= 0xFFFFu) {
    tmp[0] = (uint8_t)(0xE0u | ((cp >> 12) & 0x0Fu));
    tmp[1] = (uint8_t)(0x80u | ((cp >> 6) & 0x3Fu));
    tmp[2] = (uint8_t)(0x80u | (cp & 0x3Fu));
    n = 3;
  } else if (cp <= 0x10FFFFu) {
    tmp[0] = (uint8_t)(0xF0u | ((cp >> 18) & 0x07u));
    tmp[1] = (uint8_t)(0x80u | ((cp >> 12) & 0x3Fu));
    tmp[2] = (uint8_t)(0x80u | ((cp >> 6) & 0x3Fu));
    tmp[3] = (uint8_t)(0x80u | (cp & 0x3Fu));
    n = 4;
  } else {
    return -1;
  }

  return sbuf_append(buf, cap, len, (const char *)tmp, n);
}

// Parses a JSON string and returns an allocated, unescaped UTF-8 buffer.
// Advances *pp to the character after the closing quote.
static int json_parse_string_alloc(const char **pp, char **out) {
  if (!pp || !*pp || !out)
    return -1;
  const char *p = json_skip_ws(*pp);
  if (!p || *p != '"')
    return -1;
  p++; // skip opening quote

  char *buf = NULL;
  size_t cap = 0, len = 0;

  while (*p) {
    unsigned char c = (unsigned char)*p++;
    if (c == '"') {
      // end
      *pp = p;
      *out = buf ? buf : (char *)calloc(1, 1);
      return *out ? 0 : -1;
    }
    if (c != '\\') {
      if (sbuf_append(&buf, &cap, &len, (const char *)&c, 1) != 0)
        goto fail;
      continue;
    }

    // escape
    unsigned char e = (unsigned char)*p++;
    if (e == 0)
      goto fail;
    switch (e) {
    case '"':
    case '\\':
    case '/':
      if (sbuf_append(&buf, &cap, &len, (const char *)&e, 1) != 0)
        goto fail;
      break;
    case 'b': {
      char x = '\b';
      if (sbuf_append(&buf, &cap, &len, &x, 1) != 0)
        goto fail;
      break;
    }
    case 'f': {
      char x = '\f';
      if (sbuf_append(&buf, &cap, &len, &x, 1) != 0)
        goto fail;
      break;
    }
    case 'n': {
      char x = '\n';
      if (sbuf_append(&buf, &cap, &len, &x, 1) != 0)
        goto fail;
      break;
    }
    case 'r': {
      char x = '\r';
      if (sbuf_append(&buf, &cap, &len, &x, 1) != 0)
        goto fail;
      break;
    }
    case 't': {
      char x = '\t';
      if (sbuf_append(&buf, &cap, &len, &x, 1) != 0)
        goto fail;
      break;
    }
    case 'u': {
      if (!p[0] || !p[1] || !p[2] || !p[3])
        goto fail;
      uint32_t cp = 0;
      if (json_hex4(p, &cp) != 0)
        goto fail;
      p += 4;

      // surrogate pair
      if (cp >= 0xD800u && cp <= 0xDBFFu) {
        if (p[0] != '\\' || p[1] != 'u')
          goto fail;
        p += 2;
        if (!p[0] || !p[1] || !p[2] || !p[3])
          goto fail;
        uint32_t lo = 0;
        if (json_hex4(p, &lo) != 0)
          goto fail;
        p += 4;
        if (lo < 0xDC00u || lo > 0xDFFFu)
          goto fail;
        cp = 0x10000u + (((cp - 0xD800u) << 10) | (lo - 0xDC00u));
      } else if (cp >= 0xDC00u && cp <= 0xDFFFu) {
        goto fail;
      }

      if (append_utf8(&buf, &cap, &len, cp) != 0)
        goto fail;
      break;
    }
    default:
      goto fail;
    }
  }

fail:
  free(buf);
  return -1;
}

static int json_skip_value(const char **pp) {
  if (!pp || !*pp)
    return -1;
  const char *p = json_skip_ws(*pp);
  if (!p || *p == '\0')
    return -1;

  if (*p == '"') {
    char *tmp = NULL;
    if (json_parse_string_alloc(&p, &tmp) != 0)
      return -1;
    free(tmp);
    *pp = p;
    return 0;
  }

  if (*p == '-' || isdigit((unsigned char)*p)) {
    // number (we don't fully validate here)
    const char *q = p;
    while (*q && (isdigit((unsigned char)*q) || *q == '-' || *q == '+' || *q == '.' ||
                  *q == 'e' || *q == 'E'))
      q++;
    if (q == p)
      return -1;
    *pp = q;
    return 0;
  }

  if (strncmp(p, "true", 4) == 0) {
    *pp = p + 4;
    return 0;
  }
  if (strncmp(p, "false", 5) == 0) {
    *pp = p + 5;
    return 0;
  }
  if (strncmp(p, "null", 4) == 0) {
    *pp = p + 4;
    return 0;
  }

  // Keep verify implementation small: JSONL from this tool never emits nested
  // values. Reject to avoid accidentally accepting malformed inputs.
  return -1;
}

static int json_parse_u64_digits(const char **pp, uint64_t *out) {
  if (!pp || !*pp || !out)
    return -1;
  const char *p = json_skip_ws(*pp);
  if (!p || !isdigit((unsigned char)*p))
    return -1;
  uint64_t v = 0;
  while (*p && isdigit((unsigned char)*p)) {
    uint64_t d = (uint64_t)(*p - '0');
    if (v > (UINT64_MAX - d) / 10)
      return -1;
    v = v * 10 + d;
    p++;
  }
  *pp = p;
  *out = v;
  return 0;
}

static int verify_jsonl_stream(FILE *in) {
  if (!in)
    return 1;

  char *line = NULL;
  size_t cap = 0;
  ssize_t nread;
  uint64_t lineno = 0;

  while ((nread = getline(&line, &cap, in)) != -1) {
    (void)nread;
    lineno++;
    rstrip_newlines(line);
    if (line[0] == '\0')
      continue;
    if (line[0] == '#')
      continue;

    const char *p = json_skip_ws(line);
    if (!p || *p != '{') {
      fprintf(stderr, "Verify error on line %" PRIu64 ": expected JSON object.\n",
              lineno);
      free(line);
      return 2;
    }
    p++; // {

    char *pw = NULL;
    char *algo = NULL;
    char *hash_hex = NULL;
    char *salt_hex = NULL;
    uint64_t iters_u64 = 0;
    uint64_t dklen_u64 = 0;
    int have_iters = 0;
    int have_dklen = 0;

    for (;;) {
      p = json_skip_ws(p);
      if (!p) {
        fprintf(stderr, "Verify error on line %" PRIu64 ": parse failed.\n", lineno);
        goto json_fail;
      }
      if (*p == '}') {
        p++;
        break;
      }

      char *key = NULL;
      if (json_parse_string_alloc(&p, &key) != 0) {
        fprintf(stderr, "Verify error on line %" PRIu64 ": bad JSON key.\n",
                lineno);
        free(key);
        goto json_fail;
      }
      p = json_skip_ws(p);
      if (!p || *p != ':') {
        fprintf(stderr, "Verify error on line %" PRIu64 ": expected ':'.\n", lineno);
        free(key);
        goto json_fail;
      }
      p++; // :
      p = json_skip_ws(p);

      if (strcmp(key, "password") == 0) {
        free(pw);
        pw = NULL;
        if (p && *p == '"') {
          if (json_parse_string_alloc(&p, &pw) != 0) {
            fprintf(stderr,
                    "Verify error on line %" PRIu64 ": bad password string.\n",
                    lineno);
            free(key);
            goto json_fail;
          }
        } else {
          // null / missing password isn't verifiable
          if (json_skip_value(&p) != 0) {
            fprintf(stderr,
                    "Verify error on line %" PRIu64 ": bad password value.\n",
                    lineno);
            free(key);
            goto json_fail;
          }
        }
        free(key);
      } else if (strcmp(key, "algo") == 0) {
        free(algo);
        algo = NULL;
        if (json_parse_string_alloc(&p, &algo) != 0) {
          fprintf(stderr, "Verify error on line %" PRIu64 ": bad algo string.\n",
                  lineno);
          free(key);
          goto json_fail;
        }
        free(key);
      } else if (strcmp(key, "hash_hex") == 0) {
        free(hash_hex);
        hash_hex = NULL;
        if (json_parse_string_alloc(&p, &hash_hex) != 0) {
          fprintf(stderr,
                  "Verify error on line %" PRIu64 ": bad hash_hex string.\n",
                  lineno);
          free(key);
          goto json_fail;
        }
        free(key);
      } else if (strcmp(key, "salt_hex") == 0) {
        free(salt_hex);
        salt_hex = NULL;
        if (json_parse_string_alloc(&p, &salt_hex) != 0) {
          fprintf(stderr,
                  "Verify error on line %" PRIu64 ": bad salt_hex string.\n",
                  lineno);
          free(key);
          goto json_fail;
        }
        free(key);
      } else if (strcmp(key, "iterations") == 0) {
        if (json_parse_u64_digits(&p, &iters_u64) != 0) {
          fprintf(stderr,
                  "Verify error on line %" PRIu64 ": bad iterations number.\n",
                  lineno);
          free(key);
          goto json_fail;
        }
        have_iters = 1;
        free(key);
      } else if (strcmp(key, "dk_len") == 0) {
        if (json_parse_u64_digits(&p, &dklen_u64) != 0) {
          fprintf(stderr, "Verify error on line %" PRIu64 ": bad dk_len number.\n",
                  lineno);
          free(key);
          goto json_fail;
        }
        have_dklen = 1;
        free(key);
      } else {
        if (json_skip_value(&p) != 0) {
          fprintf(stderr, "Verify error on line %" PRIu64 ": bad JSON value.\n",
                  lineno);
          free(key);
          goto json_fail;
        }
        free(key);
      }

      p = json_skip_ws(p);
      if (*p == ',') {
        p++;
        continue;
      }
      if (*p == '}') {
        p++;
        break;
      }
      fprintf(stderr, "Verify error on line %" PRIu64 ": expected ',' or '}'.\n",
              lineno);
      goto json_fail;
    }

    if (!pw) {
      fprintf(stderr, "Verify error on line %" PRIu64 ": password is omitted.\n",
              lineno);
      goto json_fail;
    }
    if (!algo || !hash_hex) {
      fprintf(stderr, "Verify error on line %" PRIu64 ": missing required fields.\n",
              lineno);
      goto json_fail;
    }
    if (normalize_hex_lower_inplace(hash_hex) != 0) {
      fprintf(stderr, "Verify error on line %" PRIu64 ": invalid hash hex.\n",
              lineno);
      goto json_fail;
    }

    if (strncmp(algo, "pbkdf2-", 7) == 0) {
      if (!salt_hex || !have_iters || !have_dklen) {
        fprintf(stderr,
                "Verify error on line %" PRIu64 ": missing PBKDF2 parameters.\n",
                lineno);
        goto json_fail;
      }

      const char *prf_name = algo + 7;
      crypto_algo_t prf_algo;
      if (crypto_parse_algo(prf_name, &prf_algo) != 0 ||
          prf_algo == CRYPTO_ALGO_MD5) {
        fprintf(stderr, "Verify error on line %" PRIu64 ": invalid PBKDF2 algo.\n",
                lineno);
        goto json_fail;
      }

      if (iters_u64 == 0 || iters_u64 > 0xFFFFFFFFu) {
        fprintf(stderr, "Verify error on line %" PRIu64 ": bad iterations.\n",
                lineno);
        goto json_fail;
      }
      if (dklen_u64 == 0 || dklen_u64 > 1024u) {
        fprintf(stderr, "Verify error on line %" PRIu64 ": bad dk_len.\n", lineno);
        goto json_fail;
      }
      uint32_t iters = (uint32_t)iters_u64;
      size_t dk_len = (size_t)dklen_u64;

      if (strlen(hash_hex) != dk_len * 2) {
        fprintf(stderr,
                "Verify error on line %" PRIu64 ": hash length mismatch for dk_len.\n",
                lineno);
        goto json_fail;
      }

      uint8_t *salt = NULL;
      size_t salt_len = 0;
      if (parse_hex(salt_hex, &salt, &salt_len) != 0 || salt_len == 0 ||
          salt_len > 1024) {
        fprintf(stderr, "Verify error on line %" PRIu64 ": bad salt hex.\n",
                lineno);
        free(salt);
        goto json_fail;
      }

      char *computed = (char *)calloc(1, dk_len * 2 + 1);
      if (!computed) {
        perror("calloc");
        free(salt);
        goto json_internal;
      }
      if (crypto_pbkdf2_hex(prf_algo, pw, salt, salt_len, iters, dk_len,
                            computed, dk_len * 2 + 1) != 0) {
        fprintf(stderr, "Verify error on line %" PRIu64 ": PBKDF2 failed.\n",
                lineno);
        free(computed);
        free(salt);
        goto json_internal;
      }
      if (strcmp(computed, hash_hex) != 0) {
        fprintf(stderr, "Verify mismatch on line %" PRIu64 ".\n", lineno);
        free(computed);
        free(salt);
        goto json_mismatch;
      }
      free(computed);
      free(salt);
    } else {
      crypto_algo_t d_algo;
      if (crypto_parse_algo(algo, &d_algo) != 0) {
        fprintf(stderr, "Verify error on line %" PRIu64 ": invalid algo.\n",
                lineno);
        goto json_fail;
      }
      size_t dlen = crypto_digest_size(d_algo);
      if (dlen == 0) {
        fprintf(stderr, "Verify error on line %" PRIu64 ": invalid digest.\n",
                lineno);
        goto json_fail;
      }
      if (strlen(hash_hex) != dlen * 2) {
        fprintf(stderr,
                "Verify error on line %" PRIu64 ": digest length mismatch.\n",
                lineno);
        goto json_fail;
      }

      char computed[64 * 2 + 1];
      if (crypto_digest_hex(d_algo, (const uint8_t *)pw, strlen(pw), computed,
                            sizeof(computed)) != 0) {
        fprintf(stderr, "Verify error on line %" PRIu64 ": digest failed.\n",
                lineno);
        goto json_internal;
      }
      if (strcmp(computed, hash_hex) != 0) {
        fprintf(stderr, "Verify mismatch on line %" PRIu64 ".\n", lineno);
        goto json_mismatch;
      }
    }

    free(pw);
    free(algo);
    free(hash_hex);
    free(salt_hex);
    continue;

json_mismatch:
    free(pw);
    free(algo);
    free(hash_hex);
    free(salt_hex);
    free(line);
    return 4;

json_internal:
    free(pw);
    free(algo);
    free(hash_hex);
    free(salt_hex);
    free(line);
    return 1;

json_fail:
    free(pw);
    free(algo);
    free(hash_hex);
    free(salt_hex);
    free(line);
    return 2;
  }

  free(line);
  if (ferror(in)) {
    fprintf(stderr, "Verify error: failed reading input.\n");
    return 1;
  }
  return 0;
}

static int parse_stream_format(const char *s, stream_format_t *out_fmt) {
  if (!s || !out_fmt)
    return -1;
  char buf[16];
  size_t n = strlen(s);
  if (n == 0 || n >= sizeof(buf))
    return -1;
  for (size_t i = 0; i < n; i++)
    buf[i] = (char)tolower((unsigned char)s[i]);
  buf[n] = '\0';
  if (strcmp(buf, "tsv") == 0) {
    *out_fmt = STREAM_TSV;
    return 0;
  }
  if (strcmp(buf, "jsonl") == 0) {
    *out_fmt = STREAM_JSONL;
    return 0;
  }
  return -1;
}

static void json_fprint_string(FILE *out, const char *s) {
  fputc('"', out);
  for (const unsigned char *p = (const unsigned char *)s; p && *p; p++) {
    unsigned char c = *p;
    switch (c) {
    case '"':
      fputs("\\\"", out);
      break;
    case '\\':
      fputs("\\\\", out);
      break;
    case '\b':
      fputs("\\b", out);
      break;
    case '\f':
      fputs("\\f", out);
      break;
    case '\n':
      fputs("\\n", out);
      break;
    case '\r':
      fputs("\\r", out);
      break;
    case '\t':
      fputs("\\t", out);
      break;
    default:
      if (c < 0x20) {
        // Keep output valid JSON even for control bytes.
        fprintf(out, "\\u%04x", (unsigned int)c);
      } else {
        fputc((int)c, out);
      }
    }
  }
  fputc('"', out);
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
  int output_set = 0;
  int append = 0;
  stream_format_t output_stream_fmt = STREAM_TSV;
  int output_stream_set = 0;
  stream_format_t input_stream_fmt = STREAM_TSV;
  int input_stream_set = 0;
  int header = 0;
  int omit_password = 0;
  int escape_tsv = 0;
  int verify = 0;
  hash_mode_t mode = MODE_DIGEST;
  crypto_algo_t digest_algo = CRYPTO_ALGO_SHA256;
  crypto_algo_t pbkdf2_prf_algo = CRYPTO_ALGO_SHA256;
  const char *algo_name = "sha256";
  int algo_set = 0;

  output_format_t outfmt = OUTFMT_V1;
  int format_set = 0;

  uint32_t pbkdf2_iterations = 0;
  int iterations_set = 0;
  size_t pbkdf2_dk_len = 32;
  int dk_len_set = 0;
  size_t pbkdf2_salt_len = 16;
  int salt_len_set = 0;
  const char *salt_hex_arg = NULL;
  int salt_hex_set = 0;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--verify") == 0) {
      verify = 1;
      continue;
    }
    if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
      input_path = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
      output_path = argv[++i];
      output_set = 1;
      continue;
    }
    if (strcmp(argv[i], "--append") == 0) {
      append = 1;
      continue;
    }
    if (strcmp(argv[i], "--output-format") == 0 && i + 1 < argc) {
      stream_format_t f;
      if (parse_stream_format(argv[++i], &f) != 0) {
        fprintf(stderr, "Invalid --output-format value (use tsv or jsonl).\n");
        return 2;
      }
      output_stream_fmt = f;
      output_stream_set = 1;
      continue;
    }
    if (strcmp(argv[i], "--input-format") == 0 && i + 1 < argc) {
      stream_format_t f;
      if (parse_stream_format(argv[++i], &f) != 0) {
        fprintf(stderr, "Invalid --input-format value (use tsv or jsonl).\n");
        return 2;
      }
      input_stream_fmt = f;
      input_stream_set = 1;
      continue;
    }
    if (strcmp(argv[i], "--header") == 0) {
      header = 1;
      continue;
    }
    if (strcmp(argv[i], "--omit-password") == 0) {
      omit_password = 1;
      continue;
    }
    if (strcmp(argv[i], "--escape-tsv") == 0) {
      escape_tsv = 1;
      continue;
    }
    if (strcmp(argv[i], "--algo") == 0 && i + 1 < argc) {
      const char *val = argv[++i];
      algo_set = 1;
      if (parse_algo_or_kdf(val, &mode, &digest_algo, &pbkdf2_prf_algo,
                            &algo_name) != 0) {
        fprintf(stderr, "Unsupported --algo value.\n");
        usage(argv[0]);
        return 2;
      }
      continue;
    }
    if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
      uint32_t v = 0;
      if (parse_u32_strict(argv[++i], 1, 0xFFFFFFFFu, &v) != 0) {
        fprintf(stderr, "Invalid --iterations value.\n");
        return 2;
      }
      pbkdf2_iterations = v;
      iterations_set = 1;
      continue;
    }
    if (strcmp(argv[i], "--dk-len") == 0 && i + 1 < argc) {
      size_t v = 0;
      if (parse_size_strict(argv[++i], 1, 1024, &v) != 0) {
        fprintf(stderr, "Invalid --dk-len value (1..1024).\n");
        return 2;
      }
      pbkdf2_dk_len = v;
      dk_len_set = 1;
      continue;
    }
    if (strcmp(argv[i], "--salt-len") == 0 && i + 1 < argc) {
      size_t v = 0;
      if (parse_size_strict(argv[++i], 1, 1024, &v) != 0) {
        fprintf(stderr, "Invalid --salt-len value (1..1024).\n");
        return 2;
      }
      pbkdf2_salt_len = v;
      salt_len_set = 1;
      continue;
    }
    if (strcmp(argv[i], "--salt-hex") == 0 && i + 1 < argc) {
      salt_hex_arg = argv[++i];
      salt_hex_set = 1;
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

  if (verify) {
    if (omit_password) {
      fprintf(stderr, "--verify requires password column; do not use --omit-password.\n");
      return 2;
    }
    if (output_set || append || output_stream_set || header || algo_set || format_set ||
        iterations_set || dk_len_set || salt_len_set || salt_hex_set) {
      fprintf(stderr,
              "--verify does not accept output/algo/format/PBKDF2 parameter flags.\n");
      return 2;
    }
    if (input_stream_fmt == STREAM_JSONL && escape_tsv) {
      fprintf(stderr, "--escape-tsv is only valid for TSV verification.\n");
      return 2;
    }

    FILE *vin = stdin;
    int vin_is_stdio = 1;
    if (strcmp(input_path, "-") != 0) {
      vin = fopen(input_path, "r");
      vin_is_stdio = 0;
      if (!vin) {
        perror("Error opening input file");
        return 1;
      }
    }
    int rc = 0;
    if (input_stream_fmt == STREAM_JSONL) {
      rc = verify_jsonl_stream(vin);
    } else {
      rc = verify_tsv_stream(vin, escape_tsv);
    }
    if (!vin_is_stdio)
      fclose(vin);
    return rc;
  }

  if (input_stream_set) {
    fprintf(stderr, "--input-format is only valid with --verify.\n");
    return 2;
  }

  if (output_stream_fmt == STREAM_JSONL) {
    if (escape_tsv) {
      fprintf(stderr, "--escape-tsv is only valid with --output-format tsv.\n");
      return 2;
    }
    if (header) {
      fprintf(stderr, "--header is only valid with --output-format tsv.\n");
      return 2;
    }
    if (format_set) {
      fprintf(stderr, "--format is only valid with --output-format tsv.\n");
      return 2;
    }
  }

  if (mode == MODE_DIGEST) {
    if (iterations_set || dk_len_set || salt_len_set || salt_hex_set) {
      fprintf(stderr,
              "PBKDF2-only flags (--iterations/--dk-len/--salt-len/--salt-hex) "
              "require a PBKDF2 algo.\n");
      return 2;
    }
  }

  if (mode == MODE_PBKDF2) {
    // PBKDF2 needs salt+params in output. Default to v2 unless user forced v1.
    if (format_set && outfmt == OUTFMT_V1) {
      fprintf(stderr, "PBKDF2 requires --format v2.\n");
      return 2;
    }
    if (!format_set)
      outfmt = OUTFMT_V2;

    // Iterations default depends on the PRF.
    if (!iterations_set) {
      switch (pbkdf2_prf_algo) {
      case CRYPTO_ALGO_SHA1:
        pbkdf2_iterations = 1300000;
        break;
      case CRYPTO_ALGO_SHA256:
        pbkdf2_iterations = 600000;
        break;
      case CRYPTO_ALGO_SHA512:
        pbkdf2_iterations = 210000;
        break;
      default:
        fprintf(stderr, "Unsupported PBKDF2 PRF.\n");
        return 2;
      }
    }
    if (pbkdf2_iterations == 0) {
      fprintf(stderr, "Invalid PBKDF2 iterations.\n");
      return 2;
    }
  }

  FILE *in = stdin;
  int in_is_stdio = 1;
  if (strcmp(input_path, "-") != 0) {
    in = fopen(input_path, "r");
    in_is_stdio = 0;
    if (!in) {
      perror("Error opening input file");
      return 1;
    }
  }

  FILE *out = stdout;
  int out_is_stdio = 1;
  if (output_path && strcmp(output_path, "-") != 0) {
    out = fopen(output_path, append ? "a" : "w");
    out_is_stdio = 0;
    if (!out) {
      perror("Error opening output file");
      if (!in_is_stdio)
        fclose(in);
      return 1;
    }
  }

  uint8_t *fixed_salt = NULL;
  size_t fixed_salt_len = 0;
  if (salt_hex_arg) {
    if (parse_hex(salt_hex_arg, &fixed_salt, &fixed_salt_len) != 0) {
      fprintf(stderr, "Invalid --salt-hex value (must be even-length hex).\n");
      if (!in_is_stdio)
        fclose(in);
      if (!out_is_stdio)
        fclose(out);
      return 2;
    }
    if (fixed_salt_len == 0) {
      fprintf(stderr, "--salt-hex must not be empty.\n");
      free(fixed_salt);
      if (!in_is_stdio)
        fclose(in);
      if (!out_is_stdio)
        fclose(out);
      return 2;
    }
    if (fixed_salt_len > 1024) {
      fprintf(stderr, "--salt-hex decoded length must be <= 1024 bytes.\n");
      free(fixed_salt);
      if (!in_is_stdio)
        fclose(in);
      if (!out_is_stdio)
        fclose(out);
      return 2;
    }
  }

  if (mode == MODE_DIGEST) {
    size_t digest_len = crypto_digest_size(digest_algo);
    if (digest_len == 0) {
      fprintf(stderr, "Internal error: unknown digest size.\n");
      if (!in_is_stdio)
        fclose(in);
      if (!out_is_stdio)
        fclose(out);
      return 1;
    }
  }

  char *line = NULL;
  size_t line_cap = 0;
  ssize_t nread;
  int warned_tabs = 0;

  if (output_stream_fmt == STREAM_TSV && header) {
    if (outfmt == OUTFMT_V1) {
      if (!omit_password) {
        fprintf(out, "#password\talgo\thash_hex\tentropy_bits\n");
      } else {
        fprintf(out, "#algo\thash_hex\tentropy_bits\n");
      }
    } else {
      if (!omit_password) {
        fprintf(out, "#password\talgo\thash_hex\tentropy_bits\tsalt_hex\titerations\tdk_len\n");
      } else {
        fprintf(out, "#algo\thash_hex\tentropy_bits\tsalt_hex\titerations\tdk_len\n");
      }
    }
  }

  while ((nread = getline(&line, &line_cap, in)) != -1) {
    (void)nread;
    rstrip_newlines(line);
    if (line[0] == '\0')
      continue;

    if (output_stream_fmt == STREAM_TSV && !omit_password && !escape_tsv &&
        !warned_tabs && strchr(line, '\t') != NULL) {
      fprintf(stderr,
              "Warning: input contains a TAB character; output TSV will be ambiguous. "
              "Use --escape-tsv or --omit-password.\n");
      warned_tabs = 1;
    }

    double entropy = estimate_entropy_bits(line);
    const char *pw_field = line;
    char *pw_escaped = NULL;
    if (!omit_password && escape_tsv) {
      pw_escaped = tsv_escape_alloc(line);
      if (pw_escaped)
        pw_field = pw_escaped;
    }

    if (mode == MODE_DIGEST) {
      char hash_hex[64 * 2 + 1];
      if (crypto_digest_hex(digest_algo, (const uint8_t *)line, strlen(line),
                            hash_hex, sizeof(hash_hex)) != 0) {
        fprintf(stderr, "Hashing failed for a line.\n");
        free(pw_escaped);
        free(line);
        free(fixed_salt);
        if (!in_is_stdio)
          fclose(in);
        if (!out_is_stdio)
          fclose(out);
        return 1;
      }

      if (output_stream_fmt == STREAM_TSV) {
        if (outfmt == OUTFMT_V1) {
          if (!omit_password) {
            fprintf(out, "%s\t%s\t%s\t%.2f\n", pw_field,
                    crypto_algo_name(digest_algo), hash_hex, entropy);
          } else {
            fprintf(out, "%s\t%s\t%.2f\n", crypto_algo_name(digest_algo), hash_hex,
                    entropy);
          }
        } else {
          if (!omit_password) {
            fprintf(out, "%s\t%s\t%s\t%.2f\t\t\t\n", pw_field,
                    crypto_algo_name(digest_algo), hash_hex, entropy);
          } else {
            fprintf(out, "%s\t%s\t%.2f\t\t\t\n", crypto_algo_name(digest_algo),
                    hash_hex, entropy);
          }
        }
      } else {
        // JSONL
        fputc('{', out);
        int first = 1;
        if (!omit_password) {
          fputs("\"password\":", out);
          json_fprint_string(out, line);
          first = 0;
        }
        if (!first)
          fputc(',', out);
        fputs("\"algo\":", out);
        json_fprint_string(out, crypto_algo_name(digest_algo));
        fputc(',', out);
        fputs("\"hash_hex\":", out);
        json_fprint_string(out, hash_hex);
        fprintf(out, ",\"entropy_bits\":%.2f", entropy);
        fputs("}\n", out);
      }
      free(pw_escaped);
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
        free(pw_escaped);
        free(line);
        if (!in_is_stdio)
          fclose(in);
        if (!out_is_stdio)
          fclose(out);
        return 1;
      }
      if (crypto_random_bytes(tmp_salt, salt_len) != 0) {
        fprintf(stderr, "Salt generation failed.\n");
        free(tmp_salt);
        free(pw_escaped);
        free(line);
        if (!in_is_stdio)
          fclose(in);
        if (!out_is_stdio)
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
      free(pw_escaped);
      free(line);
      free(fixed_salt);
      if (!in_is_stdio)
        fclose(in);
      if (!out_is_stdio)
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
      free(pw_escaped);
      free(line);
      free(fixed_salt);
      if (!in_is_stdio)
        fclose(in);
      if (!out_is_stdio)
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

    if (output_stream_fmt == STREAM_TSV) {
      if (!omit_password) {
        fprintf(out, "%s\t%s\t%s\t%.2f\t%s\t%u\t%zu\n", pw_field, algo_name,
                hash_hex, entropy, salt_hex, pbkdf2_iterations, pbkdf2_dk_len);
      } else {
        fprintf(out, "%s\t%s\t%.2f\t%s\t%u\t%zu\n", algo_name, hash_hex, entropy,
                salt_hex, pbkdf2_iterations, pbkdf2_dk_len);
      }
    } else {
      fputc('{', out);
      int first = 1;
      if (!omit_password) {
        fputs("\"password\":", out);
        json_fprint_string(out, line);
        first = 0;
      }
      if (!first)
        fputc(',', out);
      fputs("\"algo\":", out);
      json_fprint_string(out, algo_name);
      fputc(',', out);
      fputs("\"hash_hex\":", out);
      json_fprint_string(out, hash_hex);
      fprintf(out, ",\"entropy_bits\":%.2f", entropy);
      fputc(',', out);
      fputs("\"salt_hex\":", out);
      json_fprint_string(out, salt_hex);
      fprintf(out, ",\"iterations\":%u", pbkdf2_iterations);
      fprintf(out, ",\"dk_len\":%zu", pbkdf2_dk_len);
      fputs("}\n", out);
    }

    free(pw_escaped);
    free(hash_hex);
    free(salt_hex);
    free(tmp_salt);
  }

  free(line);
  free(fixed_salt);

  if (!in_is_stdio)
    fclose(in);
  if (!out_is_stdio)
    fclose(out);
  return 0;
}

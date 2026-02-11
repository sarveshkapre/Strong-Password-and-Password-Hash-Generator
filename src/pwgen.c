#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"

static void usage(const char *argv0) {
  fprintf(stderr,
          "Usage: %s [--length N] [--count N] [--lower|--no-lower] [--upper|--no-upper]\n"
          "          [--digits|--no-digits] [--symbols|--no-symbols] [--avoid-ambiguous]\n"
          "          [--chars STR] [--exclude STR] [--require-each|--no-require-each]\n"
          "          [--min-lower N] [--min-upper N] [--min-digits N] [--min-symbols N]\n"
          "          [--show-entropy]\n"
          "       %s --passphrase --wordlist PATH [--words N] [--separator STR]\n"
          "          [--capitalize] [--include-number] [--count N] [--show-entropy]\n"
          "\n"
          "Defaults (password): length=20, count=1, lower/upper/digits/symbols enabled, require-each enabled,\n"
          "                     min-lower/min-upper/min-digits/min-symbols=0.\n"
          "Defaults (passphrase): words=4, separator='-', capitalize disabled, include-number disabled.\n"
          "Output: one value per line. With --show-entropy: value<TAB>entropy_bits\n",
          argv0, argv0);
}

static int parse_size_strict(const char *s, size_t min, size_t max, size_t *out) {
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

static int rand_u32(uint32_t *out) {
  uint8_t b[4];
  if (crypto_random_bytes(b, sizeof(b)) != 0)
    return -1;
  *out = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) |
         (uint32_t)b[3];
  return 0;
}

// Rejection sampling for unbiased selection in [0, n).
static int rand_index(size_t n, size_t *out_idx) {
  if (n == 0 || !out_idx)
    return -1;
  uint32_t x;
  uint32_t limit = (uint32_t)(UINT32_MAX - (UINT32_MAX % (uint32_t)n));
  do {
    if (rand_u32(&x) != 0)
      return -1;
  } while (x >= limit);
  *out_idx = (size_t)(x % (uint32_t)n);
  return 0;
}

static void remove_chars(char *set, const char *remove) {
  size_t w = 0;
  for (size_t r = 0; set[r] != '\0'; r++) {
    if (strchr(remove, set[r]) != NULL)
      continue;
    set[w++] = set[r];
  }
  set[w] = '\0';
}

static int has_unsupported_chars(const char *s) {
  if (!s)
    return 0;
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    if (*p == '\t' || *p == '\n' || *p == '\r' || iscntrl(*p))
      return 1;
  }
  return 0;
}

static int build_pool_from_chars(const char *chars, int avoid_ambiguous, char *out,
                                 size_t out_cap) {
  if (!chars || !out || out_cap == 0)
    return -1;
  if (has_unsupported_chars(chars))
    return -2;

  uint8_t seen[256];
  memset(seen, 0, sizeof(seen));

  size_t w = 0;
  for (const unsigned char *p = (const unsigned char *)chars; *p; p++) {
    unsigned char c = *p;
    if (!seen[c]) {
      if (w + 1 >= out_cap)
        return -1;
      out[w++] = (char)c;
      seen[c] = 1;
    }
  }
  out[w] = '\0';

  if (avoid_ambiguous) {
    // Common “look-alike” set.
    remove_chars(out, "O0Il1");
  }

  return out[0] ? 0 : -1;
}

static void build_category_sets(const char *pool, char *lower, char *upper,
                                char *digits, char *symbols) {
  if (!pool || !lower || !upper || !digits || !symbols)
    return;
  size_t li = 0, ui = 0, di = 0, si = 0;
  for (const unsigned char *p = (const unsigned char *)pool; *p; p++) {
    if (islower(*p))
      lower[li++] = (char)*p;
    else if (isupper(*p))
      upper[ui++] = (char)*p;
    else if (isdigit(*p))
      digits[di++] = (char)*p;
    else if (ispunct(*p))
      symbols[si++] = (char)*p;
  }
  lower[li] = '\0';
  upper[ui] = '\0';
  digits[di] = '\0';
  symbols[si] = '\0';
}

static int shuffle(char *s, size_t len) {
  if (len < 2)
    return 0;
  for (size_t i = len - 1; i > 0; i--) {
    size_t j = 0;
    if (rand_index(i + 1, &j) != 0)
      return -1;
    char tmp = s[i];
    s[i] = s[j];
    s[j] = tmp;
  }
  return 0;
}

static int shuffle_indices(size_t *a, size_t len) {
  if (len < 2)
    return 0;
  for (size_t i = len - 1; i > 0; i--) {
    size_t j = 0;
    if (rand_index(i + 1, &j) != 0)
      return -1;
    size_t tmp = a[i];
    a[i] = a[j];
    a[j] = tmp;
  }
  return 0;
}

static int assign_required_chars(char *out, const char *set, size_t set_len, size_t count,
                                 const size_t *positions, size_t *pidx) {
  if (count == 0)
    return 0;
  if (!out || !set || set_len == 0 || !positions || !pidx)
    return -1;
  for (size_t i = 0; i < count; i++) {
    size_t idx = 0;
    if (rand_index(set_len, &idx) != 0)
      return -1;
    size_t pos = positions[(*pidx)++];
    out[pos] = set[idx];
  }
  return 0;
}

static double entropy_bits(size_t pool, size_t length) {
  if (pool <= 1 || length == 0)
    return 0.0;
  return log2((double)pool) * (double)length;
}

static void trim_ascii_space(char *s) {
  if (!s)
    return;
  size_t n = strlen(s);
  while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ' ||
                   s[n - 1] == '\t')) {
    s[n - 1] = '\0';
    n--;
  }
  size_t i = 0;
  while (s[i] == ' ' || s[i] == '\t')
    i++;
  if (i > 0)
    memmove(s, s + i, strlen(s + i) + 1);
}

static void free_wordlist(char **words, size_t count);

static int read_wordlist(const char *path, char ***out_words, size_t *out_count,
                         size_t *out_max_word_len) {
  if (!path || !out_words || !out_count || !out_max_word_len)
    return -1;
  *out_words = NULL;
  *out_count = 0;
  *out_max_word_len = 0;

  FILE *fp = fopen(path, "r");
  if (!fp)
    return -1;

  char *line = NULL;
  size_t cap = 0;
  ssize_t nread;

  while ((nread = getline(&line, &cap, fp)) != -1) {
    (void)nread;
    trim_ascii_space(line);
    if (line[0] == '\0')
      continue;
    if (line[0] == '#')
      continue;

    size_t len = strlen(line);
    char *w = (char *)calloc(1, len + 1);
    if (!w)
      goto fail;
    memcpy(w, line, len);
    w[len] = '\0';

    char **tmp = (char **)realloc(*out_words, (*out_count + 1) * sizeof(char *));
    if (!tmp) {
      free(w);
      goto fail;
    }
    *out_words = tmp;
    (*out_words)[*out_count] = w;
    (*out_count)++;
    if (len > *out_max_word_len)
      *out_max_word_len = len;
  }

  free(line);
  fclose(fp);
  return *out_count > 0 ? 0 : -1;

fail:
  free(line);
  fclose(fp);
  free_wordlist(*out_words, *out_count);
  *out_words = NULL;
  *out_count = 0;
  *out_max_word_len = 0;
  return -1;
}

static void free_wordlist(char **words, size_t count) {
  if (!words)
    return;
  for (size_t i = 0; i < count; i++)
    free(words[i]);
  free(words);
}

static int append_bytes(char **buf, size_t *cap, size_t *len, const char *src,
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

static int append_word_capitalized(char **buf, size_t *cap, size_t *len,
                                   const char *word) {
  if (!word)
    return -1;
  size_t n = strlen(word);
  if (n == 0)
    return 0;
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)word[i];
    if (i == 0 && isalpha(c))
      c = (unsigned char)toupper(c);
    else if (isalpha(c))
      c = (unsigned char)tolower(c);
    if (append_bytes(buf, cap, len, (const char *)&c, 1) != 0)
      return -1;
  }
  return 0;
}

int main(int argc, char **argv) {
  size_t length = 20;
  size_t count = 1;
  int use_lower = 1, use_upper = 1, use_digits = 1, use_symbols = 1;
  int avoid_ambiguous = 0;
  int require_each = 1;
  int show_entropy = 0;
  size_t min_lower = 0, min_upper = 0, min_digits = 0, min_symbols = 0;

  int passphrase = 0;
  const char *wordlist_path = NULL;
  size_t words = 4;
  const char *separator = "-";
  int capitalize = 0;
  int include_number = 0;
  const char *custom_chars = NULL;
  const char *exclude_chars = NULL;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--length") == 0 && i + 1 < argc) {
      if (parse_size_strict(argv[++i], 1, 4096, &length) != 0) {
        fprintf(stderr, "Invalid --length value (1..4096).\n");
        return 2;
      }
      continue;
    }
    if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
      if (parse_size_strict(argv[++i], 1, 100000, &count) != 0) {
        fprintf(stderr, "Invalid --count value (1..100000).\n");
        return 2;
      }
      continue;
    }
    if (strcmp(argv[i], "--lower") == 0) {
      use_lower = 1;
      continue;
    }
    if (strcmp(argv[i], "--no-lower") == 0) {
      use_lower = 0;
      continue;
    }
    if (strcmp(argv[i], "--upper") == 0) {
      use_upper = 1;
      continue;
    }
    if (strcmp(argv[i], "--no-upper") == 0) {
      use_upper = 0;
      continue;
    }
    if (strcmp(argv[i], "--digits") == 0) {
      use_digits = 1;
      continue;
    }
    if (strcmp(argv[i], "--no-digits") == 0) {
      use_digits = 0;
      continue;
    }
    if (strcmp(argv[i], "--symbols") == 0) {
      use_symbols = 1;
      continue;
    }
    if (strcmp(argv[i], "--no-symbols") == 0) {
      use_symbols = 0;
      continue;
    }
    if (strcmp(argv[i], "--avoid-ambiguous") == 0) {
      avoid_ambiguous = 1;
      continue;
    }
    if (strcmp(argv[i], "--chars") == 0 && i + 1 < argc) {
      custom_chars = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--exclude") == 0 && i + 1 < argc) {
      exclude_chars = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--require-each") == 0) {
      require_each = 1;
      continue;
    }
    if (strcmp(argv[i], "--no-require-each") == 0) {
      require_each = 0;
      continue;
    }
    if (strcmp(argv[i], "--min-lower") == 0 && i + 1 < argc) {
      if (parse_size_strict(argv[++i], 0, 4096, &min_lower) != 0) {
        fprintf(stderr, "Invalid --min-lower value (0..4096).\n");
        return 2;
      }
      continue;
    }
    if (strcmp(argv[i], "--min-upper") == 0 && i + 1 < argc) {
      if (parse_size_strict(argv[++i], 0, 4096, &min_upper) != 0) {
        fprintf(stderr, "Invalid --min-upper value (0..4096).\n");
        return 2;
      }
      continue;
    }
    if (strcmp(argv[i], "--min-digits") == 0 && i + 1 < argc) {
      if (parse_size_strict(argv[++i], 0, 4096, &min_digits) != 0) {
        fprintf(stderr, "Invalid --min-digits value (0..4096).\n");
        return 2;
      }
      continue;
    }
    if (strcmp(argv[i], "--min-symbols") == 0 && i + 1 < argc) {
      if (parse_size_strict(argv[++i], 0, 4096, &min_symbols) != 0) {
        fprintf(stderr, "Invalid --min-symbols value (0..4096).\n");
        return 2;
      }
      continue;
    }
    if (strcmp(argv[i], "--show-entropy") == 0) {
      show_entropy = 1;
      continue;
    }
    if (strcmp(argv[i], "--passphrase") == 0) {
      passphrase = 1;
      continue;
    }
    if (strcmp(argv[i], "--wordlist") == 0 && i + 1 < argc) {
      wordlist_path = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--words") == 0 && i + 1 < argc) {
      if (parse_size_strict(argv[++i], 1, 64, &words) != 0) {
        fprintf(stderr, "Invalid --words value (1..64).\n");
        return 2;
      }
      continue;
    }
    if (strcmp(argv[i], "--separator") == 0 && i + 1 < argc) {
      separator = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--capitalize") == 0) {
      capitalize = 1;
      continue;
    }
    if (strcmp(argv[i], "--include-number") == 0) {
      include_number = 1;
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

  if (count == 0) {
    fprintf(stderr, "count must be > 0.\n");
    return 2;
  }
  if (!passphrase && length == 0) {
    fprintf(stderr, "length must be > 0.\n");
    return 2;
  }

  if (passphrase) {
    if (custom_chars) {
      fprintf(stderr, "--chars is not valid with --passphrase.\n");
      return 2;
    }
    if (exclude_chars) {
      fprintf(stderr, "--exclude is not valid with --passphrase.\n");
      return 2;
    }
    if (min_lower > 0 || min_upper > 0 || min_digits > 0 || min_symbols > 0) {
      fprintf(stderr, "--min-lower/--min-upper/--min-digits/--min-symbols are not valid with --passphrase.\n");
      return 2;
    }
    if (!wordlist_path) {
      fprintf(stderr, "--passphrase requires --wordlist PATH.\n");
      return 2;
    }
    if (separator == NULL)
      separator = "-";

    char **wl = NULL;
    size_t wl_count = 0;
    size_t wl_max_word_len = 0;
    if (read_wordlist(wordlist_path, &wl, &wl_count, &wl_max_word_len) != 0) {
      fprintf(stderr, "Failed to read wordlist: %s\n", wordlist_path);
      return 1;
    }

    double ent = 0.0;
    if (wl_count > 1)
      ent = log2((double)wl_count) * (double)words;
    if (include_number)
      ent += log2(10.0);

    size_t sep_len = strlen(separator);

    for (size_t n = 0; n < count; n++) {
      size_t out_cap = 0;
      // Pre-size to avoid a few reallocs for typical wordlists.
      size_t est = words * (wl_max_word_len + sep_len) + 32;
      if (est < 128)
        est = 128;
      char *out = (char *)calloc(1, est);
      if (!out) {
        perror("calloc");
        free_wordlist(wl, wl_count);
        return 1;
      }
      out_cap = est;
      size_t out_len = 0;

      for (size_t i = 0; i < words; i++) {
        if (i > 0) {
          if (append_bytes(&out, &out_cap, &out_len, separator, sep_len) != 0) {
            fprintf(stderr, "Random generation failed.\n");
            free(out);
            free_wordlist(wl, wl_count);
            return 1;
          }
        }

        size_t idx = 0;
        if (rand_index(wl_count, &idx) != 0) {
          fprintf(stderr, "Random generation failed.\n");
          free(out);
          free_wordlist(wl, wl_count);
          return 1;
        }

        if (!capitalize) {
          const char *w = wl[idx];
          if (append_bytes(&out, &out_cap, &out_len, w, strlen(w)) != 0) {
            fprintf(stderr, "Random generation failed.\n");
            free(out);
            free_wordlist(wl, wl_count);
            return 1;
          }
        } else {
          if (append_word_capitalized(&out, &out_cap, &out_len, wl[idx]) != 0) {
            fprintf(stderr, "Random generation failed.\n");
            free(out);
            free_wordlist(wl, wl_count);
            return 1;
          }
        }
      }

      if (include_number) {
        size_t d = 0;
        if (rand_index(10, &d) != 0) {
          fprintf(stderr, "Random generation failed.\n");
          free(out);
          free_wordlist(wl, wl_count);
          return 1;
        }
        char c = (char)('0' + (int)d);
        if (append_bytes(&out, &out_cap, &out_len, &c, 1) != 0) {
          fprintf(stderr, "Random generation failed.\n");
          free(out);
          free_wordlist(wl, wl_count);
          return 1;
        }
      }

      if (!show_entropy) {
        printf("%s\n", out ? out : "");
      } else {
        printf("%s\t%.2f\n", out ? out : "", ent);
      }
      free(out);
    }

    free_wordlist(wl, wl_count);
    return 0;
  }

  // Base sets (ASCII).
  char lower[] = "abcdefghijklmnopqrstuvwxyz";
  char upper[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  char digits[] = "0123456789";
  // Excludes whitespace. Keeps common shell-safe-ish symbols; still may need quoting.
  char symbols[] = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

  char pool[256];
  pool[0] = '\0';
  const char *lower_set = NULL, *upper_set = NULL, *digits_set = NULL,
             *symbols_set = NULL;
  size_t lower_len = 0, upper_len = 0, digits_len = 0, symbols_len = 0;

  char custom_lower[256], custom_upper[256], custom_digits[256], custom_symbols[256];
  custom_lower[0] = custom_upper[0] = custom_digits[0] = custom_symbols[0] = '\0';
  if (exclude_chars && has_unsupported_chars(exclude_chars)) {
    fprintf(stderr, "--exclude contains unsupported characters (no tabs/newlines/control chars).\n");
    return 2;
  }

  if (custom_chars) {
    int rc = build_pool_from_chars(custom_chars, avoid_ambiguous, pool, sizeof(pool));
    if (rc == -2) {
      fprintf(stderr, "--chars contains unsupported characters (no tabs/newlines/control chars).\n");
      return 2;
    }
    if (rc != 0) {
      fprintf(stderr, "--chars must contain at least one usable character.\n");
      return 2;
    }
    if (exclude_chars)
      remove_chars(pool, exclude_chars);
    if (pool[0] == '\0') {
      fprintf(stderr, "No characters remain after applying --exclude.\n");
      return 2;
    }
    build_category_sets(pool, custom_lower, custom_upper, custom_digits, custom_symbols);
    lower_set = custom_lower;
    upper_set = custom_upper;
    digits_set = custom_digits;
    symbols_set = custom_symbols;
    lower_len = strlen(custom_lower);
    upper_len = strlen(custom_upper);
    digits_len = strlen(custom_digits);
    symbols_len = strlen(custom_symbols);
  } else {
    if (avoid_ambiguous) {
      // Common “look-alike” set.
      remove_chars(lower, "l");
      remove_chars(upper, "IO");
      remove_chars(digits, "01");
    }
    if (exclude_chars) {
      remove_chars(lower, exclude_chars);
      remove_chars(upper, exclude_chars);
      remove_chars(digits, exclude_chars);
      remove_chars(symbols, exclude_chars);
    }

    if (use_lower)
      strncat(pool, lower, sizeof(pool) - strlen(pool) - 1);
    if (use_upper)
      strncat(pool, upper, sizeof(pool) - strlen(pool) - 1);
    if (use_digits)
      strncat(pool, digits, sizeof(pool) - strlen(pool) - 1);
    if (use_symbols)
      strncat(pool, symbols, sizeof(pool) - strlen(pool) - 1);

    lower_set = lower;
    upper_set = upper;
    digits_set = digits;
    symbols_set = symbols;
    lower_len = use_lower ? strlen(lower) : 0;
    upper_len = use_upper ? strlen(upper) : 0;
    digits_len = use_digits ? strlen(digits) : 0;
    symbols_len = use_symbols ? strlen(symbols) : 0;
  }

  if (min_lower > 0 && lower_len == 0) {
    fprintf(stderr, "Cannot satisfy --min-lower with the current character pool.\n");
    return 2;
  }
  if (min_upper > 0 && upper_len == 0) {
    fprintf(stderr, "Cannot satisfy --min-upper with the current character pool.\n");
    return 2;
  }
  if (min_digits > 0 && digits_len == 0) {
    fprintf(stderr, "Cannot satisfy --min-digits with the current character pool.\n");
    return 2;
  }
  if (min_symbols > 0 && symbols_len == 0) {
    fprintf(stderr, "Cannot satisfy --min-symbols with the current character pool.\n");
    return 2;
  }

  size_t pool_len = strlen(pool);
  if (pool_len == 0) {
    fprintf(stderr, "No characters available for generation.\n");
    return 2;
  }

  size_t req_lower = min_lower;
  size_t req_upper = min_upper;
  size_t req_digits = min_digits;
  size_t req_symbols = min_symbols;
  if (require_each) {
    if (lower_len > 0 && req_lower == 0)
      req_lower = 1;
    if (upper_len > 0 && req_upper == 0)
      req_upper = 1;
    if (digits_len > 0 && req_digits == 0)
      req_digits = 1;
    if (symbols_len > 0 && req_symbols == 0)
      req_symbols = 1;
  }
  size_t total_required = req_lower + req_upper + req_digits + req_symbols;
  if (total_required > length) {
    fprintf(stderr, "Sum of minimum class requirements (%zu) must be <= --length (%zu).\n",
            total_required, length);
    return 2;
  }

  char *out = (char *)calloc(length + 1, 1);
  if (!out) {
    perror("calloc");
    return 1;
  }

  size_t *positions = NULL;
  if (total_required > 0) {
    positions = (size_t *)calloc(length, sizeof(size_t));
    if (!positions) {
      perror("calloc");
      free(out);
      return 1;
    }
  }

  for (size_t n = 0; n < count; n++) {
    // Start with uniformly random characters from full pool.
    for (size_t i = 0; i < length; i++) {
      size_t idx = 0;
      if (rand_index(pool_len, &idx) != 0) {
        fprintf(stderr, "Random generation failed.\n");
        free(positions);
        free(out);
        return 1;
      }
      out[i] = pool[idx];
    }
    out[length] = '\0';

    // Enforce minimum class counts by overwriting random positions.
    if (total_required > 0) {
      for (size_t i = 0; i < length; i++)
        positions[i] = i;
      if (shuffle_indices(positions, length) != 0) {
        fprintf(stderr, "Random generation failed.\n");
        free(positions);
        free(out);
        return 1;
      }

      size_t pidx = 0;
      if (assign_required_chars(out, lower_set, lower_len, req_lower, positions, &pidx) !=
              0 ||
          assign_required_chars(out, upper_set, upper_len, req_upper, positions, &pidx) !=
              0 ||
          assign_required_chars(out, digits_set, digits_len, req_digits, positions,
                                &pidx) != 0 ||
          assign_required_chars(out, symbols_set, symbols_len, req_symbols, positions,
                                &pidx) != 0) {
        fprintf(stderr, "Random generation failed.\n");
        free(positions);
        free(out);
        return 1;
      }

      // Shuffle to avoid having the "required" characters correlated with selection order.
      if (shuffle(out, length) != 0) {
        fprintf(stderr, "Random generation failed.\n");
        free(positions);
        free(out);
        return 1;
      }
    }

    if (!show_entropy) {
      printf("%s\n", out);
    } else {
      printf("%s\t%.2f\n", out, entropy_bits(pool_len, length));
    }
  }

  free(positions);
  free(out);
  return 0;
}

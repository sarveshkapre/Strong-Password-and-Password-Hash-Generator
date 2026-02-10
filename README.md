# Strong Password and Password Hash Generator

Tools for generating strong passwords and hashing password lists (educational + utility).

## Build

macOS:

```sh
make
```

Linux (Ubuntu/Debian):

```sh
sudo apt-get update
sudo apt-get install -y libssl-dev
make
```

Build outputs land in `./bin/`.

## Usage

Generate strong passwords (cryptographically secure RNG):

```sh
./bin/pwgen --length 32 --avoid-ambiguous
./bin/pwgen --length 20 --count 5 --show-entropy
./bin/pwgen --length 24 --chars 'abcdef0123456789' --show-entropy
```

Generate passphrases (wordlist-based):

```sh
./bin/pwgen --passphrase --wordlist examples/wordlist.example.txt --words 4 --separator - --show-entropy
./bin/pwgen --passphrase --wordlist examples/wordlist.example.txt --words 5 --capitalize --include-number
```

Hash a file of passwords (one per line):

```sh
./bin/pass2hash -i GitHub-Brute-Force/passwordfile.txt --algo sha256
```

Piping (stdin/stdout):

```sh
printf "password\n" | ./bin/pass2hash -i - --algo sha256
```

JSONL output (one JSON object per password; easiest for robust downstream parsing):

```sh
./bin/pass2hash -i GitHub-Brute-Force/passwordfile.txt --algo sha256 --output-format jsonl
```

PBKDF2 (slow KDF, recommended if you are storing password hashes):

```sh
./bin/pass2hash -i GitHub-Brute-Force/passwordfile.txt --algo pbkdf2-sha256 --format v2
```

PBKDF2 defaults are shown in `./bin/pass2hash --help` (defaults vary by PRF; `pbkdf2-sha256` uses 600,000 iterations).

Brute-force demo (educational; safe by default):

```sh
# Print the first 100 3-digit candidates (and their hashes).
./bin/brute --length 3 --max 100 --charset digits

# Match mode: stop on the first hash match (exits 0 if found, 3 if not found).
./bin/brute --length 1 --max 20 --charset digits --algo sha256 --target-hex <hash_hex>
```

Output format:

```
password<TAB>algo<TAB>hash_hex<TAB>entropy_bits
```

If your input passwords may contain tabs, the output TSV becomes ambiguous. Prefer `--omit-password` (safest) or `--escape-tsv` (escapes the password field with `\\t`, `\\n`, `\\r`, `\\\\`).

If you need a delimiter-free format for downstream parsing, use `--output-format jsonl`.

For high-throughput pipelines, you can skip entropy estimation (emits `entropy_bits=0.00`) with `--no-entropy`:

```sh
./bin/pass2hash -i GitHub-Brute-Force/passwordfile.txt --algo sha256 --no-entropy
```

If you are generating hashes for storage, prefer `--omit-password` to avoid emitting plaintext passwords in the output:

```sh
./bin/pass2hash -i GitHub-Brute-Force/passwordfile.txt --algo pbkdf2-sha256 --format v2 --omit-password
```

PBKDF2 output format (`--format v2`):

```
password<TAB>algo<TAB>hash_hex<TAB>entropy_bits<TAB>salt_hex<TAB>iterations<TAB>dk_len
```

Verify an output TSV (recompute and compare, exits non-zero on mismatch):

```sh
./bin/pass2hash --verify -i hashes.tsv
./bin/pass2hash --verify -i hashes.tsv --escape-tsv
```

Verify an output JSONL (recompute and compare, exits non-zero on mismatch):

```sh
./bin/pass2hash --verify -i hashes.jsonl --input-format jsonl
```

Optional: TSV header (comment line starting with `#`, ignored by `--verify`):

```sh
./bin/pass2hash -i GitHub-Brute-Force/passwordfile.txt --algo sha256 --header > hashes.tsv
```

## Security Notes

- `MD5` is included for compatibility and demos, but it is not suitable for protecting passwords.
- If you are storing passwords, use a slow password hashing scheme (KDF) like PBKDF2, bcrypt, scrypt, or Argon2 with a unique salt per password.

## Source Files

- `GitHub-Brute-Force/pwgen.c`: password generator
- `GitHub-Brute-Force/pass2hash.c`: hash a password list
- `GitHub-Brute-Force/brute.c`: brute-force demo (educational; requires explicit limits)

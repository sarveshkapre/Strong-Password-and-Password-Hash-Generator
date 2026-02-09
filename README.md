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
```

Hash a file of passwords (one per line):

```sh
./bin/pass2hash -i GitHub-Brute-Force/passwordfile.txt --algo sha256
```

PBKDF2 (slow KDF, recommended if you are storing password hashes):

```sh
./bin/pass2hash -i GitHub-Brute-Force/passwordfile.txt --algo pbkdf2-sha256 --format v2
```

Output format:

```
password<TAB>algo<TAB>hash_hex<TAB>entropy_bits
```

PBKDF2 output format (`--format v2`):

```
password<TAB>algo<TAB>hash_hex<TAB>entropy_bits<TAB>salt_hex<TAB>iterations<TAB>dk_len
```

## Security Notes

- `MD5` is included for compatibility and demos, but it is not suitable for protecting passwords.
- If you are storing passwords, use a slow password hashing scheme (KDF) like PBKDF2, bcrypt, scrypt, or Argon2 with a unique salt per password.

## Source Files

- `GitHub-Brute-Force/pwgen.c`: password generator
- `GitHub-Brute-Force/pass2hash.c`: hash a password list
- `GitHub-Brute-Force/brute.c`: brute-force demo (not practical for large lengths)

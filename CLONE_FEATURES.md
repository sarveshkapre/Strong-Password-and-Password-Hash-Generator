# Clone Feature Tracker

## Context Sources
- README and docs
- TODO/FIXME markers in code
- Test and build failures
- Gaps found during codebase exploration

## Candidate Features To Do
- Selected For This Session (Cycle 1):
- [x] Reproducible builds + clean repo artifacts
- [x] Fix crypto portability
- [x] Harden `pass2hash`
- [x] Add `pwgen` CLI (secure RNG)
- [x] Add smoke tests + `make test`
- [x] Add GitHub Actions CI
- [x] Update `README.md` usage + security notes

- Selected For This Session (Cycle 2):
- [x] (P0) Add PBKDF2 output mode to `pass2hash` with per-password random salts + configurable iterations, plus stable TSV output including salt+params. (Impact: high, Effort: medium, Strategic fit: high, Differentiation: medium, Risk: medium, Confidence: high)
- [x] (P0) Fix `pass2hash` line reading to avoid truncation (support long passwords safely) and tighten input validation/exit codes. (Impact: high, Effort: low, Strategic fit: high, Differentiation: low, Risk: low, Confidence: high)
- [x] (P1) Add `pwgen` passphrase mode (wordlist-based) with word count + separator + optional capitalization/number, with entropy estimate. (Impact: medium, Effort: medium, Strategic fit: high, Differentiation: high, Risk: medium, Confidence: medium)
- [x] (P2) Make `brute` demo safe-by-default: require explicit flags (`--length`, `--max`) and remove implicit `log.txt` writes; document that it is educational only. (Impact: medium, Effort: low, Strategic fit: medium, Differentiation: low, Risk: low, Confidence: high)
- [x] (P2) Expand `tests/smoke.sh` to cover PBKDF2 known vectors + basic format enforcement. (Impact: medium, Effort: low, Strategic fit: high, Differentiation: low, Risk: low, Confidence: medium)
- [x] (P3) Update `README.md` examples and output format documentation for PBKDF2. (Impact: medium, Effort: low, Strategic fit: high, Differentiation: low, Risk: low, Confidence: high)
- [x] (P2) Expand `tests/smoke.sh` to cover passphrase invariants. (Impact: medium, Effort: low, Strategic fit: high, Differentiation: low, Risk: low, Confidence: medium)
- [x] (P2) Expand `tests/smoke.sh` to cover brute safety behavior. (Impact: medium, Effort: low, Strategic fit: high, Differentiation: low, Risk: low, Confidence: medium)
- [x] (P3) Update `README.md` examples for passphrase mode. (Impact: medium, Effort: low, Strategic fit: high, Differentiation: low, Risk: low, Confidence: high)
- [x] (P3) Update `README.md` documentation for `brute` safety. (Impact: medium, Effort: low, Strategic fit: high, Differentiation: low, Risk: low, Confidence: high)

- Selected For This Session (Cycle 3):
- [x] (P0) Make `brute` demo safe-by-default: require explicit `--length` and `--max`, add an opt-in `--log` flag (no implicit file writes), and add a simple `--target-hex` matching mode; document educational intent. (Impact: high, Effort: low, Strategic fit: high, Differentiation: low, Risk: low, Confidence: high)
- [x] (P0) Align `pass2hash` PBKDF2 defaults with current security guidance: PRF-specific iteration defaults (SHA1/SHA256/SHA512) and updated `--help`/README text. (Impact: high, Effort: low, Strategic fit: high, Differentiation: low, Risk: low, Confidence: medium)
- [x] (P1) Add `pass2hash --omit-password` to avoid emitting plaintext passwords in output TSV; keep current behavior as default; add smoke coverage and docs. (Impact: high, Effort: low, Strategic fit: high, Differentiation: medium, Risk: low, Confidence: high)
- [x] (P2) Harden `pwgen` numeric flag parsing (`--length`, `--count`) with strict validation and sane bounds to avoid accidental huge allocations/outputs; add smoke coverage for invalid values. (Impact: medium, Effort: low, Strategic fit: high, Differentiation: low, Risk: low, Confidence: high)
- [x] (P3) Refresh market-scan notes for this segment (password generation + password hashing/KDF) and keep links under “Insights” only. (Impact: low, Effort: low, Strategic fit: medium, Differentiation: low, Risk: low, Confidence: medium)

- Selected For This Session (Cycle 4):
- [x] (P0) Make `pass2hash` outputs safely parseable: add `--escape-tsv` (escape password field) plus a warning when passwords contain raw tabs without escaping; document behavior and add smoke coverage. (Impact: high, Effort: low, Strategic fit: high, Differentiation: medium, Risk: low, Confidence: high)
- [x] (P0) Make `pass2hash` pipe-friendly: support `-i -` (stdin) and `-o -` (stdout), keep current defaults, and add smoke coverage + README examples. (Impact: high, Effort: low, Strategic fit: high, Differentiation: low, Risk: low, Confidence: high)
- [x] (P1) Harden `pass2hash` CLI validation: strict numeric parsing for PBKDF2 flags and reject PBKDF2-only flags in digest mode; bound `--salt-hex` decoded size to match `--salt-len` limits; add smoke coverage. (Impact: medium, Effort: low, Strategic fit: high, Differentiation: low, Risk: low, Confidence: high)
- [x] (P1) Add `pass2hash --verify` mode to validate v1/v2 TSV lines (digest + PBKDF2 v2) and fail-fast on mismatch; support `--escape-tsv` for verifying escaped inputs; add smoke coverage + docs. (Impact: medium, Effort: medium, Strategic fit: high, Differentiation: medium, Risk: medium, Confidence: medium)

- [x] (P0) Reproducible builds + clean repo artifacts: add root `Makefile`, add `.gitignore`, and remove committed ELF binaries + generated outputs from git. (Impact: high, Effort: low, Risk: low, Confidence: high)
- [x] (P0) Fix crypto portability: replace broken Apple/OpenSSL preprocessor logic and implement a small `crypto` module that supports macOS (CommonCrypto) and Linux (OpenSSL libcrypto) for digests + PBKDF2. (Impact: high, Effort: medium, Risk: medium, Confidence: medium)
- [x] (P0) Harden `pass2hash`: correct file-reading loop (no `feof`), trim newlines, close/free resources, avoid infinite growth of output file, and add CLI flags for input/output paths + algorithm selection. (Impact: high, Effort: low, Risk: low, Confidence: high)
- [x] (P1) Add a real strong password generator CLI (`pwgen`): secure RNG, length + charset toggles, avoid ambiguous characters, optional minimum digits/symbols, and entropy estimate output. (Impact: high, Effort: medium, Risk: low, Confidence: high)
- [x] (P1) Add local verification: `tests/smoke.sh` that builds and validates known digests + basic `pwgen` invariants; wire into `make test`. (Impact: medium, Effort: low, Risk: low, Confidence: high)
- [x] (P1) Add GitHub Actions CI: build + smoke tests on `ubuntu-latest` and `macos-latest`. (Impact: medium, Effort: low, Risk: low, Confidence: medium)
- [x] (P1) Update `README.md`: precise build/run usage, security notes (MD5 is legacy; recommend PBKDF2), and examples for both CLIs. (Impact: medium, Effort: low, Risk: low, Confidence: high)
- [x] (P2) Improve brute-force demo safety: require explicit `--max`/`--length` to prevent accidental massive runs; clarify this is educational only. (Impact: low, Effort: low, Risk: low, Confidence: high)

## Implemented
- 2026-02-09: Cleaned repository artifacts (removed committed ELF binaries, moved generated output to example, added `.gitignore`). Evidence: `.gitignore`, `examples/HashofPassword.example.txt`. Commits: `14c97f5`.
- 2026-02-09: Added portable crypto layer + reproducible build; fixed `pass2hash` correctness/CLI; ensured macOS builds via CommonCrypto and Linux builds via OpenSSL (`libcrypto`). Evidence: `Makefile`, `GitHub-Brute-Force/crypto.c`, `GitHub-Brute-Force/pass2hash.c`, `make -j4`. Commits: `214a9e0`.
- 2026-02-09: Added `pwgen` (secure RNG) and runnable smoke tests hooked into `make test`. Evidence: `GitHub-Brute-Force/pwgen.c`, `tests/smoke.sh`, `make test`. Commits: `2ab592b`.
- 2026-02-09: Added CI to build + run smoke tests on macOS and Ubuntu. Evidence: `.github/workflows/ci.yml`. Commits: `b40ee84`.
- 2026-02-09: Updated README with build and usage instructions for `pwgen` and `pass2hash`. Evidence: `README.md`. Commits: `e71bced`.
- 2026-02-09: Added PBKDF2 modes to `pass2hash` (with salts/iterations output), fixed long-line input handling, and expanded smoke tests with a PBKDF2 known vector. Evidence: `GitHub-Brute-Force/pass2hash.c`, `tests/smoke.sh`, `README.md`, `make test`. Commits: `f748338`.
- 2026-02-09: Added `pwgen` passphrase mode (wordlist-based) with entropy output, plus smoke coverage and an example wordlist. Evidence: `GitHub-Brute-Force/pwgen.c`, `tests/smoke.sh`, `examples/wordlist.example.txt`, `make test`. Commits: `5813207`.
- 2026-02-09: Made `brute` demo safe-by-default (explicit `--length/--max`, optional `--target-hex`, no implicit file writes), and added smoke coverage + README docs. Evidence: `GitHub-Brute-Force/brute.c`, `tests/smoke.sh`, `README.md`, `make test`. Commits: `83c14a6`.
- 2026-02-09: Updated PBKDF2 default iterations to be PRF-specific and documented in `--help` + README. Evidence: `GitHub-Brute-Force/pass2hash.c`, `README.md`, `make test`. Commits: `89ce683`.
- 2026-02-09: Added `pass2hash --omit-password` to avoid emitting plaintext passwords, with smoke coverage and README docs. Evidence: `GitHub-Brute-Force/pass2hash.c`, `tests/smoke.sh`, `README.md`, `make test`. Commits: `a0b58f5`.
- 2026-02-09: Hardened `pwgen` numeric flag parsing with strict validation/bounds and added smoke coverage. Evidence: `GitHub-Brute-Force/pwgen.c`, `tests/smoke.sh`, `make test`. Commits: `88f86f4`.
- 2026-02-09: Made `pass2hash` pipe-friendly (`-i -`, `-o -`) and hardened PBKDF2 flag parsing/validation (strict numeric parsing, reject PBKDF2-only flags in digest mode, bound `--salt-hex`). Evidence: `GitHub-Brute-Force/pass2hash.c`, `tests/smoke.sh`, `README.md`, `make test`. Commits: `7db0133`.
- 2026-02-09: Added `pass2hash --escape-tsv` plus a warning for raw TABs to keep TSV parseable, with smoke coverage and README notes. Evidence: `GitHub-Brute-Force/pass2hash.c`, `tests/smoke.sh`, `README.md`, `make test`. Commits: `070e749`.
- 2026-02-09: Added `pass2hash --verify` mode to validate v1/v2 TSV outputs (digest + PBKDF2 v2), including support for verifying escaped TSV inputs via `--escape-tsv`, with smoke coverage and docs. Evidence: `GitHub-Brute-Force/pass2hash.c`, `tests/smoke.sh`, `README.md`, `make test`. Commits: `c57654b`.

## Insights
- Baseline UX expectations (external references, treat as untrusted): configurable length, character classes, “avoid ambiguous/look-alike” option, optional “minimum digits/special” constraints (ideally kept low), and (optionally) passphrase mode.
- Passphrase UX expectations (external references, treat as untrusted): word count, separator, optional capitalization, and optionally “include a number” in one word; tools often display a strength/entropy estimate and allow very low minimums but recommend 4+ words.
- Password hashing expectations (external references, treat as untrusted): for password storage, prefer memory-hard KDFs (Argon2id/scrypt) or bcrypt; if PBKDF2 is used, iteration counts should vary by PRF and be high enough to slow offline guessing; store salt+parameters alongside the hash to enable future upgrades.
- Password policy expectations (external references, treat as untrusted): for user-chosen passwords, prefer length + blocklist checks over composition rules; support long passwords (64+), accept all printing ASCII (including space), and avoid forced periodic rotation unless compromise is suspected.
- References:
- https://bitwarden.com/help/generator/
- https://bitwarden.com/passphrase-generator/
- https://www.lastpass.com/password-generator
- https://keepass.info/help/base/pwgenerator.html
- https://support.keepassium.com/docs/password-generator/
- https://1password.com/password-generator/
- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- https://pages.nist.gov/800-63-4/sp800-63b.html

## Notes
- This file is maintained by the autonomous clone loop.

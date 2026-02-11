# Clone Feature Tracker

## Context Sources
- README and docs
- TODO/FIXME markers in code
- Test and build failures
- Gaps found during codebase exploration

## Candidate Features To Do
- Selected For This Session (Global Cycle 1, 2026-02-11):
- [x] (P0) Add `pwgen --exclude STR` to remove disallowed characters from the effective pool (works with both default class-based pools and `--chars`), with strict rejection of control characters. (Impact: high, Effort: low, Strategic fit: high, Differentiation: medium, Risk: low, Confidence: high)
- [x] (P0) Add explicit composition constraints to `pwgen`: `--min-lower N`, `--min-upper N`, `--min-digits N`, `--min-symbols N`, including conflict checks with `--length`, `--chars`, and `--require-each`. (Impact: high, Effort: medium, Strategic fit: high, Differentiation: medium, Risk: medium, Confidence: medium)
- [x] (P1) Extend smoke tests and docs for the new `pwgen` policy flags with both success and failure coverage. (Impact: medium, Effort: low, Strategic fit: high, Differentiation: low, Risk: low, Confidence: high)
- [ ] (P1) Add `pwgen --output-format plain|jsonl` for machine-readable generation metadata (value + entropy + mode). (Impact: medium, Effort: medium, Strategic fit: medium, Differentiation: medium, Risk: medium, Confidence: medium)
- [ ] (P1) Add PBKDF2 PHC-string output mode in `pass2hash` for interoperable password-hash storage strings. (Impact: high, Effort: medium, Strategic fit: high, Differentiation: medium, Risk: medium, Confidence: low)
- [ ] (P1) Add `pass2hash --skip-empty` to avoid hashing accidental blank lines in pipeline/list inputs. (Impact: medium, Effort: low, Strategic fit: medium, Differentiation: low, Risk: low, Confidence: high)
- [ ] (P1) Add deterministic `pwgen --seed HEX` test-only mode behind an explicit unsafe flag for reproducible fixture generation. (Impact: low, Effort: medium, Strategic fit: low, Differentiation: low, Risk: medium, Confidence: medium)
- [ ] (P2) Add fuzz-like randomized regression tests for `pass2hash --verify --input-format jsonl` parser robustness. (Impact: medium, Effort: medium, Strategic fit: high, Differentiation: low, Risk: low, Confidence: medium)
- [ ] (P2) Add `make lint` (`-Werror`) and wire it into CI to tighten compile-time quality gates. (Impact: medium, Effort: low, Strategic fit: high, Differentiation: low, Risk: low, Confidence: high)
- [ ] (P2) Add `shellcheck` coverage for `tests/smoke.sh` in CI (best-effort on Ubuntu). (Impact: low, Effort: low, Strategic fit: medium, Differentiation: low, Risk: low, Confidence: high)
- [ ] (P2) Add micro-benchmark scripts for `pwgen` and `pass2hash` throughput baselines under `examples/` or `scripts/`. (Impact: low, Effort: low, Strategic fit: medium, Differentiation: low, Risk: low, Confidence: medium)
- [ ] (P2) Shorten `README.md` to a 1-2 screen quickstart and move deep option details to a dedicated docs page. (Impact: medium, Effort: low, Strategic fit: medium, Differentiation: low, Risk: low, Confidence: high)
- [ ] (P3) Add optional Unicode-aware passphrase word normalization mode (NFKC) for imported wordlists. (Impact: low, Effort: medium, Strategic fit: low, Differentiation: low, Risk: medium, Confidence: low)
- [ ] (P3) Add release packaging metadata and checksum automation for tagged builds. (Impact: low, Effort: medium, Strategic fit: medium, Differentiation: low, Risk: low, Confidence: medium)

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

- Selected For This Session (Cycle 5):
- [x] (P0) Add structured output to `pass2hash`: `--output-format jsonl` for robust downstream parsing (no delimiter ambiguity), supporting both digest and PBKDF2 modes, and respecting `--omit-password`. (Impact: high, Effort: medium, Strategic fit: high, Differentiation: medium, Risk: medium, Confidence: medium)
- [x] (P0) Extend `pass2hash --verify` to support JSONL via `--input-format jsonl` (rejecting JSONL lines missing required fields; fail-fast on mismatch). (Impact: high, Effort: medium, Strategic fit: high, Differentiation: medium, Risk: medium, Confidence: medium)
- [x] (P1) Add TSV self-describing output: `pass2hash --header` (commented `#...` header) and teach `--verify` to skip comment lines (`#`) for both TSV and JSONL. (Impact: medium, Effort: low, Strategic fit: high, Differentiation: low, Risk: low, Confidence: high)
- [x] (P2) Expand `tests/smoke.sh` to cover JSONL generation + JSONL verify + header skipping behavior. (Impact: medium, Effort: low, Strategic fit: high, Differentiation: low, Risk: low, Confidence: high)
- [x] (P2) Update `README.md` with JSONL examples, `--input-format/--output-format` docs, and header semantics. (Impact: medium, Effort: low, Strategic fit: high, Differentiation: low, Risk: low, Confidence: high)

- Selected For This Session (Cycle 6):
- [x] (P0) Add `pwgen --chars STR` (explicit allowed charset) with strict validation + de-duplication (avoid biased selection) + smoke coverage + docs; keep existing presets as default. (Impact: high, Effort: medium, Strategic fit: high, Differentiation: medium, Risk: low, Confidence: high)
- [x] (P0) Add `pass2hash --no-entropy` to skip entropy computation for throughput (emit `entropy_bits=0.00` in TSV/JSONL) + smoke coverage + docs. (Impact: medium, Effort: low, Strategic fit: high, Differentiation: low, Risk: low, Confidence: high)

- [x] (P0) Reproducible builds + clean repo artifacts: add root `Makefile`, add `.gitignore`, and remove committed ELF binaries + generated outputs from git. (Impact: high, Effort: low, Risk: low, Confidence: high)
- [x] (P0) Fix crypto portability: replace broken Apple/OpenSSL preprocessor logic and implement a small `crypto` module that supports macOS (CommonCrypto) and Linux (OpenSSL libcrypto) for digests + PBKDF2. (Impact: high, Effort: medium, Risk: medium, Confidence: medium)
- [x] (P0) Harden `pass2hash`: correct file-reading loop (no `feof`), trim newlines, close/free resources, avoid infinite growth of output file, and add CLI flags for input/output paths + algorithm selection. (Impact: high, Effort: low, Risk: low, Confidence: high)
- [x] (P1) Add a real strong password generator CLI (`pwgen`): secure RNG, length + charset toggles, avoid ambiguous characters, optional minimum digits/symbols, and entropy estimate output. (Impact: high, Effort: medium, Risk: low, Confidence: high)
- [x] (P1) Add local verification: `tests/smoke.sh` that builds and validates known digests + basic `pwgen` invariants; wire into `make test`. (Impact: medium, Effort: low, Risk: low, Confidence: high)
- [x] (P1) Add GitHub Actions CI: build + smoke tests on `ubuntu-latest` and `macos-latest`. (Impact: medium, Effort: low, Risk: low, Confidence: medium)
- [x] (P1) Update `README.md`: precise build/run usage, security notes (MD5 is legacy; recommend PBKDF2), and examples for both CLIs. (Impact: medium, Effort: low, Risk: low, Confidence: high)
- [x] (P2) Improve brute-force demo safety: require explicit `--max`/`--length` to prevent accidental massive runs; clarify this is educational only. (Impact: low, Effort: low, Risk: low, Confidence: high)

## Implemented
- 2026-02-11: Added `pwgen --exclude` and per-class minimum constraints (`--min-lower`, `--min-upper`, `--min-digits`, `--min-symbols`) with strict compatibility validation, plus smoke coverage and README updates. Evidence: `src/pwgen.c`, `tests/smoke.sh`, `README.md`, `make test`, `./bin/pwgen --length 16 --count 3 --exclude 'O0Il1{}[]' --min-lower 2 --min-upper 2 --min-digits 2 --min-symbols 1 --show-entropy`. Commits: pending.
- 2026-02-09: Cleaned repository artifacts (removed committed ELF binaries, moved generated output to example, added `.gitignore`). Evidence: `.gitignore`, `examples/HashofPassword.example.txt`. Commits: `14c97f5`.
- 2026-02-09: Added portable crypto layer + reproducible build; fixed `pass2hash` correctness/CLI; ensured macOS builds via CommonCrypto and Linux builds via OpenSSL (`libcrypto`). Evidence: `Makefile`, `src/crypto.c`, `src/pass2hash.c`, `make -j4`. Commits: `214a9e0`.
- 2026-02-09: Added `pwgen` (secure RNG) and runnable smoke tests hooked into `make test`. Evidence: `src/pwgen.c`, `tests/smoke.sh`, `make test`. Commits: `2ab592b`.
- 2026-02-09: Added CI to build + run smoke tests on macOS and Ubuntu. Evidence: `.github/workflows/ci.yml`. Commits: `b40ee84`.
- 2026-02-09: Updated README with build and usage instructions for `pwgen` and `pass2hash`. Evidence: `README.md`. Commits: `e71bced`.
- 2026-02-09: Added PBKDF2 modes to `pass2hash` (with salts/iterations output), fixed long-line input handling, and expanded smoke tests with a PBKDF2 known vector. Evidence: `src/pass2hash.c`, `tests/smoke.sh`, `README.md`, `make test`. Commits: `f748338`.
- 2026-02-09: Added `pwgen` passphrase mode (wordlist-based) with entropy output, plus smoke coverage and an example wordlist. Evidence: `src/pwgen.c`, `tests/smoke.sh`, `examples/wordlist.example.txt`, `make test`. Commits: `5813207`.
- 2026-02-09: Made `brute` demo safe-by-default (explicit `--length/--max`, optional `--target-hex`, no implicit file writes), and added smoke coverage + README docs. Evidence: `src/brute.c`, `tests/smoke.sh`, `README.md`, `make test`. Commits: `83c14a6`.
- 2026-02-09: Updated PBKDF2 default iterations to be PRF-specific and documented in `--help` + README. Evidence: `src/pass2hash.c`, `README.md`, `make test`. Commits: `89ce683`.
- 2026-02-09: Added `pass2hash --omit-password` to avoid emitting plaintext passwords, with smoke coverage and README docs. Evidence: `src/pass2hash.c`, `tests/smoke.sh`, `README.md`, `make test`. Commits: `a0b58f5`.
- 2026-02-09: Hardened `pwgen` numeric flag parsing with strict validation/bounds and added smoke coverage. Evidence: `src/pwgen.c`, `tests/smoke.sh`, `make test`. Commits: `88f86f4`.
- 2026-02-09: Made `pass2hash` pipe-friendly (`-i -`, `-o -`) and hardened PBKDF2 flag parsing/validation (strict numeric parsing, reject PBKDF2-only flags in digest mode, bound `--salt-hex`). Evidence: `src/pass2hash.c`, `tests/smoke.sh`, `README.md`, `make test`. Commits: `7db0133`.
- 2026-02-09: Added `pass2hash --escape-tsv` plus a warning for raw TABs to keep TSV parseable, with smoke coverage and README notes. Evidence: `src/pass2hash.c`, `tests/smoke.sh`, `README.md`, `make test`. Commits: `070e749`.
- 2026-02-09: Added `pass2hash --verify` mode to validate v1/v2 TSV outputs (digest + PBKDF2 v2), including support for verifying escaped TSV inputs via `--escape-tsv`, with smoke coverage and docs. Evidence: `src/pass2hash.c`, `tests/smoke.sh`, `README.md`, `make test`. Commits: `c57654b`.
- 2026-02-10: Added JSONL output (`--output-format jsonl`) and JSONL verify (`--input-format jsonl`) to `pass2hash`, plus optional commented TSV headers (`--header`) and comment skipping in verify mode. Evidence: `src/pass2hash.c`, `tests/smoke.sh`, `README.md`, `make test`. Commits: `47ae42b`, `d1e68b8`.
- 2026-02-10: Added `pass2hash --no-entropy` to skip entropy estimation for throughput (emits `entropy_bits=0.00` in TSV/JSONL), plus smoke coverage and docs. Evidence: `src/pass2hash.c`, `tests/smoke.sh`, `README.md`, `make test`. Commits: `294b097`.
- 2026-02-10: Added `pwgen --chars STR` for explicit custom character sets (validated + de-duplicated, respects `--avoid-ambiguous`, and enforces `--require-each` by available categories), plus smoke coverage and docs. Evidence: `src/pwgen.c`, `tests/smoke.sh`, `README.md`, `make test`. Commits: `8f07b67`.

## Insights
- Market scan (2026-02-11, external references treated as untrusted): KeePassXC CLI exposes both `--exclude` and `--every-group` (minimum-per-group style) options, which map closely to the new `pwgen` constraints shipped this cycle.
- Market scan (2026-02-11, external references treated as untrusted): Bitwarden CLI (`bw generate`) supports password and passphrase generation modes, reinforcing parity value for keeping both modes first-class in this repo.
- Gap map (2026-02-11, untrusted market + trusted local code): missing -> explicit exclusion and minimum class controls in `pwgen` (now addressed this cycle); weak -> interoperable KDF storage strings (PHC-style) in `pass2hash`; parity -> secure RNG, passphrase mode, JSONL outputs, verification path; differentiator -> built-in hash output verification and strict TSV/JSONL parsing modes.
- Baseline UX expectations (external references, treat as untrusted): configurable length, character classes, “avoid ambiguous/look-alike” option, optional “minimum digits/special” constraints (ideally kept low), and (optionally) passphrase mode.
- Passphrase UX expectations (external references, treat as untrusted): word count, separator, optional capitalization, and optionally “include a number” in one word; tools often display a strength/entropy estimate and allow very low minimums but recommend 4+ words.
- Custom charset UX expectations (external references, treat as untrusted): allow explicit “character set” input; treat it as a set (ignore duplicates) and reject tabs/newlines to keep output parseable.
- Password hashing expectations (external references, treat as untrusted): for password storage, prefer memory-hard KDFs (Argon2id/scrypt) or bcrypt; if PBKDF2 is used, iteration counts should vary by PRF and be high enough to slow offline guessing; store salt+parameters alongside the hash to enable future upgrades.
- Password policy expectations (external references, treat as untrusted): for user-chosen passwords, prefer length + blocklist checks over composition rules; support long passwords (64+), accept all printing ASCII (including space), and avoid forced periodic rotation unless compromise is suspected.
- CLI expectations (external references, treat as untrusted): machine-readable outputs (JSON or JSONL) are a common opt-in for automation; generators typically offer length, character groups, exclude-similar, and passphrase options.
- References:
- https://bitwarden.com/help/generator/
- https://bitwarden.com/passphrase-generator/
- https://www.lastpass.com/password-generator
- https://keepass.info/help/base/pwgenerator.html
- https://support.keepassium.com/docs/password-generator/
- https://1password.com/password-generator/
- https://bitwarden.com/help/cli/
- https://developer.1password.com/docs/cli/reference/
- https://manpages.debian.org/testing/keepassxc/keepassxc-cli.1.en.html
- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- https://pages.nist.gov/800-63-4/sp800-63b.html

## Notes
- This file is maintained by the autonomous clone loop.

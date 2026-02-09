# Project Memory

## Objective
- Keep Strong-Password-and-Password-Hash-Generator production-ready. Current focus: Strong Password and Password Hash Generator. Find the highest-impact pending work, implement it, test it, and push to main.

## Architecture Snapshot
- Language: C (single-repo utilities).
- Build: root `Makefile` builds binaries into `./bin/`.
- Binaries:
- `bin/pwgen`: cryptographically secure password generator (configurable charset/length).
- `bin/pass2hash`: hashes a password list file (one password per line) with selectable digest algorithm.
- Crypto portability: `GitHub-Brute-Force/crypto.c` uses CommonCrypto on macOS and OpenSSL libcrypto on Linux.

## Open Problems
- `brute` is intentionally an educational demo; it is now safe-by-default but still not intended for large-scale cracking.
- `pass2hash` outputs a TSV; passwords containing raw tabs make the output ambiguous unless `--escape-tsv` (or `--omit-password`) is used. The tool warns once, but consumers must opt into escaping.
- Consider adding a structured output mode (e.g., JSONL) for robust downstream parsing.

## Recent Decisions
- Template: YYYY-MM-DD | Decision | Why | Evidence (tests/logs) | Commit | Confidence (high/medium/low) | Trust (trusted/untrusted)
- 2026-02-09 | Remove committed binaries and ignore generated artifacts | Keep repo portable, reproducible, and clean | `git ls-files` no longer includes ELF binaries; `.gitignore` added | 14c97f5 | high | trusted
- 2026-02-09 | Add portable crypto module and make SHA-256 the default for `pass2hash` | Fix macOS build breakage and avoid defaulting to legacy MD5 | `make -j4` + `./bin/pass2hash --algo sha256` output sanity | 214a9e0 | high | trusted
- 2026-02-09 | Add `pwgen` strong password generator CLI and smoke tests | Deliver core “strong password generator” value with a runnable verification path | `make test` | 2ab592b | high | trusted
- 2026-02-09 | Add CI workflow (macOS + Ubuntu) | Prevent regressions and validate portability automatically | `.github/workflows/ci.yml` + local `make test` | b40ee84 | medium | trusted
- 2026-02-09 | Update README with build/run instructions | Align docs with shipped behavior and reduce setup friction | README examples + `make test` | e71bced | high | trusted
- 2026-02-09 | Make `brute` demo safe-by-default | Prevent accidental massive runs and implicit file writes; add deterministic matching mode for demos | `make test`; `gh run watch 21832258489 --exit-status` | 83c14a6 | high | trusted
- 2026-02-09 | Update PBKDF2 default iterations to be PRF-specific | Keep KDF defaults aligned with current guidance while remaining configurable | `make test`; `gh run watch 21832329843 --exit-status` | 89ce683 | medium | trusted
- 2026-02-09 | Add `pass2hash --omit-password` | Reduce risk of accidentally emitting plaintext passwords in outputs/logs | `make test`; `gh run watch 21832392384 --exit-status` | a0b58f5 | high | trusted
- 2026-02-09 | Harden `pwgen` numeric flag parsing | Avoid partial parses (e.g., `20x`) and prevent accidental huge outputs | `make test`; `gh run watch 21832459352 --exit-status` | 88f86f4 | high | trusted
- 2026-02-09 | Make `pass2hash` pipe-friendly and harden PBKDF2 flag validation | Improve CLI UX for pipelines and prevent footguns/invalid PBKDF2 parameter usage | `make test` | 7db0133 | high | trusted
- 2026-02-09 | Add `pass2hash --escape-tsv` + warn on raw TABs | Make outputs safely parseable while keeping default behavior | `make test` | 070e749 | high | trusted
- 2026-02-09 | Add `pass2hash --verify` mode | Provide a correctness check workflow for digest + PBKDF2 v2 outputs | `make test` | c57654b | medium | trusted

## Mistakes And Fixes
- Template: YYYY-MM-DD | Issue | Root cause | Fix | Prevention rule | Commit | Confidence
- 2026-02-09 | `pwgen` sometimes violated `--require-each` constraints | Required characters could overwrite each other due to position collisions | Enforced unique positions via shuffled index array | 2ab592b | high
- 2026-02-09 | Smoke test expected the wrong escaping for `--escape-tsv` | Confused single backslash escape sequences with double-escaped string literals | Updated smoke assertion to expect `\\t` (one backslash in output) | When adding escaping, document the exact wire format and match tests to the tool's output, not shell escaping rules | 070e749 | high

## Known Risks
- `pass2hash` uses fast digests (SHA-256/SHA-512/MD5/SHA-1). This is not suitable for password storage; use a KDF (PBKDF2/bcrypt/scrypt/Argon2) for real systems.
- Entropy values are estimates (assumes uniform random selection from a simplified character pool).

## Next Prioritized Tasks
- Consider adding a structured output mode (e.g., `pass2hash --output jsonl`) and a matching `--verify` path to avoid delimiter ambiguity entirely.
- Consider adding optional header rows (`--header`) to make outputs self-describing for casual use.

## Verification Evidence
- Template: YYYY-MM-DD | Command | Key output | Status (pass/fail)
- 2026-02-09 | `make -j4` | Built `bin/pass2hash`, `bin/pwgen`, `bin/brute` | pass
- 2026-02-09 | `./tests/smoke.sh` | All smoke checks passed | pass
- 2026-02-09 | `make test` | All smoke checks passed | pass
- 2026-02-09 | `gh run watch 21816690042 --exit-status` | GitHub Actions `ci` completed `success` on `main` | pass
- 2026-02-09 | `gh run watch 21816706432 --exit-status` | GitHub Actions `ci` completed `success` on `main` | pass
- 2026-02-09 | `make test` | All smoke checks passed | pass
- 2026-02-09 | `gh run watch 21832258489 --exit-status` | GitHub Actions `ci` completed `success` on `main` | pass
- 2026-02-09 | `gh run watch 21832329843 --exit-status` | GitHub Actions `ci` completed `success` on `main` | pass
- 2026-02-09 | `gh run watch 21832392384 --exit-status` | GitHub Actions `ci` completed `success` on `main` | pass
- 2026-02-09 | `gh run watch 21832459352 --exit-status` | GitHub Actions `ci` completed `success` on `main` | pass
- 2026-02-09 | `gh run watch 21832566422 --exit-status` | GitHub Actions `ci` completed `success` on `main` | pass
- 2026-02-09 | `make test` | All smoke checks passed | pass
- 2026-02-09 | `gh run list -b main -L 3` | GitHub Actions `ci` shows `success` for run `21841375127` on `main` | pass

## Historical Summary
- Keep compact summaries of older entries here when file compaction runs.

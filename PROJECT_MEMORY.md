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
- Brute-force demo (`GitHub-Brute-Force/brute.c`) remains unsafe to run at large lengths; needs explicit limits and clearer UX.
- `pwgen` passphrase mode not implemented yet.

## Recent Decisions
- Template: YYYY-MM-DD | Decision | Why | Evidence (tests/logs) | Commit | Confidence (high/medium/low) | Trust (trusted/untrusted)
- 2026-02-09 | Remove committed binaries and ignore generated artifacts | Keep repo portable, reproducible, and clean | `git ls-files` no longer includes ELF binaries; `.gitignore` added | 14c97f5 | high | trusted
- 2026-02-09 | Add portable crypto module and make SHA-256 the default for `pass2hash` | Fix macOS build breakage and avoid defaulting to legacy MD5 | `make -j4` + `./bin/pass2hash --algo sha256` output sanity | 214a9e0 | high | trusted
- 2026-02-09 | Add `pwgen` strong password generator CLI and smoke tests | Deliver core “strong password generator” value with a runnable verification path | `make test` | 2ab592b | high | trusted
- 2026-02-09 | Add CI workflow (macOS + Ubuntu) | Prevent regressions and validate portability automatically | `.github/workflows/ci.yml` + local `make test` | b40ee84 | medium | trusted
- 2026-02-09 | Update README with build/run instructions | Align docs with shipped behavior and reduce setup friction | README examples + `make test` | e71bced | high | trusted

## Mistakes And Fixes
- Template: YYYY-MM-DD | Issue | Root cause | Fix | Prevention rule | Commit | Confidence
- 2026-02-09 | `pwgen` sometimes violated `--require-each` constraints | Required characters could overwrite each other due to position collisions | Enforced unique positions via shuffled index array | 2ab592b | high

## Known Risks
- `pass2hash` uses fast digests (SHA-256/SHA-512/MD5/SHA-1). This is not suitable for password storage; use a KDF (PBKDF2/bcrypt/scrypt/Argon2) for real systems.
- Entropy values are estimates (assumes uniform random selection from a simplified character pool).

## Next Prioritized Tasks
- Add `pwgen` passphrase mode (wordlist-based) and document recommended defaults.
- Make `brute` demo opt-in and safe by default (require explicit length/max outputs).

## Verification Evidence
- Template: YYYY-MM-DD | Command | Key output | Status (pass/fail)
- 2026-02-09 | `make -j4` | Built `bin/pass2hash`, `bin/pwgen`, `bin/brute` | pass
- 2026-02-09 | `./tests/smoke.sh` | All smoke checks passed | pass
- 2026-02-09 | `make test` | All smoke checks passed | pass
- 2026-02-09 | `gh run watch 21816690042 --exit-status` | GitHub Actions `ci` completed `success` on `main` | pass
- 2026-02-09 | `gh run watch 21816706432 --exit-status` | GitHub Actions `ci` completed `success` on `main` | pass

## Historical Summary
- Keep compact summaries of older entries here when file compaction runs.

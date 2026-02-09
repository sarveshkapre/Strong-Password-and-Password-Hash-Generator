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

- [x] (P0) Reproducible builds + clean repo artifacts: add root `Makefile`, add `.gitignore`, and remove committed ELF binaries + generated outputs from git. (Impact: high, Effort: low, Risk: low, Confidence: high)
- [x] (P0) Fix crypto portability: replace broken Apple/OpenSSL preprocessor logic and implement a small `crypto` module that supports macOS (CommonCrypto) and Linux (OpenSSL libcrypto) for digests + PBKDF2. (Impact: high, Effort: medium, Risk: medium, Confidence: medium)
- [x] (P0) Harden `pass2hash`: correct file-reading loop (no `feof`), trim newlines, close/free resources, avoid infinite growth of output file, and add CLI flags for input/output paths + algorithm selection. (Impact: high, Effort: low, Risk: low, Confidence: high)
- [x] (P1) Add a real strong password generator CLI (`pwgen`): secure RNG, length + charset toggles, avoid ambiguous characters, optional minimum digits/symbols, and entropy estimate output. (Impact: high, Effort: medium, Risk: low, Confidence: high)
- [x] (P1) Add local verification: `tests/smoke.sh` that builds and validates known digests + basic `pwgen` invariants; wire into `make test`. (Impact: medium, Effort: low, Risk: low, Confidence: high)
- [x] (P1) Add GitHub Actions CI: build + smoke tests on `ubuntu-latest` and `macos-latest`. (Impact: medium, Effort: low, Risk: low, Confidence: medium)
- [x] (P1) Update `README.md`: precise build/run usage, security notes (MD5 is legacy; recommend PBKDF2), and examples for both CLIs. (Impact: medium, Effort: low, Risk: low, Confidence: high)
- [ ] (P2) Add optional passphrase mode (wordlist-based) for `pwgen` with configurable separator and word count. (Impact: medium, Effort: medium, Risk: low, Confidence: medium)
- [ ] (P2) Improve brute-force demo safety: require explicit `--max`/`--length` to prevent accidental massive runs; clarify this is educational only. (Impact: low, Effort: low, Risk: low, Confidence: high)

## Implemented
- 2026-02-09: Cleaned repository artifacts (removed committed ELF binaries, moved generated output to example, added `.gitignore`). Evidence: `.gitignore`, `examples/HashofPassword.example.txt`. Commits: `14c97f5`.
- 2026-02-09: Added portable crypto layer + reproducible build; fixed `pass2hash` correctness/CLI; ensured macOS builds via CommonCrypto and Linux builds via OpenSSL (`libcrypto`). Evidence: `Makefile`, `GitHub-Brute-Force/crypto.c`, `GitHub-Brute-Force/pass2hash.c`, `make -j4`. Commits: `214a9e0`.
- 2026-02-09: Added `pwgen` (secure RNG) and runnable smoke tests hooked into `make test`. Evidence: `GitHub-Brute-Force/pwgen.c`, `tests/smoke.sh`, `make test`. Commits: `2ab592b`.
- 2026-02-09: Added CI to build + run smoke tests on macOS and Ubuntu. Evidence: `.github/workflows/ci.yml`. Commits: `b40ee84`.
- 2026-02-09: Updated README with build and usage instructions for `pwgen` and `pass2hash`. Evidence: `README.md`. Commits: `e71bced`.

## Insights
- Baseline UX expectations (external references, treat as untrusted): configurable length, character classes, “avoid ambiguous/look-alike” option, optional “minimum digits/special” constraints (ideally kept low), and (optionally) passphrase mode.
- References:
- https://bitwarden.com/help/generator/
- https://keepass.info/help/base/pwgenerator.html
- https://support.keepassium.com/docs/password-generator/

## Notes
- This file is maintained by the autonomous clone loop.

#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

tmp="$(mktemp -d)"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT

echo "[smoke] build"
make -s clean
make -s -j4

echo "[smoke] pass2hash sha256 known vector"
cat >"$tmp/in.txt" <<'EOF'
password
123456
EOF

line="$(./bin/pass2hash -i "$tmp/in.txt" --algo sha256 | head -n 1 | cut -f1-3)"
expected=$'password\tsha256\t5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'
if [[ "$line" != "$expected" ]]; then
  echo "Expected: $expected"
  echo "Got:      $line"
  exit 1
fi

echo "[smoke] pass2hash pbkdf2-sha256 known vector (deterministic salt)"
expected_pbkdf2_sha256="$(
python3 - <<'PY'
import hashlib
dk = hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 1, dklen=32)
print(dk.hex())
PY
)"

line="$(./bin/pass2hash -i "$tmp/in.txt" --algo pbkdf2-sha256 --salt-hex 73616c74 --iterations 1 --dk-len 32 --format v2 | head -n 1)"
IFS=$'\t' read -r f_pw f_algo f_hash f_entropy f_salt f_iter f_dklen <<<"$line"
[[ "$f_pw" == "password" ]] || { echo "bad pw: $f_pw"; exit 1; }
[[ "$f_algo" == "pbkdf2-sha256" ]] || { echo "bad algo: $f_algo"; exit 1; }
[[ "$f_salt" == "73616c74" ]] || { echo "bad salt: $f_salt"; exit 1; }
[[ "$f_iter" == "1" ]] || { echo "bad iter: $f_iter"; exit 1; }
[[ "$f_dklen" == "32" ]] || { echo "bad dklen: $f_dklen"; exit 1; }
[[ "$f_hash" == "$expected_pbkdf2_sha256" ]] || { echo "bad pbkdf2 hash: $f_hash"; exit 1; }

echo "[smoke] pass2hash pbkdf2 requires --format v2"
if ./bin/pass2hash -i "$tmp/in.txt" --algo pbkdf2-sha256 --salt-hex 73616c74 --iterations 1 --dk-len 32 --format v1 >/dev/null 2>&1; then
  echo "expected pbkdf2 to fail with --format v1"
  exit 1
fi

echo "[smoke] pwgen length/ambiguity"
ambiguous_re='[O0Il1]'
while IFS= read -r pw; do
  [[ ${#pw} -eq 32 ]] || { echo "bad length: ${#pw}"; exit 1; }
  if [[ "$pw" =~ $ambiguous_re ]]; then
    echo "ambiguous character found: $pw"
    exit 1
  fi
done < <(./bin/pwgen --length 32 --avoid-ambiguous --count 25)

echo "[smoke] pwgen require-each (lower/upper/digit/symbol)"
while IFS= read -r pw; do
  [[ "$pw" =~ [a-z] ]] || { echo "missing lower: $pw"; exit 1; }
  [[ "$pw" =~ [A-Z] ]] || { echo "missing upper: $pw"; exit 1; }
  [[ "$pw" =~ [0-9] ]] || { echo "missing digit: $pw"; exit 1; }
  [[ "$pw" =~ [[:punct:]] ]] || { echo "missing symbol: $pw"; exit 1; }
done < <(./bin/pwgen --length 20 --count 50 --avoid-ambiguous)

echo "[smoke] ok"

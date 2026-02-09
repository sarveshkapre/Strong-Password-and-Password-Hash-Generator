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


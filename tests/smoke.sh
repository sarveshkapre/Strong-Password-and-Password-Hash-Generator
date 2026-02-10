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

echo "[smoke] brute requires explicit limits"
if ./bin/brute >/dev/null 2>&1; then
  echo "expected brute to fail without --length/--max"
  exit 1
fi

echo "[smoke] brute does not write log.txt by default"
rm -f log.txt
./bin/brute --length 1 --max 2 --charset digits >/dev/null
[[ ! -f log.txt ]] || { echo "unexpected log.txt created"; exit 1; }

echo "[smoke] brute target match (sha256 of '0')"
expected_brute_sha256="$(
python3 - <<'PY'
import hashlib
print(hashlib.sha256(b"0").hexdigest())
PY
)"
found="$(./bin/brute --length 1 --max 20 --charset digits --algo sha256 --target-hex "$expected_brute_sha256" | head -n 1 | cut -f1)"
[[ "$found" == "0" ]] || { echo "expected to find '0', got: $found"; exit 1; }

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

echo "[smoke] pass2hash --omit-password"
line="$(./bin/pass2hash -i "$tmp/in.txt" --algo sha256 --omit-password | head -n 1 | cut -f1-2)"
expected=$'sha256\t5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'
if [[ "$line" != "$expected" ]]; then
  echo "Expected: $expected"
  echo "Got:      $line"
  exit 1
fi

echo "[smoke] pass2hash stdin/stdout via -"
line="$(printf 'password\n' | ./bin/pass2hash -i - -o - --algo sha256 | head -n 1 | cut -f1-3)"
expected=$'password\tsha256\t5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'
if [[ "$line" != "$expected" ]]; then
  echo "Expected: $expected"
  echo "Got:      $line"
  exit 1
fi

echo "[smoke] pass2hash --escape-tsv for tabbed passwords"
printf $'a\tb\n' >"$tmp/tabpw.txt"
line="$(./bin/pass2hash -i "$tmp/tabpw.txt" --algo sha256 --escape-tsv | head -n 1 | cut -f1)"
[[ "$line" == 'a\tb' ]] || { echo "expected escaped tab field, got: $line"; exit 1; }

echo "[smoke] pass2hash warns on raw tabs without --escape-tsv"
./bin/pass2hash -i "$tmp/tabpw.txt" --algo sha256 >/dev/null 2>"$tmp/warn.txt"
grep -qi "tab" "$tmp/warn.txt" || { echo "expected warning about TABs"; cat "$tmp/warn.txt"; exit 1; }

echo "[smoke] pass2hash rejects non-numeric PBKDF2 flags"
if ./bin/pass2hash -i "$tmp/in.txt" --algo pbkdf2-sha256 --salt-hex 73616c74 --iterations 1x --dk-len 32 --format v2 >/dev/null 2>&1; then
  echo "expected pass2hash to fail for --iterations 1x"
  exit 1
fi
if ./bin/pass2hash -i "$tmp/in.txt" --algo pbkdf2-sha256 --salt-hex 73616c74 --iterations 1 --dk-len 32x --format v2 >/dev/null 2>&1; then
  echo "expected pass2hash to fail for --dk-len 32x"
  exit 1
fi
if ./bin/pass2hash -i "$tmp/in.txt" --algo pbkdf2-sha256 --salt-len 16x --format v2 >/dev/null 2>&1; then
  echo "expected pass2hash to fail for --salt-len 16x"
  exit 1
fi

echo "[smoke] pass2hash rejects PBKDF2-only flags in digest mode"
if ./bin/pass2hash -i "$tmp/in.txt" --algo sha256 --iterations 1 >/dev/null 2>&1; then
  echo "expected pass2hash to fail for digest algo with --iterations"
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

echo "[smoke] pass2hash --verify (pbkdf2 v2)"
out_tsv="$tmp/out.tsv"
./bin/pass2hash -i "$tmp/in.txt" --algo pbkdf2-sha256 --salt-hex 73616c74 --iterations 1 --dk-len 32 --format v2 >"$out_tsv"
./bin/pass2hash --verify -i "$out_tsv" >/dev/null

echo "[smoke] pass2hash --verify (escaped TSV)"
esc_tsv="$tmp/escaped.tsv"
./bin/pass2hash -i "$tmp/tabpw.txt" --algo sha256 --escape-tsv >"$esc_tsv"
./bin/pass2hash --verify -i "$esc_tsv" --escape-tsv >/dev/null

echo "[smoke] pass2hash --verify detects mismatches"
bad_tsv="$tmp/bad.tsv"
python3 - <<PY
import pathlib
src_path = pathlib.Path("$out_tsv")
lines = src_path.read_text(encoding="utf-8").splitlines()
fields = lines[0].split("\\t")
assert len(fields) >= 3
h = fields[2]
fields[2] = h[:-1] + ("0" if h[-1] != "0" else "1")
lines[0] = "\\t".join(fields)
pathlib.Path("$bad_tsv").write_text("\\n".join(lines) + "\\n", encoding="utf-8")
PY
if ./bin/pass2hash --verify -i "$bad_tsv" >/dev/null 2>&1; then
  echo "expected --verify to fail on mismatched hash"
  exit 1
fi

echo "[smoke] pass2hash --header (TSV) + verify skips comments"
hdr_tsv="$tmp/with_header.tsv"
./bin/pass2hash -i "$tmp/in.txt" --algo sha256 --header >"$hdr_tsv"
./bin/pass2hash --verify -i "$hdr_tsv" >/dev/null

echo "[smoke] pass2hash jsonl output (digest)"
json_line="$(./bin/pass2hash -i "$tmp/in.txt" --algo sha256 --output-format jsonl | head -n 1)"
python3 - <<'PY' <<<"$json_line"
import json,sys,hashlib
obj = json.loads(sys.stdin.read())
assert obj["password"] == "password"
assert obj["algo"] == "sha256"
assert obj["hash_hex"] == hashlib.sha256(b"password").hexdigest()
assert isinstance(obj["entropy_bits"], (int, float))
PY

echo "[smoke] pass2hash jsonl output (pbkdf2)"
json_line="$(./bin/pass2hash -i "$tmp/in.txt" --algo pbkdf2-sha256 --salt-hex 73616c74 --iterations 1 --dk-len 32 --output-format jsonl | head -n 1)"
python3 - <<PY <<<"$json_line"
import json,sys
obj = json.loads(sys.stdin.read())
assert obj["password"] == "password"
assert obj["algo"] == "pbkdf2-sha256"
assert obj["salt_hex"] == "73616c74"
assert obj["iterations"] == 1
assert obj["dk_len"] == 32
assert obj["hash_hex"] == "$expected_pbkdf2_sha256"
PY

echo "[smoke] pass2hash --verify (jsonl)"
out_jsonl="$tmp/out.jsonl"
./bin/pass2hash -i "$tmp/in.txt" --algo sha256 --output-format jsonl >"$out_jsonl"
./bin/pass2hash --verify -i "$out_jsonl" --input-format jsonl >/dev/null

echo "[smoke] pass2hash jsonl + --omit-password omits plaintext"
json_line="$(./bin/pass2hash -i "$tmp/in.txt" --algo sha256 --output-format jsonl --omit-password | head -n 1)"
python3 - <<'PY' <<<"$json_line"
import json,sys
obj = json.loads(sys.stdin.read())
assert "password" not in obj
assert obj["algo"] == "sha256"
assert "hash_hex" in obj
PY

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

echo "[smoke] pwgen passphrase mode (wordlist-based)"
cat >"$tmp/words.txt" <<'EOF'
alpha
bravo
charlie
delta
EOF

echo "[smoke] pwgen rejects non-numeric values"
if ./bin/pwgen --length 20x >/dev/null 2>&1; then
  echo "expected pwgen to fail for --length 20x"
  exit 1
fi
if ./bin/pwgen --count 2x >/dev/null 2>&1; then
  echo "expected pwgen to fail for --count 2x"
  exit 1
fi
if ./bin/pwgen --passphrase --wordlist "$tmp/words.txt" --words 4x >/dev/null 2>&1; then
  echo "expected pwgen to fail for --words 4x"
  exit 1
fi

allowed_re='^(alpha|bravo|charlie|delta)$'
while IFS= read -r phrase; do
  IFS='-' read -r w1 w2 w3 w4 <<<"$phrase"
  [[ -n "${w1:-}" && -n "${w2:-}" && -n "${w3:-}" && -n "${w4:-}" ]] || { echo "bad phrase: $phrase"; exit 1; }
  [[ "$w1" =~ $allowed_re ]] || { echo "bad word: $w1"; exit 1; }
  [[ "$w2" =~ $allowed_re ]] || { echo "bad word: $w2"; exit 1; }
  [[ "$w3" =~ $allowed_re ]] || { echo "bad word: $w3"; exit 1; }
  [[ "$w4" =~ $allowed_re ]] || { echo "bad word: $w4"; exit 1; }
done < <(./bin/pwgen --passphrase --wordlist "$tmp/words.txt" --words 4 --separator - --count 50)

echo "[smoke] pwgen passphrase mode (capitalize + include-number)"
phrase="$(./bin/pwgen --passphrase --wordlist "$tmp/words.txt" --words 4 --separator - --capitalize --include-number --count 1)"
[[ "$phrase" =~ ^[A-Z][a-z]+-[A-Z][a-z]+-[A-Z][a-z]+-[A-Z][a-z]+[0-9]$ ]] || { echo "bad capitalized phrase: $phrase"; exit 1; }

echo "[smoke] ok"

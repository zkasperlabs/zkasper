#!/usr/bin/env bash
set -euo pipefail

# Verify one published proof end to end, from the API alone, in a directory that
# has never held a proving key.
#
# Usage: ./scripts/verify_published_proof.sh [epoch]
#   epoch: defaults to the newest epoch the API reports a proof for.
#
# Environment:
#   ZKASPER_API       base URL, default https://api.zkasper.com
#   ZKASPER_COLD_DIR  scratch root, default ./zkasper-cold-verify
#   CARGO_TARGET_DIR  build output, default $ZKASPER_COLD_DIR/target
#
# Needs: curl, python3, git, make, a C compiler, a stable Rust toolchain. It
# needs no Zisk install, no `cargo-zisk`, and no proving key -- the verifier is
# the pure-Rust `proofman-verifier` crate, which `zkasper-common` reaches
# through `ziskos`. The run asserts that: it clears the environment, points HOME
# and CARGO_HOME at fresh directories, and refuses to start if a Zisk install is
# reachable from either.
#
# What it does NOT check: that the guest ELF named by `verify.elf_sha256` is the
# program `verify.program_vk` identifies. That is step 3 of "Verifying a proof"
# in docs/finality/api-v1.md, it needs a Zisk toolchain and a proving key to
# rebuild the guest, and it is a separate exercise from this one. This script
# checks the STARK, and that the STARK commits to the key and the public inputs
# the API published.

API=${ZKASPER_API:-https://api.zkasper.com}
COLD=${ZKASPER_COLD_DIR:-$PWD/zkasper-cold-verify}
EPOCH=${1:-}

say() { printf '\n=== %s ===\n' "$*"; }

mkdir -p "$COLD"
COLD=$(cd "$COLD" && pwd)
HOME_DIR="$COLD/home"
CARGO_DIR="$COLD/cargo"
WORK="$COLD/work"
mkdir -p "$HOME_DIR" "$CARGO_DIR" "$WORK"

# The whole point of the exercise. A stray install under either of these would
# make the run prove nothing.
for d in "$HOME_DIR/.zisk" "$COLD/.zisk"; do
  if [ -e "$d" ]; then
    echo "REFUSING: $d exists; this is meant to be a machine that has never held a proving key" >&2
    exit 1
  fi
done

say "1. what the API says"
if [ -z "$EPOCH" ]; then
  EPOCH=$(curl -fsS "$API/v1/epochs?limit=10" | python3 -c '
import json, sys
for e in json.load(sys.stdin)["epochs"]:
    p = e.get("proof")
    if p and p.get("available"):
        print(e["epoch"])
        break
')
fi
echo "epoch $EPOCH"
curl -fsS "$API/v1/epochs/$EPOCH" -o "$WORK/epoch.json"

read -r STAGE PROGRAM PROGRAM_VK PUBLIC_BYTES ELF_SHA ZISK_VERSION COMMIT PROOF_URL PROOF_SHA PROOF_WORDS ANCHOR <<EOF
$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
v, p = d["verify"], d["proof"]
print(v["stage"], v["program"], v["program_vk"], v["public_bytes"], v["elf_sha256"],
      v["zisk_version"], v["zkasper_commit"], v["proof_url"], p["sha256"], p["words"],
      p.get("vadcop_final_vk") or v.get("vadcop_final_vk") or "absent")
' "$WORK/epoch.json")
EOF

echo "stage          $STAGE"
echo "program        $PROGRAM"
echo "program_vk     $PROGRAM_VK"
echo "elf_sha256     $ELF_SHA"
echo "zisk_version   $ZISK_VERSION"
echo "zkasper_commit $COMMIT"
echo "vadcop_final_vk $ANCHOR"

say "2. the proof bytes"
curl -fsS "$API$PROOF_URL" -o "$WORK/proof.bin"
GOT_SHA=0x$(sha256sum "$WORK/proof.bin" | cut -d' ' -f1)
echo "bytes          $(stat -c%s "$WORK/proof.bin")"
echo "sha256         $GOT_SHA"
if [ "$GOT_SHA" != "$PROOF_SHA" ]; then
  echo "FAIL: served bytes do not match the sha256 the index published ($PROOF_SHA)" >&2
  exit 1
fi
echo "sha256 matches the index"

say "3. what the proof commits to, before any STARK check"
python3 - "$WORK/proof.bin" "$PROGRAM_VK" "$PUBLIC_BYTES" "$PROOF_WORDS" <<'PY'
import struct, sys

raw = open(sys.argv[1], "rb").read()
words = list(struct.unpack("<%dQ" % (len(raw) // 8), raw))
assert len(words) == int(sys.argv[4]), "word count differs from the index"
minimal, n_publics = words[0], words[1]
assert minimal == 0, "a compressed proof; this layout is for uncompressed ones"
assert n_publics == 69, f"n_publics {n_publics}, want 69"
stark_publics = words[2:2 + n_publics]
assert stark_publics[0] == 1, "is_vadcop_final flag is not set"

vk = b"".join(struct.pack("<Q", w) for w in stark_publics[1:5])
want_vk = bytes.fromhex(sys.argv[2][2:])
assert vk == want_vk, "program_vk in the proof differs from the published one"

publics = b"".join(struct.pack("<I", w & 0xFFFFFFFF) for w in stark_publics[5:])
want_pub = bytes.fromhex(sys.argv[3][2:])
assert publics[:len(want_pub)] == want_pub, "public bytes differ from the published ones"
assert not any(publics[len(want_pub):]), "unused public words are not zero"

print("program_vk     matches")
print("public_bytes   matches, %d bytes, rest zero" % len(want_pub))
print("proof vadcop vk %s" % list(struct.unpack("<4Q", raw[-32:])))
PY

say "3b. the anchor the API publishes, against the proof's own tail"
# This is the step that decides whether the API alone is enough. Verifying a
# vadcop_final proof means knowing the rootC it was proved under, and upstream
# rebuilt v1.1.0-alpha in place on 2026-08-19 and changed that root -- so the
# version string no longer identifies it, and a fresh install of the tag this
# proof names refuses every proof published before that date. The daemon
# therefore publishes the root it actually proves under, compiled into the
# binary rather than configured.
#
# An anchor merely asserted beside the proofs would be worse than none, because
# a reader would trust it. So it is checked against the proof's own last four
# words, which cost nothing to read, and a disagreement is fatal here.
if [ "$ANCHOR" = "absent" ]; then
  echo "the API publishes no vadcop_final_vk yet."
  echo "A third party therefore cannot get the anchor from the API and must take"
  echo "it from this source tree, which is what step 5 compiles in. That is the"
  echo "gap the anchor closes; until the daemon that publishes it is deployed,"
  echo "this run leans on the repository and does not prove the criterion."
else
  python3 - "$WORK/proof.bin" "$ANCHOR" <<'ANCHORPY'
import struct, sys
tail = list(struct.unpack("<4Q", open(sys.argv[1], "rb").read()[-32:]))
published = list(struct.unpack("<4Q", bytes.fromhex(sys.argv[2][2:])))
if tail != published:
    raise SystemExit(
        "FAIL: the published anchor %s is not the one the proof carries %s. "
        "An anchor that disagrees with its own proof is worse than none."
        % (published, tail))
print("published anchor matches the proof's own tail")
ANCHORPY
fi

say "4. the vadcop_final key upstream serves today"
# Cheap, and it is the failure everyone hits. Upstream rebuilt the
# v1.1.0-alpha proving key in place on 2026-08-19 and changed this root while
# leaving the tag and the .hash file alone, so a fresh install refuses every
# proof published before that date. Naming it here keeps it from being read as
# a fault in the proof.
curl -fsS "https://storage.googleapis.com/zisk-setup/zisk-verifykey-${ZISK_VERSION#v}.tar.gz" \
  -o "$WORK/verifykey.tar.gz"
tar xzf "$WORK/verifykey.tar.gz" -C "$WORK"
python3 - "$WORK/provingKey/zisk/vadcop_final/vadcop_final.verkey.bin" "$WORK/proof.bin" <<'PY'
import struct, sys
fresh = list(struct.unpack("<4Q", open(sys.argv[1], "rb").read()))
proof = list(struct.unpack("<4Q", open(sys.argv[2], "rb").read()[-32:]))
print("upstream today %s" % fresh)
if fresh != proof:
    print("NOTE: the release the proof names now ships a different vadcop_final root.")
    print("      That is the upstream in-place rebuild of 2026-08-19, not a fault in")
    print("      the proof. The root the proof was made under is pinned as")
    print("      VADCOP_FINAL_VK in crates/common/src/recursion.rs, and that is what")
    print("      the verifier below compiles in.")
PY

say "5. the STARK, in a cold directory"
CRATE="$WORK/zkasper-verify"
mkdir -p "$CRATE/src"
cat > "$CRATE/Cargo.toml" <<EOF
[package]
name = "zkasper-verify"
version = "0.0.0"
edition = "2021"

[dependencies]
zkasper-common = { git = "https://github.com/zkasperlabs/zkasper", rev = "$COMMIT" }
EOF
cat > "$CRATE/src/main.rs" <<'RS'
use std::time::Instant;
use zkasper_common::recursion;

fn unhex(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 4 {
        eprintln!("usage: zkasper-verify <proof.bin> <program_vk_hex> <public_bytes_hex>");
        std::process::exit(2);
    }
    let raw = std::fs::read(&a[1]).expect("read proof");
    assert_eq!(raw.len() % 8, 0, "proof is not a whole number of u64 words");
    let words: Vec<u64> = raw
        .chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect();
    let vk_bytes = unhex(&a[2]);
    assert_eq!(vk_bytes.len(), 32, "program_vk must be 32 bytes");
    let mut program_vk = [0u64; 4];
    for (i, w) in program_vk.iter_mut().enumerate() {
        *w = u64::from_le_bytes(vk_bytes[i * 8..i * 8 + 8].try_into().unwrap());
    }
    let publics = unhex(&a[3]);

    println!("compiled-in vk {:?}", recursion::VADCOP_FINAL_VK);
    let t = Instant::now();
    let ok = recursion::verify_child(&words, &program_vk, &publics);
    println!("verify_child   {} in {:.3} s", ok, t.elapsed().as_secs_f64());
    if !ok {
        std::process::exit(1);
    }
}
RS

# env -i, so nothing this shell inherited reaches the build or the verifier.
# RUSTUP_HOME is kept because a Rust toolchain is not a proving key; CARGO_HOME
# is not, so every crate is fetched from crates.io and GitHub in front of you.
env -i \
  PATH="$PATH" \
  HOME="$HOME_DIR" \
  CARGO_HOME="$CARGO_DIR" \
  RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" \
  CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$COLD/target}" \
  cargo build --release --manifest-path "$CRATE/Cargo.toml"

BIN="${CARGO_TARGET_DIR:-$COLD/target}/release/zkasper-verify"
env -i \
  PATH="$PATH" \
  HOME="$HOME_DIR" \
  "$BIN" "$WORK/proof.bin" "$PROGRAM_VK" "$PUBLIC_BYTES"

say "VERIFIED"
echo "epoch $EPOCH, $STAGE, $PROGRAM"
echo "cold root  $COLD"
echo "zisk dirs  $(find "$HOME_DIR" "$CARGO_DIR" -maxdepth 2 -name '.zisk' | wc -l) (want 0)"

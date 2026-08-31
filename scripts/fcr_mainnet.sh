#!/bin/bash
set -euo pipefail

# Confirm a mainnet block under the FCR specification, end to end.
#
#   ./scripts/fcr_mainnet.sh <beacon-url> [slot] [count]
#
# Everything here runs on CPU. A GPU changes one number -- the prove step, ~94x,
# 14m14s against a modelled 9.09s -- and nothing else. On a rented card install
# the toolchain with:
#
#   ziskup --version 1.2.0-alpha --gpu --provingkey --prefix <dir>
#
# and point ZISK_PREFIX at it. Use --prefix: a bare install would take over
# ~/.zisk and the proving key an earlier release left there is not replaceable.

BEACON="${1:?usage: fcr_mainnet.sh <beacon-url> [slot] [count]}"
SLOT="${2:-}"
COUNT="${3:-1}"
ZISK="${ZISK_PREFIX:-/mnt/ssd/zisk-1.2.0}"
OUT="${OUT_DIR:-/mnt/ssd}"
export PATH="$ZISK/bin:$PATH" ZISK_HOME="$ZISK"

# The RANDAO mix two epochs back is what get_seed hashes. Supplying it is what
# makes the committee assignment proven rather than the node's word.
head_slot=$( curl -sf "$BEACON/eth/v1/beacon/headers/head" |
  python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["header"]["message"]["slot"])' )
[ -n "$SLOT" ] || SLOT=$(( head_slot - 64 - head_slot % 32 ))
randao=$( curl -sf "$BEACON/eth/v1/beacon/states/head/randao?epoch=$(( SLOT / 32 - 2 ))" |
  python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["randao"])' )

echo "== collecting slot $SLOT (+$COUNT), proving the assignment, judging =="
cargo build --release --bin gen_fcr_mainnet_witness
./target/release/gen_fcr_mainnet_witness \
  --beacon-url "$BEACON" --slot "$SLOT" --count "$COUNT" \
  --randao "$randao" --out "$OUT/fcr-witness.bin"

echo "== proving =="
cargo-zisk build --release -p zkasper-fcr-proof-guest
python3 scripts/zisk_input.py "$OUT/fcr-witness.bin" "$OUT/fcr-input.bin"
time cargo-zisk prove \
  -e target/elf/riscv64ima-zisk-zkvm-elf/release/zkasper-fcr-proof-guest \
  -i "$OUT/fcr-input.bin" -o "$OUT/fcr-proof.bin" -a -y

echo "== verifying =="
cargo-zisk verify -p "$OUT/fcr-proof.bin"

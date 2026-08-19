#!/bin/bash
set -euo pipefail
# Emulate the recursion bench guest at 0..3 children and print steps and cost units.
#
# `ziskemu -X` reports STEPS, BASE, VARIABLE and TOTAL. TOTAL is the trace area a
# prove has to cover, so the difference between n and n+1 children is one
# recursion in the currency the prover charges in, with no timing noise at all.
cd "$(dirname "$0")/.."
export ZISK_DIR=${ZISK_DIR:-/mnt/ssd/zisk-1.1.0}
export PATH="$ZISK_DIR/bin:$PATH"

ELF=target/elf/riscv64ima-zisk-zkvm-elf/release/zkasper-recursion-bench-guest
WORK=${WORK:-/mnt/ssd/recursion-bench}
PROOFS=${PROOFS:-/mnt/ssd/zkasper-helios-demo/proof-469424.bin /mnt/ssd/zkasper-helios-demo/proof-469425.bin}
mkdir -p "$WORK"

for n in 0 1 2 3; do
  python3 scripts/recursion_bench_input.py "$WORK/children_$n.bin" "$n" $PROOFS
  echo "--- children=$n ---"
  ziskemu -X -e "$ELF" -i "$WORK/children_$n.bin" | grep -E "^STEPS|^BASE|^VARIABLE|^TOTAL|verified"
done

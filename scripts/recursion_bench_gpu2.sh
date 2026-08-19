#!/bin/bash
set -euo pipefail

# The same 0..3 ladder against a child that was NOT wrapped to
# `VadcopFinalMinimal`. `verify_zisk_proof` dispatches on the flag in the proof:
# a minimal child is checked by `vadcop_final_compressed`, whose leaf and
# Merkle-compression hashes are Poseidon1 at width 8 and therefore software, and
# an unwrapped one by `vadcop_final`, which is width 16 and therefore the
# `poseidon1` precompile. Under the emulator that is 23.1x, and this is what it
# is worth in seconds.

ELF=${ELF:-$HOME/zkasper-recursion-bench-guest}
WORK=${WORK:-$HOME/rb}
REPEATS=${REPEATS:-2}
. "$HOME/.cargo/env"
export PATH="$HOME/.zisk/bin:$PATH"
mkdir -p "$WORK"

echo "=== cost units ==="
for n in 0 1 2 3; do
  echo "--- nm children=$n ---"
  ziskemu -X -e "$ELF" -i "$HOME/nm_$n.bin" | grep -E "^STEPS|^VARIABLE|^TOTAL"
done

echo "=== prove ==="
for run in $(seq 1 "$REPEATS"); do
  for n in 0 1 2 3; do
    echo "--- nm run=$run children=$n ---"
    /usr/bin/time -f "WALL nm run=$run children=$n %e s  maxrss %M kB" \
      cargo-zisk prove -e "$ELF" -i "$HOME/nm_$n.bin" \
        -o "$WORK/nm_proof_$n.bin" -g -y 2>&1 | grep -E "Proof generated|WALL|error|Error" || true
  done
done
echo "=== nm done ==="

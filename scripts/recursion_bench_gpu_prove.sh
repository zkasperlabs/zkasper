#!/bin/bash
set -uo pipefail

# Prove the 0..3 ladder for one input prefix. Split out of
# `recursion_bench_gpu.sh` because that script wrapped every prove in
# `/usr/bin/time`, which the CUDA image does not ship, so all eight proves
# vanished into `|| true` and the run reported nothing.
#
# Usage: recursion_bench_gpu_prove.sh <input-prefix> [repeats]
#   children   the minimal children the pipeline uses today
#   nm         the same proofs unwrapped (VadcopFinal)

PREFIX=${1:-children}
REPEATS=${2:-2}
ELF=${ELF:-$HOME/zkasper-recursion-bench-guest}
WORK=${WORK:-$HOME/rb}
. "$HOME/.cargo/env"
export PATH="$HOME/.zisk/bin:$PATH"
mkdir -p "$WORK"

for run in $(seq 1 "$REPEATS"); do
  for n in 0 1 2 3; do
    echo "--- $PREFIX run=$run children=$n ---"
    start=$(date +%s.%N)
    cargo-zisk prove -e "$ELF" -i "$HOME/${PREFIX}_$n.bin" \
      -o "$WORK/${PREFIX}_proof_$n.bin" -g -y > "$WORK/${PREFIX}_${run}_$n.log" 2>&1
    status=$?
    end=$(date +%s.%N)
    echo "WALL $PREFIX run=$run children=$n $(echo "$end - $start" | bc) s status=$status"
    grep -E "Proof generated|Vadcop Final" "$WORK/${PREFIX}_${run}_$n.log" | tail -2
    [ "$status" -eq 0 ] || tail -5 "$WORK/${PREFIX}_${run}_$n.log"
  done
done
echo "=== $PREFIX ladder done ==="

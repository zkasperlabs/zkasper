#!/bin/bash
set -euo pipefail

# Does the box, rather than the guest, set the per-child cost?
#
# The published 1.49x between `justification-guest` and the streaming guests
# cannot be a difference in work — the emulator says one child is 24.933 G cost
# units whatever verifies it. Witness generation is CPU-bound and is inside
# `prove_millis`, so a box with fewer cores charges more for the same child.
# This proves one child at several core counts on one card.

ELF=${ELF:-$HOME/zkasper-recursion-bench-guest}
WORK=${WORK:-$HOME/rb}
. "$HOME/.cargo/env"
export PATH="$HOME/.zisk/bin:$PATH"
mkdir -p "$WORK"

for cores in 255 63 31 15; do
  echo "--- cores=$((cores + 1)) children=1 ---"
  /usr/bin/time -f "WALL cores=$((cores + 1)) %e s" \
    taskset -c "0-$cores" cargo-zisk prove -e "$ELF" -i "$HOME/children_1.bin" \
      -o "$WORK/cores_proof.bin" -g -y 2>&1 | grep -E "Proof generated|WALL|Node has|threads" || true
done
echo "=== cores done ==="

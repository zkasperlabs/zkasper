#!/bin/bash
set -euo pipefail

# Generate and verify a real Zisk proof, and report how long proving took.
#
# Usage: ./scripts/test_zisk_proof.sh [proof-type]
#   proof-type: bootstrap | epoch-diff | slot-proof | justification | finalization
#
# Requires a proving key: ziskup --version 1.0.0-alpha --cpu --provingkey -y

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

PROOF_TYPE=${1:-bootstrap}
GUEST_BIN="zkasper-${PROOF_TYPE}-guest"
ELF="target/elf/riscv64ima-zisk-zkvm-elf/release/${GUEST_BIN}"
WORK="target/proofs/${PROOF_TYPE}"
mkdir -p "$WORK"

echo "=== Zisk proof: ${PROOF_TYPE} ==="

echo "--- Witness ---"
cargo run --release --bin gen-test-witness -- "$PROOF_TYPE" "${WORK}/witness.bin"
# The emulator and prover take length-prefixed, 8-byte-aligned input.
python3 scripts/zisk_input.py "${WORK}/witness.bin" "${WORK}/input.bin"

echo "--- Build guest ---"
cargo-zisk build --release -p "${GUEST_BIN}"

echo "--- Cost report ---"
ziskemu -X -e "$ELF" -i "${WORK}/input.bin" | head -16

echo "--- ROM setup ---"
cargo-zisk setup -e "$ELF"

echo "--- Prove ---"
# Wall-clock here is what turns the emulator's trace-cell counts into seconds;
# see BENCHMARKS.md.
/usr/bin/time -v cargo-zisk prove -e "$ELF" -i "${WORK}/input.bin" -o "${WORK}/proof" -a -y \
  2>&1 | grep -E "Elapsed|Maximum resident|error" || true

echo "--- Verify ---"
cargo-zisk verify -p "${WORK}/proof/vadcop_final_proof.bin"

echo "=== PASSED: ${PROOF_TYPE} ==="

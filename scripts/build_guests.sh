#!/bin/bash
set -euo pipefail

# Build every guest ELF, where `--prover zisk` expects to find them.
#
# Usage: ./scripts/build_guests.sh [guest-name ...]
#
# A bare `cargo-zisk build` would also build the host workspace, which needs
# libssl-dev and is not wanted here; each guest is named explicitly instead.
#
# ELFs land in target/elf/riscv64ima-zisk-zkvm-elf/release/. That is the default
# `--elf-dir`, and a guest's verification key is derived from its ELF, so a
# rebuilt guest is a different program to every proof that binds it — rebuild all
# of them together rather than one at a time.

cd "$(dirname "$0")/.."
export PATH="${ZISK_BIN:-$HOME/.zisk/bin}:$PATH"

GUESTS=(
  epoch-diff-guest
  committee-proof-guest
  slot-proof-guest
  justification-guest
  finalization-guest
  group-proof-guest
  aggregation-guest
  stream-final-guest
)

for guest in "${@:-${GUESTS[@]}}"; do
  echo "=== $guest ==="
  cargo-zisk build --release -p "zkasper-$guest"
done

ls -la target/elf/riscv64ima-zisk-zkvm-elf/release/ | grep -E "zkasper-[a-z-]+-guest$"

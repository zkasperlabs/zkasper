#!/bin/bash
set -euo pipefail
# Build the recursion bench guest with the v1.1.0-alpha toolchain.
cd "$(dirname "$0")/.."
export ZISK_DIR=${ZISK_DIR:-/mnt/ssd/zisk-1.1.0}
export PATH="$ZISK_DIR/bin:$PATH"
cargo-zisk build --release -p zkasper-recursion-bench-guest
ls -la target/elf/riscv64ima-zisk-zkvm-elf/release/ | grep recursion

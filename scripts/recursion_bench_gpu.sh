#!/bin/bash
set -euo pipefail

# What one recursive child verification costs, on a GPU, with the stage floor
# separated from the per-child slope.
#
# Runs on a rented RTX 5090 box. It brings nothing of the zkasper workspace with
# it: the guest ELF and the four inputs are staged from the machine that built
# them, so the box needs the Zisk toolchain and the proving key and nothing else.
#
#   scp target/elf/riscv64ima-zisk-zkvm-elf/release/zkasper-recursion-bench-guest \
#       /mnt/ssd/recursion-bench/children_*.bin scripts/recursion_bench_gpu.sh <box>:
#   ssh <box> 'setsid nohup ./recursion_bench_gpu.sh > bench.log 2>&1 &'
#
# Read `Proof generated in` out of the log, not the wall clock: wall minus that
# is process start plus GPU allocation, which the pipeline pays once per process
# and not once per proof.

ZISK_VERSION=1.1.0-alpha
ELF=${ELF:-$HOME/zkasper-recursion-bench-guest}
WORK=${WORK:-$HOME/rb}
REPEATS=${REPEATS:-2}

echo "=== 0. Preflight ==="
nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader
nproc && free -g | head -2 && df -h / | tail -1

echo "=== 1. System dependencies ==="
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
for pkg in \
  build-essential curl git jq xz-utils nasm python3 ca-certificates \
  libgmp-dev libomp5 libomp-dev \
  libopenmpi-dev openmpi-bin openmpi-common \
  libsodium23 pkg-config clang libclang-dev
do
  apt-get install -y --no-install-recommends "$pkg" >/dev/null \
    || echo "WARNING: failed to install $pkg, continuing"
done

echo "=== 2. Rust + Zisk ==="
# ziskup links its toolchain into rustup, so rustup must exist first or ziskup
# aborts before fetching the proving key and the box looks set up but is not.
command -v cargo >/dev/null || {
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
}
. "$HOME/.cargo/env"
curl -sSf https://raw.githubusercontent.com/0xPolygonHermez/zisk/main/ziskup/install.sh | bash -s -- \
  --version "$ZISK_VERSION" --gpu --provingkey -y
export PATH="$HOME/.zisk/bin:$PATH"
# The saved template ships 1.0.0-alpha and a populated ~/.zisk is not evidence
# of anything; this project needs 1.1.0-alpha.
cargo-zisk --version
cargo-zisk --version | grep -q "$ZISK_VERSION" || { echo "WRONG ZISK VERSION"; exit 1; }

echo "=== 3. ROM setup ==="
mkdir -p "$WORK"
time cargo-zisk setup -e "$ELF"

echo "=== 4. Cost units, for the record ==="
for n in 0 1 2 3; do
  echo "--- children=$n ---"
  ziskemu -X -e "$ELF" -i "$HOME/children_$n.bin" | grep -E "^STEPS|^BASE|^VARIABLE|^TOTAL"
done

echo "=== 5. Prove 0..3 children ==="
# The very first prove regenerates Vadcop constant polynomials and trees, which
# is a one-time global cost; every point is therefore proved REPEATS times and
# only the last is quoted.
for run in $(seq 1 "$REPEATS"); do
  for n in 0 1 2 3; do
    echo "--- run=$run children=$n ---"
    /usr/bin/time -f "WALL run=$run children=$n %e s  maxrss %M kB" \
      cargo-zisk prove -e "$ELF" -i "$HOME/children_$n.bin" \
        -o "$WORK/proof_$n.bin" -g -y 2>&1 | grep -E "Proof generated|WALL|GPU 0:|Minimum free|error|Error" || true
  done
done

echo "=== 6. Done ==="
grep -E "^--- run|Proof generated|WALL" "$HOME/bench.log" | tail -60 || true

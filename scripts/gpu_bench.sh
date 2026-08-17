#!/bin/bash
set -euo pipefail

# Calibrate Zisk proving throughput on a GPU box.
#
# Reproduces the two CPU measurements in BENCHMARKS.md on GPU hardware, so the
# CPU->GPU speedup stops being an inference and becomes a number. Everything in
# BENCHMARKS.md is denominated in Zisk cost units (trace area), which are
# hardware-independent; only the units-per-second conversion changes.
#
# CPU baseline (14-core i5-13500, no GPU):
#   slot-proof   575,610,460 units ->  795.9 s
#   bench n=220k 866,953,297 units -> 1030.0 s
#   fit: time = 333.4 s + units / 1,244,523
#
# Usage: ./scripts/gpu_bench.sh
#
# Requires: NVIDIA driver >= 525.60.13, ~60 GB free disk, ~32 GB RAM.

ZISK_VERSION="1.0.0-alpha"

echo "=== 0. Preflight ==="
nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader
nproc && free -g | head -2 && df -h . | tail -1

echo "=== 1. System dependencies ==="
# libmpi (cargo-zisk links it), libomp (ziskemu), gmp+nasm (lib-c build).
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
  build-essential curl git jq xz-utils nasm \
  libgmp-dev libomp5 libomp-dev libopenmpi-dev openmpi-bin openmpi-common \
  python3

echo "=== 2. Rust + Zisk toolchain (GPU build) ==="
command -v cargo >/dev/null || {
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  . "$HOME/.cargo/env"
}
curl -sSf https://raw.githubusercontent.com/0xPolygonHermez/zisk/main/ziskup/install.sh | bash
# --gpu selects the CUDA build; --provingkey pulls the 3.2 GB key (25 GB unpacked).
"$HOME/.zisk/bin/ziskup" --version "$ZISK_VERSION" --gpu --provingkey -y
export PATH="$HOME/.zisk/bin:$PATH"
cargo-zisk --version

echo "=== 3. Build guests ==="
cargo-zisk build --release -p zkasper-slot-proof-guest
cargo-zisk build --release -p zkasper-bench-guest

echo "=== 4. Inputs ==="
mkdir -p target/gpu
cargo run --release --bin gen-test-witness -- slot-proof target/gpu/slot_witness.bin
# Zisk stdin is length-prefixed and must be a multiple of 8 bytes.
python3 scripts/zisk_input.py target/gpu/slot_witness.bin target/gpu/slot_input.bin
python3 -c "
import struct
open('target/gpu/bench_input.bin','wb').write(struct.pack('<QII', 8, 1, 220000))"

echo "=== 5. Confirm the workloads match the CPU baseline ==="
for e in slot-proof bench; do
  case $e in
    slot-proof) ELF=target/elf/riscv64ima-zisk-zkvm-elf/release/zkasper-slot-proof-guest; IN=target/gpu/slot_input.bin ;;
    bench)      ELF=target/elf/riscv64ima-zisk-zkvm-elf/release/zkasper-bench-guest;      IN=target/gpu/bench_input.bin ;;
  esac
  echo "--- $e ---"
  ziskemu -X -e "$ELF" -i "$IN" | grep -E "^STEPS|^VARIABLE|^BASE|^TOTAL"
done

echo "=== 6. Setup + prove, timed ==="
# -o takes a FILE path, not a directory.
for e in slot-proof bench; do
  case $e in
    slot-proof) ELF=target/elf/riscv64ima-zisk-zkvm-elf/release/zkasper-slot-proof-guest; IN=target/gpu/slot_input.bin ;;
    bench)      ELF=target/elf/riscv64ima-zisk-zkvm-elf/release/zkasper-bench-guest;      IN=target/gpu/bench_input.bin ;;
  esac
  echo "--- setup $e ---"
  time cargo-zisk setup -e "$ELF"
  echo "--- prove $e ---"
  time cargo-zisk prove -e "$ELF" -i "$IN" -o "target/gpu/${e}_proof.bin" -y
  cargo-zisk verify -p "target/gpu/${e}_proof.bin" || true
done

echo
echo "=== 7. Fit ==="
echo "Take the two (TOTAL cost, prove wall-clock) pairs and solve:"
echo "    marginal = (c2 - c1) / (t2 - t1)      fixed = t1 - c1 / marginal"
echo "Speedup vs the CPU baseline = marginal / 1,244,523"
echo "Then: scripts/proving_cost.py --cells-per-second <marginal> --dollars-per-hour <gpu rate>"

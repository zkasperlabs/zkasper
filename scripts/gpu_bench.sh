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
# Requires: NVIDIA driver >= 525.60.13, ~90 GB free disk, ~32 GB RAM.
#
# Run it under `setsid nohup ./scripts/gpu_bench.sh > gpu_bench.log 2>&1 &` and
# tail the log. Setup plus two proofs takes tens of minutes, and an ssh session
# that drops takes a foreground run with it.

ZISK_VERSION="1.0.0-alpha"
SLOT_ELF=target/elf/riscv64ima-zisk-zkvm-elf/release/zkasper-slot-proof-guest
BENCH_ELF=target/elf/riscv64ima-zisk-zkvm-elf/release/zkasper-bench-guest

echo "=== 0. Preflight ==="
nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader
nproc && free -g | head -2 && df -h . | tail -1

echo "=== 1. System dependencies ==="
# libmpi (cargo-zisk links it), libomp (ziskemu), gmp+nasm (lib-c build),
# libsodium+pkg-config+clang/libclang (bindgen in the Zisk build scripts).
#
# Install one package per apt invocation. A single apt call is atomic: if any
# package in the list is unresolvable on this image, apt installs *nothing* and
# every other dependency silently goes missing.
#
# libssl-dev is deliberately absent. On the CUDA base images it hits an
# unresolvable version conflict against the preinstalled libssl. It is only
# needed by the host-side `witness-gen` crate, never by the guest ELFs, so this
# script builds guests only and consumes pre-staged inputs (see step 4).
sudo apt-get update -qq
for pkg in \
  build-essential curl git jq xz-utils nasm python3 ca-certificates \
  libgmp-dev libomp5 libomp-dev \
  libopenmpi-dev openmpi-bin openmpi-common \
  libsodium23 pkg-config clang libclang-dev
do
  echo "--- apt: $pkg ---"
  sudo apt-get install -y --no-install-recommends "$pkg" \
    || echo "WARNING: failed to install $pkg, continuing"
done

echo "=== 2. Rust + Zisk toolchain (GPU build) ==="
command -v cargo >/dev/null || {
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  . "$HOME/.cargo/env"
}
curl -sSf https://raw.githubusercontent.com/0xPolygonHermez/zisk/main/ziskup/install.sh | bash
# --gpu selects the CUDA build; --provingkey pulls the 3.2 GB key (26 GB
# unpacked); --with-snark adds the final SNARK key that `cargo-zisk wrap` needs.
"$HOME/.zisk/bin/ziskup" --version "$ZISK_VERSION" --gpu --provingkey --with-snark -y
export PATH="$HOME/.zisk/bin:$PATH"
cargo-zisk --version

echo "=== 3. Build guests ==="
# Guest packages only. A bare `cargo-zisk build` would also build the host
# workspace, which needs libssl-dev (see step 1).
cargo-zisk build --release -p zkasper-slot-proof-guest
cargo-zisk build --release -p zkasper-bench-guest

echo "=== 4. Inputs ==="
mkdir -p target/gpu
# The bench input is three integers, so generate it anywhere.
python3 -c "
import struct
open('target/gpu/bench_input.bin','wb').write(struct.pack('<QII', 8, 1, 220000))"
# The slot-proof witness comes from `gen-test-witness`, which lives in the host
# `witness-gen` crate and needs OpenSSL. If that crate cannot build here, stage
# the input from a machine that can:
#   cargo run --release --bin gen-test-witness -- slot-proof slot_witness.bin
#   python3 scripts/zisk_input.py slot_witness.bin slot_input.bin
#   scp slot_input.bin <gpu-box>:<repo>/target/gpu/slot_input.bin
if [ ! -f target/gpu/slot_input.bin ]; then
  cargo run --release --bin gen-test-witness -- slot-proof target/gpu/slot_witness.bin
  # Zisk stdin is length-prefixed and must be a multiple of 8 bytes.
  python3 scripts/zisk_input.py target/gpu/slot_witness.bin target/gpu/slot_input.bin
fi

echo "=== 5. Confirm the workloads match the CPU baseline ==="
for e in slot-proof bench; do
  case $e in
    slot-proof) ELF=$SLOT_ELF; IN=target/gpu/slot_input.bin ;;
    bench)      ELF=$BENCH_ELF; IN=target/gpu/bench_input.bin ;;
  esac
  echo "--- $e ---"
  ziskemu -X -e "$ELF" -i "$IN" | grep -E "^STEPS|^VARIABLE|^BASE|^TOTAL"
done

echo "=== 6. Setup + prove, timed ==="
# -o takes a FILE path, not a directory.
# -g is what puts the proof on the GPU. Without it cargo-zisk proves on the CPU
# and the whole run measures the wrong machine.
for e in slot-proof bench; do
  case $e in
    slot-proof) ELF=$SLOT_ELF; IN=target/gpu/slot_input.bin ;;
    bench)      ELF=$BENCH_ELF; IN=target/gpu/bench_input.bin ;;
  esac
  echo "--- setup $e ---"
  time cargo-zisk setup -e "$ELF"
  echo "--- prove $e ---"
  time cargo-zisk prove -e "$ELF" -i "$IN" -o "target/gpu/${e}_proof.bin" -g -y
done

echo "=== 6b. Wrap the slot proof, timed ==="
# Wrapping is its own subcommand, not a flag on `prove`. It compresses the
# VADCOP STARK into the final proof that goes on the latency critical path, so
# it belongs in the measurement.
time cargo-zisk wrap --proof target/gpu/slot-proof_proof.bin \
  --output target/gpu/slot-proof_wrapped.bin -g

echo
echo "=== 7. Fit ==="
echo "Take the two (TOTAL cost, prove wall-clock) pairs and solve:"
echo "    marginal = (c2 - c1) / (t2 - t1)      fixed = t1 - c1 / marginal"
echo "Speedup vs the CPU baseline = marginal / 1,244,523"
echo "Then: scripts/proving_cost.py --cells-per-second <marginal> --dollars-per-hour <gpu rate>"

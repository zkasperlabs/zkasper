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
# GPU result (RTX 5090, Zisk 1.0.0-alpha, 2026-08-18), warm proves:
#   slot-proof   575,395,812 units ->  27.70 s   (5 samples, 27.09-28.70)
#   bench n=220k 866,953,297 units ->  32.30 s   (2 samples, 32.03-32.56)
#   fit: time = 19.5 s + units / 67,452,592
#   -> 54x the CPU marginal throughput; 29x end-to-end on the slot proof.
#   wrap --minimal: 18.5 s wall, of which only 0.2 s is the compression itself.
#
# That fit is a least-squares line over five bench sizes (n = 55k, 110k, 220k,
# 440k, 660k), not the two points below; residuals are under 0.12 s. The
# slot-proof measurement was not used to build it and lands 1.3% off it, which
# is the evidence that Zisk cost units really are hardware-portable across two
# very different workloads (BLS precompiles vs poseidon2).
#
# Usage: ./scripts/gpu_bench.sh
#
# Requires: NVIDIA driver >= 525.60.13, ~120 GB free disk, ~32 GB RAM.
#
# Disk is the easy thing to underestimate. The downloaded proving key is 26 GB,
# but the first `setup`/`prove` regenerates constant trees into it and it grows
# to ~85 GB. Each program's setup adds a further ~3 GB to ~/.zisk/cache.
#
# Run it under `setsid nohup ./scripts/gpu_bench.sh > gpu_bench.log 2>&1 &` and
# tail the log. Setup plus two proofs takes tens of minutes, and an ssh session
# that drops takes a foreground run with it.
#
# Timings on a fresh RTX 5090 box, for planning a rental:
#   apt + rustup + ziskup --provingkey   ~16 min  (3.2 GB download)
#   cargo-zisk setup, per ELF             ~6.4 min for the first one
#   first prove                            ~99 s  (INITIALIZING_PROOFMAN 71.7 s)
#   warm prove, small workload             ~19 s wall
# Disk: 3.2 GB compressed -> 34 GB unpacked -> 72 GB after the first setup.
#
# MEASUREMENT PROTOCOL. `time cargo-zisk prove` measures three things at once
# and the pipeline pays for one of them. The prover brackets its own phases:
#   >>> INITIALIZING_PROOFMAN ... <<< INITIALIZING_PROOFMAN (Nms)
#   Proof generated in X s
# Read `Proof generated in`, and treat wall-minus-that as process start plus GPU
# allocation. Fitting wall clock instead puts ~13.6 s of startup into the
# intercept and calls it a per-proof floor, which is how the old 19.52 s
# "fixed cost" and the 293.6 M "BASE" came to be quoted as if they were the
# same kind of thing. They are not.
#
# GPU MEMORY. The prover does not allocate what the witness needs, it allocates
# what the card has: it reads *free* VRAM and fills it. Every prove in this
# campaign logged
#   Minimum free memory available for GPU usage: 30.609253 GB
#   GPU 0: Allocated 30.135334 GB (28.413327 GB unified + 1.722007 GB const pols)
# on a 32.61 GB card, for workloads spanning 40x in cost. Two provers therefore
# do not fit on one card; see BENCHMARKS.md. `cargo-zisk prove` does expose
# `-m/--minimal-memory` and `-x/--max-witness-stored <bytes>` if you want to try.

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
# libssl-dev is not installed here because the guest ELFs never need it, and
# this script builds guests only and consumes pre-staged inputs (see step 4).
#
# It is NOT unresolvable, despite what this comment used to claim: on
# nvidia/cuda:12.8.1-devel-ubuntu24.04 `apt-get install -y libssl-dev` succeeds
# (verified 2026-08-18, it pulls openssl 3.0.13-0ubuntu3.12 over 3.0.13-0ubuntu3.5).
# Install it if you want the host `witness-gen` crate on the box, which you do
# for `cargo test --features zisk-prover` — the warm in-process prover is the
# only way to measure per-proof latency without process startup in the number.
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
# unpacked). That key is enough for `wrap --minimal`; only `wrap --plonk` needs
# the extra SNARK key, which is `ziskup ... --provingkey --with-snark`.
"$HOME/.zisk/bin/ziskup" --version "$ZISK_VERSION" --gpu --provingkey -y
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
  echo "--- prove $e (cold: includes one-time const-tree regeneration) ---"
  time cargo-zisk prove -e "$ELF" -i "$IN" -o "target/gpu/${e}_proof.bin" -g -y
  # The very first prove on a fresh box spends ~70 s inside INITIALIZING_PROOFMAN
  # regenerating Vadcop constant polynomials and trees. That is a one-time global
  # cost, not part of per-proof latency, and it would poison the fit. Prove a
  # second time and use the warm number.
  echo "--- prove $e (warm: this is the number to use) ---"
  time cargo-zisk prove -e "$ELF" -i "$IN" -o "target/gpu/${e}_proof.bin" -g -y
done

echo "=== 6b. Wrap the slot proof, timed ==="
# Wrapping is its own subcommand, not a flag on `prove` (there is no `prove -f`).
# It compresses the VADCOP STARK into the final proof that goes on the latency
# critical path, so it belongs in the measurement.
#
# `wrap` refuses to run without one of --minimal or --plonk. --minimal is the
# recursive STARK compression and works with the standard proving key (verified:
# no --with-snark needed). --plonk targets the on-chain EVM verifier and does
# additionally need the SNARK key (`ziskup ... --provingkey --with-snark`).
#
# Almost all of wrap's wall-clock is process startup and GPU allocation; the
# compression itself is ~0.2 s. Read the GENERATE_VADCOP_FINAL_COMPRESSED_PROOF
# line in the log, not just the `time` output.
time cargo-zisk wrap --proof target/gpu/slot-proof_proof.bin \
  --output target/gpu/slot-proof_wrapped.bin -g --minimal

echo
echo "=== 7. Fit ==="
echo "Take the two (TOTAL cost, warm prove wall-clock) pairs and solve:"
echo "    marginal = (c2 - c1) / (t2 - t1)      fixed = t1 - c1 / marginal"
echo "Speedup vs the CPU baseline = marginal / 1,244,523"
echo
echo "Two points is a fragile fit: the costs differ by ~1.5x but the times by"
echo "only ~4.6 s, against ~0.5 s of run-to-run noise. For a number worth"
echo "quoting, sweep the bench guest instead - it takes n on stdin, so several"
echo "sizes cost minutes and turn the extrapolation into a regression:"
echo "    for n in 55000 110000 220000 440000 660000; do"
echo "      python3 -c \"import struct,sys;n=int(sys.argv[1]);open('target/gpu/bench_%d.bin'%n,'wb').write(struct.pack('<QII',8,1,n))\" \$n"
echo "      ziskemu -X -e $BENCH_ELF -i target/gpu/bench_\$n.bin | grep '^TOTAL'"
echo "      time cargo-zisk prove -e $BENCH_ELF -i target/gpu/bench_\$n.bin -o target/gpu/sweep.bin -g"
echo "    done"
echo "Then keep the slot proof out of the fit and use it to check the line."
echo
echo "Then: scripts/proving_cost.py --cells-per-second <marginal> --dollars-per-hour <gpu rate>"

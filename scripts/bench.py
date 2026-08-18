#!/usr/bin/env python3
"""Measure the marginal Zisk cost of each zkasper primitive.

Runs every mode of the bench guest at two different iteration counts and
subtracts, so program setup, input parsing and output commitment cancel out and
what remains is the per-operation cost.

Usage: scripts/bench.py [--build]
"""
import argparse
import os
import re
import struct
import subprocess
import sys
import tempfile

ELF = "target/elf/riscv64ima-zisk-zkvm-elf/release/zkasper-bench-guest"
ZISKEMU = os.path.expanduser("~/.zisk/bin/ziskemu")

# mode id, label, (low iterations, high iterations)
MODES = [
    (0, "loop baseline",            2000, 4000),
    (1, "poseidon2 permutation",    2000, 4000),
    (2, "acc::compress (node)",     2000, 4000),
    (3, "acc::leaf (validator)",    2000, 4000),
    (4, "sha256_pair (SSZ node)",   2000, 4000),
    (5, "G1 decompress (pubkey)",    100,  200),
    (6, "G1 add (complete-safe)",    200,  400),
    (10, "G1 add (raw precompile)",  200,  400),
    (7, "hash-to-curve G2",           50,  100),
    (8, "pairing check (2 Miller)",   10,   20),
    (20, "fp12 multiply",             200,  400),
    (21, "final exponentiation",       10,   20),
    (23, "commit_fp12",               200,  400),
    (24, "Miller loop, batch of one",  10,   20),
    (25, "G2 subgroup check",          10,   20),
]

# `n` is the batch size here, so the delta is the cost of one extra Miller loop.
BATCH = (9, "marginal Miller loop", 2, 10)

# Same, with the final exponentiation left off: the streaming pipeline's group
# proofs stop here, so this is what they actually pay per attestation.
BATCH_MILLER_ONLY = (22, "marginal Miller loop (no final exp)", 2, 10)


def run(mode, n):
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(struct.pack("<QII", 8, mode, n))
        path = f.name
    try:
        out = subprocess.run(
            [ZISKEMU, "-e", ELF, "-i", path, "-X"],
            capture_output=True, text=True, check=True,
        ).stdout
    finally:
        os.unlink(path)
    return parse(out)


def parse(report):
    def grab(pattern):
        m = re.search(pattern, report, re.M)
        return int(m.group(1).replace(",", "")) if m else 0

    counts = {}
    for name, count, cost in re.findall(
        r"^OP (\S+)\s+([\d,]+)\s+[\d.]+%\s+([\d,]+)", report, re.M
    ):
        counts[name] = (int(count.replace(",", "")), int(cost.replace(",", "")))

    return {
        "steps": grab(r"^STEPS\s+([\d,]+)"),
        "variable": grab(r"^VARIABLE\s+([\d,]+)"),
        "base": grab(r"^BASE\s+([\d,]+)"),
        "precompiles": grab(r"^PRECOMPILES\s+([\d,]+)"),
        "memory": grab(r"^MEMORY\s+([\d,]+)"),
        "main": grab(r"^MAIN\s+([\d,]+)"),
        "ops": counts,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", action="store_true", help="build the guest first")
    args = ap.parse_args()

    if args.build:
        env = dict(os.environ, PATH=os.path.expanduser("~/.zisk/bin") + ":" + os.environ["PATH"])
        subprocess.run(
            ["cargo-zisk", "build", "--release", "-p", "zkasper-bench-guest"],
            check=True, env=env,
        )

    if not os.path.exists(ELF):
        sys.exit(f"{ELF} not found — run with --build")

    base = None
    rows = []
    for mode, label, lo, hi in MODES:
        a, b = run(mode, lo), run(mode, hi)
        d = hi - lo
        steps = (b["steps"] - a["steps"]) / d
        cost = (b["variable"] - a["variable"]) / d
        if base is None:
            base = b["base"]
        precompiles = sorted(
            name for name in b["ops"]
            if b["ops"][name][0] - a["ops"].get(name, (0, 0))[0] > 0
            and name not in ("add", "and", "or", "xor", "sll", "srl", "eq", "ltu",
                             "sub", "lt", "signextend_b", "signextend_h",
                             "signextend_w", "sra", "mul", "mulh", "muluh",
                             "div", "rem", "copyb", "flag", "dma_memcpy",
                             "dma_xmemset", "min", "max")
        )
        rows.append((label, steps, cost, ",".join(precompiles) or "-"))

    baseline_cost = rows[0][2]
    baseline_steps = rows[0][1]

    print(f"\nFixed cost floor per proof (BASE): {base:,}\n")
    print(f"{'primitive':<28} {'steps/op':>10} {'cost/op':>12} {'net of loop':>12}  precompiles")
    print("-" * 94)
    for label, steps, cost, pre in rows:
        net = cost - baseline_cost
        net_s = f"{net:>12,.0f}" if label != "loop baseline" else f"{'—':>12}"
        print(f"{label:<28} {steps - (baseline_steps if label != 'loop baseline' else 0):>10,.1f} "
              f"{cost:>12,.0f} {net_s}  {pre}")
    print()

    mode, label, lo, hi = BATCH
    a, b = run(mode, lo), run(mode, hi)
    miller = (b["variable"] - a["variable"]) / (hi - lo)
    pairing2 = next(c for l, _, c, _ in rows if l.startswith("pairing check")) - baseline_cost
    final_exp = pairing2 - 2 * miller
    print(f"{label:<28} {'':>10} {miller:>12,.0f} {'':>12}")
    print(f"{'final exponentiation':<28} {'':>10} {final_exp:>12,.0f} {'':>12}  (pairing check minus 2 Miller loops)")

    mode, label, lo, hi = BATCH_MILLER_ONLY
    a, b = run(mode, lo), run(mode, hi)
    miller_split = (b["variable"] - a["variable"]) / (hi - lo)
    print(f"{label:<28} {'':>10} {miller_split:>12,.0f} {'':>12}  (zkasper's own loop)")
    print(f"{'  agrees with zisklib':<28} {'':>10} {'':>12} {'':>12}  "
          f"{abs(miller_split - miller) / miller * 100:.2f}% apart")
    print()

    poseidon = next(c for l, _, c, _ in rows if l.startswith("acc::compress")) - baseline_cost
    sha = next(c for l, _, c, _ in rows if l.startswith("sha256_pair")) - baseline_cost
    print(f"accumulator node vs SSZ node: {sha / poseidon:.2f}x in favour of Poseidon2\n")


if __name__ == "__main__":
    main()

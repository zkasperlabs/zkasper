#!/usr/bin/env python3
"""Measure what proving Ethereum's validator shuffle costs inside a Zisk guest.

`crates/shuffle-bench-guest` computes the same function every way that is worth
computing it — the spec transcribed literally, the whole-set form every client
implements, a bit-sliced form, and the two halves of a sampled check — and
`V_SELFTEST` holds all of them to the same assignment. This runs each under
`ziskemu -X` at two sizes and subtracts, so program setup, input parsing and the
final checksum cancel and what is left is **marginal cost per validator**, the
only figure that extrapolates to mainnet.

    scripts/shuffle_bench.py --build      # every variant, per validator
    scripts/shuffle_bench.py --selftest   # every variant agrees, natively
    scripts/shuffle_bench.py --specref    # and agrees with the spec, in Python
    scripts/shuffle_bench.py --mainnet    # the whole-set forms at full size
    scripts/shuffle_bench.py --sweep      # is per-validator cost flat?

**Neither cost units nor executed steps convert to seconds on their own.**
Effective throughput spans 18M to 665M units/s across real guests, and a step
that drives a precompile is worth thirty of a step that does not. The rates
below are per work class, MEASURED on an RTX 5090 over 18 proved points, and
`zkasper-pm/technical/shuffle-proof-cost.md` carries the campaign. For the
integer-and-memory class every whole-set variant here belongs to:

    seconds = 2.158 + 206.11 ns * executed steps

which puts the bit-sliced shuffle over the mainnet active set at 44.2 s, and
that figure is a direct measurement rather than an extrapolation.
"""
import argparse
import os
import re
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ELF = os.path.join(
    ROOT, "target/elf/riscv64ima-zisk-zkvm-elf/release/zkasper-shuffle-bench-guest"
)
NATIVE = os.path.join(ROOT, "target/release/zkasper-shuffle-bench-guest")
ZISK_BIN = os.environ.get("ZISK_BIN", os.path.expanduser("~/.zisk/bin"))
ZISKEMU = os.path.join(ZISK_BIN, "ziskemu")

# Active validators on mainnet: the shuffle's domain is the active set, not the
# registry. 901,001 committee places is what epoch 469506 reported.
MAINNET_ACTIVE = 901_001
# MEASURED, RTX 5090, Zisk v1.1.0-alpha: OLS over five bit-sliced sizes from
# 6.5M to 203.7M executed steps. It holds for the whole-set `u32` form too
# (196-205 ns/step over three sizes) and for nothing that is precompile-bound.
SECONDS_FLOOR = 2.158
NS_PER_STEP = 206.11

# variant id, label, the axis its cost scales with, and the pair to subtract.
PER_INDEX = "param"
PER_VALIDATOR = "n"
VARIANTS = [
    (0, "spec compute_shuffled_index", PER_INDEX, 20, 40),
    (1, "spec, pivots hoisted", PER_INDEX, 20, 40),
    (2, "whole set, u32 index array", PER_VALIDATOR, 32768, 65536),
    (3, "whole set, u8 slot labels", PER_VALIDATOR, 32768, 65536),
    (4, "whole set, bit-sliced", PER_VALIDATOR, 32768, 65536),
    (10, "whole set, bit-sliced plane-major", PER_VALIDATOR, 32768, 65536),
    (5, "source bitmaps only", PER_VALIDATOR, 32768, 65536),
    (6, "sampled trajectory, off bitmaps", PER_INDEX, 200, 400),
    (7, "read a claimed label and commit it", PER_VALIDATOR, 32768, 65536),
    (8, "read a claimed label only", PER_VALIDATOR, 32768, 65536),
]
SELFTEST = 9
DOMAIN = 1 << 20  # the domain the per-index variants run against


def run(variant, n, param):
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(struct.pack("<QQQQ", 24, variant, n, param))
        path = f.name
    try:
        out = subprocess.run(
            [ZISKEMU, "-e", ELF, "-i", path, "-X", "-n", "400000000000"],
            capture_output=True, text=True, check=True,
        ).stdout
    finally:
        os.unlink(path)
    return parse(out)


def parse(report):
    def grab(pattern):
        m = re.search(pattern, report, re.M)
        return int(m.group(1).replace(",", "")) if m else 0

    ops = {
        name: int(count.replace(",", ""))
        for name, count in re.findall(r"^OP (\S+)\s+([\d,]+)\s+", report, re.M)
    }
    return {
        "steps": grab(r"^STEPS\s+([\d,]+)"),
        "cost": grab(r"^VARIABLE\s+([\d,]+)"),
        "main": grab(r"^MAIN\s+([\d,]+)"),
        "memory": grab(r"^MEMORY\s+([\d,]+)"),
        "opcodes": grab(r"^OPCODES\s+([\d,]+)"),
        "precompiles": grab(r"^PRECOMPILES\s+([\d,]+)"),
        "sha256": ops.get("sha256", 0),
        "poseidon2": ops.get("poseidon2", 0),
    }


def marginal(variant, axis, lo, hi):
    if axis == PER_INDEX:
        a, b = run(variant, DOMAIN, lo), run(variant, DOMAIN, hi)
    else:
        a, b = run(variant, lo, 0), run(variant, hi, 0)
    return {k: (b[k] - a[k]) / (hi - lo) for k in a}


def table(rows, headers):
    widths = [max(len(str(r[i])) for r in [headers] + rows) for i in range(len(headers))]
    print("  ".join(h.ljust(w) if i == 0 else h.rjust(w)
                    for i, (h, w) in enumerate(zip(headers, widths))))
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print("  ".join(str(c).ljust(w) if i == 0 else str(c).rjust(w)
                        for i, (c, w) in enumerate(zip(row, widths))))
    print()


def variants(args):
    print(f"\nMarginal cost of one validator, mainnet domain {DOMAIN:,} for the "
          f"per-index rows\n")
    rows = []
    for variant, label, axis, lo, hi in VARIANTS:
        m = marginal(variant, axis, lo, hi)
        rows.append([
            label, axis, f"{m['steps']:,.1f}", f"{m['cost']:,.0f}",
            f"{m['sha256']:.4f}", f"{100 * m['main'] / m['cost']:.0f}%",
            f"{100 * m['memory'] / m['cost']:.0f}%",
            f"{100 * m['precompiles'] / m['cost']:.0f}%",
            f"{MAINNET_ACTIVE * m['steps'] / 1e6:,.0f}",
        ])
    table(rows, ["variant", "per", "steps", "cost", "sha256",
                 "main", "mem", "pre", "M steps"])
    print(f"`M steps` scales the marginal step count to {MAINNET_ACTIVE:,} active "
          f"validators. Seconds follow steps only within a work class; see the "
          f"module docstring.\n")


def sweep(args):
    print("\nIs the marginal cost flat in the size it is read at?\n")
    rows = []
    sizes = [int(s) for s in args.sizes.split(",")]
    for variant, label, axis, _, _ in VARIANTS:
        if axis != PER_VALIDATOR:
            continue
        for lo, hi in zip(sizes, sizes[1:]):
            m = marginal(variant, axis, lo, hi)
            rows.append([label, f"{lo:,} -> {hi:,}", f"{m['steps']:,.1f}",
                         f"{m['cost']:,.0f}"])
    table(rows, ["variant", "validators", "steps", "cost"])


def mainnet(args):
    print(f"\nThe whole-set forms at the full mainnet active set, "
          f"{MAINNET_ACTIVE:,} validators — no extrapolation\n")
    rows = []
    for variant, label, axis, _, _ in VARIANTS:
        if axis != PER_VALIDATOR:
            continue
        r = run(variant, MAINNET_ACTIVE, 0)
        rows.append([
            label, f"{r['steps']:,}", f"{r['cost']:,}", f"{r['sha256']:,}",
            f"{r['cost'] / MAINNET_ACTIVE:,.0f}",
            f"{(SECONDS_FLOOR + NS_PER_STEP * r['steps'] / 1e9):,.1f}",
        ])
    table(rows, ["variant", "steps", "cost", "sha256", "per validator",
                 "modelled s"])
    print("`modelled s` applies the integer-class rate, which is right for the "
          "whole-set rows and\nwrong for `source bitmaps only` — that one is "
          "sha256-bound and measures 20.2 s, not 12.\n")


def selftest(args):
    if not os.path.exists(NATIVE):
        sys.exit(f"{NATIVE} not found — cargo build --release -p "
                 f"zkasper-shuffle-bench-guest")
    for n in [3, 7, 33, 64, 65, 127, 129, 255, 257, 999, 1025, 4096]:
        subprocess.run([NATIVE, str(SELFTEST), str(n), "0"],
                       check=True, stdout=subprocess.DEVNULL)
    print("\nselftest passed: every variant produces the same assignment\n")


def specref(args):
    """Check the guest against a Python transcription of the spec.

    `--selftest` proves the variants agree with each other, which they would
    also do if they were all wrong in the same way. This is the outside check:
    `compute_shuffled_index` written straight out of the consensus spec against
    `hashlib`, and the assignment it implies compared with the guest's.
    """
    import hashlib

    seed = bytes([7] * 32)

    def shuffled(index, count):
        for r in range(90):
            pivot = int.from_bytes(
                hashlib.sha256(seed + bytes([r])).digest()[0:8], "little") % count
            flip = (pivot + count - index) % count
            position = max(index, flip)
            source = hashlib.sha256(
                seed + bytes([r]) + (position // 256).to_bytes(4, "little")).digest()
            if (source[(position % 256) // 8] >> (position % 8)) & 1:
                index = flip
        return index

    for n in [3, 33, 64, 129, 257, 1000, 1025]:
        want = 0
        for p in range(n):
            v = shuffled(p, n)
            want = (want + (min(31, (32 * (p + 1) - 1) // n) << (v & 7))) % (1 << 64)
        out = subprocess.run([NATIVE, str(SELFTEST), str(n), "0"],
                             capture_output=True, text=True, check=True).stdout
        got = int(out.strip().split("checksum=")[1], 16)
        if want != got:
            sys.exit(f"n={n}: guest {got:#018x} != spec {want:#018x}")
        print(f"n={n:5d}  {got:#018x}  matches the spec")
    print()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", action="store_true")
    ap.add_argument("--sweep", action="store_true")
    ap.add_argument("--mainnet", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--specref", action="store_true")
    ap.add_argument("--sizes", default="16384,32768,65536,131072")
    args = ap.parse_args()

    if args.build:
        env = dict(os.environ, PATH=ZISK_BIN + ":" + os.environ["PATH"])
        subprocess.run(["cargo-zisk", "build", "--release", "-p",
                        "zkasper-shuffle-bench-guest"], cwd=ROOT, check=True, env=env)
        subprocess.run(["cargo", "build", "--release", "-p",
                        "zkasper-shuffle-bench-guest"], cwd=ROOT, check=True)

    if args.specref:
        specref(args)
    elif args.selftest:
        selftest(args)
    elif args.sweep:
        sweep(args)
    elif args.mainnet:
        mainnet(args)
    else:
        variants(args)


if __name__ == "__main__":
    main()

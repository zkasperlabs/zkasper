#!/usr/bin/env python3
"""Measure the committee proof at a size a person can wait for.

The committee proof is the fleet's whole cost and a mainnet run is 961k
validators, so a strategy for making it cheaper cannot be evaluated against a
mainnet run. This runs `crates/committee-bench-guest` under `ziskemu -X` over a
real witness of a few hundred to a few thousand validators, at whatever
accumulator depth is asked for, and reports **steps and cost units per
validator** — the only figures that extrapolate.

Two runs at different validator counts are subtracted, so program setup, the
32-leaf committee tree and the part of the accumulator opening that does not
scale all cancel, and what is left is marginal per-validator cost.

    scripts/committee_bench.py --build          # every variant, per validator
    scripts/committee_bench.py --sweep          # is per-validator cost flat?
    scripts/committee_bench.py --depths 8,12,16,20,22
    scripts/committee_bench.py --occupancy      # what the inactive gaps cost
    scripts/committee_bench.py --selftest       # candidates == committee::verify

Fixtures are cached under `test_data/committee_bench/`, which is gitignored.
Cost units are trace area and are not seconds: see `common/src/op_counter.rs`.
"""
import argparse
import os
import re
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ELF = os.path.join(
    ROOT, "target/elf/riscv64ima-zisk-zkvm-elf/release/zkasper-committee-bench-guest"
)
ZISKEMU = os.path.expanduser("~/.zisk/bin/ziskemu")
FIXTURES = os.path.join(ROOT, "test_data/committee_bench")

# variant id, label, and whether it is a whole verification (a candidate, whose
# cost stands on its own) or a term removed from one (an ablation, which only
# means anything as a difference from `committee::verify`).
VARIANTS = [
    (0, "committee::verify", "candidate"),
    (1, "witness I/O only", "ablation"),
    (2, "no curve adds", "ablation"),
    (3, "no accumulator tree", "ablation"),
    (4, "no leaf hashes", "ablation"),
    (5, "4-ary accumulator", "candidate"),
    (6, "batch-inverted adds", "candidate"),
    (7, "copying add, superseded", "candidate"),
    (8, "leaf packed in place", "candidate"),
]

SELFTEST = 9
MAX_STEPS = 200_000_000


def fixture(active, depth, registry=None, slots=32):
    """Generate, and cache, one witness. Returns the flat words as bytes."""
    registry = active if registry is None else registry
    os.makedirs(FIXTURES, exist_ok=True)
    path = os.path.join(FIXTURES, f"c_{active}_{registry}_{depth}_{slots}.bin")
    if not os.path.exists(path):
        subprocess.run(
            ["cargo", "run", "--release", "--quiet", "--bin", "gen-committee-witness",
             "--", path, str(active), str(registry), str(depth), str(slots)],
            cwd=ROOT, check=True,
        )
    with open(path, "rb") as f:
        return f.read()


def run(variant, depth, witness):
    """One emulator run. `None` if the guest rejected the input."""
    payload = struct.pack("<QQ", variant, depth) + witness
    blob = struct.pack("<Q", len(payload)) + payload
    blob += b"\x00" * (-len(blob) % 8)
    path = os.path.join(FIXTURES, "input.bin")
    with open(path, "wb") as f:
        f.write(blob)

    # A rejected variant leaves the guest spinning in its panic handler until
    # the emulator's step limit, which by default is 68 billion and takes seven
    # minutes to reach. The cap is far above anything a real run needs.
    proc = subprocess.run(
        [ZISKEMU, "-e", ELF, "-i", path, "-X", "-n", str(MAX_STEPS)],
        capture_output=True, text=True,
    )
    report = parse(proc.stdout) if "STEPS" in proc.stdout else None
    return None if report is None or report["steps"] >= MAX_STEPS else report


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
        "precompiles": grab(r"^PRECOMPILES\s+([\d,]+)"),
        "poseidon2": ops.get("poseidon2", 0),
        "g1_add": ops.get("bls12_381_curve_add", 0),
        "arith384": ops.get("arith384_mod", 0),
    }


def marginal(variant, depth, lo, hi, registry_share=1):
    """Per-validator cost, with everything that does not scale subtracted out.

    Both fixtures sit in a tree of the same depth and carry the same share of
    inactive validators, so depth and occupancy stay properties of the pair
    rather than terms in the difference.
    """
    a = run(variant, depth, fixture(lo, depth, lo * registry_share))
    b = run(variant, depth, fixture(hi, depth, hi * registry_share))
    if a is None or b is None:
        return None
    return {k: (b[k] - a[k]) / (hi - lo) for k in a}


def table(rows, headers):
    widths = [max(len(str(r[i])) for r in [headers] + rows) for i in range(len(headers))]
    print("  ".join(h.rjust(w) for h, w in zip(headers, widths)))
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print("  ".join(str(c).rjust(w) for c, w in zip(row, widths)))
    print()


def variants(args):
    print(f"\nPer validator, {args.lo} -> {args.hi} validators, accumulator depth "
          f"{args.depth}, registry == active\n")
    rows, baseline = [], None
    for variant, label, kind in VARIANTS:
        m = marginal(variant, args.depth, args.lo, args.hi)
        if m is None:
            rows.append([label, kind, "rejected", "", "", "", "", ""])
            continue
        baseline = m["cost"] if baseline is None else baseline
        rows.append([
            label, kind, f"{m['steps']:,.0f}", f"{m['cost']:,.0f}",
            f"{m['cost'] / baseline:.2f}x", f"{m['poseidon2']:.2f}",
            f"{m['g1_add']:.2f}", f"{m['arith384']:.2f}",
        ])
    table(rows, ["variant", "kind", "steps", "cost", "vs verify",
                 "poseidon2", "g1 add", "arith384"])


def sweep(args):
    print(f"\nMarginal cost per validator against size, accumulator depth "
          f"{args.depth}\n")
    sizes = [int(s) for s in args.sizes.split(",")]
    rows = []
    for lo, hi in zip(sizes, sizes[1:]):
        m = marginal(0, args.depth, lo, hi)
        rows.append([
            f"{lo} -> {hi}", f"{m['steps']:,.0f}", f"{m['cost']:,.0f}",
            f"{m['main']:,.0f}", f"{m['memory']:,.0f}", f"{m['precompiles']:,.0f}",
            f"{m['poseidon2']:.2f}", f"{m['g1_add']:.2f}",
        ])
    table(rows, ["validators", "steps", "cost", "main", "memory",
                 "precompiles", "poseidon2", "g1 add"])


def depths(args):
    print("\nDoes accumulator depth move the per-validator cost?")
    print("(the same leaf set every time; only the height above it changes)\n")
    rows = []
    for depth in [int(d) for d in args.depths.split(",")]:
        m = marginal(0, depth, args.lo, args.hi)
        rows.append([depth, f"{m['steps']:,.0f}", f"{m['cost']:,.0f}",
                     f"{m['poseidon2']:.2f}", f"{m['g1_add']:.2f}"])
    table(rows, ["acc depth", "steps", "cost", "poseidon2", "g1 add"])


def occupancy(args):
    print("\nWhat the inactive gaps cost: active validators out of a larger registry")
    print("(an unopened leaf costs the multi-proof an auxiliary to skip past it)\n")
    rows = []
    for share in [int(s) for s in args.occupancy.split(",")]:
        m = marginal(0, args.depth, args.lo, args.hi, registry_share=share)
        if m is None:
            rows.append([f"1 in {share}", "rejected", "", "", ""])
            continue
        rows.append([f"1 in {share}", f"{m['steps']:,.0f}", f"{m['cost']:,.0f}",
                     f"{m['poseidon2']:.2f}", f"{m['g1_add']:.2f}"])
    table(rows, ["active share", "steps", "cost", "poseidon2", "g1 add"])


def selftest(args):
    if run(SELFTEST, args.depth, fixture(args.lo, args.depth)) is None:
        sys.exit("selftest FAILED: a candidate does not publish verify's aggregates")
    print(f"\nselftest passed at {args.lo} validators, depth {args.depth}: every "
          f"candidate publishes committee::verify's aggregates\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", action="store_true", help="build the guest first")
    ap.add_argument("--lo", type=int, default=1024)
    ap.add_argument("--hi", type=int, default=2048)
    ap.add_argument("--depth", type=int, default=None,
                    help="accumulator depth; defaults to log2(hi), a full tree")
    ap.add_argument("--sizes", default="256,512,1024,2048,4096")
    ap.add_argument("--depths", help="comma-separated accumulator depths to compare")
    ap.add_argument("--occupancy", nargs="?", const="1,2,4",
                    help="comma-separated registry-to-active ratios")
    ap.add_argument("--sweep", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.depth is None:
        args.depth = max(args.hi - 1, 1).bit_length()

    if args.build:
        env = dict(os.environ,
                   PATH=os.path.expanduser("~/.zisk/bin") + ":" + os.environ["PATH"])
        subprocess.run(
            ["cargo-zisk", "build", "--release", "-p", "zkasper-committee-bench-guest"],
            cwd=ROOT, check=True, env=env,
        )
    if not os.path.exists(ELF):
        sys.exit(f"{ELF} not found — run with --build")

    if args.selftest:
        selftest(args)
    elif args.sweep:
        sweep(args)
    elif args.depths:
        depths(args)
    elif args.occupancy:
        occupancy(args)
    else:
        variants(args)


if __name__ == "__main__":
    main()

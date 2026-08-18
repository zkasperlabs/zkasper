#!/usr/bin/env python3
"""What the committee proof's opened set actually costs, against what a model assumes.

The committee proof opens every active validator against the accumulator. How
much that costs depends on *which* indices those are: a batched multi-proof
computes every internal node with at least one opened descendant, so a
contiguous run is cheap and a scattered set is not.

`batched_nodes` in streaming_cost.py assumes uniformly random leaves, which is
right for a slot proof's absentees — whoever failed to attest is scattered — and
badly wrong here. Ethereum's registry is append-only and exits are rare, so the
active set is close to a dense suffix rather than a random sample.

Run against the real mainnet fixture. Node counts are exact, not sampled: the
set of internal nodes a multi-proof must compute is a pure function of the
opened indices, so this needs no guest and no prover.

    python3 scripts/scatter_cost.py [test_data/finality_epoch_430529.json.gz]
"""
import gzip, json, random, sys

DEPTH = 22
ACC_NODE = 3_033        # measured, scripts/bench.py
MEMBER_UNITS = 29_916   # measured, scripts/committee_bench.py
COMMITTEE_S = 146.0     # measured committee proof, 960,974 active


def internal_nodes(indices, depth=DEPTH):
    """Internal nodes a batched multi-proof over `indices` must compute."""
    level, total = set(indices), 0
    for _ in range(depth):
        level = {i >> 1 for i in level}
        total += len(level)
    return total


def main(path):
    committees = json.load(gzip.open(path))["committees"]
    active = sorted({int(v) for c in committees for v in c["validators"]})
    n, hi = len(active), active[-1]

    random.seed(1)
    real = internal_nodes(active)
    contiguous = internal_nodes(range(n))
    uniform = internal_nodes(sorted(random.sample(range(hi + 1), n)))

    print(f"active {n:,}   highest index {hi:,}   density below max {n / (hi + 1):.3f}\n")
    print(f"{'layout':<30}{'nodes':>12}{'per member':>12}{'vs contiguous':>15}")
    for name, count in (("REAL mainnet active set", real),
                        ("contiguous 0..n", contiguous),
                        ("uniform random, same count", uniform)):
        print(f"{name:<30}{count:>12,}{count / n:>12.3f}{count / contiguous:>14.2f}x")

    extra = (real - contiguous) / n * ACC_NODE
    print(f"\nreal scatter costs {extra:,.0f} units a member "
          f"({extra / MEMBER_UNITS * 100:.1f}%), which is "
          f"{(real - contiguous) / (uniform - contiguous) * 100:.0f}% of what "
          f"uniform scatter would cost.")
    print(f"An active-index accumulator would save {extra / MEMBER_UNITS * COMMITTEE_S:.1f}s "
          f"of the {COMMITTEE_S:.0f}s committee proof.")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "test_data/finality_epoch_430529.json.gz")

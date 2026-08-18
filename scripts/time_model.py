#!/usr/bin/env python3
"""Predict seconds, not cost units.

Everything downstream of `scripts/bench.py` used to be denominated in Zisk cost
units against one throughput constant. The RTX 5090 campaign in
`data/gpu_bench/` disproved that. Measured effective throughput spans 18M to
249M units/s across real guests, a 13.8x range, because padded and constant rows
prove about 4.3x faster per cell than poseidon2 rows: `bench` mode 0 at n=0 and
at n=100,000 differ by 83,558,605 cost units, instantiate the identical eleven
AIRs, and differ in wall time by 0.059 s.

So this model predicts wall-clock directly, from the quantities that drive it,
calibrated per work class rather than by one rate:

    stage floor        a whole trace for every AIR the guest touches, paid
                       whatever the workload
    opened validators  a leaf out of the accumulator, a curve addition, and the
                       2,311 executed steps of walking one validator's bincode
                       witness
    committee members  the same leaf and curve addition out of a flat witness
                       the guest reads in place: 328 steps, not 2,311
    accumulator nodes  poseidon2 permutations above the opened leaves
    Fp2-tower work     hash-to-curve, Miller loops, the final exponentiation
    recursion          verifying a child proof, which nothing measured

Times are the prover's own `Proof generated`, which excludes process start and
GPU allocation. A warm prover pays exactly that; a cold one pays
`COLD_PENALTY_S` on top. There is no separate per-invocation constant to add —
the floor already is it, which is what the old model got wrong when it added
19.52 s to a `proof_base` term.

Usage:
    python3 scripts/time_model.py            # the fit and its residuals
"""
from __future__ import annotations

import math

# ---------------------------------------------------------------------------
# Constants. Every one names the measurement that set it.
# ---------------------------------------------------------------------------

# MEASURED. Empty guest, 496 executed steps, 3 warm proves, sd 0.027 s
# (`data/gpu_bench/trivial_times.tsv`, m0n0). Eleven AIRs and nothing else.
EMPTY_FLOOR_S = 4.843

# MEASURED. `data/gpu_bench/stubbed_times.tsv`, aggregation with recursion
# removed: 34,002 executed steps and 3.31M cost units, 3 warm proves, sd 0.084 s.
# That is 82x the empty guest's cost units for 2.33 s more time, which can only
# be the AIRs a poseidon2-and-Fp12 guest instantiates that an empty one does
# not. It is the floor of any zkasper stage.
STAGE_FLOOR_S = 7.176

# MEASURED. `data/gpu_bench/attester_*.tsv`, the enumerating group proof over
# 2,048 .. 154,000 attesters, OLS slope, se 6.5 us. The fixture argument is
# validators and one group covers half of them, so this is per *attester* and
# twice the per-argument slope. 2,311 executed steps and 226,483 cost units go
# with it, of which the old cost model counted 6,407.
PER_ATTESTER_S = 878.2e-6

# MEASURED under `ziskemu -X` on the committee guest itself at 16,000, 32,000
# and 64,000 members: 328.0 executed steps and 36,473 cost units a member,
# linear to five figures. Converted at the rate PER_ATTESTER_S sets for this
# work class — 223,450 units bought 834.7 us, both figures less one internal
# node — which is a within-class ratio and not a proving time of its own; the
# step ratio 328 / 2,311 puts it at 124.6 us, so the two agree to 0.2%.
#
# It was 404.5 us while the witness travelled as bincode. A CommitteeMember is
# fifteen u64s in the layout the guest already wants, and decoding it as fifteen
# self-describing records cost 829 of the 1,157 steps a member took.
PER_MEMBER_S = 124.9e-6

# MEASURED. `data/gpu_bench/bench_*.tsv`, 29 sizes, 3 warm proves each, OLS on
# the poseidon2 guest: 37.381 us per permutation, se 0.225 us, at 2,606 cost
# units per permutation.
POSEIDON_UNITS_PER_S = 69_714_770

# FITTED on the fixture stages, against their Fp2-tower cost-unit content: least
# squares through the origin on what the group and slot proofs cost above
# STAGE_FLOOR_S. This is the weakest constant in the file — no measurement in
# the campaign exercises BLS at mainnet scale, so it is a within-family rate
# read off floor-dominated proofs. `--report` prints the bracket it sits in.
BLS_UNITS_PER_S = 207_400_000

# MEASURED. `data/gpu_bench/wrap_times.tsv`, the prover's own
# GENERATE_VADCOP_FINAL_COMPRESSED_PROOF over the five warm wraps: 157, 151,
# 152, 170, 153 ms. The 12.5 s of wall around it is process startup.
WRAP_S = 0.157

# MEASURED. 87 warm proves: mean wall 30.46 s against mean `Proof generated`
# 16.97 s, of which INITIALIZING_PROOFMAN is 7.74 s +/- 0.71. This is what a
# long-lived prover saves per proof. It is NOT a proving floor and must never be
# added to one; the 19.52 s that used to be quoted was this plus the floor.
COLD_PENALTY_S = 13.49

# MEASURED cost units, `scripts/bench.py`. Used only as *ratios* inside one work
# class, never as a currency across classes.
UNITS = {
    "acc_node": 3_033,
    "acc_leaf": 3_979,
    "g1_add": 2_428,
    "hash_to_curve": 18_594_521,
    "miller_pair": 33_222_822,
    "miller_batch": 39_633_399,
    "final_exp": 132_665_557,
    "pair_validation": 6_076_715,
    "fp12_mul": 737_503,
    "commit_fp12": 78_002,
    "g2_subgroup": 8_219_617,
}

ACC_DEPTH = 22
COMMITTEE_DEPTH = 5
SLOTS_PER_EPOCH = 32


def scattered_nodes(leaves: float, depth: int = ACC_DEPTH) -> float:
    """Internal compressions a multi-proof over `leaves` *random* leaves needs.

    A node at level k covers 2^k leaves, so it is touched unless every one of
    those slots is empty. This is the absentee case: a slot's absentees are
    scattered across the registry, so a hundred of them touch fifteen nodes
    apiece.
    """
    capacity = 2.0 ** depth
    total = 0.0
    for k in range(1, depth + 1):
        covered = 2.0 ** k
        total += capacity / covered * (1.0 - (1.0 - covered / capacity) ** leaves)
    return total


def contiguous_nodes(leaves: float, depth: int = ACC_DEPTH) -> float:
    """The same count when the leaves are one index range.

    Barely more than one node per leaf at any size, against fifteen for a
    scattered hundred. This is the committee-proof case, and it is also what the
    attester sweep measured — the fixture hands validators out in index order —
    which is why that sweep is linear to within 1%.
    """
    return sum(math.ceil(leaves / 2 ** j) for j in range(1, depth + 1))


ACC_NODE_S = UNITS["acc_node"] / POSEIDON_UNITS_PER_S

# The sweep opened a contiguous range, so its slope carries about one internal
# node per leaf. Take that out and what is left is per-validator work proper.
PER_VALIDATOR_S = PER_ATTESTER_S - ACC_NODE_S


def bls_s(units: float) -> float:
    return units / BLS_UNITS_PER_S


def open_leaves_s(leaves: float, depth: int = ACC_DEPTH, contiguous: bool = False) -> float:
    """Opening `leaves` validators out of a depth-`depth` accumulator."""
    nodes = contiguous_nodes(leaves, depth) if contiguous else scattered_nodes(leaves, depth)
    return leaves * PER_VALIDATOR_S + nodes * ACC_NODE_S


def committee_tree_s() -> float:
    """Rebuilding the 32-leaf committee tree from its summed buckets."""
    return (2 ** COMMITTEE_DEPTH + 2 ** COMMITTEE_DEPTH - 1) * ACC_NODE_S


def attestation_s(named: float, slots: float, messages: float,
                  depth: int = ACC_DEPTH) -> float:
    """A set of slot complements, short of the final exponentiation.

    `named` is what the proof opens against the accumulator — absentees plus the
    signers of any minority head vote. `messages` is distinct signing roots,
    because the Miller accumulator keys on the root.
    """
    return (
        open_leaves_s(named, depth)
        + open_leaves_s(slots, COMMITTEE_DEPTH)
        + bls_s(UNITS["miller_batch"] + UNITS["g2_subgroup"]
                + messages * (UNITS["hash_to_curve"] + UNITS["miller_pair"]))
    )


def group_s(named: float, slots: float, messages: float, depth: int = ACC_DEPTH) -> float:
    return STAGE_FLOOR_S + attestation_s(named, slots, messages, depth)


def fold_s(children: float, recursion_s: float = 0.0) -> float:
    return (
        STAGE_FLOOR_S
        + (children + 1.0) * recursion_s
        + children * bls_s(UNITS["fp12_mul"] + UNITS["commit_fp12"])
    )


def final_s(named: float, slots: float, messages: float, absorbed: float,
            folded: bool, recursion_s: float = 0.0, depth: int = ACC_DEPTH) -> float:
    return (
        STAGE_FLOOR_S
        + (attestation_s(named, slots, messages, depth) if slots > 0 else 0.0)
        + bls_s(UNITS["final_exp"])
        + (absorbed + (1.0 if folded else 2.0)) * recursion_s
        + (absorbed + 1.0) * bls_s(UNITS["fp12_mul"] + UNITS["commit_fp12"])
    )


def committee_chunk_s(validators: float, chunks: float, depth: int = ACC_DEPTH) -> float:
    """One chunk of the per-epoch committee proof.

    A chunk owns an index range, so its opening is contiguous, and it reads its
    members in place rather than deserialising them — PER_MEMBER_S, not
    PER_VALIDATOR_S. `validators` is the *active* set, which is what committees
    are formed from and all this proof opens.
    """
    share = validators / chunks
    return (
        STAGE_FLOOR_S
        + share * PER_MEMBER_S
        + contiguous_nodes(share, depth) * ACC_NODE_S
        + (committee_tree_s() if chunks == 1 else 0.0)
    )


def committee_fold_s(chunks: float, recursion_s: float = 0.0) -> float:
    return STAGE_FLOOR_S + (chunks + 1.0) * recursion_s + committee_tree_s()


# ---------------------------------------------------------------------------
# The fit, against everything the campaign measured
# ---------------------------------------------------------------------------

def _measurements():
    import csv
    import os
    import statistics as st

    d = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "data", "gpu_bench")
    times = {}
    with open(os.path.join(d, "bench_phases.tsv")) as f:
        for r in csv.DictReader(f, delimiter="\t"):
            name = r["log"]
            if not name.endswith(".log") or not r.get("PROOF_GENERATED"):
                continue
            head, _, tail = name[:-4].rpartition("_")
            base, rep = (head, int(tail)) if head and tail.isdigit() else (name[:-4], 0)
            times.setdefault(base, {})[rep] = float(r["PROOF_GENERATED"])

    def warm(base, drop_first):
        reps = sorted(times[base])[1:] if drop_first else sorted(times[base])
        vals = [times[base][r] for r in reps]
        return st.mean(vals), (st.stdev(vals) if len(vals) > 1 else 0.0)

    def costs(path, ncols):
        out = {}
        with open(os.path.join(d, path)) as f:
            for r in csv.reader(f, delimiter="\t"):
                if len(r) >= ncols:
                    out[r[0]] = (int(r[ncols - 4]), int(r[ncols - 3]))
        return out

    return warm, costs


def _report():
    warm, costs = _measurements()

    def line(label, pred, obs, sd):
        err = 100.0 * (pred - obs) / obs
        print(f"  {label:<38}{pred:>8.2f}s{obs:>9.2f}s +/- {sd:<7.3f}{err:>+8.1f}%")
        return err

    print(__doc__.split("Usage:")[0].rstrip())

    print("\n=== constants ===")
    print(f"  stage floor                  {STAGE_FLOOR_S:>14.3f} s    MEASURED, aggregation stub")
    print(f"  empty-guest floor            {EMPTY_FLOOR_S:>14.3f} s    MEASURED, eleven AIRs")
    print(f"  per opened validator         {PER_VALIDATOR_S * 1e6:>14.1f} us   DERIVED, attester sweep")
    print(f"  per accumulator node         {ACC_NODE_S * 1e6:>14.1f} us   MEASURED, poseidon2 sweep")
    print(f"  Fp2-tower rate               {BLS_UNITS_PER_S:>14,.0f} u/s  FITTED, fixtures")
    print(f"    one message                {bls_s(UNITS['hash_to_curve'] + UNITS['miller_pair']):>14.3f} s")
    print(f"    per-proof Miller batch     {bls_s(UNITS['miller_batch'] + UNITS['g2_subgroup']):>14.3f} s")
    print(f"    final exponentiation       {bls_s(UNITS['final_exp']):>14.3f} s")
    print(f"  wrap compression             {WRAP_S:>14.3f} s    MEASURED")
    print(f"  cold penalty per invocation  {COLD_PENALTY_S:>14.3f} s    MEASURED, 87 proves")

    print("\n=== residuals: the fixture stages (4 validators, 1 slot, 1 message) ===")
    print(f"  {'stage':<38}{'model':>9}{'measured':>10}{'':<12}{'error':>8}")
    errs = []
    errs.append(line("aggregation, recursion removed", fold_s(0.0), *warm("prove_stub_aggregation", True)))
    errs.append(line("group proof", group_s(0.0, 1.0, 1.0), *warm("prove_group-proof", True)))
    errs.append(line(
        "slot proof, own final exponentiation",
        group_s(0.0, 1.0, 1.0) + bls_s(UNITS["final_exp"] + 2 * UNITS["pair_validation"]),
        *warm("prove_slot-proof", True)))
    errs.append(line("stream-final, recursion removed",
                     final_s(0.0, 1.0, 1.0, 0.0, True), *warm("prove_stub_stream-final", True)))
    print(f"  worst {max(abs(e) for e in errs):.1f}%")

    print("\n=== residuals: the group stage against attester count ===")
    print("  The sweep is the *enumerating* group proof, which is where the")
    print("  per-validator term comes from; it opens a contiguous range and has")
    print("  no committee aggregate to subtract, so the complement guest's floor")
    print("  is about 1 s higher and the model runs high at the small end.")
    att = costs("attester_costs.tsv", 6)
    print(f"  {'attesters':>10}{'steps':>14}{'units/s':>14}{'model':>9}{'measured':>10}{'sd':>7}{'error':>8}")
    for key in sorted(att, key=int):
        steps, variable = att[key]
        a = int(key) / 2
        m, sd = warm(f"prove_a{key}", False)
        pred = STAGE_FLOOR_S + open_leaves_s(a, contiguous=True) + attestation_s(0, 1, 1)
        print(f"  {a:>10,.0f}{steps:>14,}{variable / m:>14,.0f}{pred:>8.1f}s{m:>9.1f}s"
              f"{sd:>7.2f}{100 * (pred - m) / m:>+8.1f}%")
    print("  The units/s column is the whole point: one prover, one guest, one")
    print(f"  workload family, and the rate still moves {2_511_870 / 167_773:.0f}x across it.")

    print("\n=== the bracket on the Fp2-tower rate ===")
    print("  Nothing in the campaign runs BLS at scale, so this rate is read off")
    print("  floor-dominated proofs and is the model's largest uncertainty.")
    g, _ = warm("prove_group-proof", True)
    s, _ = warm("prove_slot-proof", True)
    a, _ = warm("prove_stub_aggregation", True)
    tower = (UNITS["miller_batch"] + UNITS["g2_subgroup"]
             + UNITS["hash_to_curve"] + UNITS["miller_pair"])
    lo = (UNITS["final_exp"] + 2 * UNITS["pair_validation"]) / (s - g)
    hi = tower / (g - a)
    print(f"    slot minus group, inside one AIR instance {lo:>14,.0f} units/s   too fast")
    print(f"    group minus aggregation stub              {hi:>14,.0f} units/s   too slow")
    print(f"    least squares on both                     {BLS_UNITS_PER_S:>14,.0f} units/s   <- used")

    print("\n=== what the model says about the pipeline ===")
    for label, secs in [
        ("group proof, 1 slot, 1 message", group_s(0, 1, 1)),
        ("group proof, 10 slots, 28 messages", group_s(980, 10, 28)),
        ("fold of 3 groups", fold_s(3)),
        ("final proof, 1 slot inline", final_s(98, 1, 3, 2, True)),
        ("wrap", WRAP_S),
        ("committee proof, 960,974 active validators", committee_chunk_s(960_974, 1)),
        ("  ...in 4 chunks, each", committee_chunk_s(960_974, 4)),
    ]:
        print(f"  {label:<44}{secs:>9.2f}s")
    print()


if __name__ == "__main__":
    _report()

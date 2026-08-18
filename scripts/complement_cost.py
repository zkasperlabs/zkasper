#!/usr/bin/env python3
"""What complement proving costs, against what enumerating attesters cost.

A slot proof used to open a Merkle path for every attester. It now opens paths
for the absentees only, against a per-slot committee aggregate that a per-epoch
committee proof summed out of the same accumulator. This script prices both
sides of that trade: the epoch total, which pays for the committee proof, and
the critical path, which is what the trade is actually for.

Constants come from scripts/bench.py; see BENCHMARKS.md.
"""
import argparse

COST = {
    "acc_node": 3_033,
    "acc_leaf": 3_979,
    "g1_add": 2_428,
    "hash_to_curve": 18_594_521,
    "miller_pair": 33_222_822,
    "miller_batch": 39_633_399,
    "final_exp": 132_665_557,
    "fp12_mul": 737_503,
    "commit_fp12": 78_002,
    "g2_subgroup": 8_219_617,
    "proof_base": 293_601_280,
}

ACC_DEPTH = 22
DEDUP_DEPTH = ACC_DEPTH - 8
COMMITTEE_DEPTH = 5
SLOTS_PER_EPOCH = 32

GPU_UNITS_PER_S = 67_452_592
GPU_WARM_FIXED_S = 0.5
WRAP_COMPRESSION_S = 0.192


def batched_nodes(num_leaves, depth=ACC_DEPTH):
    """Internal compressions a multi-proof over `num_leaves` random leaves needs."""
    capacity = 2 ** depth
    total = 0
    for k in range(1, depth + 1):
        total += 2 ** (depth - k) * (1 - (1 - 2 ** k / capacity) ** num_leaves)
    return total


def open_leaves(n, depth=ACC_DEPTH):
    return n * COST["acc_leaf"] + batched_nodes(n, depth) * COST["acc_node"]


def dedup_open(indices):
    """Opening the counted-set tree over `indices`, 256 indices to a leaf."""
    leaves = 2 ** DEDUP_DEPTH * (1 - (1 - 2 ** -DEDUP_DEPTH) ** indices)
    return (leaves + batched_nodes(leaves, DEDUP_DEPTH)) * COST["acc_node"]


def bls(messages):
    """Hash-to-curve, Miller loops and the subgroup check for `messages`."""
    return (
        messages * COST["hash_to_curve"]
        + COST["miller_batch"]
        + (messages + 1) * COST["miller_pair"]
        + COST["g2_subgroup"]
    )


def enumerated_slot(attesters, aggregates):
    """One slot proved by naming every attester."""
    return (
        open_leaves(attesters)
        + attesters * COST["g1_add"]
        + bls(aggregates)
    )


def complement_slot(absentees, messages=1):
    """One slot proved by naming only its absentees.

    The committee arrives already summed, so the point sum starts from it and
    walks down: one curve addition per absentee, none per attester. The committee
    leaf is opened against a tree five levels deep.
    """
    return (
        open_leaves(absentees)
        + open_leaves(1, COMMITTEE_DEPTH)
        + absentees * COST["g1_add"]
        + bls(messages)
    )


def committee_proof(validators):
    """Sum every slot's committee out of the accumulator. Once per epoch."""
    return (
        COST["proof_base"]
        + open_leaves(validators)
        + validators * COST["g1_add"]
        + (2 ** COMMITTEE_DEPTH * COST["acc_leaf"] + (2 ** COMMITTEE_DEPTH - 1) * COST["acc_node"])
    )


def fmt(n):
    return f"{n / 1e9:>12,.2f}B"


def gpu_seconds(cost, proofs):
    return GPU_WARM_FIXED_S * (proofs + 1) + cost / GPU_UNITS_PER_S + WRAP_COMPRESSION_S


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--validators", type=int, default=1_050_000)
    ap.add_argument("--aggregates-per-slot", type=int, default=8)
    ap.add_argument("--participation", type=float, default=0.997)
    ap.add_argument("--tail-attesters", type=int, default=26_813,
                    help="attesters in the marginal aggregate, measured on epoch 430529")
    args = ap.parse_args()

    committee = args.validators / SLOTS_PER_EPOCH
    attesters = committee * args.participation
    absentees = committee - attesters

    print(f"\n{args.validators:,} active validators, {committee:,.0f} to a committee, "
          f"{args.participation:.1%} attesting => {absentees:,.0f} absentees per slot\n")

    print("Per slot")
    print("-" * 58)
    for label, cost in [
        ("enumerate attesters", enumerated_slot(attesters, args.aggregates_per_slot)),
        ("name absentees", complement_slot(absentees)),
    ]:
        print(f"  {label:<26}{fmt(cost)}")

    print("\nWhole epoch")
    print("-" * 58)
    before = SLOTS_PER_EPOCH * (
        enumerated_slot(attesters, args.aggregates_per_slot) + COST["proof_base"]
    ) + COST["proof_base"]
    after = (
        SLOTS_PER_EPOCH * (complement_slot(absentees) + COST["proof_base"])
        + COST["proof_base"]
        + committee_proof(args.validators)
    )
    print(f"  {'32 slot proofs, before':<26}{fmt(before)}")
    print(f"  {'committee proof':<26}{fmt(committee_proof(args.validators))}")
    print(f"  {'32 slot proofs, after':<26}{fmt(after)}")
    print(f"  {'change':<26}{(after - before) / before * 100:>11.1f}%")

    # The marginal unit was one aggregate; it is now one slot, because a slot is
    # the smallest thing a committee aggregate can be the complement of. The
    # comparison is therefore a measured aggregate against a whole committee.
    print(f"\nCritical path: one aggregate of {args.tail_attesters:,} against one whole committee")
    print("-" * 58)
    critical_before = (
        COST["proof_base"]
        + enumerated_slot(args.tail_attesters, 1)
        + dedup_open(args.tail_attesters)
        + COST["final_exp"]
        + COST["fp12_mul"]
        + COST["commit_fp12"]
    )
    critical_after = (
        COST["proof_base"]
        + complement_slot(absentees)
        + COST["final_exp"]
        + COST["fp12_mul"]
        + COST["commit_fp12"]
    )
    for label, cost in [("enumerate", critical_before), ("complement", critical_after)]:
        print(f"  {label:<26}{fmt(cost)}{gpu_seconds(cost, 1):>10,.1f}s")
    print(f"  {'':<26}{'':>12}{critical_before / critical_after:>9.1f}x")
    print()


if __name__ == "__main__":
    main()

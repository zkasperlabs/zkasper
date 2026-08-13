#!/usr/bin/env python3
"""Project measured Zisk costs to a mainnet epoch.

Constants come from scripts/bench.py; see BENCHMARKS.md. Everything below is
derived from them, so re-running bench.py after a Zisk bump and updating COST
here keeps this honest.
"""
import argparse

COST = {
    "acc_node": 3_033,
    "acc_leaf": 3_979,
    "acc_leaf_compressed": 3_460,   # previous format, for the comparison
    "decompress": 49_311,
    "g1_add": 2_428,
    "g1_add_complete": 67_854,   # previous path, for the comparison
    "hash_to_curve": 18_594_336,
    "miller": 39_299_490,
    "final_exp": 169_455_773,
    "proof_base": 293_601_280,
}

ACC_DEPTH = 22
SLOTS_PER_EPOCH = 32


def batched_nodes(num_leaves, depth=ACC_DEPTH):
    """Internal compressions a multi-proof over `num_leaves` random leaves needs.

    A node at level k covers 2^k leaves, so it is touched unless every one of
    those slots is empty. Near the bottom almost every touched node is distinct;
    higher up the set collapses and the whole level is rebuilt.
    """
    capacity = 2 ** depth
    total = 0
    for k in range(1, depth + 1):
        nodes = 2 ** (depth - k)
        p_touched = 1 - (1 - 2 ** k / capacity) ** num_leaves
        total += nodes * p_touched
    return total


def epoch_cost(validators, attestations_per_slot, leaf_cost, decompress_per_attester,
               g1_add=None):
    per_slot_attesters = validators / SLOTS_PER_EPOCH

    accumulator = per_slot_attesters * leaf_cost + batched_nodes(per_slot_attesters) * COST["acc_node"]
    add_cost = COST["g1_add"] if g1_add is None else g1_add
    pubkeys = per_slot_attesters * (add_cost + (COST["decompress"] if decompress_per_attester else 0))
    bls = (
        attestations_per_slot * COST["hash_to_curve"]
        + (attestations_per_slot + 1) * COST["miller"]
        + COST["final_exp"]
    )

    slot_total = accumulator + pubkeys + bls + COST["proof_base"]
    return {
        "accumulator": accumulator * SLOTS_PER_EPOCH,
        "pubkeys": pubkeys * SLOTS_PER_EPOCH,
        "bls": bls * SLOTS_PER_EPOCH,
        "base": COST["proof_base"] * (SLOTS_PER_EPOCH + 1),
        "total": slot_total * SLOTS_PER_EPOCH + COST["proof_base"],
    }


def fmt(n):
    return f"{n / 1e9:>12,.1f}B"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--validators", type=int, default=1_050_000)
    ap.add_argument("--attestations-per-slot", type=int, default=8,
                    help="aggregates per block; post-Electra a single aggregate covers all committees")
    args = ap.parse_args()

    before = epoch_cost(args.validators, args.attestations_per_slot,
                        COST["acc_leaf_compressed"], decompress_per_attester=True,
                        g1_add=COST["g1_add_complete"])
    after = epoch_cost(args.validators, args.attestations_per_slot,
                       COST["acc_leaf"], decompress_per_attester=False)

    print(f"\nOne epoch: {args.validators:,} active validators, "
          f"{args.attestations_per_slot} aggregates/slot, "
          f"{SLOTS_PER_EPOCH} slot proofs + 1 justification\n")
    print(f"{'component':<24}{'before':>16}{'after':>16}{'change':>12}")
    print("-" * 68)
    for key, label in [
        ("accumulator", "accumulator hashing"),
        ("pubkeys", "public keys"),
        ("bls", "pairings"),
        ("base", "per-proof floor"),
        ("total", "TOTAL"),
    ]:
        if key == "total":
            print("-" * 68)
        delta = (after[key] - before[key]) / before[key] * 100
        print(f"{label:<24}{fmt(before[key])}{fmt(after[key])}{delta:>11.1f}%")

    old = COST["acc_leaf_compressed"] + COST["decompress"] + COST["g1_add_complete"]
    new = COST["acc_leaf"] + COST["g1_add"]
    print(f"\nper attester: {old:,} -> {new:,}  ({(1 - new / old) * 100:.1f}% off)")
    print(f"epoch-diff pays {COST['decompress']:,} per changed validator instead"
          f" ({COST['decompress'] * 200 / 1e9:.2f}B for 200 mutations)\n")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Project measured Zisk costs to a mainnet epoch.

Constants come from scripts/bench.py; see BENCHMARKS.md. Everything below is
derived from them, so re-running bench.py after a Zisk bump and updating COST
here keeps this honest.

**Cost units are trace area, not time.** They are used here to compare one
implementation of a thing against another implementation of the same thing —
compressed leaf against point leaf, wrapper curve-add against raw precompile —
which is what ratios are good for. They are not divided by a throughput constant
anywhere, because measured throughput on real guests spans 18M to 249M units/s.
Wall-clock comes from `scripts/time_model.py`, which is calibrated per work
class, and the two are reported side by side rather than one derived from the
other.
"""
import argparse

import time_model as tm

COST = {
    "acc_node": 3_033,
    "acc_leaf": 3_979,
    "acc_leaf_compressed": 3_460,   # previous format, for the comparison
    "decompress": 49_311,
    "g1_add": 2_428,
    "g1_add_complete": 67_854,   # previous path, for the comparison
    "hash_to_curve": 18_594_521,
    # Marginal Miller loop and the fixed cost of the batch that holds it, split
    # apart in BENCHMARKS.md. The old single figure of 39,299,490 folded the
    # per-pair validation of `pairing_check_safe_bls12_381` into the loop.
    "miller": 33_222_822,
    "miller_batch": 39_633_399,
    "final_exp": 132_665_557,
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
        + COST["miller_batch"]
        + (attestations_per_slot + 1) * COST["miller"]
        + COST["final_exp"]
    )

    return {
        "accumulator": accumulator * SLOTS_PER_EPOCH,
        "pubkeys": pubkeys * SLOTS_PER_EPOCH,
        "bls": bls * SLOTS_PER_EPOCH,
        "total": (accumulator + pubkeys + bls) * SLOTS_PER_EPOCH,
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
    print(f"{'trace area':<24}{'before':>16}{'after':>16}{'change':>12}")
    print("-" * 68)
    for key, label in [
        ("accumulator", "accumulator hashing"),
        ("pubkeys", "public keys"),
        ("bls", "pairings"),
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
          f" ({COST['decompress'] * 200 / 1e9:.2f}B for 200 mutations)")

    # The floor is not in the table above, because it is not trace area that
    # scales with anything and it cannot be converted from cost units.
    per_slot = args.validators / SLOTS_PER_EPOCH
    enumerating = tm.STAGE_FLOOR_S + tm.open_leaves_s(per_slot) + tm.bls_s(
        COST["miller_batch"] + tm.UNITS["g2_subgroup"] + COST["final_exp"]
        + args.attestations_per_slot * (COST["hash_to_curve"] + COST["miller"]))
    complemented = tm.group_s(per_slot * 0.003, 1, args.attestations_per_slot) \
        + tm.bls_s(COST["final_exp"])
    print(f"\nwall clock, one warm RTX 5090 (scripts/time_model.py)\n")
    print(f"  {'per-proof floor, MEASURED':<44}{tm.STAGE_FLOOR_S:>9.2f}s")
    print(f"  {'one slot proof, enumerating its attesters':<44}{enumerating:>9.2f}s")
    print(f"  {'one slot proof, naming its absentees':<44}{complemented:>9.2f}s"
          f"   ({enumerating / complemented:.0f}x)")
    print(f"  {'32 of the latter, serial':<44}{32 * complemented:>9.2f}s"
          f"   against a {SLOTS_PER_EPOCH * 12}s epoch")
    print(f"  {'committee proof, whole registry':<44}"
          f"{tm.committee_chunk_s(args.validators, 1):>9.2f}s"
          f"   {tm.committee_chunk_s(args.validators, 1) / (SLOTS_PER_EPOCH * 12):.1f} cards held")
    print("\n  The committee proof is now the fleet-sizing constraint. The cost")
    print("  model made it 215 s because it charged a leaf hash and a curve")
    print("  addition per validator and none of the 2,311 executed steps that")
    print("  walk one; measured, a validator costs 878 us.\n")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""What sits between "enough attestations" and "postable proof".

T is the moment the chain has published enough attestations to justify the
target; T2 is the moment a proof of it exists. Only the work that *depends on
the last attestation* is between them, so this script models the last proof in
the chain rather than the epoch.

Two schedules, same measured constants:

  fixed groups   slots proven eight at a time, then justification, then
                 finalization, then the SNARK wrap — four sequential proofs, the
                 last group's eight slots of work among them.

  streaming      groups that shrink toward the threshold, a running aggregate
                 folded as they finish, and one final proof that does the
                 marginal aggregate inline, multiplies the Miller accumulators,
                 runs the single final exponentiation and emits the
                 finalization.

Constants come from scripts/bench.py; see BENCHMARKS.md.
"""
import argparse

# Measured, zisk v1.0.0-alpha, `python3 scripts/bench.py`.
COST = {
    "acc_node": 3_033,
    "acc_leaf": 3_979,
    "g1_add": 2_428,
    "hash_to_curve": 18_594_521,
    # Marginal cost of one more pair in a multi-Miller-loop, no validation.
    "miller_pair": 33_222_822,
    # Fixed cost of any multi-Miller-loop: 63 Fp12 squarings the pairs share.
    "miller_batch": 39_633_399,
    "final_exp": 132_665_557,
    "fp12_mul": 737_503,
    "commit_fp12": 78_002,
    "g2_subgroup": 8_219_617,
    "proof_base": 293_601_280,
}

ACC_DEPTH = 22
DEDUP_DEPTH = ACC_DEPTH - 8
SLOTS_PER_EPOCH = 32

# Prover throughput.
CPU_UNITS_PER_S = 1_244_523
CPU_FIXED_S = 333.4
GPU_UNITS_PER_S = 67_452_592
GPU_COLD_FIXED_S = 19.52   # process startup + 30 GB of GPU allocation
GPU_WARM_FIXED_S = 0.5     # a prover that keeps the allocation open
WRAP_COMPRESSION_S = 0.192


def batched_nodes(num_leaves, depth):
    """Internal compressions a multi-proof over `num_leaves` random leaves needs."""
    capacity = 2 ** depth
    total = 0
    for k in range(1, depth + 1):
        nodes = 2 ** (depth - k)
        total += nodes * (1 - (1 - 2 ** k / capacity) ** num_leaves)
    return total


def accumulator(attesters):
    """Opening `attesters` leaves against the accumulator."""
    return attesters * COST["acc_leaf"] + batched_nodes(attesters, ACC_DEPTH) * COST["acc_node"]


def dedup_open(indices):
    """Opening the counted-set tree over `indices`, 256 indices to a leaf."""
    leaves = 2 ** DEDUP_DEPTH * (1 - (1 - 2 ** -DEDUP_DEPTH) ** indices)
    return (leaves + batched_nodes(leaves, DEDUP_DEPTH)) * COST["acc_node"]


def attestation_work(attesters, aggregates):
    """Everything an attestation set costs short of the final exponentiation."""
    return (
        accumulator(attesters)
        + attesters * COST["g1_add"]
        + aggregates * COST["hash_to_curve"]
        + COST["miller_batch"]
        + (aggregates + 1) * COST["miller_pair"]
        + COST["g2_subgroup"]
    )


def fixed_group_critical_path(validators, aggregates_per_slot, group_slots):
    """Last group, justification, finalization — three proofs, in series."""
    attesters = validators / SLOTS_PER_EPOCH * group_slots
    group = (
        COST["proof_base"]
        + attestation_work(attesters, aggregates_per_slot * group_slots)
        + COST["final_exp"]
    )
    # The justification proof re-derives the epoch's counted indices to check
    # them against each slot proof's commitment, eight to a permutation.
    justification = COST["proof_base"] + validators / 8 * COST["acc_node"]
    finalization = COST["proof_base"]
    return {
        "last group": group,
        "justification": justification,
        "finalization": finalization,
        "proofs": 3,
    }


def streaming_critical_path(validators, aggregates_per_slot, absorbed_groups=0,
                            tail_attesters=None, tail_counted=None):
    """One proof: the marginal aggregate inline, and everything else recursed."""
    attesters = tail_attesters or validators / SLOTS_PER_EPOCH / aggregates_per_slot
    final = (
        COST["proof_base"]
        + attestation_work(attesters, 1)
        + dedup_open(tail_counted if tail_counted is not None else attesters)
        + COST["final_exp"]
        + (1 + absorbed_groups) * COST["fp12_mul"]
        + (1 + absorbed_groups) * COST["commit_fp12"]
    )
    return {"final proof": final, "proofs": 1}


def seconds(cost, proofs, mode):
    if mode == "cpu":
        return CPU_FIXED_S * proofs + cost / CPU_UNITS_PER_S
    fixed = GPU_COLD_FIXED_S if mode == "gpu-cold" else GPU_WARM_FIXED_S
    # The SNARK wrap is one more invocation on top of the proofs.
    return fixed * (proofs + 1) + cost / GPU_UNITS_PER_S + WRAP_COMPRESSION_S


def report(name, parts):
    proofs = parts.pop("proofs")
    total = sum(parts.values())
    print(f"\n{name}")
    for label, cost in parts.items():
        print(f"  {label:<24}{cost / 1e9:>10,.3f}B")
    print(f"  {'':<24}{'':>10}  {proofs} proof{'s' if proofs != 1 else ''} + wrap")
    print(f"  {'TOTAL':<24}{total / 1e9:>10,.3f}B")
    for mode, label in [("cpu", "CPU"), ("gpu-cold", "GPU cold"), ("gpu-warm", "GPU warm")]:
        print(f"  {label:<24}{seconds(total, proofs, mode):>10,.1f}s")
    return total


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--validators", type=int, default=1_050_000)
    ap.add_argument("--aggregates-per-slot", type=int, default=8)
    ap.add_argument("--group-slots", type=int, default=8,
                    help="fixed-schedule group size, for the baseline")
    ap.add_argument("--tail-attesters", type=int, default=None,
                    help="attesters in the marginal aggregate, if measured rather than modelled")
    ap.add_argument("--tail-counted", type=int, default=None,
                    help="how many of those are counted for the first time")
    args = ap.parse_args()

    print(f"\nT2 - T at {args.validators:,} active validators, "
          f"{args.aggregates_per_slot} aggregates per slot")

    baseline = report(
        f"fixed groups of {args.group_slots}, four-stage tail",
        fixed_group_critical_path(args.validators, args.aggregates_per_slot, args.group_slots),
    )
    streaming = report(
        "streaming, collapsed tail",
        streaming_critical_path(
            args.validators,
            args.aggregates_per_slot,
            tail_attesters=args.tail_attesters,
            tail_counted=args.tail_counted,
        ),
    )

    print(f"\n  critical path {baseline / streaming:.1f}x shorter in cost units")
    for mode, label in [("cpu", "CPU"), ("gpu-cold", "GPU cold"), ("gpu-warm", "GPU warm")]:
        b = seconds(baseline, 3, mode)
        s = seconds(streaming, 1, mode)
        print(f"  {label:<10}{b:>8,.1f}s -> {s:>6,.1f}s   ({b / s:.1f}x)")
    print()


if __name__ == "__main__":
    main()

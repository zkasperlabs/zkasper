#!/usr/bin/env python3
"""What sits between "enough attestations" and "postable proof", in seconds.

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
                 marginal slot inline, multiplies the Miller accumulators, runs
                 the single final exponentiation and emits the finalization.

Everything here is seconds. The previous version of this script was denominated
in Zisk cost units against one throughput constant and added a 19.52 s "cold
fixed cost" on top of a per-proof floor — double-counting the floor, because the
19.52 s was a regression intercept that already contained it. See
`scripts/time_model.py` for what replaced it and why.
"""
import argparse

import time_model as tm

SLOTS_PER_EPOCH = tm.SLOTS_PER_EPOCH


def fixed_group_critical_path(validators, aggregates_per_slot, group_slots):
    """Last group, justification, finalization — three proofs, in series.

    The pre-streaming schedule enumerated attesters rather than naming absentees,
    so its last group opens every attester in eight slots.
    """
    attesters = validators / SLOTS_PER_EPOCH * group_slots
    group = (
        tm.STAGE_FLOOR_S
        + tm.open_leaves_s(attesters)
        + tm.bls_s(
            tm.UNITS["miller_batch"]
            + tm.UNITS["g2_subgroup"]
            + aggregates_per_slot * group_slots
            * (tm.UNITS["hash_to_curve"] + tm.UNITS["miller_pair"])
            + tm.UNITS["final_exp"]
        )
    )
    # The justification proof re-derived the epoch's counted indices to check
    # them against each slot proof's commitment.
    justification = tm.STAGE_FLOOR_S + validators / 8 * tm.ACC_NODE_S
    finalization = tm.STAGE_FLOOR_S
    return {
        "last group": group,
        "justification": justification,
        "finalization": finalization,
        "proofs": 3,
    }


def streaming_critical_path(validators, aggregates_per_slot, absorbed_groups=0,
                            tail_named=None, tail_messages=None, absentee_rate=0.003):
    """One proof: the marginal slot inline, and everything else recursed."""
    named = tail_named if tail_named is not None else validators / SLOTS_PER_EPOCH * absentee_rate
    messages = tail_messages if tail_messages is not None else 1
    return {
        "final proof": tm.final_s(named, 1, messages, absorbed_groups, True),
        "proofs": 1,
    }


def report(name, parts):
    proofs = parts.pop("proofs")
    total = sum(parts.values())
    print(f"\n{name}")
    for label, secs in parts.items():
        print(f"  {label:<26}{secs:>10,.2f}s")
    print(f"  {'':<26}{'':>10}  {proofs} proof{'s' if proofs != 1 else ''} + wrap")
    print(f"  {'warm prover':<26}{total + tm.WRAP_S:>10,.2f}s")
    print(f"  {'cold, per invocation':<26}"
          f"{total + tm.WRAP_S + tm.COLD_PENALTY_S * (proofs + 1):>10,.2f}s")
    return total, proofs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--validators", type=int, default=1_050_000)
    ap.add_argument("--aggregates-per-slot", type=int, default=8)
    ap.add_argument("--group-slots", type=int, default=8,
                    help="fixed-schedule group size, for the baseline")
    ap.add_argument("--tail-named", type=int, default=None,
                    help="validators the marginal slot opens: its absentees plus "
                         "any minority-head-vote signers")
    ap.add_argument("--tail-messages", type=int, default=None,
                    help="distinct signing roots in the marginal slot")
    ap.add_argument("--absentee-rate", type=float, default=0.003,
                    help="share of a committee that does not attest")
    args = ap.parse_args()

    print(f"\nT2 - T at {args.validators:,} active validators, "
          f"{args.aggregates_per_slot} aggregates per slot")

    baseline, base_proofs = report(
        f"fixed groups of {args.group_slots}, four-stage tail, attesters enumerated",
        fixed_group_critical_path(args.validators, args.aggregates_per_slot,
                                  args.group_slots),
    )
    streaming, stream_proofs = report(
        "streaming, collapsed tail, absentees named",
        streaming_critical_path(
            args.validators,
            args.aggregates_per_slot,
            tail_named=args.tail_named,
            tail_messages=args.tail_messages,
            absentee_rate=args.absentee_rate,
        ),
    )

    warm_b = baseline + tm.WRAP_S
    warm_s = streaming + tm.WRAP_S
    cold_b = warm_b + tm.COLD_PENALTY_S * (base_proofs + 1)
    cold_s = warm_s + tm.COLD_PENALTY_S * (stream_proofs + 1)
    print(f"\n  warm  {warm_b:>7,.1f}s -> {warm_s:>6,.1f}s   ({warm_b / warm_s:.1f}x)")
    print(f"  cold  {cold_b:>7,.1f}s -> {cold_s:>6,.1f}s   ({cold_b / cold_s:.1f}x)")
    print("\n  Where the streaming number goes:")
    for label, secs in [
        ("stage floor", tm.STAGE_FLOOR_S),
        ("final exponentiation", tm.bls_s(tm.UNITS["final_exp"])),
        ("the marginal slot's messages", tm.bls_s(
            tm.UNITS["miller_batch"] + tm.UNITS["g2_subgroup"]
            + (args.tail_messages or 1) * (tm.UNITS["hash_to_curve"] + tm.UNITS["miller_pair"]))),
        ("naming its absentees", tm.open_leaves_s(
            args.tail_named
            if args.tail_named is not None
            else args.validators / SLOTS_PER_EPOCH * args.absentee_rate)),
        ("wrap", tm.WRAP_S),
    ]:
        print(f"    {label:<32}{secs:>8.2f}s  {secs / warm_s * 100:>5.1f}%")
    print("\n  The floor is most of it and it is pure overhead, which is the")
    print("  argument for fewer, larger proofs — and the one thing a faster card")
    print("  buys directly.\n")


if __name__ == "__main__":
    main()

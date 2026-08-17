#!/usr/bin/env python3
"""Turn trace-cell counts into proving time and dollars.

Zisk's cost unit is trace cells — `BASE_COST` in the emulator is
`(21 + 55 + 35 + 29) << 21`, i.e. columns times 2^21 rows. Proving work is
essentially linear in that, so one measured throughput figure converts the whole
cost model into seconds.

Measure throughput by proving something real and dividing:

    scripts/test_zisk_proof.sh slot-proof     # prints TOTAL cost and wall-clock

Then pass --cells-per-second. Anything derived from a default is labelled as an
assumption, because the default is a guess and the measurement is not.
"""
import argparse

EPOCH_SECONDS = 384          # 32 slots x 12s
EPOCHS_PER_DAY = 86_400 / EPOCH_SECONDS


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--epoch-cost", type=float, default=60.6e9,
                    help="trace cells per epoch, from scripts/mainnet_cost.py")
    ap.add_argument("--cells-per-second", type=float, required=True,
                    help="measured prover throughput")
    ap.add_argument("--dollars-per-hour", type=float, default=1.50,
                    help="cost of one prover machine")
    ap.add_argument("--slot-proofs", type=int, default=32,
                    help="proofs that can run in parallel across machines")
    args = ap.parse_args()

    epoch_seconds = args.epoch_cost / args.cells_per_second
    per_slot_seconds = epoch_seconds / args.slot_proofs
    machine_seconds = epoch_seconds  # total work, however it is spread

    cost_per_epoch = machine_seconds / 3600 * args.dollars_per_hour

    print(f"\nthroughput           {args.cells_per_second / 1e6:>12,.1f}M cells/s")
    print(f"epoch cost           {args.epoch_cost / 1e9:>12,.1f}B cells\n")

    print(f"{'sequential, 1 machine':<28}{epoch_seconds:>10,.0f} s")
    print(f"{'one slot proof':<28}{per_slot_seconds:>10,.0f} s")
    print(f"{'wall-clock on ' + str(args.slot_proofs) + ' machines':<28}"
          f"{per_slot_seconds:>10,.0f} s  (vs {EPOCH_SECONDS}s of chain time)")

    realtime = "keeps up" if per_slot_seconds < EPOCH_SECONDS else "does NOT keep up"
    print(f"{'':<28}{'':>10}  -> {realtime}\n")

    print(f"{'$/epoch':<28}{cost_per_epoch:>10,.2f}")
    print(f"{'$/day':<28}{cost_per_epoch * EPOCHS_PER_DAY:>10,.2f}")
    print(f"{'$/month':<28}{cost_per_epoch * EPOCHS_PER_DAY * 30:>10,.2f}")
    print(f"{'$/year':<28}{cost_per_epoch * EPOCHS_PER_DAY * 365:>10,.2f}\n")

    print(f"at ${args.dollars_per_hour}/hour per machine; scale linearly for other rates\n")


if __name__ == "__main__":
    main()

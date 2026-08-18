#!/usr/bin/env python3
"""How many GPUs zkasper needs, and what they cost.

This used to be a thousand-line re-implementation of the scheduler in
`crates/witness-gen/src/streaming.rs`, denominated in Zisk cost units, modelling
an enumeration scheme that complement proving replaced and an FCR shuffle the
pipeline no longer has. All of that is gone. The schedule is the Rust one — it
is the code that runs, it reports the card count it needs as
`Schedule::lanes`, and `cargo test --release --test ssz_file_tests
test_ssz_file_streaming_schedule -- --ignored --nocapture` prints it against a
real mainnet epoch. What is left here is the part that was never in Rust: the
arithmetic from cards to dollars.

The sizing question has changed shape, and the measured time model is why.

  deadline work   the epoch's group proofs, folds and final proof. Bound by
                  arrival times, not throughput: a slot's marginal work is under
                  a second against twelve seconds of wall clock to do it in. The
                  schedule settles on one or two cards and extra ones buy
                  nothing, because a proof cannot start before its attestations
                  exist.

  committee proof the per-epoch proof that opens every active validator's leaf
                  and aggregates every public key. MEASURED at 125 us per
                  member, that is ~169 s at 960,974 active validators, inside
                  the 384 s epoch that owes it, in one chunk on one card.

The committee proof used to size the fleet at five cards. Two things were wrong
with that and both are fixed: the model charged it the whole 2,212,792-entry
registry when committees are formed from active validators only, and the guest
spent 94% of the proof deserialising a witness Zisk had already handed it in the
layout it wanted. Neither the deadline work nor the committee proof needs cards
beyond the one or two the schedule settles on.

Every constant is labelled MEASURED (a timed run on the RTX 5090, see
`scripts/time_model.py`), QUOTED (a vendor or marketplace price), or MODELLED
(computed here). Run `--help` for what can be moved.
"""
from __future__ import annotations

import argparse
import math
from dataclasses import dataclass, replace

import time_model as tm

SLOTS_PER_EPOCH = tm.SLOTS_PER_EPOCH
SECONDS_PER_SLOT = 12
EPOCH_SECONDS = SLOTS_PER_EPOCH * SECONDS_PER_SLOT       # 384
EPOCHS_PER_YEAR = 365.25 * 24 * 3600 / EPOCH_SECONDS     # MODELLED, 82,152

# MEASURED, `data/gpu_bench/pair2.tsv` and `vram.tsv`. A second warm prover on
# one RTX 5090 runs — the ~30 GB the prover takes is greed, not a requirement,
# and it works down to 12.9 GB allocated — but the two share the card: each runs
# at 1.4-1.7x its solo latency for about 1.2x aggregate throughput. Worth having
# for throughput work, never for the critical path.
PACKED_THROUGHPUT = 1.2
PACKED_LATENCY = 1.55
# MEASURED: the prover refuses to start below about 14 GB free.
MIN_PROVER_GB = 14.0


# ---------------------------------------------------------------------------
# Workload
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Epoch:
    """One mainnet epoch, as the streaming schedule sees it.

    Defaults are epoch 430529 as `streaming::plan` cuts it: 115 slot
    complements, the threshold crossed at slot 22, 2.8 distinct messages a slot
    from minority head votes.
    """
    validators: float = 1_050_000
    absentee_rate: float = 0.003          # MEASURED, 99.7% participation
    messages_per_slot: float = 2.8        # MEASURED, epoch 430529
    slots_before_threshold: int = 23      # MEASURED, epoch 430529
    groups: int = 4                       # what the schedule chooses; see the Rust test

    def named_per_slot(self) -> float:
        return self.validators / SLOTS_PER_EPOCH * self.absentee_rate

    def deadline_s(self) -> float:
        """Prover-seconds the epoch's own proofs spend, groups through wrap."""
        per_group_slots = self.slots_before_threshold / self.groups
        groups = self.groups * tm.group_s(
            self.named_per_slot() * per_group_slots,
            per_group_slots,
            self.messages_per_slot * per_group_slots,
        )
        folds = self.groups * tm.fold_s(1)
        final = tm.final_s(self.named_per_slot(), 1, self.messages_per_slot, 0, True)
        return groups + folds + final + tm.WRAP_S

    def committee_s(self, chunks: int) -> float:
        """Prover-seconds the next epoch's committee proof spends."""
        return chunks * tm.committee_chunk_s(self.validators, chunks) + (
            tm.committee_fold_s(chunks) if chunks > 1 else 0.0
        )


def committee_cards(epoch: Epoch, chunks: int, rate: float, packed: int) -> tuple:
    """Cards the committee proof needs, and when the last chunk lands.

    A chunk is indivisible, so the bound is both throughput — the chunks have to
    fit in an epoch of card time — and latency, since one chunk longer than an
    epoch can never land inside one however many cards there are.

    `packed` provers on one card each run at `PACKED_LATENCY` of solo speed, so
    a card gets through `packed / PACKED_LATENCY` chunks in the time it would
    otherwise get through one. That is the measured 1.2x, not 2x.
    """
    chunk_s = tm.committee_chunk_s(epoch.validators, chunks) / rate
    fold_s = (tm.committee_fold_s(chunks) / rate) if chunks > 1 else 0.0
    if packed > 1:
        chunk_s *= PACKED_LATENCY
        fold_s *= PACKED_LATENCY
    budget = EPOCH_SECONDS - fold_s
    if chunk_s > budget:
        return math.inf, math.inf
    # Chunks one card gets through in an epoch, in series, across its provers.
    per_card = int(budget // chunk_s) * packed
    cards = math.ceil(chunks / per_card)
    rounds = math.ceil(chunks / (cards * packed))
    return cards, rounds * chunk_s + fold_s


# ---------------------------------------------------------------------------
# SKUs
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Sku:
    name: str
    vram_gb: float          # QUOTED, vendor spec
    tdp_w: float            # QUOTED, vendor spec
    buy_usd: float | None   # QUOTED street price, new
    rent_usd_h: float | None    # QUOTED, vast.ai quality-filtered median
    scale: float = 1.0      # MODELLED, see below
    note: str = ""


# Prices QUOTED, observed 2026-08-18. Rental is the vast.ai median across
# verified hosts with reliability above 95%, which is the tier a service that
# has to stay up can actually use; the marketplace floor is 30-50% lower and
# sits on deverified hosts.
#
# `scale` is MODELLED and it is not the bandwidth ratio. Goldilocks modmul is
# integer-multiply bound, and `mad.lo.s32` is 64 results per clock per SM on
# every compute capability from 7.5 to 12.1, so throughput tracks SM count times
# clock far more than it tracks HBM. These figures blend the two ratios 25/75 in
# favour of integer multiply, which reproduces both public cross-card
# measurements: Ethproofs has Zisk at 69.7 s on a 5090 against a Zisk derivative
# at 91.0 s on a 4090, and Surge has 8x L40 at 13-14 s against 8x RTX 5090 at
# 10-11 s. They remain MODELLED and every dollar below inherits their error.
SKUS = [
    Sku("RTX 5090", 32, 575, 4200, 0.565, 1.00, "measured baseline"),
    Sku("RTX 4090", 24, 450, 2899, 0.374, 0.72, "EOL, resale only; runs Zisk on Ethproofs today"),
    Sku("RTX PRO 6000 Blackwell", 96, 600, 14900, 1.203, 1.14, "188 SMs against the 5090's 170"),
    Sku("RTX 6000 Ada", 48, 300, 8200, 0.668, 0.75, "thin supply"),
    Sku("L40S", 48, 350, 8800, 0.801, 0.73, "8 hosts on vast.ai"),
    Sku("RTX A6000", 48, 300, 4500, 0.481, 0.38, "cheapest 48 GB, slowest chip in the set"),
    Sku("H100 80GB SXM", 80, 700, 24875, 3.068, 0.76, "HGX baseboard only; FP64 this never touches"),
    Sku("H200 141GB SXM", 141, 700, 26500, 4.047, 0.79, "same GH100 with more HBM"),
]


@dataclass
class Config:
    epoch: Epoch = Epoch()
    chunks: int = 4
    pack: int = 1                          # warm provers per card
    power_usd_kwh: float = 0.12            # QUOTED, US commercial average
    pue: float = 1.4                       # ASSUMED, colo overhead
    amortisation_years: float = 3.0
    hosting_usd_card_month: float = 120.0  # QUOTED, typical colo per-GPU slot
    deadline_cards: int = 1                # what `streaming::schedule` settles on
    redundancy: int = 0


def fits(sku: Sku, pack: int) -> bool:
    return sku.vram_gb >= pack * MIN_PROVER_GB


def price(cfg: Config, sku: Sku) -> dict:
    if not fits(sku, cfg.pack):
        return {"sku": sku.name, "cards": math.inf}
    cards, done_s = committee_cards(cfg.epoch, cfg.chunks, sku.scale, cfg.pack)
    if cards is math.inf:
        return {"sku": sku.name, "cards": math.inf}
    cards = max(cards, cfg.deadline_cards) + cfg.redundancy
    busy = (cfg.epoch.deadline_s() + cfg.epoch.committee_s(cfg.chunks)) / sku.scale
    rent_year = math.inf if sku.rent_usd_h is None else cards * sku.rent_usd_h * 24 * 365.25
    own_year = math.inf if sku.buy_usd is None else (
        cards * sku.buy_usd / cfg.amortisation_years
        + cards * sku.tdp_w / 1000 * cfg.pue * 24 * 365.25 * cfg.power_usd_kwh
        + cards * cfg.hosting_usd_card_month * 12
    )
    return {
        "sku": sku.name,
        "cards": cards,
        "committee_done_s": done_s,
        "utilisation": busy / (cards * EPOCH_SECONDS),
        "rent_epoch": rent_year / EPOCHS_PER_YEAR,
        "rent_year": rent_year,
        "own_year": own_year,
    }


def money(x):
    if x is math.inf:
        return "n/a"
    if x >= 1000:
        return f"${x:,.0f}"
    if x >= 1:
        return f"${x:,.2f}"
    return f"${x:.4f}"


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

def report_workload(cfg: Config):
    e = cfg.epoch
    print(f"\nOne epoch at {e.validators:,.0f} active validators, "
          f"{e.absentee_rate:.1%} absent, {e.messages_per_slot:.1f} messages a slot")
    print(f"  {'deadline work, groups through wrap':<42}{e.deadline_s():>9.1f}s")
    print(f"  {'  of which after the last attestation':<42}"
          f"{tm.final_s(e.named_per_slot(), 1, e.messages_per_slot, 0, True) + tm.WRAP_S:>9.1f}s"
          f"   <- T2 - T")
    print(f"  {'committee proof for the next epoch':<42}{e.committee_s(1):>9.1f}s"
          f"   {e.committee_s(1) / EPOCH_SECONDS:.1f}x an epoch")
    print(f"  {'total prover-seconds':<42}"
          f"{e.deadline_s() + e.committee_s(cfg.chunks):>9.1f}s"
          f"   against {EPOCH_SECONDS}s of one card")


def report_chunks(cfg: Config):
    print("\nCommittee-proof chunking on RTX 5090, one warm prover a card")
    print(f"  {'chunks':>7}{'per chunk':>12}{'cards':>8}{'done by':>10}{'total':>10}")
    for chunks in (1, 2, 3, 4, 6, 8, 16, 32):
        cards, done = committee_cards(cfg.epoch, chunks, 1.0, cfg.pack)
        chunk_s = tm.committee_chunk_s(cfg.epoch.validators, chunks)
        cards_s = "—" if cards is math.inf else f"{cards:.0f}"
        done_s = "never" if done is math.inf else f"{done:.0f}s"
        print(f"  {chunks:>7}{chunk_s:>11.0f}s{cards_s:>8}{done_s:>10}"
              f"{cfg.epoch.committee_s(chunks):>9.0f}s")
    print(f"  A chunk longer than the {EPOCH_SECONDS}s epoch can never land inside one,")
    print("  which is the whole reason to chunk; past that, chunks trade a floor")
    print("  each against cards.")


def report_packing(cfg: Config):
    print("\nTwo warm provers on one card, MEASURED")
    print(f"  aggregate throughput {PACKED_THROUGHPUT:.1f}x, per-proof latency {PACKED_LATENCY:.2f}x")
    for pack in (1, 2):
        cards, done = committee_cards(cfg.epoch, cfg.chunks, 1.0, pack)
        cards_s = "—" if cards is math.inf else f"{cards:.0f}"
        done_s = "never" if done is math.inf else f"{done:.0f}s"
        print(f"  {pack} prover(s) a card: {cards_s} card(s), committee done by {done_s}")
    print("  Packing is a throughput trade and the committee proof is throughput")
    print("  work, so it applies there and never to the proof after T.")


def report_skus(cfg: Config):
    print(f"\n{'SKU':<26}{'VRAM':>6}{'scale':>7}{'cards':>7}{'committee':>11}"
          f"{'$/epoch':>10}{'$/yr rent':>11}{'$/yr own':>10}{'util':>6}")
    print("-" * 94)
    for sku in SKUS:
        r = price(cfg, sku)
        if r["cards"] is math.inf:
            print(f"{sku.name:<26}{sku.vram_gb:>5.0f}G{sku.scale:>7.2f}{'—':>7}"
                  f"{'—':>11}{'—':>10}{'—':>11}{'—':>10}{'—':>6}")
            continue
        print(f"{sku.name:<26}{sku.vram_gb:>5.0f}G{sku.scale:>7.2f}{r['cards']:>7.0f}"
              f"{r['committee_done_s']:>10.0f}s{money(r['rent_epoch']):>10}"
              f"{money(r['rent_year']):>11}{money(r['own_year']):>10}"
              f"{r['utilisation'] * 100:>5.0f}%")
    print("\n  scale is MODELLED: SM count x clock blended 75/25 with bandwidth.")
    print("  It is the weakest number in the table and every dollar inherits it.")
    print("  rent is vast.ai's verified-host median; own is capex over "
          f"{cfg.amortisation_years:.0f} years plus power and hosting.")


def report_sensitivity(cfg: Config):
    sku = SKUS[0]
    print(f"\nSensitivity on {sku.name}. One assumption moves per row.")
    print(f"  {'assumption':<50}{'cards':>7}{'$/yr rent':>11}")
    print("  " + "-" * 68)

    def row(label, c):
        r = price(c, sku)
        cards = "chunk > epoch" if r["cards"] is math.inf else f"{r['cards']:.0f}"
        print(f"  {label:<50}{cards:>7}{money(r.get('rent_year', math.inf)):>11}")

    row("baseline", cfg)
    for chunks in (2, 8, 16):
        row(f"committee proof in {chunks} chunks", replace(cfg, chunks=chunks))
    row("two warm provers a card", replace(cfg, pack=2))
    for v in (500_000, 2_000_000):
        row(f"{v:,} active validators",
            replace(cfg, epoch=replace(cfg.epoch, validators=v)))
    row("one spare card", replace(cfg, redundancy=1))
    print("\n  Validator count is the axis that matters, because the committee")
    print("  proof is linear in it and everything else is not.")


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--report", default="all",
                    choices=["all", "workload", "chunks", "packing", "skus", "sensitivity"])
    ap.add_argument("--validators", type=float, default=1_050_000)
    ap.add_argument("--chunks", type=int, default=4)
    ap.add_argument("--pack", type=int, default=1,
                    help="warm provers per card; 2 fits an RTX 5090 at 1.2x aggregate")
    ap.add_argument("--deadline-cards", type=int, default=1,
                    help="cards the streaming schedule needs; see the Rust test")
    ap.add_argument("--redundancy", type=int, default=0)
    args = ap.parse_args()

    cfg = Config(
        epoch=Epoch(validators=args.validators),
        chunks=args.chunks,
        pack=args.pack,
        deadline_cards=args.deadline_cards,
        redundancy=args.redundancy,
    )
    for name, fn in (("workload", report_workload), ("chunks", report_chunks),
                     ("packing", report_packing), ("skus", report_skus),
                     ("sensitivity", report_sensitivity)):
        if args.report in ("all", name):
            fn(cfg)
    print()


if __name__ == "__main__":
    main()

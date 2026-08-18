#!/usr/bin/env python3
"""How many GPUs zkasper needs, and what they cost.

Earlier sizing divided an epoch's total cost by an epoch's length and called the
answer one GPU. That is the wrong question. Proving an epoch is not a batch job:
a group proof cannot start before the blocks it covers have been published, and
the running aggregate has to be complete before the proof that crosses the
threshold can start. The fleet is sized by concurrency under arrival times, and
on the measured schedule that is four cards rather than one.

Three facts out of Zisk's source fix the shape, and between them they make the
sizing question a single number:

  proofman.rs      `computing: Mutex<()>`, "Serializes proof-generation entry
                   points" — one process proves one thing at a time.
  proof_ctx.rs     a prover sizes itself to the free VRAM on its card. The
                   ~30 GB prover.rs records is a 32.6 GB card being filled, not
                   a requirement; the minimum is about 18 GB, so one card holds
                   one prover and cross-process sharing exits(1) anyway.
  emu.rs           the program cache is a HashMap and `prove` takes the program
                   per call, so a prover is not pinned to one guest ELF.

So **GPU count = peak concurrent proofs**, and everything here is in service of
computing that honestly.

  1. `epoch_jobs`   the proof DAG for one epoch: cost, arrival time, dependency
  2. `simulate`     run that DAG on a fleet, proofs on one card sharing it
  3. `card_curve`   T2 - T as a function of card count, which is what sizes it
  4. `price`        cards -> dollars, rented and owned

Everything the model does not know is a flag; run `--help`. Every constant is
labelled MEASURED (a timed run or `scripts/bench.py`), QUOTED (a vendor or
marketplace price), SOURCE-DERIVED (read out of Zisk rather than run) or
MODELLED (computed here).

The two numbers to re-run this with when they land are the per-proof floor,
which dominates everything, and how much of a card a single warm prover keeps
busy, which decides whether VRAM is worth buying. See technical/gpu-fleet.md in
the PM repo.
"""
from __future__ import annotations

import argparse
import json
import math
from dataclasses import dataclass, field, replace

# ---------------------------------------------------------------------------
# Measured constants
# ---------------------------------------------------------------------------

# MEASURED, zisk v1.0.0-alpha, `python3 scripts/bench.py`. Cost units are trace
# area and are hardware-independent; see BENCHMARKS.md.
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
    "decompress": 49_311,
    # SOURCE-DERIVED, superseding the 293,601,280 that emu_costs.rs models and
    # `ziskemu -X` prints as BASE. That constant encodes ROM at 2^21 and three
    # table AIRs; the shipped v1.0.0-alpha proving key has ROM at 2^22 and two,
    # and reconstructing the key's actual AIR set gives ~789M cells. Nothing in
    # the prover ever read the old number, which is why it survived.
    #
    # This is not a free 2.7x, because the throughput below was fitted by
    # regressing wall time on VARIABLE cost alone (see fit_gpu_bench.py), so
    # floor and rate are separately identified: a bigger floor is bigger in
    # seconds too. At the measured rate the floor alone is 11.7s of every proof.
    # A GPU agent is fitting both on hardware; `--proof-floor` overrides.
    "proof_base": 789_000_000,
    "proof_base_emulator_model": 293_601_280,
    # MEASURED, per active validator, 5-bit-plane swap-or-not over 90 rounds.
    "shuffle_per_validator": 49_116,
}

ACC_DEPTH = 22
DEDUP_DEPTH = ACC_DEPTH - 8
SLOTS_PER_EPOCH = 32
SECONDS_PER_SLOT = 12
EPOCH_SECONDS = SLOTS_PER_EPOCH * SECONDS_PER_SLOT  # 384
EPOCHS_PER_YEAR = 365.25 * 24 * 3600 / EPOCH_SECONDS  # MODELLED, 82,152

# MEASURED, RTX 5090 against Zisk 1.0.0-alpha.
RTX5090_UNITS_PER_S = 67_452_592
RTX5090_VRAM_GB = 32.6
WARM_OVERHEAD_S = 0.5       # MEASURED, per-proof fixed cost on a warm prover
COLD_OVERHEAD_S = 19.52     # MEASURED, process startup + GPU allocation
WRAP_COMPRESSION_S = 0.192  # MEASURED, `cargo-zisk wrap --minimal -g`

# MEASURED, epoch 430529 as `streaming::plan` schedules it.
EPOCH_430529 = {
    "active_validators": 960_974,
    "participation": 0.997,
    "aggregates": 115,
    "groups": [37, 15, 10, 2, 1, 3, 1],      # units per group
    "group_last_slot": [10, 15, 18, 19, 20, 21, 22],
    "crossing_slot": 22,
    "tail_attesters": 26_813,
    "attesting_fraction": 0.716,
}

PROPAGATION_S = 2.0  # ASSUMED, block to a well-connected node


# ---------------------------------------------------------------------------
# Cost of the pieces
# ---------------------------------------------------------------------------

def batched_nodes(num_leaves: float, depth: int = ACC_DEPTH) -> float:
    """Internal compressions a multi-proof over `num_leaves` random leaves needs."""
    capacity = 2 ** depth
    total = 0.0
    for k in range(1, depth + 1):
        total += 2 ** (depth - k) * (1 - (1 - 2 ** k / capacity) ** num_leaves)
    return total


def accumulator(attesters: float) -> float:
    return attesters * COST["acc_leaf"] + batched_nodes(attesters) * COST["acc_node"]


def dedup_open(indices: float) -> float:
    leaves = 2 ** DEDUP_DEPTH * (1 - (1 - 2 ** -DEDUP_DEPTH) ** indices)
    return (leaves + batched_nodes(leaves, DEDUP_DEPTH)) * COST["acc_node"]


def attestation_work(attesters: float, aggregates: int) -> float:
    """Everything an attestation set costs short of the final exponentiation."""
    return (
        accumulator(attesters)
        + attesters * COST["g1_add"]
        + aggregates * COST["hash_to_curve"]
        + COST["miller_batch"]
        + (aggregates + 1) * COST["miller_pair"]
        + COST["g2_subgroup"]
    )


# ---------------------------------------------------------------------------
# The job DAG
# ---------------------------------------------------------------------------

@dataclass
class Job:
    name: str
    program: str          # which guest ELF; drives the specialised-fleet count
    cost: float           # cost units
    ready: float          # earliest start, seconds from epoch start
    deps: list = field(default_factory=list)
    critical: bool = False   # after T, so a faster card shortens the product claim
    splittable: bool = False  # can be cut into independent sub-proofs

    def seconds(self, units_per_s: float, overhead: float) -> float:
        return overhead + self.cost / units_per_s


def fold_chain(jobs: list, groups: list, fold_cost: float, cfg: "Config") -> str | None:
    """Fold the group proofs into one running aggregate.

    Two shapes. A chain is what `aggregation-guest` does today: each fold takes
    the previous aggregate and one more group, so N groups cost N folds in
    series. That is fine when a fold is cheap and ruinous when it is not — at a
    789M floor a fold is 11.7s of GPU on its own, and six of them in series is
    73 seconds that cannot overlap with anything.

    A tree folds pairs instead, so the depth is log2(N) rather than N: the same
    number of proofs, most of them concurrent. It needs the aggregate guest to
    verify two aggregates rather than an aggregate and a group, which is the
    same recursion it already does.
    """
    if not groups:
        return None
    if not cfg.fold_tree:
        prev = None
        for name, ready in groups:
            fold = f"fold_{name.split('_')[1]}"
            jobs.append(Job(fold, "aggregate", fold_cost, ready=ready,
                            deps=[name] + ([prev] if prev else [])))
            prev = fold
        return prev

    level = list(groups)
    depth = 0
    while len(level) > 1:
        nxt = []
        for k in range(0, len(level), 2):
            pair = level[k:k + 2]
            if len(pair) == 1:
                nxt.append(pair[0])
                continue
            name = f"fold_{depth}_{k // 2}"
            jobs.append(Job(name, "aggregate", fold_cost,
                            ready=max(r for _, r in pair),
                            deps=[n for n, _ in pair]))
            nxt.append((name, max(r for _, r in pair)))
        level, depth = nxt, depth + 1
    return level[0][0]


def epoch_jobs(cfg: "Config") -> tuple:
    """The proofs one mainnet epoch needs, and T.

    Structure follows `crates/witness-gen/src/streaming.rs`: groups that shrink
    toward the threshold, a running aggregate folded as each group finishes, and
    one final proof that verifies the marginal aggregate inline.

    T is the arrival of the aggregate that crosses the scheduling threshold —
    the moment the last input to the last proof exists. T2 is when the wrapped
    proof exists. Everything the product claims lives in the gap.
    """
    e = EPOCH_430529
    floor = cfg.proof_floor
    per_slot = e["active_validators"] * e["participation"] / SLOTS_PER_EPOCH
    T = e["crossing_slot"] * SECONDS_PER_SLOT + PROPAGATION_S + cfg.witness_gen_s

    jobs = [Job("epoch_diff", "epoch_diff",
                floor + cfg.mutations * COST["decompress"], ready=0.0)]

    prev_slot = -1
    absorbed = []
    groups = []
    for i, (units, last_slot) in enumerate(zip(e["groups"], e["group_last_slot"])):
        slots = last_slot - prev_slot
        prev_slot = last_slot
        attesters = per_slot * slots
        if last_slot == e["crossing_slot"]:
            # The crossing block also carries the tail aggregate, which the
            # final proof takes inline; do not count those attesters twice.
            attesters = max(per_slot - e["tail_attesters"], 0.0)
        ready = last_slot * SECONDS_PER_SLOT + PROPAGATION_S + cfg.witness_gen_s

        if ready >= T - cfg.absorb_window_s:
            # Too late to be worth its own proof and fold: hand it to the final
            # proof, which pays the attestation work but not a floor or a
            # recursive verification.
            absorbed.append((attesters, units))
            continue

        jobs.append(Job(f"group_{i}", "group",
                        floor + attestation_work(attesters, units),
                        ready=ready, splittable=True))
        groups.append((f"group_{i}", ready))

    fold_cost = floor + COST["fp12_mul"] + COST["commit_fp12"]
    fold_dep = fold_chain(jobs, groups, fold_cost, cfg)

    tail = e["tail_attesters"]
    final_cost = (
        floor
        + attestation_work(tail, 1)
        + dedup_open(tail)
        + COST["final_exp"]
        + (1 + len(e["groups"])) * (COST["fp12_mul"] + COST["commit_fp12"])
        + sum(attestation_work(a, u) for a, u in absorbed)
    )
    # The wrap is not a separate lane. `client.wrap_proof(.., VadcopFinalMinimal)`
    # runs on the same client and reuses pctx, setups, aux_trace, const_pols and
    # const_tree with no additional setup, so whichever process proved
    # stream_final wraps it: one more invocation on the slot already held.
    jobs.append(Job("stream_final", "stream_final",
                    final_cost + WRAP_COMPRESSION_S * RTX5090_UNITS_PER_S,
                    ready=T, deps=[fold_dep] if fold_dep else [], critical=True))
    return jobs, T


def fcr_jobs(cfg: "Config") -> list:
    """The second pipeline: a committee shuffle plus a proof per slot.

    The shuffle for epoch E is fixed at the end of E-2, so it has a whole epoch
    of slack: throughput work, not deadline work, and shardable across lanes.
    The slot proofs are the opposite — a fast confirmation that lands two slots
    late is not a fast confirmation — so each gets one slot to finish in.
    """
    e = EPOCH_430529
    floor = cfg.proof_floor
    jobs = []

    shuffle_total = e["active_validators"] * COST["shuffle_per_validator"]
    for i in range(cfg.shuffle_shards):
        jobs.append(Job(f"shuffle_{i}", "shuffle",
                        floor + shuffle_total / cfg.shuffle_shards, ready=0.0))

    per_slot = e["active_validators"] * e["participation"] / SLOTS_PER_EPOCH
    aggregates = max(1, round(e["aggregates"] / SLOTS_PER_EPOCH))
    slot_cost = floor + attestation_work(per_slot, aggregates) + COST["final_exp"]
    for s in range(SLOTS_PER_EPOCH):
        jobs.append(Job(f"fcr_slot_{s}", "fcr_slot", slot_cost,
                        ready=s * SECONDS_PER_SLOT + PROPAGATION_S + cfg.witness_gen_s,
                        critical=True, splittable=True))
    return jobs


def split_jobs(jobs: list, lanes: int, units_per_s: float, cfg: "Config") -> list:
    """Cut oversized independent proofs into `--split` pieces.

    A group proof is a multi-proof over a set of attesters; nothing stops it
    being two proofs over two halves, folded twice. It costs one extra floor and
    one extra fold per split, and buys latency when a lane is otherwise idle.
    """
    if cfg.split <= 1:
        return jobs
    floor = cfg.proof_floor
    out = []
    for j in jobs:
        if not j.splittable or j.cost < cfg.split_min_cost:
            out.append(j)
            continue
        variable = max(j.cost - floor, 0.0)
        for k in range(cfg.split):
            out.append(replace(j, name=f"{j.name}.{k}",
                               cost=floor + variable / cfg.split))
        # Anything that depended on the whole now depends on every piece.
        for other in jobs:
            if j.name in other.deps:
                other.deps = [d for d in other.deps if d != j.name] + \
                    [f"{j.name}.{k}" for k in range(cfg.split)]
    return out


# ---------------------------------------------------------------------------
# Scheduling
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Card:
    """One physical GPU: how fast it is, how many warm provers fit, and tenancy.

    `slots` is the concurrency the card's VRAM allows, not a promise of that
    much throughput. A Zisk process already fills the card it is given — it
    measures free VRAM at startup and opens as many prover streams as fit — so a
    second process on the same card does not find idle silicon. What extra slots
    buy is the right to have several proofs in flight, which matters for a
    workload that is 20% utilised and bound by arrival times.
    """
    rate: float          # cost units/s for a proof with the card to itself
    slots: int = 1
    spot: bool = False


def simulate(jobs: list, cards: list, overhead: float) -> dict:
    """Run the DAG on a fleet, with proofs on one card sharing its throughput.

    Processor sharing rather than fixed lanes: when two proofs occupy one card
    they each get half of it, and when one of them finishes the other speeds
    back up. That is the honest model of a GPU — the card is one resource — and
    it is what decides whether packing several provers onto a big card is worth
    anything. Fixed-rate lanes would answer yes automatically.

    Placement is highest-level-first: the proof with the most work downstream of
    it goes first. Proofs after T never land on a preemptible card, because
    losing one costs the whole product claim while the work before T has slack
    to absorb a restart — and for the same reason the work before T is sent to
    the preemptible cards by preference, leaving the on-demand ones clear.
    """
    by_name = {j.name: j for j in jobs}
    # A slice of the DAG can reference proofs outside it; drop those edges
    # rather than deadlocking on them.
    jobs = [replace(j, deps=[d for d in j.deps if d in by_name]) for j in jobs]
    by_name = {j.name: j for j in jobs}
    memo = {}

    def downstream(name):
        if name not in memo:
            memo[name] = by_name[name].cost + max(
                [downstream(o.name) for o in jobs if name in o.deps], default=0.0)
        return memo[name]

    order = sorted(cards, key=lambda c: (c.spot, -c.rate))
    unstarted = sorted(jobs, key=lambda j: -downstream(j.name))
    running = {}     # job name -> (card index, cost units left)
    finish = {}
    load = [0] * len(order)
    t = 0.0

    while unstarted or running:
        # Place whatever can start now, hardest job first, fastest free card.
        for j in list(unstarted):
            if j.ready > t + 1e-9 or not all(d in finish for d in j.deps):
                continue
            free = [i for i, c in enumerate(order)
                    if load[i] < c.slots and not (j.critical and c.spot)]
            if not free:
                continue
            # Work before T prefers the preemptible cards, so the on-demand ones
            # stay clear for the proof that cannot afford to be preempted.
            i = min(free, key=lambda i: (not order[i].spot, -order[i].rate)) \
                if not j.critical else free[0]
            running[j.name] = (i, j.cost + overhead * order[i].rate)
            load[i] += 1
            unstarted.remove(j)

        if not running:
            waiting = [j.ready for j in unstarted
                       if j.ready > t and all(d in finish for d in j.deps)]
            if not waiting:
                raise ValueError("nothing runnable and nothing to wait for")
            t = min(waiting)
            continue

        rate = {name: order[i].rate / load[i] for name, (i, _) in running.items()}
        dt = min(left / rate[name] for name, (_, left) in running.items())
        # Stop early if a proof becomes ready before the current one finishes,
        # so it can take an idle slot instead of waiting.
        ahead = [j.ready for j in unstarted
                 if t < j.ready < t + dt and all(d in finish for d in j.deps)]
        if ahead and any(load[i] < c.slots for i, c in enumerate(order)):
            dt = min(ahead) - t

        t += dt
        for name in list(running):
            i, left = running[name]
            left -= rate[name] * dt
            if left <= 1e-6:
                finish[name] = t
                load[i] -= 1
                del running[name]
            else:
                running[name] = (i, left)
    return finish


def latency(jobs: list, cards: list, overhead: float, T: float) -> float:
    """T2 - T: the gap the product sells.

    T2 is when the wrapped proof lands, which is when `stream_final` finishes
    because the wrap runs inside it. On a slice of the DAG that does not contain
    it, T2 is the last finish of anything.
    """
    finish = simulate(jobs, cards, overhead)
    return finish.get("stream_final", max(finish.values())) - T


def slot_latency(jobs: list, cards: list, overhead: float) -> float:
    """Worst confirmation lag on the FCR path: finish minus the block's arrival.

    A fast confirmation is only fast if it lands inside its slot, so this is
    what FCR is sized against, not T2 - T.
    """
    finish = simulate(jobs, cards, overhead)
    lags = [finish[j.name] - j.ready for j in jobs if j.program == "fcr_slot"]
    return max(lags) if lags else 0.0


def card_curve(jobs: list, rate: float, slots: int, overhead: float, T: float,
               cap: int = 16):
    return [(n, latency(jobs, [Card(rate, slots)] * n, overhead, T))
            for n in range(1, cap + 1)]


def min_cards(jobs: list, rate: float, slots: int, overhead: float, T: float,
              budget: float, eps: float = 1.0, cap: int = 16) -> tuple:
    """Fewest cards that meet the latency budget, else fewest at the knee.

    Adding cards stops helping once the schedule is bound by a chain of
    dependent proofs rather than by contention; `eps` is what a marginal card
    has to buy to be worth its price. With FCR in the fleet a card count is only
    enough if it also lands each slot proof inside its slot.
    """
    curve = card_curve(jobs, rate, slots, overhead, T, cap)
    floor = min(v for _, v in curve)
    fcr = any(j.program == "fcr_slot" for j in jobs)
    for n, v in curve:
        ok = v <= budget
        if fcr and ok:
            ok = slot_latency(jobs, [Card(rate, slots)] * n, overhead) <= SECONDS_PER_SLOT
        if ok:
            return n, v, True
    for n, v in curve:
        if v - floor < eps and not fcr:
            return n, v, False
    return curve[-1][0], curve[-1][1], False


# ---------------------------------------------------------------------------
# SKUs
# ---------------------------------------------------------------------------

@dataclass
class Sku:
    name: str
    vram_gb: float          # QUOTED, nominal vendor spec
    bandwidth_gbs: float    # QUOTED, vendor spec
    tdp_w: float            # QUOTED, vendor spec
    buy_usd: float | None   # QUOTED street price, new
    rent_usd_h: float | None    # QUOTED, vast.ai quality-filtered median
    spot_usd_h: float | None = None  # QUOTED, vast.ai interruptible floor
    # MODELLED: STARK proving is memory-bandwidth bound, so throughput is scaled
    # from bandwidth against the one card with a measured Zisk number. Replace
    # with a per-card measurement before spending money on the conclusion.
    scale: float = 1.0
    dlperf: float | None = None  # QUOTED, vast.ai's own index, for cross-check
    note: str = ""

    def units_per_s(self, baseline: float) -> float:
        return baseline * self.scale


# Prices QUOTED, observed 2026-08-18. Rental is the vast.ai median across
# verified hosts with reliability above 95%, which is the tier a service that
# has to stay up can actually use; the marketplace floor is 30-50% lower and
# sits on deverified hosts. `spot` is the vast.ai interruptible floor — fine for
# work that can be restarted, useless for the critical path. Purchase is street
# price for a new card; SXM parts are an 8-GPU baseboard divided by eight and
# cannot be bought singly at all.
#
# `scale` is MODELLED, and it is not the bandwidth ratio. A first pass scaled
# throughput from memory bandwidth and made an H200 2.68x an RTX 5090. Two
# independent measurements say otherwise:
#
#   Ethproofs      Zisk on one RTX 5090 proves an Ethereum block in 69.7s; a
#                  Zisk derivative on one RTX 4090 takes 91.0s, so a 4090 is
#                  ~0.77x — and that derivative is an optimised fork, so stock
#                  Zisk on a 4090 is below 0.77x, not the 0.56x bandwidth says.
#   Surge          8x L40 at 13-14s against 8x RTX 5090 at 10-11s: L40 ~0.78x,
#                  against 0.48x from bandwidth.
#
# The mechanism is in the ISA. Goldilocks modmul is integer-multiply bound, and
# `mad.lo.s32` is 64 results per clock per SM on *every* compute capability from
# 7.5 to 12.1 — Blackwell's "doubled integer throughput" is unified INT/FP
# lanes, which multiply does not benefit from. So throughput tracks SM count
# times clock far more than it tracks HBM, and the HBM parts lose: an H100 has
# 132 SMs at 1.98 GHz against a 5090's 170 at 2.41. These figures blend the two
# ratios 25/75 in favour of integer multiply, which is the blend that reproduces
# both measurements above. They remain MODELLED and every dollar below inherits
# their error.
#
# Corroboration from the market: every active Ethproofs cluster is a 4090 or a
# 5090. There are no A100, H100, L40S or H200 entries at all.
SKUS = [
    Sku("RTX 5090",               32,  1792, 575,  4200, 0.565, 0.107, 1.00, 162,
        "measured baseline; used street $2.9-3.7k"),
    Sku("RTX 4090",               24,  1008, 450,  2899, 0.374, 0.080, 0.72, 96,
        "EOL, resale only; runs Zisk today on Ethproofs"),
    Sku("RTX PRO 6000 Blackwell", 96,  1792, 600, 14900, 1.203, 0.240, 1.14, 283,
        "188 SMs against the 5090's 170; the only non-consumer part above 1.0"),
    Sku("RTX 6000 Ada",           48,   960, 300,  8200, 0.668, None,  0.75, 113,
        "thin supply, 11 machines"),
    Sku("L40S",                   48,   864, 350,  8800, 0.801, None,  0.73, 94,
        "8 hosts on vast.ai — a fleet would exhaust the market"),
    Sku("RTX A6000",              48,   768, 300,  4500, 0.481, None,  0.38, 54,
        "cheapest 48 GB to buy or rent, slowest chip in the set"),
    Sku("RTX 5000 Ada",           32,   576, 250,  5700, 0.434, None,  0.50, None,
        "3 machines on vast.ai — not obtainable at fleet scale"),
    Sku("A100 80GB SXM",          80,  2039, 400, 11100, 1.281, None,  0.45, 129,
        "108 SMs at 1.41 GHz; HBM it cannot use, HGX baseboard only"),
    Sku("H100 80GB SXM",          80,  3350, 700, 24875, 3.068, 0.285, 0.76, 301,
        "HGX baseboard only; FP64 silicon this workload never touches"),
    Sku("H200 141GB SXM",        141,  4800, 700, 26500, 4.047, 0.403, 0.79, 455,
        "same GH100 as the H100 with more HBM; 9 machines on vast.ai"),
]

SKU_BY_NAME = {s.name: s for s in SKUS}


# ---------------------------------------------------------------------------
# VRAM: how many warm provers fit on a card
# ---------------------------------------------------------------------------

def slots_per_card(sku: Sku, cfg: "Config") -> int:
    """How many warm provers a card has the VRAM for.

    The ~30 GB `prover.rs` records is not a requirement, it is the whole card.
    Zisk measures free VRAM at startup and opens as many prover streams as fit
    (`proof_ctx.rs`), so the same key occupies ~21 GB on a 24 GB card and ~78 GB
    on an H100. Reconstructed for the RTX 5090: 8.13 GB of resident proving key,
    two basic streams at 8.43 GB, three recursive at 1.63 GB — 29.9 GB against
    the ~30 GB observed.

    What binds is the *minimum*: one basic stream plus the key, about 18 GB. A
    32.6 GB card therefore holds exactly one prover and cannot hold two, and no
    amount of care changes that — cross-process sharing of the key is refused in
    `starks_api.cu` and would be pointless anyway, since each process loads its
    own copy.

    The 8.43 GB per stream is set by the widest AIR in the key: Keccakf's
    compressor at 7.99 GB and VirtualTableZisk0 at 7.90 GB. zkasper uses
    neither. A proving key built for zkasper's actual AIR set would put the
    minimum near 6-8 GB, which is the difference between one prover per card and
    four. `--min-footprint-gb` is that lever.

    Note what VRAM does buy, which is not packing: a card with more of it runs
    more streams *inside one process* — Zisk's own guidance is one stream per
    ~8 GB — and that is why a 96 GB card beats a 32 GB one of the same die. That
    effect is already inside the `scale` figures, which come from cross-card
    measurements, so it is not counted a second time here.
    """
    if cfg.slots_per_card is not None:
        return max(1, cfg.slots_per_card)
    return max(0, int(sku.vram_gb * cfg.vram_usable // cfg.min_footprint_gb))


# ---------------------------------------------------------------------------
# Fleet and money
# ---------------------------------------------------------------------------

@dataclass
class Config:
    # workload
    mutations: int = 200
    witness_gen_s: float = 1.0
    latency_budget_s: float = 25.0
    shuffle_shards: int = 4
    absorb_window_s: float = 0.0
    fold_tree: bool = False
    split: int = 1
    split_min_cost: float = 1e9
    proof_floor: float = float(COST["proof_base"])
    # prover
    units_per_s: float = RTX5090_UNITS_PER_S
    overhead_s: float = WARM_OVERHEAD_S
    # VRAM. 18 GB is the reconstructed hard minimum for a warm prover against
    # the shipped v1.0.0-alpha key: one basic stream plus the resident key.
    min_footprint_gb: float = 18.0
    vram_usable: float = 0.94
    slots_per_card: int | None = None
    # What fraction of a card one warm prover actually keeps busy. 1.0 says a
    # single prover saturates the SMs, so a second process on the same card only
    # halves both of them and packing buys nothing but scheduling slack. Below
    # 1.0 says the card is idle waiting on something — memory, the host, the
    # `computing` mutex between instances — and a second process is close to
    # free throughput. This one number decides whether the custom-AIR VRAM work
    # is worth three to five weeks, and it is being measured.
    saturation: float = 1.0
    include_fcr: bool = False
    redundancy: int = 0
    # money
    power_usd_kwh: float = 0.12            # QUOTED, US commercial average
    pue: float = 1.4                       # ASSUMED, colo overhead
    amortisation_years: float = 3.0
    hosting_usd_card_month: float = 120.0  # QUOTED, typical colo per-GPU slot


@dataclass
class Fleet:
    sku: str
    lanes: int
    cards: float
    per_card: int
    t2_minus_t: float
    met: bool
    shape: dict
    usd_epoch_rent: float
    usd_year_rent: float
    usd_year_own: float
    utilisation: float


def card_requirement(cfg: Config, jobs: list, T: float, rate: float, slots: int):
    """Cards the schedule needs.

    There is one pool and it is fungible. A warm prover is not pinned to a
    program: the cache is `HashMap<ProgramId, Arc<ZiskRom>>`, `prove` takes the
    program per call, and switching costs a `fs::metadata` and a 32-byte read
    with nothing device-side. What a process cannot do is prove two things at
    once — `proofman.rs` holds `computing: Mutex<()>`, "Serializes
    proof-generation entry points" — so the fleet is sized by peak concurrent
    proofs and by nothing else.
    """
    cards, lat, met = min_cards(jobs, rate, slots, cfg.overhead_s, T,
                                cfg.latency_budget_s)
    return cards, lat, met, {"pool": cards}


def price(cfg: Config, sku: Sku, jobs: list, T: float) -> Fleet:
    """Cards and dollars for one SKU.

    VRAM sets how many warm provers a card *can* hold; it does not follow that
    it should hold that many, because proofs sharing a card share its
    throughput. So the packing density is searched: for each density from one
    prover per card up to what fits, find the card count that meets the target
    and keep the cheapest fleet that gets there.
    """
    rate = sku.units_per_s(cfg.units_per_s)
    max_slots = slots_per_card(sku, cfg)
    if max_slots == 0:
        return Fleet(sku.name, 0, math.inf, 0, math.inf, False, {},
                     math.inf, math.inf, math.inf, 0.0)

    best = None
    for slots in range(1, max_slots + 1):
        # k provers on one card deliver min(k * saturation, 1) of it between
        # them, so each gets that divided by k.
        per_prover = rate * min(slots * cfg.saturation, 1.0) / slots
        cards, lat, met, shape = card_requirement(cfg, jobs, T, per_prover, slots)
        cards += cfg.redundancy
        # Meeting the target comes first; after that fewer cards. When nothing
        # meets it, rank by how close it gets rather than by how cheap it is —
        # a fleet that misses by twenty minutes is not a cheaper fleet.
        key = (0, cards, lat) if met else (1, lat, cards)
        if best is None or key < best[0]:
            best = (key, slots, cards, lat, met, shape)
    _, slots, cards, lat, met, shape = best

    busy = sum(j.cost for j in jobs) / rate + len(jobs) * cfg.overhead_s
    util = busy / (cards * EPOCH_SECONDS) if cards else 0.0

    if sku.rent_usd_h is None:
        rent_year = rent_epoch = math.inf
    else:
        rent_year = cards * sku.rent_usd_h * 24 * 365.25
        rent_epoch = rent_year / EPOCHS_PER_YEAR

    own_year = (
        cards * sku.buy_usd / cfg.amortisation_years
        + cards * sku.tdp_w / 1000 * cfg.pue * 24 * 365.25 * cfg.power_usd_kwh
        + cards * cfg.hosting_usd_card_month * 12
    ) if sku.buy_usd is not None else math.inf

    return Fleet(sku.name, cards * slots, cards, slots, lat, met, shape,
                 rent_epoch, rent_year, own_year, util)


def build(cfg: Config) -> tuple:
    jobs, T = epoch_jobs(cfg)
    if cfg.include_fcr:
        jobs = jobs + fcr_jobs(cfg)
    jobs = split_jobs(jobs, 0, cfg.units_per_s, cfg)
    return jobs, T


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

def money(x):
    if x is math.inf:
        return "n/a"
    if x < 0:
        return "-" + money(-x)
    if x >= 1000:
        return f"${x:,.0f}"
    if x >= 1:
        return f"${x:,.2f}"
    return f"${x:.4f}"


def report_workload(cfg: Config, jobs: list, T: float):
    ups = cfg.units_per_s
    total = sum(j.cost for j in jobs)
    serial = total / ups + len(jobs) * cfg.overhead_s
    print(f"\nOne epoch: {len(jobs)} proofs, {total / 1e9:,.2f}B cost units, "
          f"T = {T:.0f}s")
    print(f"  end to end on a single warm RTX 5090: {serial:,.0f}s "
          f"({serial / EPOCH_SECONDS * 100:.0f}% of the {EPOCH_SECONDS}s epoch)")
    print(f"\n  {'proof':<16}{'cost':>10}{'runs':>8}{'ready at':>10}{'alone by':>10}")
    for j in sorted(jobs, key=lambda j: (j.ready, j.name)):
        run = j.seconds(ups, cfg.overhead_s)
        print(f"  {j.name:<16}{j.cost / 1e9:>9,.2f}B{run:>7.1f}s{j.ready:>9.0f}s"
              f"{j.ready + run:>9.0f}s")

    late = [(j.name, j.ready + j.seconds(ups, cfg.overhead_s) - T)
            for j in jobs if not j.critical
            and j.ready + j.seconds(ups, cfg.overhead_s) > T]
    if late:
        print("\n  Proofs that cannot be finished by T even alone on an idle card.")
        print("  Buying GPUs does not fix these; only the schedule does.")
        for name, over in late:
            print(f"    {name:<16} finishes {over:,.1f}s after T")


def report_cards(cfg: Config, jobs: list, T: float):
    print("\nT2 - T against card count, RTX 5090, one warm prover each")
    rate = cfg.units_per_s
    curve = card_curve(jobs, rate, 1, cfg.overhead_s, T, cap=10)
    best = min(v for _, v in curve)
    for n, v in curve:
        gain = "" if n == 1 else f"  ({curve[n - 2][1] - v:+.1f}s)"
        knee = abs(v - best) < 1.0 and (n == 1 or curve[n - 2][1] - best >= 1.0)
        print(f"  {n:>2} card{'s' if n > 1 else ' '}   T2-T = {v:>6.1f}s{gain}"
              f"{'  <- knee' if knee else ''}")
    print(f"  floor however many cards you buy: {best:.1f}s")
    print("\n  One process proves one thing at a time — proofman holds")
    print("  `computing: Mutex<()>`, \"Serializes proof-generation entry points\" —")
    print("  and a 32.6 GB card holds one process. So this axis is literally")
    print("  peak concurrent proofs, and it is the whole fleet-sizing question.")


def report_skus(cfg: Config, jobs: list, T: float):
    print(f"\n{'SKU':<26}{'VRAM':>6}{'BW':>7}{'scale':>7}{'/card':>6}{'cards':>6}"
          f"{'T2-T':>8}{'$/epoch':>10}{'$/yr rent':>11}{'$/yr own':>10}{'util':>6}")
    print("-" * 104)
    rows = []
    for sku in SKUS:
        r = price(cfg, sku, jobs, T)
        rows.append(r)
        cards = "—" if r.cards is math.inf else f"{r.cards:.0f}"
        lat = "—" if r.t2_minus_t is math.inf else f"{r.t2_minus_t:.1f}s"
        print(f"{r.sku:<26}{sku.vram_gb:>5.0f}G{sku.bandwidth_gbs:>7.0f}"
              f"{sku.scale:>7.2f}{r.per_card:>6}{cards:>6}{lat:>8}"
              f"{money(r.usd_epoch_rent):>10}{money(r.usd_year_rent):>11}"
              f"{money(r.usd_year_own):>10}{r.utilisation * 100:>5.0f}%")
    print("\n  scale is MODELLED: SM count x clock blended 75/25 with bandwidth,")
    print("  calibrated against Ethproofs 5090-vs-4090 and Surge 5090-vs-L40. It")
    print("  is the weakest number in the table and every dollar inherits it.")
    print(f"  /card is how many warm provers the model chose to run on each card.")
    print(f"  rent is vast.ai's verified-host median; own is capex over "
          f"{cfg.amortisation_years:.0f} years plus power and hosting.")
    print(f"  Budget is {cfg.latency_budget_s:.0f}s; a card missing it is not a"
          " candidate at any price.")
    return rows


def report_vram(cfg: Config):
    """What a smaller per-prover footprint would be worth.

    The 8.43 GB a prover stream takes is set by the widest AIR in the shipped
    proving key — Keccakf's compressor at 7.99 GB, VirtualTableZisk0 at 7.90 GB
    — and zkasper uses neither. A key built for zkasper's AIR set would put the
    minimum near 6-8 GB instead of 18, which is the difference between one warm
    prover per card and four.
    """
    show = ["RTX 5090", "RTX PRO 6000 Blackwell", "A100 80GB SXM",
            "H100 80GB SXM", "H200 141GB SXM"]
    print("\nPer-prover VRAM: how many warm provers a card holds")
    print(f"\n  {'minimum GB':<12}" + "".join(f"{n.split()[0] + ' ' + n.split()[1]:>22}"
                                              for n in show) + "   note")
    print("  " + "-" * 145)
    for gb, note in ((18.0, "shipped key, reconstructed"),
                     (12.0, "partial AIR trim"),
                     (8.0, "zkasper-specific AIR config"),
                     (6.0, "aggressive AIR config")):
        c = replace(cfg, min_footprint_gb=gb, slots_per_card=None)
        jobs, T = build(c)
        cells = ""
        for name in show:
            sku = SKU_BY_NAME[name]
            r = price(c, sku, jobs, T)
            fit = slots_per_card(sku, c)
            cells += f"{f'fits {fit}, buy {r.cards:.0f}: {money(r.usd_year_rent)}':>22}"
        print(f"  {gb:>9.0f}G  {cells}   {note}")
    print("\n  Cell is how many provers the VRAM allows, how many cards the")
    print("  schedule then needs, and the annual rental. Fitting more provers on")
    print("  a card only helps where the card was idle waiting on arrivals — the")
    print("  proofs on one card share its throughput, they do not multiply it.")

    print("\n  What the custom-AIR VRAM work is worth, against the one number that")
    print("  decides it: how much of a card a single warm prover keeps busy.")
    print(f"\n  {'saturation':<12}{'18 GB minimum (today)':>28}{'8 GB minimum (custom AIR)':>30}"
          f"{'saved':>10}")
    print("  " + "-" * 80)
    for sat in (1.0, 0.75, 0.5, 0.33):
        line = []
        for gb in (18.0, 8.0):
            c = replace(cfg, min_footprint_gb=gb, slots_per_card=None, saturation=sat)
            jobs, T = build(c)
            rows = [r for r in (price(c, sk, jobs, T) for sk in SKUS)
                    if r.cards is not math.inf]
            fit = [r for r in rows if r.met] or rows
            best = min(fit, key=lambda r: r.usd_year_rent)
            line.append(best)
        print(f"  {sat:<12}{f'{line[0].cards:.0f}x {line[0].sku}, {money(line[0].usd_year_rent)}':>28}"
              f"{f'{line[1].cards:.0f}x {line[1].sku}, {money(line[1].usd_year_rent)}':>30}"
              f"{money(line[0].usd_year_rent - line[1].usd_year_rent):>10}")
    print("\n  At saturation 1.0 the work is worth nothing to the fleet: proofs on")
    print("  one card share it, so more slots never reduce the card count. It only")
    print("  pays where a single prover leaves the card idle.")


def report_mixed(cfg: Config, jobs: list, T: float):
    """Fast on-demand cards where the deadline is, cheap ones everywhere else.

    Only `stream_final` runs after T, so only it shortens the product claim by
    going faster. Every group proof has between one and two minutes of slack.
    Two ways to spend that:

      cheaper silicon   an older card for the bulk work
      cheaper tenancy   the same card interruptible, which is 5x less on
                        vast.ai. A preempted group proof loses time and nothing
                        else, and time is what it has spare — provided the
                        critical path never lands on a preemptible card.

    Priced by running the whole DAG on the mixed fleet rather than by pricing
    two fleets and adding them, because a slow card that picks up a group proof
    it cannot finish by T pushes the fold chain out and lands back on T2 - T.
    """
    print("\nMixed fleet: on-demand where the deadline is, cheap or interruptible")
    print("  for the group proofs, which have slack.")
    fast = SKU_BY_NAME["RTX 5090"]
    ref = price(cfg, fast, jobs, T)
    print(f"\n  all-{fast.name} on demand: {ref.cards:.0f} cards, "
          f"T2-T {ref.t2_minus_t:.1f}s, {money(ref.usd_year_rent)}/yr")

    def cost(card, n, attr):
        if not n:
            return 0.0, 0.0
        rate = getattr(card, attr)
        rent = math.inf if rate is None else n * rate * 24 * 365.25
        own = (n * card.buy_usd / cfg.amortisation_years
               + n * card.tdp_w / 1000 * cfg.pue * 24 * 365.25 * cfg.power_usd_kwh
               + n * cfg.hosting_usd_card_month * 12)
        return rent, own

    print(f"\n  {'mix':<46}{'T2-T':>8}{'$/yr rent':>11}{'$/yr own':>10}{'saving':>9}")
    print("  " + "-" * 84)
    rows = []
    for cheap in SKUS:
        slots = slots_per_card(cheap, cfg)
        if slots == 0:
            continue
        for tier, attr in (("on demand", "rent_usd_h"), ("spot", "spot_usd_h")):
            if getattr(cheap, attr) is None:
                continue
            for n_fast in (1, 2):
                for n_cheap in range(0, 20):
                    fleet = [Card(fast.units_per_s(cfg.units_per_s),
                                  slots_per_card(fast, cfg))] * n_fast \
                        + [Card(cheap.units_per_s(cfg.units_per_s), slots,
                                tier == "spot")] * n_cheap
                    lat = latency(jobs, fleet, cfg.overhead_s, T)
                    if lat > ref.t2_minus_t + 0.5:
                        continue
                    f_rent, f_own = cost(fast, n_fast, "rent_usd_h")
                    b_rent, b_own = cost(cheap, n_cheap, attr)
                    label = f"{n_fast}x {fast.name}"
                    if n_cheap:
                        label += f" + {n_cheap}x {cheap.name} {tier}"
                    rows.append((label, lat, f_rent + b_rent, f_own + b_own))
                    break
                else:
                    continue
                break
    seen = set()
    for label, lat, rent, own in sorted(rows, key=lambda r: r[2]):
        if label in seen:
            continue
        seen.add(label)
        saving = ref.usd_year_rent - rent
        print(f"  {label:<46}{lat:>7.1f}s{money(rent):>11}{money(own):>10}"
              f"{money(saving) if abs(saving) > 1 else '—':>9}")
    return rows


def report_fcr(cfg: Config):
    """The second pipeline, sized on its own deadline rather than on T2 - T.

    FCR sells a confirmation inside one slot, so what it is sized against is the
    lag between a block arriving and its proof existing — 12 seconds, not the 30
    the finality path gets. The committee shuffle is the opposite: fixed two
    epochs ahead, pure throughput, shards freely.
    """
    e = EPOCH_430529
    shuffle = e["active_validators"] * COST["shuffle_per_validator"]
    ups = cfg.units_per_s
    print("\nFCR: committee shuffle plus one proof per slot")
    print(f"  shuffle, whole epoch      {shuffle / 1e9:>8,.2f}B  {shuffle / ups:>7,.0f}s"
          f"   {shuffle / ups / EPOCH_SECONDS:.2f} cards held continuously")

    c = replace(cfg, include_fcr=True)
    jobs, T = build(c)
    one = [j for j in jobs if j.program == "fcr_slot"][0]
    run = one.seconds(ups, cfg.overhead_s)
    print(f"  one slot proof            {one.cost / 1e9:>8,.2f}B  {run:>7,.1f}s"
          f"   against a {SECONDS_PER_SLOT}s slot")
    if run > SECONDS_PER_SLOT:
        print(f"  A slot proof outlasts its slot, so no card count reaches the 12s")
        print(f"  target: the proof has to be split, and --split does that.")

    for label, cc in (("as scheduled", c), ("split four ways", replace(c, split=4))):
        jj, TT = build(cc)
        print(f"\n  {label}:")
        print(f"  {'cards':>6}{'worst slot lag':>16}{'finality T2-T':>16}")
        for n in (4, 6, 8, 10, 12, 16, 20):
            fleet = [Card(ups, 1)] * n
            print(f"  {n:>6}{slot_latency(jj, fleet, cfg.overhead_s):>15.1f}s"
                  f"{latency(jj, fleet, cfg.overhead_s, TT):>15.1f}s")


def report_sensitivity(cfg: Config, sku_name="RTX 5090"):
    sku = SKU_BY_NAME[sku_name]
    print(f"\nSensitivity on {sku_name}. One assumption moves per row.")
    print(f"  {'assumption':<46}{'cards':>6}{'T2-T':>8}{'$/yr rent':>11}")
    print("  " + "-" * 71)

    def row(label, c):
        jobs, T = build(c)
        r = price(c, sku, jobs, T)
        cards = "—" if r.cards is math.inf else f"{r.cards:.0f}"
        lat = "—" if r.t2_minus_t is math.inf else f"{r.t2_minus_t:.1f}s"
        print(f"  {label:<46}{cards:>6}{lat:>8}{money(r.usd_year_rent):>11}")

    row("baseline", cfg)
    row(f"floor {COST['proof_base_emulator_model'] / 1e6:,.0f}M, the old emulator model",
        replace(cfg, proof_floor=float(COST["proof_base_emulator_model"])))
    for m, label in ((0.5, "half"), (2.0, "double")):
        row(f"per-proof floor {label} ({COST['proof_base'] * m / 1e6:,.0f}M)",
            replace(cfg, proof_floor=COST["proof_base"] * m))
    for m, label in ((0.5, "half"), (2.0, "double")):
        row(f"GPU throughput {label} of measured",
            replace(cfg, units_per_s=cfg.units_per_s * m))
    for gb in (12.0, 8.0):
        row(f"per-prover minimum {gb:.0f} GB (custom AIR config)",
            replace(cfg, min_footprint_gb=gb))
    for sat in (0.75, 0.5):
        row(f"one prover keeps only {sat:.0%} of a card busy",
            replace(cfg, saturation=sat))
        row(f"  ...and per-prover minimum 8 GB",
            replace(cfg, saturation=sat, min_footprint_gb=8.0))
    row("cold prover, 19.52s per proof", replace(cfg, overhead_s=COLD_OVERHEAD_S))
    row("group proofs split in two", replace(cfg, split=2))
    row("group proofs split in four", replace(cfg, split=4))
    row("group proofs split in eight", replace(cfg, split=8))
    row("folds as a tree instead of a chain", replace(cfg, fold_tree=True))
    row("fold tree and groups split in two",
        replace(cfg, fold_tree=True, split=2))
    row("late groups absorbed into the final proof",
        replace(cfg, absorb_window_s=SECONDS_PER_SLOT * 1.5))
    row("both pipelines (finality + FCR)", replace(cfg, include_fcr=True))
    row("both pipelines, split four ways",
        replace(cfg, include_fcr=True, split=4))


# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--report", default="all",
                    choices=["all", "workload", "cards", "skus", "vram", "mixed",
                             "fcr", "sensitivity", "json"])
    ap.add_argument("--min-footprint-gb", type=float, default=18.0,
                    help="VRAM one warm prover needs at minimum")
    ap.add_argument("--slots-per-card", type=int, default=None,
                    help="override: measured warm provers that fit one card")
    ap.add_argument("--saturation", type=float, default=1.0,
                    help="fraction of a card one warm prover keeps busy")
    ap.add_argument("--units-per-s", type=float, default=RTX5090_UNITS_PER_S)
    ap.add_argument("--overhead-s", type=float, default=WARM_OVERHEAD_S)
    ap.add_argument("--proof-floor", type=float, default=float(COST["proof_base"]),
                    help="cost units every proof pays regardless of workload")
    ap.add_argument("--latency-budget-s", type=float, default=30.0)
    ap.add_argument("--split", type=int, default=1,
                    help="cut each group proof into this many sub-proofs")
    ap.add_argument("--absorb-window-s", type=float, default=0.0,
                    help="groups arriving this close to T go inline into the final proof")
    ap.add_argument("--fold-tree", action="store_true",
                    help="fold group proofs pairwise instead of in a chain")
    ap.add_argument("--fcr", action="store_true", help="include the FCR pipeline")
    ap.add_argument("--redundancy", type=int, default=0)
    args = ap.parse_args()

    cfg = Config(
        min_footprint_gb=args.min_footprint_gb,
        slots_per_card=args.slots_per_card,
        saturation=args.saturation,
        units_per_s=args.units_per_s, overhead_s=args.overhead_s,
        proof_floor=args.proof_floor,
        latency_budget_s=args.latency_budget_s,
        split=args.split, absorb_window_s=args.absorb_window_s,
        fold_tree=args.fold_tree,
        include_fcr=args.fcr, redundancy=args.redundancy,
    )
    jobs, T = build(cfg)

    if args.report == "json":
        print(json.dumps([{
            **{k: (None if v is math.inf else v) for k, v in
               price(cfg, sku, jobs, T).__dict__.items()}
        } for sku in SKUS], indent=2))
        return

    for name, fn in (("workload", lambda: report_workload(cfg, jobs, T)),
                     ("cards", lambda: report_cards(cfg, jobs, T)),
                     ("skus", lambda: report_skus(cfg, jobs, T)),
                     ("vram", lambda: report_vram(cfg)),
                     ("mixed", lambda: report_mixed(cfg, jobs, T)),
                     ("fcr", lambda: report_fcr(cfg)),
                     ("sensitivity", lambda: report_sensitivity(cfg))):
        if args.report in ("all", name):
            fn()
    print()


if __name__ == "__main__":
    main()

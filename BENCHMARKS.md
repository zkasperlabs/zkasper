# Measured costs

Every constant this project predicts with, its value, and the measurement that
produced it.

**All numbers are Zisk v1.1.0-alpha on an RTX 5090, unless a row says
otherwise.** Cost units are a property of the prover, not of zkasper, so re-run
the campaign after any version bump.

Raw data:

- `data/gpu_bench_v1.1.0/` — the v1.1.0-alpha campaign.
- `data/gpu_bench/` — the v1.0.0-alpha campaign. Two constants are still carried
  forward from it, and the attester sweep exists nowhere else.

Reproduce:

```sh
python3 scripts/bench.py --build          # precompile costs, via ziskemu -X
ZISK_BIN=/path/to/other/zisk/bin python3 scripts/bench.py
python3 scripts/fit_gpu_bench.py          # floor and slope, from a proving sweep
python3 scripts/time_model.py             # the seconds model
python3 scripts/committee_bench.py        # one committee strategy, in a minute
```

The toolchain and `ziskos` must match. v1.1.0-alpha changed the guest linker
script (`_global_pointer`, `_init_stack_top`, `_kernel_heap_*`). A guest that is
built against one version and linked by the other fails with undefined symbols.

## Cost units are not comparable across Zisk versions

v1.1.0-alpha re-based `POSEIDON_COST` from `14 * 75` to `14 * 392`, and **392 is
the column count of the Poseidon AIR**. Every v1.1.0-alpha precompile constant
now equals the width of its own AIR — Sha256f 122, Keccakf 3023, ArithEq 90,
ArithEq384 80 — and no v1.0.0-alpha constant did.

The price of a Poseidon2 permutation moved by 5.23x. The work did not move at
all, and three independent checks say so:

- On the same committee fixture, both versions run **exactly** 4,159 `poseidon2`
  calls and 2,016 `bls12_381_curve_add` calls.
- `precompiles/poseidon/` changed by 13 lines between the two tags, and no
  `.pil` file was touched, so the arithmetization is identical.
- On a GPU, a guest that is almost all `poseidon2` proves faster, not slower.

Never compare a cost-unit figure across the two versions. Compare wall clock, or
re-measure.

The correction moves one architectural number. An accumulator node against an
SSZ node was 16.70x in favour of Poseidon2 and is now **4.85x**. The accumulator
is still the right structure, and the margin is a third of what the design was
argued on.

## Precompiles and primitives

`scripts/bench.py` runs each primitive at two iteration counts inside a guest
and subtracts the results, so program setup, input parsing and output commitment
cancel out.

| primitive | cost | steps | precompiles used |
|---|---:|---:|---|
| `syscall_poseidon2` (raw) | 6,463 | 5 | `poseidon2` |
| `acc::compress` — accumulator node | 7,462 | 12 | `poseidon2` |
| `acc::leaf` — one validator | 8,617 | 30 | `poseidon2` |
| `sha256_pair` — one SSZ node | 36,207 | 131 | `sha256` x2 |
| G1 decompress — one public key | 45,349 | 326 | `arith384_mod` |
| G1 add — `add_complete_safe_bls12_381` | 54,241 | 276 | `bls12_381_curve_add` |
| G1 add — raw `syscall_bls12_381_curve_add` | 2,730 | 3 | `bls12_381_curve_add` |
| hash-to-curve G2 | 12,748,974 | 47,416 | Fp2 tower |
| Miller loop, marginal pair | 22,701,833 | | Fp2 tower |
| final exponentiation | 85,147,848 | 224,710 | Fp2 tower |
| Fp12 multiply | 492,687 | 1,486 | Fp2 tower |
| `acc::commit_fp12` | 156,329 | 503 | `poseidon2` |
| G2 subgroup check | 5,565,696 | 19,458 | Fp2 tower |
| pairing check, 2 pairs (`pairing_check_safe`) | 163,974,164 | 465,339 | Fp2 tower |
| `BASE`, the reported per-proof floor | 287,309,824 | | — |

## The time model

`scripts/time_model.py`, mirrored by `ProverModel` in
`crates/witness-gen/src/streaming.rs`. It predicts seconds from the quantities
that drive them, with one rate per work class.

| term | value | what set it |
|---|---:|---|
| stage floor | **3.640 s ± 0.053** | MEASURED — the committee proof over 64 members, 21,680 executed steps, 3 warm proves |
| empty-guest floor | 2.429 s ± 0.040 | MEASURED — 496 steps, thirteen AIRs, 3 warm proves |
| per opened validator | 834.7 us | DERIVED, **v1.0.0-alpha** — the attester sweep OLS slope of 878.2 us ± 6.5, less one internal node |
| per committee member | 101.2 us | DERIVED, **v1.0.0-alpha** — 254 steps and 30,127 units a member, at the rate the same sweep sets |
| per accumulator node | 31.9 us | MEASURED — 7,462 cost units at 233,988,033 units/s |
| Fp2-tower rate | 200,000,000 units/s | FITTED — bracket 162M to 268M |
| ...one distinct message | 0.177 s | hash-to-curve plus a marginal Miller loop, at that rate |
| ...per-proof Miller batch | 0.160 s | the 63 shared squarings plus the G2 subgroup check |
| ...final exponentiation | 0.426 s | once per epoch |
| wrap compression | 0.048 s | MEASURED — six warm wraps, 46 to 52 ms |
| cold penalty | 5.80 s | MEASURED — the two intercepts of the sweep, wall minus `Proof generated` |
| recursive verification | **unmeasured** | a model parameter that defaults to zero |

There is deliberately no per-invocation constant. These are the prover own
`Proof generated` times, and a warm prover pays exactly them.

**Two constants were not re-measured on v1.1.0-alpha.** The attester sweep
cannot be reproduced, because a group-proof witness is now a slot complement:
`gen-test-witness group-proof n` returns the same 728 bytes at every `n`, so
there is nothing to regress against. Under `ziskemu -X` a committee member fell
from 254.0 steps to 208.0, and its price rose from 30,127 units to 36,406. The
work is 18% down and only the price is up. Every constant that was
re-measured improved, so carrying these two forward can only make the schedule
look worse than it is.

### How well the model does

Against the three fixture stages it is fitted on, the worst error is 5.0%:

| stage | model | measured | error |
|---|---:|---:|---:|
| committee proof, 64 members | 3.64 s | 3.64 s ± 0.053 | −0.0% |
| group proof | 3.98 s | 4.19 s ± 0.061 | −5.0% |
| slot proof, own final exponentiation | 4.45 s | 4.51 s ± 0.393 | −1.2% |

Against the group-size sweep, which the model was not shaped for, the worst
error is 6.0% and the model is always conservative. The one exception is the
256-attester point, whose three repeats disagree by 7 s.

### The Fp2-tower rate is the weakest constant

Nothing in the campaign runs BLS at mainnet scale, so the rate is read off
floor-dominated fixtures:

| | rate | why it is wrong |
|---|---:|---|
| slot minus group | 663,293,070 units/s | an in-instance marginal: the second proof fitted in an AIR instance the first already built |
| group minus aggregation stub | 121,351,898 units/s | attributes the whole gap to BLS when part of it is a different AIR set |
| least squares on both | **200,000,000 units/s** | what the model uses |

One sweep over message count closes this. It is the single most valuable
measurement left, after recursive verification.

## The per-proof floor

`ziskemu -X` prints `BASE` from a compile-time constant in the `emu_costs.rs` of
Zisk. Nothing in the prover reads it. It models a ROM and three lookup tables,
and the shipped proving key does not match that model: an empty guest
instantiates thirteen AIRs and 1.45B trace cells, which is 4.93x the area the
constant charges.

Do not correct the constant by that ratio. Measured as time, the floor is only
**1.15x** what the model charges, because padded and constant rows prove about
4.3x faster per cell than `poseidon2` rows. The floor is a time and this project
only ever wanted a time, so the model uses one:

| | value |
|---|---:|
| per-proof floor, prover `Proof generated` | **2.367 s ± 0.049** |
| empty guest, measured direct | 2.429 s ± 0.040 |
| stage floor, what every zkasper stage pays | **3.640 s ± 0.053** |

The 1.21 s between the empty guest and the stage floor is one set of AIRs. A
`poseidon2` guest instantiates them, and an empty guest does not.

### Cost units are not one currency

The clearest result in the campaign is a negative one. On v1.0.0-alpha, the
bench guest at `n = 0` and at `n = 100,000` differ by 83,558,605 cost units and
instantiate the same eleven AIRs. Those 83.6M units bought 0.06 s ± 0.09, which
is indistinguishable from zero.

Non-precompile work is free until it crosses an AIR-instance boundary, and then
it steps. Measured effective throughput spans 18M to 246M units per second
across the guests of one campaign. **No single units-per-second constant
describes this prover**, which is why the model predicts seconds per work class.

The 29-point proving sweep, 3 warm proves each:

| | floor | slope | residual rms |
|---|---:|---:|---:|
| wall clock per `cargo-zisk prove` | 8.168 s ± 0.128 | 238,478,901 ± 2,442,850 units/s | 0.436 s |
| prover own `Proof generated` | **2.367 s ± 0.049** | **233,988,033 ± 895,838 units/s** | 0.166 s |
| ...restricted to one `Main` instance | 2.561 s ± 0.034 | 245,451,826 ± 1,531,944 units/s | 0.084 s |

The slope looks 3.36x better than v1.0.0-alpha and it is not. The `POSEIDON_COST`
re-basing multiplies the cost units of this guest by exactly 2.669 at every one
of the 29 sizes. Only 1.26x of it is throughput. What is unambiguous is the
wall clock on identical work: `n = 10,000` proves in 2.92 s against 5.29 s, and
`n = 1,000,000` in 32.29 s against 107.38 s.

## The warm prover, on a card

Everything above is `cargo-zisk`, one process per proof. This is the same
stages through `ZiskProver` — one `zisk-sdk` `EmbeddedClient`, initialised once
and proving for the life of the process, which is what `zkasper-prover-server`
runs and what the whole streaming design assumes. Until 2026-08-18 it had only
ever been run on a CPU.

RTX 5090, driver 590.48.01, CUDA 12.9.1, Zisk v1.1.0-alpha, vast.ai, 64 vCPU.
Six warm repeats per stage over two independent processes.

```sh
ZKASPER_GPU=1 ZKASPER_REPEATS=3 cargo test --release --features zisk-prover \
  --test zisk_proof_tests -- --ignored --nocapture warm_stage_times
```

| stage | published | warm, in process | |
|---|---:|---:|---:|
| stage floor — committee proof, 64 members | 3.640 s ± 0.053 | **3.262 s ± 0.155** | −10.4% |
| group proof | 4.188 s ± 0.061 | **3.770 s ± 0.093** | −10.0% |
| slot proof | 4.506 s ± 0.393 | **3.822 s ± 0.062** | −15.2% |
| wrap compression | 0.048 s | **0.050 s ± 0.004** (n=18) | +4.6% |

Every stage is faster than the figure the schedule is built on and the wrap is
the same, so `docs/architecture.md` is conservative rather than optimistic.
Only the wrap is like for like: the other three drop the process start and the
device allocation a per-proof `cargo-zisk` pays, which is the point of holding
one client open.

**Three repeats understate the spread.** A third process, set up for two ELFs
rather than three, measured the group proof at 4.140 s — outside the six-sample
range of 3.669 to 3.931 s. Within one process the stages repeat to about 2.5%;
across processes they move about 10%. Quote a ± from repeats in one process and
it will be too tight.

**What initialisation costs, and what the second proof does not pay.**

| | value |
|---|---:|
| `EmbeddedClient::build()`, GPU, constant trees already generated | **14.8 s** |
| ROM setup per guest, cache warm | 37–48 ms |
| ROM setup per guest, cache cold | 1.9–2.2 s |
| one-time `REGENERATING_VADCOP_CONST_POLS` | 7.899 s |
| one-time `REGENERATING_VADCOP_CONST_TREE` | 25.756 s |
| first run on a fresh box, two ELFs, end to end | **57.1 s** |
| a later run on the same box, three ELFs | **16.9 s** |

Nothing is re-initialised between proofs and swapping ELFs is free at this
resolution. Measured as `call − (prove + wrap)` — the client's own native
circuit run, the serialization, and the switch — where every proof follows a
proof of a *different* guest:

| stage | gap |
|---|---:|
| committee | 9–11 ms |
| slot proof | 127–129 ms |
| group | 226–231 ms |

The committee row bounds the ELF switch itself at **under 11 ms**; the other two
are their own native circuits, which open accumulator paths and run BLS. The
same quantity on CPU was 0.36 s.

## Recursive verification

**The single largest cost in the pipeline, and it was carried as zero.**

```sh
./scripts/build_guests.sh committee-proof-guest slot-proof-guest justification-guest
ZKASPER_GPU=1 cargo test --release --features zisk-prover \
  --test zisk_proof_tests -- --ignored --nocapture recursion_cost_curve
```

One justification link per point, over real child proofs, varying how many it
verifies. RTX 5090, driver 580.159.03, CUDA 12.9.1, Zisk v1.1.0-alpha, warm
in-process prover, 2026-08-18.

| children | prove | marginal | fit |
|---:|---:|---:|---:|
| 2 | **105.787 s** | | 109.6 s |
| 3 | **161.345 s** | 55.56 s | 162.7 s |
| 4 | **221.546 s** | 60.20 s | 215.8 s |
| 23 | 1,224 s (mainnet epoch 469424, production) | 52.76 s | 1,224.5 s |

**It is linear, and the intercept is the stage floor.** Least squares over the
four is **3.47 s + 53.087 s a child**, and no point sits more than 5.7 s off it
across a span of 2 to 23 children. The intercept lands on the measured 3.640 s
stage floor, which is the cost model decomposing exactly as it claims to: a
proof is a floor plus its work, and a child is 53 s of work.

Nothing in the shape suggests a fixed cost that many children could amortise,
and nothing suggests it gets worse than linear either. That was the open
question — 1,224/22 divides to 55.6 whether the cost is per child or per proof —
and three points between 2 and 4 settle it: the second child costs the same as
the twenty-third.

### It is `justification-guest`'s price, and the streaming guests charge less

**53.087 s is a per-guest number, and the model spent a day applying it to the
wrong guests.** Every row above is `justification-guest`. The two guests on the
streaming critical path — `aggregation-guest` and `stream-final-guest` — charge
**35.629 s a child**, and the production run measures it directly.

The estimator is the fold that opens an epoch. Its child count is fixed by
construction: `verify_aggregate` takes the `previous == None` branch, which
verifies the epoch diff and the committee proof, and it refuses an empty group
list — so an opening fold that absorbs one group verifies exactly three
children. Its own non-recursion work is the stage floor plus one Fp12 multiply,
4 ms. Twenty-four of them across mainnet epochs 469,486-469,537:

| | value |
|---|---:|
| opening folds measured | 24 |
| children each, by construction | 3 |
| prove time | 107.60 to 111.87 s |
| **per child, floor held at 3.640 s** | **35.629 s, sd 0.326** |
| range | 34.65 to 36.08 s |

**53.087 s is refuted by that table on its own.** At 53.087 s a child, an
opening fold measured at 110.9 s verified 2.00 children. The source requires at
least three. No integer child count reproduces the streaming stages at that
price; at 35.629 s the three- and four-child stages come out at 2.98 and 4.12.

Forty-four stream-final proofs over the same epochs cross-check it: priced at
the folds' 35.629 s a child, and charged the child count the guest source says
they verify, the mean error is **+0.3 s** and the rms 3.8 s.

**The mechanism is not established.** Both guests were measured on the same
class of card — the `recursion_cost_curve` box and the production prover box are
both vast.ai RTX 5090s — so the 1.49x is the guest and not the hardware, and the
production fleet reproduces `justification-guest`'s 53 s itself at epoch 469424.
A child is genuinely not one price, and this document no longer pretends
otherwise. `ProverModel::recursion_verify_s` carries the streaming figure
because that is the pipeline it prices; `catch_up_test` carries the
justification figure because that is the pipeline it prices.

**A recursion costs ten proofs.** Against the 3.640 s stage floor, one recursive
verification in the streaming guests is worth about ten whole proofs of anything
else here: a slot proof is 4.2 s, a committee proof over 64 members is 3.3 s, a
mainnet slot inside a proof already running is about 1 s. Every other constant
in `ProverModel` put together is noise beside it.

**What it inverts.** The model carried it as zero, and a zero implies that
splitting work into more proofs is free. It is the opposite:

- **Children, not proofs, are the cost.** Twenty-two slots proven one at a time
  are twenty-two children — 1,222 s of recursion — where the same slots in two
  groups are two children, 111 s. Grouping is the whole of the saving.
- **A fold buys latency, never throughput.** Absorbing `k` children into a fold
  pays `k + 1` recursions to take `k` off whoever would otherwise have verified
  them. It is worth doing for the children that would otherwise land between `T`
  and `T2`, and never for any other reason.
- **Bounding a proof's child count costs work.** It is still right — a proof
  whose size is the epoch's is a proof that grows with the chain — but it is a
  safety property that is paid for, not a saving.

The measurement is possible at all only because a real prover is behind it. The
fixtures carry stub child proofs, and a guest rejects an empty proof, so every
earlier attempt to measure this had to remove the recursion first and measured
the remainder.

## `T2 - T`

`T` is the moment the chain has published enough attestations to justify a
checkpoint. `T2` is the moment a wrapped proof exists.

```sh
cargo test --release --test ssz_file_tests test_ssz_file_streaming_schedule -- --ignored --nocapture
```

On mainnet epoch 430529, 2,212,730 validators, the schedule needs **two GPUs**
and puts `T2 - T` at **83.1 s**, with the final proof verifying the running
aggregate and the previous epoch's justification and no group at all.

It was **112.4 s** until the inline tail stopped being capped at four slots; see
*the largest remaining win* below, which is now spent.

**Every figure in this section was rewritten on 2026-08-19, and the two errors
that made the old ones look right are worth stating.** The model charged the
final proof one child too few — `final_s` charged `absorbed + 1` on the folded
path where `stream-final-guest` verifies `absorbed + 2`, the third being the
previous epoch's justification, which its own module doc has always called
irreducible — and `recursion_verify_s` carried `justification-guest`'s 53.087 s,
which is 1.49x what the streaming guests charge. The two cancel exactly at three
children:

```
(n - 1) x 53.087  =  n x 35.629      at  n = 3.04
```

The folded path the live run measured has three, so the old model reproduced it
to half a second while being wrong twice. **The shape the `MAX_TAIL` change
moved the pipeline to has two**, where the errors stop cancelling in the
optimistic direction: the old model charged one child, 53.087 s, where the guest
verifies two, 71.3 s. That is the whole of the difference between the withdrawn
67.8 s and today's 83.1 s.

**It was 5.5 s on one GPU until recursion was measured, and that number is
withdrawn.** The model carried `recursion_verify_s` as zero. The final proof of
an epoch verifies two children it cannot avoid — the running aggregate and the
previous epoch's justification — and at 35.629 s those two are 71 s of the
83.1 s. Everything the schedule can actually choose is the remaining 12.

The production run confirms that the cost is **per child**, from the other
direction: a real stream-final proof took **148.2 s over four epochs, within
±1.1 s**, and did not move when its nominal work did — `tail_named` ranged from
54 to 1,319 attesters for the same 148 s. A cost that ignores the work in front
of it is a cost per child.

**The folded path has run, and it is what found the bug.** Mainnet epochs
469,501-469,509, 2026-08-19, are the first with `folded_groups > 0`. Six of them
verify an aggregate, one absorbed group and the previous justification, and their
stream-final proofs are **116.5, 117.2, 118.5, 119.8, 121.2 and 124.2 s** — mean
119.6 s, spread 7.7 s. One folded nothing and took 168.0 s.

Those two shapes differ by exactly one child, and that is what settles it. At
53.087 s and the child count the model charged, the three-child proofs come out
+1.8 s and the four-child proof +13.1 s — an error that grows with the child
count, which is the signature of counting one too few at a price that is too
high. At 35.629 s and the count the guest source states, the same proofs come
out at +0.3 s mean over 44 of them.

The opening folds beside them are the cleaner arbiter, because their child count
is not a matter of reading `late_groups`: `verify_aggregate` verifies the epoch
diff, the committee proof and at least one group, so an opening fold is at least
three children by construction. Twenty-four of them measured 107.6 to 111.9 s.
At 53.087 s that is two children, which the source forbids.

**What did not hold is the daemon's schedule, and `late_groups` is not where it
failed.** The published schedule's own optimum left one group unfolded for the
final proof to absorb — `Final absorbs [1]` in the report as it read then — so
`late_groups = 1` was the plan, and the recursion it costs was already inside the
117.7 s. It is `Final absorbs []` and `late_groups = 0` now; the paragraph is
kept because it is the reasoning the measurement was read against. Absorbing that group is right rather than merely tolerable: folding it
instead costs `stage_floor_s + recursion_verify_s` — 39.3 s — more, and cannot
finish before `T` anyway, because a continuation fold is 74.9 s and the group's
last slot arrives one slot before the crossing. `folding_the_last_group_costs_a_floor_and_a_recursion_more`
pins the arithmetic.

The gap between the model and the measurement is a single term, and it is exact:

```
T2 - T  =  late_group_millis  +  stream_final
162.540 =  41.379             +  121.215
196.299 =  76.574             +  119.776
161.406 =  44.988             +  116.459
179.736 =  61.253             +  118.529
197.534 =  29.538             +  168.048
218.376 =  94.168             +  124.208
162.990 =  45.813             +  117.177
```

The schedule places the absorbed group so that it *finishes* at `T` — `Group(1)`
runs 240.0 s to 253.0 s against a threshold at 252.0 s, one second of overhang.
The daemon *starts* it at `T`, because the trigger is only evaluated on a tick
with no proof in flight, and the tick that fires is therefore the first one after
a 110 s fold. Every slot that arrived during that fold is still unproven when the
trigger fires. **The whole 62 s of median gap is that displacement**, not the
absorption.

**`T` was stamped when the daemon looked, not when the chain crossed — fixed, and
every figure this document published before 2026-08-19 was short by it.** Same
five epochs, same cause: the threshold check sits below the in-flight-proof early
return, so `threshold_unix_millis` landed 0.22-0.33 s after a proof finished on
all five, and 8.4, 15.7, 46.7, 93.0 and 124.7 s after the crossing slot began.
`T` now comes from the chain — the crossing slot's boundary, genesis plus a slot
count — and the daemon's own notice is published beside it as
`observation_millis`. See [the corrected distribution](#the-corrected-distribution).

### The corrected distribution

The 2026-08-19 run published **median 123.0 s, p90 131.6 s** over ten folded
live-gossip epochs. **That number is withdrawn.** It was `T2` minus the tick that
noticed, and the crossing slot of every one of those epochs is recoverable from
the daemon's own logs: each group proof logs the slots it covers, the plan stops
at the unit that crosses, so the crossing slot is one past the last slot any
group covered. `T` is that slot's boundary.

| epoch | crossing slot | observation delay | published `T2 - T` | corrected `T2 - T` |
| --- | --- | --- | --- | --- |
| 469523 | 15024757 | 121.6 | 119.3 | **240.9** |
| 469524 | 15024789 | 153.4 | 123.5 | **276.9** |
| 469525 | 15024821 | 39.6 | 135.2 | **174.8** |
| 469526 | 15024853 | 84.7 | 126.4 | **211.1** |
| 469527 | 15024885 | 110.1 | 122.4 | **232.5** |
| 469528 | 15024917 | 131.0 | 116.8 | **247.8** |
| 469530 | 15024981 | 90.1 | 119.2 | **209.3** |
| 469531 | 15025013 | 105.2 | 118.7 | **223.9** |
| 469532 | 15025045 | 137.4 | 131.6 | **269.0** |
| 469533 | 15025077 | 39.5 | 125.6 | **165.1** |

    median 228.2 s    p90 269.0 s    min 165.1    max 276.9

Recomputed and not re-measured: `proof_unix_millis` is unchanged, and only the
origin moved. The five epochs of the paragraph above reproduce exactly from this
procedure — 8.4, 15.7, 46.7, 93.0, 124.7 — which is what says the crossing slots
are right. Across the 36 epochs of the run the rule resolves, the observation
delay ran a median **99.1 s**, minimum 8.4 s, maximum 549.6 s. The thirty-seventh,
469497, is dropped rather than guessed at: it took a gossip gap and was repaired
from blocks, so one group closed the whole epoch and the crossing is inside it.

**The old number was tight because of the error, not despite it.** Its spread was
18.4 s against a corrected spread of 111.8 s, and its standard deviation 6.0 s
against 36.5 s. The final proof is nearly constant — that is the 117 to 135 s the
run reported — and the observation delay carries essentially all the variance
(sd 38.6 s). Reporting `T2 - T` from the daemon's notice reported the constant
term and subtracted the variable one, which is why it looked reproducible. It is
also anti-correlated with the delay it dropped (r = **-0.42**): the epochs that
published best were, on the whole, the ones the daemon had been blindest on.

**The model is not validated by this, and was not validated by the old number
either.** `schedule` puts `threshold_s` at `arrival` of the crossing unit, and
`arrival(i)` is `(slot_i - first_slot) * seconds_per_slot` — the crossing slot's
boundary, the same origin `T` now uses. The two are finally the same quantity.
Against the 117.7 s model this run was compared with, the corrected median is
**1.94x**, not the 1.045x the run claimed, and the gap is 110.5 s against an
observation delay of 107.7 s over the same ten epochs. Against today's 83.1 s it
is 2.7x, but no daemon has run under that schedule yet. **The whole of the discrepancy between the measured `T2 - T`
and the modelled one is the blind tick.** Nothing about the prover, the recursion
cost or the fold schedule is implicated by it, and none of it was visible while
`T` was stamped where the gap was.

### What sets the observation delay

Not a late stamp. Over the 29 steady-state epochs of the run the prover was busy
for **98.5%** of the window between the chain crossing and the daemon noticing,
and the daemon looked within a median **0.30 s** of the prover coming free. It
was never idle and blind; it was working and blind.

The window splits in two, and only one half is forced:

| | share of the window |
| --- | --- |
| a proof already running when the chain crossed | **56.0%** |
| proofs *started after* it, while the daemon was not looking | **42.5%** |
| prover idle | 1.5% |

The first half cannot be recovered without preempting a proof in flight. **The
second can**: those are proofs the daemon queued because it did not know the
threshold had gone by, and 11 of them were started across 9 of the 29 epochs.
The epochs that queued nothing blind observed the crossing a median **65.5 s**
late; the epochs that queued work blind, **133.3 s**.

**Fixed.** Nine of the ten were the same proof — the fold that `collect` started
the instant a group landed, one arm below the in-flight-proof early return and so
above any evaluation of the trigger. A tick that collects a group now carries on
into the trigger instead of returning, and the fold is started only by the
`!fire` branch; a group that lands on an epoch already holding enough to justify
is held and handed whole to the final proof.

It is not free, and the ledger is worth stating. Losing the fold means losing the
aggregate, and `final_witness` attaches the epoch diff and the committee proof as
children of the final proof whenever there is no aggregate to inherit those links
from — measured at **41.5 s** over the 35 epochs of this run's interleaved window
(157.8 s against 116.3 s). Against a 112 s fold plus the late group it displaces,
the nine epochs net **76 to 130 s each**. Replayed over the run: the observation
delay's median falls **91.1 s to 41.4 s** across the 29, and the corrected
`T2 - T` of the ten published epochs falls **228.2 s to 189.5 s**.

The 41.5 s is the next thing to take, and it is a circuit change rather than a
scheduling one: the final proof could inherit the diff and committee links from
the group it absorbs, as it already does from an aggregate.

**`001b250` did not change this, and could not have.** It moved proving off the
drive loop so the tick returns while a proof runs, which is what it was for and
what it did — the head stays fresh and the next epoch gets speculated. But the
threshold check sits below the early return it introduced, and before it the same
check sat above a *blocking* prove call. Either way the trigger is evaluated
exactly once per proof, immediately after the previous one lands. The mechanism
changed; the cadence did not. No steady-state epoch predates `001b250` in this
run, so the archive cannot measure the difference — the code settles it instead.

**`6eb1302` improved it, despite appearing not to.** Measured against each
daemon's own crossing slot the median observation delay is 75.2 s under `001b250`
and 98.1 s under `6eb1302`. The comparison is invalid: before `6eb1302` the
collector discarded every network aggregate, so the daemon under-counted and
needed a median of **25** slots to reach 2/3 where it now needs **21**. Its
crossing slot was four slots — 48 s — too late, and every delay measured against
it is that much too small. Corrected, `001b250` is 123.2 s against `6eb1302`'s
98.1 s. For the same reason the corrected `T2 - T` of every pre-`6eb1302` epoch
in this document is itself a lower bound; the ten published epochs are all after
it and are unaffected.

One conservatism is left in the anchor and it is small. A slot's attestations do
not exist at its boundary; the crossing slot supplies only the last third of the
quorum, and on 193 slots of mainnet gossip (`arrivals.tsv` from this run) a third
of a slot's attestations are in **2.87 s** after it begins, p90 4.64 s. So `T` is
about 3 s earlier than the instant the chain could first have justified, and
`T2 - T` over-states by that much. The boundary is kept anyway: it is the only
instant here that is a pure function of the chain, it is the origin the schedule
already plans against, and a metric that cannot be exact should err towards
showing the problem rather than hiding it.

**The largest remaining win was inlining, not folding, and it has been taken.**
The slots no fold can reach are cheaper carried inline by the final proof than
proven as a group at all: one group is one recursion, 35.629 s, where eight
mainnet slots of complement work is about seven. The inline tail was capped at
four slots on the pre-recursion reasoning that "a group is one floor either way".
Lifting that cap takes the modelled `T2 - T` on epoch 430529 from **112.4 s to
83.1 s** on the same two cards, with the final proof absorbing nothing —
`lifting_the_tail_cap_is_worth_a_recursion_on_mainnet_430529` prices both shapes
against each other on the real epoch's per-slot numbers, offline.

**The A/B this replaces claimed 112.8 s to 67.8 s, a 45.0 s win.** It is 29.3 s.
The capped shape barely moved — 112.8 to 112.4 — because it leaves a group for
the final proof to absorb, which is the three-child shape where the missing child
and the inflated price cancelled. The uncapped shape has two children and gained
15.3 s when both were fixed. Lifting the cap is still the largest single win
available; it is two thirds of what was published.

The daemon had to change with it: `stream.rs` hardcoded the final proof's tail to
the crossing slot and threw `StreamPlan::tail` away, so the plan's choice never
reached the prover. It reads the plan now, clamped below by what the running
aggregate already covers.

**This is a model, and no prover has run it.** The last GPU exited before the
change was written. What is measured about it is that the schedule reproduces on
real fixture data and that the daemon executes the shape end to end against a
mock node; what is not measured is a stream-final proof over eight inline slots
on a card.

What it is sensitive to — today's model, all at the 4-card budget:

| | `T2 - T` | GPUs |
|---|---:|---:|
| **recursion 35.629 s per child (measured)** | **83.1 s** | **2** |
| recursion 5 s per child | 16.8 s | 2 |
| recursion 1 s per child | 7.5 s | 2 |
| recursion 0 s per child (what the model used to assume) | 5.5 s | 1 |
| stage floor 2.43 s (an empty guest) | 81.9 s | 2 |
| **stage floor 3.64 s (measured)** | **83.1 s** | **2** |
| stage floor 20.00 s | 102.3 s | 2 |
| Fp2-tower rate 162M units/s (the slow bracket) | 84.8 s | 2 |
| Fp2-tower rate 400M units/s (the fast end) | 79.2 s | 2 |

The inline tail is now the largest term the schedule chooses, and the floor moves
it: a 20 s floor puts eleven slots inline and costs 19.2 s over the measured one,
where before the cap it moved `T2 - T` by 17.7 s over the same range without
being able to change the shape.

**Recursion is the whole answer and everything else is rounding.** The stage
floor moves `T2 - T` by 20 s across a ten-fold range; the Fp2-tower rate, which
is the largest *uncertainty* in the model, moves it by 2.7 s across its whole
bracket. One child of recursion is worth more than both together.

**The critical path is two recursions, and one of them need not be there.** The
final proof has to verify the running aggregate — that is what an aggregate is
for. It also verifies the previous epoch's justification, and that proof exists
an epoch early, exactly like the epoch diff and the committee proof, both of
which were already moved into the fold that opens the epoch for this reason.
Moving the third one there would take 36 s off `T2 - T` and is the largest
single latency win available.

**The trigger threshold dominates every prover term.** At 66 to 68% of the stake
the epoch closes on 22 slots and `T2 - T` is 83.1 s. At 69 to 70% it waits for a
23rd slot and pays 99.1 s. The default is 2/3 exactly, which is the rule the
circuit enforces.

**Warm and cold are different products.** The cold penalty is 5.80 s of process
start and GPU allocation per proof. That is what a long-running prover saves,
and it is why `crates/witness-gen/src/prover.rs` takes `&self`.

## The on-chain wrap

MEASURED 2026-08-18 on a rented RTX 5090 box (64 cores, 251 GB RAM, 300 GB disk)
against Zisk **v1.0.0-alpha**, which is the newest release whose SNARK proving
key exists. The guest is a stub that commits its input verbatim, fed the real
176 public bytes of `/v1/proofs/469426`. That substitution is faithful: the wrap
circuits are fixed size and never read the guest, which is why every zkasper
proof is 254,624 bytes whatever stage produced it.

| step | time | output |
| --- | --- | --- |
| `prove`, full VadcopFinal | 689 s | 381,643 bytes |
| `wrap --plonk` | **436 s** | 2,769 bytes: 768 of proof, 1,997 of verifying key and publics |
| `wrap --minimal` | 34 s | 297,790 bytes |
| `wrap --plonk` over a **minimal** proof | fails | `Error generating witness for instance id 0 [0:0] of type RecursiveF` |

**These are CPU numbers.** `cargo-zisk` reported itself as the `[gpu]` build, but
the card held 0% utilisation and 2 MiB of VRAM for the whole run while load
average sat near 48. Treat 436 s as an upper bound; the GPU path is unmeasured.

**A PLONK wrap consumes the uncompressed proof.** `backend.plonk()` builds
`VadcopFinalProof::new(.., compressed: false, ..)` on both v1.0.0-alpha and
v1.1.0-alpha, and the last row above is that in practice. `ZiskProver::prove_input`
compresses to `VadcopFinalMinimal` and returns only the compressed words, so
nothing the pipeline keeps today can be wrapped.

Disk, on the same box:

| | |
| --- | --- |
| `provingKey` download | 3.2 GB, 216 s including const-tree regeneration |
| `provingKey` on disk | 61 GB |
| `provingKeySnark` download | 21.93 GB, 396 s at ~55 MB/s |
| md5 of that tarball | 55 s |
| extraction | 215 s |
| `provingKeySnark` on disk | 26 GB |
| `~/.zisk/cache`, one ELF | 1.5 GB |
| filesystem after the run | **92 GB** |

So about 90 GB of disk and 25 GB of download on top of a working Zisk install,
and roughly 25 minutes of setup on a fast link before the first wrap.

**Neither published SNARK key installs without hand-holding.**
`zisk-provingkey-plonk-1.1.0-alpha.tar.gz` is 660,919 bytes and holds one file,
`provingKeySnark/recursivef/recursivef.dylib` -- a macOS library. Its published
`.md5` matches, so it is not a truncated download. The 1.0.0-alpha key is
complete at 21,932,082,134 bytes, but its `.md5` names
`zisk-provingkey-plonk-pre-1.0.0-alfa.tar.gz`, so `ziskup setup_snark` fails its
own `md5sum -c` every time. The digest is correct; only the filename is stale.

Two operational notes. `cargo-zisk verify` on a PLONK proof shells out to
`snarkjs`, which nothing in the toolchain installs, so verification of the wrap
is not self-contained. And `export-solidity-calldata` emits a 256-byte
`publicValues` on v1.0.0-alpha (the u32 view) against 512 on v1.1.0-alpha (the
u64 view), so the on-chain hash preimage differs between the two releases.

## What one GPU holds

The prover does not allocate what the witness needs. It reads free VRAM at
startup and fills it. Every prove in the campaign logged the same thing on an
idle 32.61 GB RTX 5090, over a 100x span of workload:

```
Minimum free memory available for GPU usage: 30.781128 GB
GPU 0: Allocated 29.347325 GB (28.296217 GB unified + 1.051108 GB const pols)
Pinned host memory per GPU: 2.000000 GB
```

That is greed and not a requirement. Holding VRAM back before the prover starts
shows the allocation tracking what is left:

| held back | free before | prover allocated | `Proof generated` | result |
|---:|---:|---:|---:|---|
| 0 GB | 31.36 GB | 30.14 GB | 12.30 s | ok |
| 8 GB | 22.86 GB | 20.76 GB | 14.50 s | ok |
| 16 GB | 14.86 GB | 12.90 GB | 19.78 s | ok |
| 20 GB | 10.86 GB | — | — | `Not enough GPU memory to run the proof` |

The working minimum is about 14 GB free, and the penalty for running there is
61% on proving time rather than failure. Two provers fit on one GPU if the first
is capped while it starts. Each pays about 1.4 to 1.7x the per-proof latency,
for about 1.2x aggregate throughput. For a latency-bound pipeline that is a poor
trade.

`cargo-zisk prove -m/--minimal-memory` does not change any of this.

**Provisioning.** The proving key reaches **105 GB** after the first setup, and
`~/.zisk/cache` reaches 13 GB for four ELFs. Budget 150 GB of disk. The first
ELF costs 275 s of setup, including a one-time global constant-tree
regeneration, and each further ELF costs 13 to 15 s.

## What the numbers decided

**BLS is the cost, not hashing.** One pairing check costs as much as about
22,000 accumulator nodes. The accumulator multi-proof of a slot is a rounding
error next to one signature check.

**Batch the pairing.** The final exponentiation is paid once per multi-pairing,
whatever the number of pairs. Verifying attestations one at a time pays it every
time, which is 4.36x more for 64 attestations.
`bls::verify_attestation_batch` batches them. The messages must be pairwise
distinct, because a rogue-key attack can cancel one attestation against another.
The circuit enforces that rather than assuming it.

**Batch the proofs.** The per-proof floor is roughly one pairing check, so a
proof that does less work than that is more than half overhead.

**Commit the decompressed public key in the accumulator leaf.** Decompression
then happens once per changed validator in the epoch diff, rather than once per
attester per slot. The leaf grows from 3,460 to 3,979 cost units and 49,311 of
decompression disappears, which is 40.4% off the per-attester cost
(v1.0.0-alpha units). The leaf hash is the binding, so no per-attester curve
validation is needed at all.

**Aggregate with the raw precompile.** `add_complete_safe_bls12_381` re-validates
both operands on every call, and 97% of the call is that wrapper. The points
come from accumulator leaves that already commit to them, and the sum of
on-curve points is on-curve, so driving `syscall_bls12_381_curve_add` directly
is 27.9x cheaper. The precompile needs `p1 != p2` and `p1 != -p2`, and
`aggregate_points` rejects that case rather than assuming it away.

**Name the absentees, not the attesters.** At 1,050,000 active validators and
99.7% participation, a slot has about 98 absentees against 32,714 attesters.
Opening the absentees is **167x** less accumulator work. The per-epoch committee
proof that makes it possible pays 14.49B. Against that, 32 slot proofs fall from
54.86B to 14.11B, so the epoch is **47.9% cheaper overall** (v1.0.0-alpha
units).

**The committee proof fits in the epoch it must serve.** Its witness is a flat
array of `CommitteeMember`, fifteen `u64`s each, that the guest indexes in
place. While the guest deserialised that witness with `bincode`, a member cost
1,157 steps and the proof was 94% framing. Reading it in place cut that to 328
steps, and pointing the curve precompile at the running sum cut it to 254.

`scripts/committee_bench.py` closed three further questions:

- **Accumulator depth does not matter.** Per-member cost at depths 12, 16, 20
  and 22 is identical to the last unit. The proof opens an index range, so the
  levels above it are a constant.
- **Batch inversion is a 3.75x pessimisation.** In Zisk an inversion costs what
  one multiplication costs, because `inv_fp_bls12_381` is a hinted inverse plus
  one squaring to verify it. A whole affine addition is one precompile.
- **The inactive gaps are the largest term left.** The registry holds 2,212,792
  entries and the proof opens 960,974 of them. Every factor of two of scatter
  costs one more internal node per member. Real exits cluster at low indices and
  pending validators at high ones, so the true figure is an empirical question
  about a real state.

## What is still unmeasured

- **BLS at mainnet scale.** One sweep over distinct message count closes the
  Fp2-tower bracket.
- **A streaming epoch, proven end to end.** `scripts/gpu_bench.sh` is what that
  needs. Until it runs, `T2 - T` is a model.
- **The PLONK wrap on a GPU.** The 436 s above is a CPU number on v1.0.0-alpha.
  The card was idle throughout, and v1.1.0-alpha cannot be measured at all until
  upstream republishes its SNARK key.

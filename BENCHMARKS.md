# Measured Zisk costs

All numbers from `scripts/bench.py`, via `ziskemu -X`. Each primitive runs at
two iteration counts inside a guest and the results are subtracted, so program
setup, input parsing and output commitment cancel out and what remains is the
marginal cost of one operation.

Re-run after any Zisk version bump — these are properties of the prover, not of
zkasper. `ZISK_BIN` selects which install to measure with, so two versions can
be compared on one machine:

```sh
python3 scripts/bench.py --build
ZISK_BIN=/path/to/other/zisk/bin python3 scripts/bench.py
```

The toolchain and `ziskos` must match: v1.1.0-alpha changed the guest linker
script (`_global_pointer`, `_init_stack_top`, `_kernel_heap_*`), so a guest
built against one and linked by the other fails with undefined symbols.

> **Zisk v1.1.0-alpha, 2026-08-18.** The project moved from v1.0.0-alpha to
> v1.1.0-alpha and the whole campaign was re-run on an RTX 5090, same sweep,
> same fixtures. Raw data in `data/gpu_bench_v1.1.0/`; the v1.0.0-alpha campaign
> is kept beside it in `data/gpu_bench/` so the two can be diffed.
>
> | | v1.0.0-alpha | v1.1.0-alpha |
> |---|---:|---:|
> | per-proof floor (`Proof generated`) | 4.940 s | **2.367 s** |
> | empty guest, measured direct | 4.843 s | **2.429 s** |
> | stage floor | 7.176 s | **3.640 s** |
> | slot proof | 8.216 s | **4.506 s** |
> | group proof | 7.998 s | **4.188 s** |
> | wrap compression | 157 ms | **48 ms** |
> | cold penalty | 13.49 s | **5.80 s** |
> | `T2 − T` | 9.1 s on 2 cards | **5.5 s on 1 card** |
>
> **Cost units are not comparable across the two versions.** v1.1.0-alpha
> re-based `POSEIDON_COST` from `14 * 75` to `14 * 392` so that it matches the
> Poseidon AIR's actual column count, which is a 5.23x change in the *price* of
> an operation whose *work* is identical. Anything quoted in cost units below
> says which version produced it.
>
> **Recalibration, 2026-08-18.** The per-proof floor and the GPU throughput model
> in this file were re-measured on an RTX 5090 against Zisk v1.0.0-alpha over a
> 29-point sweep. `BASE = 293,601,280` is a compile-time constant in zisk that
> does not describe the shipped proving key, and every latency figure derived
> from it inherited the error. Worse, **there is no single cost-units-per-second
> constant to correct it to**: measured effective throughput spans 18M to 246M
> units/s across the campaign's own guests. Everything that used to predict
> latency now predicts *seconds* directly, from
> [the time model](#the-time-model-seconds-rather-than-cost-units) —
> `scripts/time_model.py`, and `ProverModel` in
> `crates/witness-gen/src/streaming.rs`. Numbers marked **superseded** below
> should not be quoted. Raw data in `data/gpu_bench/`; the fits are reproduced
> by `python3 scripts/fit_gpu_bench.py` and `python3 scripts/time_model.py`.

## Primitives

Both columns were measured in one session on the same fixtures: each guest built
against its own `ziskos` and read by its own `ziskemu`, because v1.1.0-alpha
changed the guest linker script and the two cannot be mixed.

| primitive | v1.0.0-alpha | v1.1.0-alpha | cost | steps | precompiles used |
|---|---:|---:|---:|---:|---|
| `syscall_poseidon2` (raw) | 1,772 | 6,463 | +265% | 3 → 5 | `poseidon2` |
| `acc::compress` — accumulator node | 3,033 | 7,462 | +146% | 19 → 12 | `poseidon2` |
| `acc::leaf` — one validator | 3,979 | 8,617 | +117% | 28 → 30 | `poseidon2` |
| `sha256_pair` — one SSZ node | 50,662 | 36,207 | −29% | 316 → 131 | `sha256` ×2 |
| G1 decompress — one public key | 49,311 | 45,349 | −8% | 414 → 326 | `arith384_mod` |
| G1 add — `add_complete_safe_bls12_381` | 67,947 | 54,241 | −20% | 525 → 276 | `bls12_381_curve_add` |
| G1 add — raw `syscall_bls12_381_curve_add` | 2,428 | 2,730 | +12% | 1 → 3 | `bls12_381_curve_add` |
| hash-to-curve G2 | 18,594,521 | 12,748,974 | −31% | 160,957 → 47,416 | Fp2 tower |
| Miller loop, marginal pair | 33,222,822 | 22,701,833 | −32% | | Fp2 tower |
| final exponentiation | 132,665,557 | 85,147,848 | −36% | 1,129,993 → 224,710 | Fp2 tower |
| Fp12 multiply | 737,503 | 492,687 | −33% | 6,369 → 1,486 | Fp2 tower |
| `acc::commit_fp12` | 78,002 | 156,329 | +100% | 524 → 503 | `poseidon2` |
| G2 subgroup check | 8,218,954 | 5,565,696 | −32% | 71,290 → 19,458 | Fp2 tower |
| pairing check, 2 pairs (`pairing_check_safe`) | 248,054,847 | 163,974,164 | −34% | 2,110,257 → 465,339 | Fp2 tower |
| **per-proof floor (BASE)** | 293,601,280 | 287,309,824 | −2% | | — |

### Poseidon2 did not get five times more expensive; it got priced

Read the `+265%` on `syscall_poseidon2` as a unit change, not a regression.
`POSEIDON_COST` went from `14 * 75` to `14 * 392`, and **392 is the Poseidon
AIR's column count**. Every v1.1.0-alpha precompile constant now equals its
AIR's width — Sha256f 122, Keccakf 3023, ArithEq 90, ArithEq384 80 — and none of
the v1.0.0-alpha constants did. Three independent checks say the work is
unchanged and only the price moved:

- On the same committee fixture both versions execute **exactly** 4,159
  `poseidon2` and 2,016 `bls12_381_curve_add` calls.
- `precompiles/poseidon/` changed by 13 lines between the tags and no `.pil`
  file was touched, so the arithmetization is the same.
- Measured on a GPU, a guest that is almost all poseidon2 proves **faster**, not
  slower — see [the campaign](#the-measured-gpu-model).

This is the same 4.3x that the v1.0.0-alpha campaign had already found from the
other end, when it reported poseidon2 work proving at 70M units/s against 299M
for padded rows. That gap was the constant being wrong, and it is now closed.

The correction does change one architectural number. An accumulator node against
an SSZ node was **16.70x in favour of poseidon2** and is now **4.85x**. The
accumulator is still the right structure, but the margin is a third of what the
design was argued on.

### The pairing numbers were three things in a trench coat

The old table split a two-pair `pairing_check_safe_bls12_381` into "Miller loop
39,299,490" and "final exponentiation 169,455,773" by measuring the marginal
pair and subtracting. Both halves were wrong, in opposite directions, and their
sum was right — which is why nothing caught it until the streaming pipeline
needed to pay for the halves separately. Measured directly, one pair of a
multi-pairing is really:

| | cost |
|---|---:|
| Miller loop, per pair | 33,222,822 |
| ...plus what `pairing_check_safe` adds per pair | 6,076,715 |
| Miller loop, fixed per batch (63 Fp12 squarings) | 39,633,399 |
| final exponentiation, once per batch | 132,665,557 |

The per-pair extra is on-curve, canonical-form and subgroup validation, and it
is not needed: public keys come out of accumulator leaves that commit to them,
message points come out of `hash_to_curve` with the cofactor cleared, and the
only input an attacker chooses freely — the summed signature — is subgroup
checked explicitly for 8,219,617. Driving the Miller loop directly saves that
6,076,715 per pair on top of everything the split buys.

The fixed 39,633,399 is the 63 squarings of `f` that every pair in a batch
shares, which is why a batch is worth having and why splitting an epoch into
seven groups costs seven of them rather than one.

Reconciling: 39,633,399 + 2 x 33,222,822 + 2 x 6,076,715 + 132,665,557 =
250,898,030, against the 248,054,847 a two-pair check actually costs. The 1.1%
left over is the batch's own vector handling, which the marginal measurement
attributes to the pair.

## The per-proof floor is a constant that does not describe the prover

`BASE` is not measured. `ziskemu -X` prints a compile-time constant from zisk's
`emulator/src/emu_costs.rs`:

```rust
pub const ROM_COST: usize = 21 << 21;
pub const TABLES_COST: usize = (55 + 35 + 29) << 21;
pub const BASE_COST: usize = ROM_COST + TABLES_COST;   // 293,601,280
```

It models a ROM of 21 columns over 2^21 rows plus three lookup tables of 55, 35
and 29 columns over 2^21 rows. Nothing in the prover reads it; only the report
printer does.

### What the prover actually instantiates

An empty guest — `bench-guest` in baseline mode with `n = 0`, 496 executed steps
— makes the prover log exactly which AIRs it builds:

```
Zisk | Binary: 1 | BinaryExtension: 1 | Dma64AlignedMem: 1 | InputData: 1 |
Main: 1 | Mem: 1 | MemAlign: 1 | Rom: 1 | RomData: 1 |
VirtualTableZisk0: 1 | VirtualTableZisk1: 1 | Total global instances: 11
```

Eleven AIRs, every one of them a full trace, on a program that does nothing.
Their geometry is in `data/gpu_bench/proving_key_airs.tsv`, dumped from the
shipped key:

| AIR | rows | columns | cells |
|---|---:|---:|---:|
| `Main` | 2^22 | 68 | 285,212,672 |
| `Binary` | 2^22 | 60 | 251,658,240 |
| `BinaryExtension` | 2^22 | 53 | 222,298,112 |
| `VirtualTableZisk0` | 2^21 | 65 | 136,314,880 |
| `Mem` | 2^22 | 28 | 117,440,512 |
| `MemAlign` | 2^21 | 53 | 111,149,056 |
| `Dma64AlignedMem` | 2^21 | 50 | 104,857,600 |
| `Rom` | 2^22 | 16 | 67,108,864 |
| `InputData` | 2^21 | 29 | 60,817,408 |
| `VirtualTableZisk1` | 2^21 | 29 | 60,817,408 |
| `RomData` | 2^21 | 14 | 29,360,128 |
| **total** | | | **1,447,034,880** |

**The real floor is 1,447,034,880 trace cells, 4.93x the 293,601,280 the model
charges.** Three separate errors compound:

1. `Rom` is at 2^22 with 16 columns, not 2^21 with 21.
2. There are **two** virtual tables (65 and 29 columns), not three of 55/35/29.
3. Six AIRs in the minimal set — `Main`, `Binary`, `BinaryExtension`, `Mem`,
   `MemAlign`, `Dma64AlignedMem` — are not in the floor at all. The model
   charges them per *executed* unit (`MAIN_COST = 68` is exactly `Main`'s column
   count) while the prover pads each to a whole instance.

### But the floor costs far less time than its area suggests

Measured directly, three proves of that empty guest take **4.843 s ± 0.028**
(`Proof generated`, GPU already allocated). The 29-point sweep extrapolates to
the same place: **4.940 s ± 0.096**.

That is 299 M cells/s on the floor's own cells, against 70 M units/s on
poseidon2 work — padded and constant rows prove about **4.3x faster per cell**,
because most of them are zero or precomputed. So:

| | |
|---|---:|
| `BASE_COST` as shipped | 293,601,280 |
| floor as trace cells actually built | 1,447,034,880 (**4.93x**) |
| floor as time, in the same units as variable work | **337,628,631** (**1.15x**) |

The three are different quantities and the middle one is not a drop-in
replacement for the first. For predicting latency — which is all this project
uses the constant for — the right correction is modest: the floor is **1.15x**
what the model charges, not 4.93x.

### Cost units are not a single currency

The clearest result in the sweep is a negative one. Baseline mode at `n = 0` and
at `n = 100,000` differ by **83,558,605** cost units and instantiate *the same
eleven AIRs*:

| | VARIABLE | instances | `Proof generated` |
|---|---:|---:|---:|
| `n = 0` | 40,371 | 11 | 4.843 s |
| `n = 100,000` | 83,598,976 | 11 | 4.902 s |

83.6M cost units bought **0.06 s ± 0.09** — indistinguishable from zero, against
the 1.24 s the published model predicts. Non-precompile work is free until it
crosses an AIR-instance boundary, and then it steps. Poseidon2 work looks smooth
only because it crosses `Poseidon` instances constantly: at `n = 1,000,000` the
prover builds 107 of them, and `Main` has gone from 1 instance to 3.

A cost model that adds `Main` steps, memory accesses and precompile calls into
one number, then divides by one throughput figure, cannot be right for both
kinds of work at once. It is roughly right for the BLS-heavy guests this project
actually proves, because those are dominated by precompiles.

### The measured GPU model

29 sizes, `n` = 10,000 to 1,000,000, 3 warm proves each, RTX 5090, Zisk
v1.0.0-alpha. Regressed on `VARIABLE`, never on `TOTAL` — `TOTAL` contains the
constant under test.

| | floor | slope | residual rms |
|---|---:|---:|---:|
| wall clock per `cargo-zisk prove` | 18.470 s ± 0.273 | 69,965,637 ± 1,199,943 units/s | 0.931 s |
| prover's own `Proof generated` | **4.940 s ± 0.096** | **69,714,770 ± 420,107 units/s** | 0.328 s |
| ...restricted to one `Main` instance | 5.170 s ± 0.094 | 73,315,993 ± 1,107,828 units/s | 0.220 s |

The same sweep on **v1.1.0-alpha**, 29 sizes, 3 warm proves each, same card:

| | floor | slope | residual rms |
|---|---:|---:|---:|
| wall clock per `cargo-zisk prove` | 8.168 s ± 0.128 | 238,478,901 ± 2,442,850 units/s | 0.436 s |
| prover's own `Proof generated` | **2.367 s ± 0.049** | **233,988,033 ± 895,838 units/s** | 0.166 s |
| ...restricted to one `Main` instance | 2.561 s ± 0.034 | 245,451,826 ± 1,531,944 units/s | 0.084 s |

The slope looks 3.36x better and is not. This guest's cost units are multiplied
by **exactly 2.669 at every one of the 29 sizes** by the `POSEIDON_COST`
re-basing, so only **1.26x** of it is throughput. What is unambiguous is the
wall clock on identical work: n = 10,000 proves in 2.92 s against the
v1.0.0-alpha model's 5.29 s, and n = 1,000,000 in 32.29 s against 107.38 s.

The floor is the result that matters, because it is what `T2 − T` is made of:
**4.940 s → 2.367 s**, and the empty guest measured directly gives 4.843 s →
2.429 s. The cold penalty — process start plus GPU allocation, which a warm
prover never pays — fell with it, 13.49 s → 5.80 s.

Against the superseded `time = 19.5 s + units / 67,452,592`: the slope was 3.4%
low, and the 19.5 s was never a proving floor. It is **13.49 s of process start
and GPU allocation** plus about 5 s of actual floor, which is why it cannot be
added to a `proof_base` term without counting the floor twice.

That fit is still only good for *this* guest. What replaces the whole approach
is below.

## The time model: seconds rather than cost units

`scripts/time_model.py`, mirrored by `ProverModel` in
`crates/witness-gen/src/streaming.rs`. It predicts seconds from the quantities
that drive them, with a rate per work class rather than one rate for everything.

All values are Zisk v1.1.0-alpha unless the row says otherwise.

| term | value | v1.0.0-alpha | what set it |
|---|---:|---:|---|
| stage floor | **3.640 s ± 0.053** | 7.176 s | MEASURED — the committee proof over 64 members: 21,680 executed steps, 3 warm proves |
| empty-guest floor | 2.429 s ± 0.040 | 4.843 s | MEASURED — 496 steps, thirteen AIRs, 3 warm proves |
| per opened validator | **834.7 µs** | 834.7 µs | **NOT re-measured** — the attester sweep cannot be reproduced, see below |
| per committee member | 101.2 µs | 101.2 µs | **NOT re-measured** — derived from the same sweep |
| per accumulator node | 31.9 µs | 43.5 µs | MEASURED — 7,462 cost units at the poseidon2 sweep's 233,988,033 units/s |
| Fp2-tower rate | 200,000,000 units/s | 207,400,000 | FITTED — bracket 162M to 268M, against 160M to 609M before |
| ...one distinct message | 0.177 s | 0.250 s | hash-to-curve plus a marginal Miller loop, at that rate |
| ...per-proof Miller batch | 0.160 s | 0.231 s | the 63 shared squarings plus the G2 subgroup check |
| ...final exponentiation | 0.426 s | 0.640 s | once per epoch |
| wrap compression | 0.048 s | 0.157 s | MEASURED — six warm wraps, 46–52 ms |
| cold penalty | 5.80 s | 13.49 s | MEASURED — the sweep's two intercepts, wall minus `Proof generated` |
| recursive verification | **unmeasured** | unmeasured | the fixtures carry stub children; it is a parameter, not a zero |

The stage floor is the load-bearing one, and it is worth being clear about what
it is. An empty guest instantiates thirteen AIRs for 2.429 s. The committee
proof over a 64-member witness executes 21,680 steps — nothing — and takes
3.640 s. The 1.21 s between them is the AIRs a poseidon2 guest instantiates and
an empty one does not, and every zkasper stage pays it.

v1.0.0-alpha measured this on the aggregation guest with recursion removed, at
7.176 s. That guest cannot stand in any more: with `verify_child` stubbed it
still fails a later assert on the fixture's stub children, and a panicking guest
never returns from `ziskemu` — it spins to the step limit. The tiny committee
proof is the same workload class at the same order of magnitude (21,680 steps
and 3.53M units against 34,002 and 3.31M) and needs no stub at all.

**Two constants were not re-measured, and both are carried forward from
v1.0.0-alpha unchanged.** `per_validator_s` came from the attester sweep, and
that sweep no longer exists as a measurement: a group-proof witness is a slot
*complement*, so `gen-test-witness group-proof n` returns the same 728 bytes at
every `n` and there is nothing to regress against. `per_member_s` is derived
from the same sweep's rate. Under `ziskemu -X` a committee member fell from
254.0 steps to 208.0 while its price rose from 30,127 units to 36,406, so the
work is down 18% — but converting that to seconds needs a committee sweep on
hardware that this campaign did not run. Every constant that *was* re-measured
improved, so carrying these two forward can only make the schedule look worse
than it is.

There is deliberately no per-invocation constant. These are the prover's own
`Proof generated` times and a warm prover pays exactly them.

### How well it does

Against the three fixture stages it is fitted on, worst error **5.0%**
(v1.1.0-alpha):

| stage | model | measured | error |
|---|---:|---:|---:|
| committee proof, 64 members | 3.64 s | 3.64 s ± 0.053 | −0.0% |
| group proof | 3.98 s | 4.19 s ± 0.061 | −5.0% |
| slot proof, own final exponentiation | 4.45 s | 4.51 s ± 0.393 | −1.2% |

It was four stages and worst error 4.3% on v1.0.0-alpha. Two of them are gone
rather than worse: the aggregation and stream-final stubs cannot be proved at
all now, because stubbing `verify_child` leaves a later assert failing on the
fixture's stub children and a panicking guest never returns from `ziskemu`.

Against the group-size sweep, which it was *not* shaped for — the sweep is the
enumerating guest, whose floor is about 1 s below a complement group proof's —
worst error **6.0%**, always conservative:

| attesters | model | measured | error |
|---:|---:|---:|---:|
| 256 | 7.9 s | 10.5 s ± 4.20 | −25.2% |
| 2,048 | 9.5 s | 8.9 s ± 0.28 | +5.7% |
| 8,192 | 14.9 s | 14.2 s ± 0.90 | +4.4% |
| 32,768 | 36.4 s | 34.4 s ± 0.81 | +6.0% |
| 62,500 | 62.5 s | 60.9 s ± 0.92 | +2.7% |
| 154,000 | 142.9 s | 142.2 s ± 1.72 | +0.5% |

The 256-attester row is the one point whose three repeats disagree by 7 s; its
own noise is larger than the error.

### What it cannot do, and what would fix that

**One model does not span every workload, and this one does not try.** It covers
zkasper's guests. The poseidon2 bench guest needs its own rate (69.7M units/s),
and plain integer work is free until it crosses an AIR-instance boundary and
then steps. Anything outside the pipeline should be measured, not extrapolated.

**The Fp2-tower rate is the weakest constant.** Nothing in the campaign runs BLS
at mainnet scale, so it is read off floor-dominated fixtures and the bracket
around it is wide:

| | rate | why it is wrong |
|---|---:|---|
| slot minus group | 663,293,070 units/s | an in-instance marginal — the second proof's work fitted in the AIR instance the first already built |
| group minus aggregation stub | 121,351,898 units/s | attributes the whole gap to BLS when part of it is a different AIR set |
| least squares on both | **207,400,000 units/s** | what the model uses |

A group carrying 64 messages is 26 s at the rate used and 18 s at the slow end.
One sweep over message count would close this, and it is the single most
valuable measurement left.

**Recursive verification is not measured at all.** Both stages that would show
it could only be proved with it removed. It is a parameter with a default of
zero, and the schedule's sensitivity to it is printed by the streaming schedule
test.


## What one GPU actually holds

The prover does not allocate what the witness needs. It reads *free* VRAM at
startup and fills it. Every prove in the campaign logged the same thing on an
idle 32.61 GB RTX 5090, for workloads spanning 40x in cost:

```
Minimum free memory available for GPU usage: 30.609253 GB
GPU 0: Allocated 30.135334 GB (28.413327 GB unified + 1.722007 GB const pols)
Pinned host memory per GPU: 2.000000 GB
```

**v1.1.0-alpha does not change this.** On the same 32.61 GB card it still reads
free VRAM and fills it, over the same 100x span of workload:

```
Minimum free memory available for GPU usage: 30.781128 GB
GPU 0: Allocated 29.347325 GB (28.296217 GB unified + 1.051108 GB const pols)
Pinned host memory per GPU: 2.000000 GB
```

The one thing that moved is the constant polynomials, 1.722 GB → **1.051 GB**,
a 39% cut. The unified arena is unchanged at 28.3 GB because it is sized by what
the card has free, not by what the witness needs. The "GPU memory usage
reporting" and "improved GPU memory planning" in the release notes did not make
a warm prover take less of the card.

Two operational numbers did get worse, and they are provisioning ones. The
proving key grows to **105 GB** after the first setup, against ~85 GB on
v1.0.0-alpha, and `~/.zisk/cache` reaches 13 GB for four ELFs. Budget 150 GB of
disk, not the 120 GB `scripts/gpu_bench.sh` still suggests. Setup itself got
much faster: 275 s for the first ELF including the one-time global constant-tree
regeneration, then **13–15 s per additional ELF** against ~6.4 min before.

`cargo-zisk prove -m/--minimal-memory` does **not** change this: same 30.135334
GB allocated, same 31,684 MiB peak, same proving time (12.455 s against
12.549 s). Whatever it reduces, it is not the GPU arena.

### The 30 GB is greed, not a requirement

Holding VRAM back with a trivial `cudaMalloc` before starting the prover shows
the allocation tracking what is left:

| held back | free before | prover allocated | `Proof generated` | result |
|---:|---:|---:|---:|---|
| 0 GB | 31.36 GB | 30.14 GB | 12.30 s | ok |
| 4 GB | 26.86 GB | 25.34 GB | 12.83 s | ok |
| 8 GB | 22.86 GB | 20.76 GB | 14.50 s | ok |
| 16 GB | 14.86 GB | 12.90 GB | 19.78 s | ok |
| 20 GB | 10.86 GB | — | — | `Not enough GPU memory to run the proof` |

**The working minimum is about 14 GB free, allocating 12.9 GB**, and the penalty
for running there is 61% on proving time (19.78 s against 12.30 s), not failure.
The card is not a hard constraint at 30 GB; the prover simply takes everything
it can see.

### Two provers on one card

Started naively and simultaneously, they race: both read free VRAM before either
allocates, both plan to take ~29 GB, and the loser dies at startup with

```
GPU 0: Available memory: 1.250488 GB / 31.356567 GB
[ERROR]: GPU 0: Insufficient memory. Need 28.606488 GB but only 1.250488 GB available
```

It is a loud, immediate failure, not an OOM or a silent serialisation. The
survivor is also degraded — it came up with `3 streams for basic proofs and 0
streams for recursive proofs` and took 24.46 s instead of 12.46 s.

But that is a race, not a requirement. Holding 17 GB back while prover A starts
makes A size itself at 12.90 GB and take one basic stream; releasing the hog
leaves 18.1 GB, and prover B then starts alongside it with one basic and two
recursive streams. **Both proofs complete.**

| | GPU allocated | streams | `Proof generated` |
|---|---:|---|---:|
| solo | 30.14 GB | 3 basic + 1 recursive | 15.43 s |
| A, capped | 12.90 GB | 1 basic + 0 recursive | 26.45 s |
| B, alongside A | ~15 GB | 1 basic + 2 recursive | 21.01 s |

(The CPU was busy building guests during this run, so all three are inflated;
the ratios are what matter.)

So **one prover does not need a whole card** — two fit, at roughly 1.4–1.7x the
per-proof latency each, for about 1.2x aggregate throughput. There is no flag to
cap the allocation, so the cap has to come from outside the process: an MPS
per-client memory limit, a co-resident allocation, or a container limit.

For a latency-bound pipeline that is a poor trade — two cards at 1x beat one
card running two provers at 1.6x — so concurrency still argues for more GPUs.
But the reason is throughput economics, not a 30 GB hardware wall, and any
capacity plan built on "one prove saturates one 5090" is built on a
configuration default rather than a requirement.


## The group stage, measured against attester count

`gen-test-witness group-proof <out> <n-validators>` builds a fixture over `n`
validators split across two slots, so the one group proved covers **`n/2`
attesters**. The ELF used was the pre-complement guest, which enumerates
attesters rather than naming absentees — which is why the sweep scales at all,
and which makes it the right calibration for a slot proof's named set. (It was
also the committee proof's calibration until that proof stopped walking a
bincode list; the sweep still sets the *rate* for that work class, but the
committee guest's own per-member figure is measured directly. See
[The committee proof was 94% framing](#the-committee-proof-was-94-framing).)
Proved on the RTX 5090, 3 warm proves each, `Proof generated`, raw data in
`data/gpu_bench/attester_*.tsv`:

| fixture `n` | attesters | STEPS | VARIABLE | `Proof generated` | effective units/s | steps/attester |
|---:|---:|---:|---:|---:|---:|---:|
| 512 | 256 | 1,769,057 | 191,762,010 | 10.54 s ± 4.20 | 18,186,262 | 6,910 |
| 4,096 | 2,048 | 5,910,479 | 595,312,633 | 8.95 s ± 0.28 | 66,532,724 | 2,886 |
| 16,384 | 8,192 | 20,110,664 | 1,982,290,621 | 14.23 s ± 0.90 | 139,342,796 | 2,455 |
| 65,536 | 32,768 | 76,911,936 | 7,539,064,642 | 34.37 s ± 0.81 | 219,341,641 | 2,347 |
| 125,000 | 62,500 | 145,632,319 | 14,267,663,844 | 60.92 s ± 0.92 | 234,195,592 | 2,330 |
| 308,000 | 154,000 | 357,111,686 | 35,009,796,558 | 142.17 s ± 1.72 | 246,253,630 | 2,319 |

(An earlier version of this table labelled the fixture argument "attesters" and
so halved the per-attester figures. The times are unchanged; only the
denominator was wrong.)

Two things fall out.

**Time is linear in attesters and the fit is tight.** OLS over the five sizes
from 2,048 attesters up: intercept **6.55 s ± 0.49**, slope **878.2 µs ± 6.5**
per attester, residuals within ±0.95 s of times spanning 8.9 s to 142 s. The
fixture hands validators out in index order, so the opening is contiguous and
carries about one internal node per leaf — which is why there is no curvature to
fit. That slope is the `per_validator_s` of the time model.

**The analytical cost model understates a group proof badly, and the missing
term is not cryptography.** At 65,536 attesters the emulator attributes **66.8%
of the cost to `MAIN`** — plain interpreted RISC-V — against 4.9% to
precompiles:

```
MAIN         5,230,011,648  66.77%
OPCODES      1,045,722,377  13.35%
MEMORY         876,798,512  11.19%
PRECOMPILES    386,532,105   4.93%
```

That is **2,347 executed steps per attester**, deserialising the witness and
walking the attester list, and `scripts/streaming_cost.py` counted none of it:
it counted `acc_leaf`, `acc_node` and BLS and nothing else, 6,407 cost units
against 226,483 really spent.

**The two errors partly cancelled, which is why nothing caught either.**
Effective throughput climbs from 18M units/s on a floor-dominated proof to
**246M units/s** at 154,000 attesters, against the 69.7M units/s measured on
poseidon2 work — a **13.5x range within one guest**. `MAIN`-heavy work proves
about 3.5x faster per cost unit than the calibration workload, so understating
the work and understating the rate landed the old model within a few per cent of
the right *time* at 62,500 attesters and 18% under it at 154,000. It was right
by accident, in one place, and there is no constant that fixes it — which is the
argument for the time model rather than a new rate.


## The pipeline stages, proved

Fixture witnesses (4 validators) staged from a machine that can build
`witness-gen`, proved on the RTX 5090. `Proof generated` is the prover own
figure, wall is the whole `cargo-zisk prove` process. 4 proves each; the first
is listed separately because it is the only one that is ever cold.

| stage | VARIABLE | TOTAL | `Proof generated` | wall |
|---|---:|---:|---:|---:|
| group proof | 135,183,320 | 428,784,600 | 8.01 s +/- 0.03 | 20.1-23.1 s |
| slot proof | 272,512,030 | 566,113,310 | 8.19 s +/- 0.12 | 19.1-22.2 s |

The two differ by 137M cost units and by **0.18 s**. Both are floor-dominated,
which is the same quantisation result as the bench guest seen from a different
angle: below an AIR-instance boundary, cost units buy very little time. That
0.18 s is an *in-instance* marginal — the slot proof's final exponentiation fits
in the `ArithEq384` instance the group proof already built — so it must not be
extrapolated to a proof large enough to need a second one. It is the fast end of
the bracket on the Fp2-tower rate.

`aggregation` and `stream-final` **could not be proved as shipped**. Their
witnesses carry stub child proofs, `verify_child` rejects an empty proof inside
a guest, and the `assert!` around it panics - a panicking guest never returns
from `ziskemu`, so both time out rather than reporting a cost. This is a
property of the fixture, not of the circuits.

Rebuilding them with that one rejection removed (`verify_child` returning true
for an empty proof) makes them run, and gives a **lower bound** that excludes
all recursive verification:

| stage, recursion removed | STEPS | VARIABLE | `Proof generated`, warm | wall |
|---|---:|---:|---:|---:|
| aggregation | 34,002 | 3,309,296 | **7.18 s +/- 0.08** | 20.0-20.9 s |
| stream-final | 2,376,988 | 275,264,815 | 8.21 s +/- 0.21 | 21.7-22.1 s |

Aggregation without recursion is **3.3M cost units** - it is nothing but the
floor, and 7.18 s of it. That is the single most useful number in this file: a
guest doing 34,002 steps of nothing takes 2.33 s longer than an empty guest
doing 496, and the only thing between them is the AIRs a poseidon2-and-Fp12
guest instantiates. It is the `stage_floor_s` of the time model.

**On v1.1.0-alpha neither stub runs at all.** With `verify_child` returning true
the guests get further and then fail a later assert on the same stub children,
and a panicking guest never returns from `ziskemu` — it spins to the step limit.
The floor is now measured on the committee proof over a 64-member witness
instead: 21,680 steps and 3.53M cost units, **3.640 s ± 0.053**, which is the
same workload class at the same size and needs no stub. Both figures sit 1.2 s
above their own version's empty guest.

What these do *not* give is the cost of recursion. Whatever an aggregation proof
really costs is almost entirely the recursive verification of its children,
which is exactly the term this fixture cannot exercise. Do not read these as
stage costs; read the floor off them, and read the rest as evidence that the
interesting cost is the part that is missing.

### Wrapping is startup, not compression

`cargo-zisk wrap --minimal -g`, 3 runs per stage, reading
`GENERATE_VADCOP_FINAL_COMPRESSED_PROOF` out of the log rather than trusting
`time`:

| stage | wall | of which compression |
|---|---:|---:|
| group proof | 13.25 / 12.47 / 11.84 s | 452 / 157 / 151 ms |
| slot proof | 11.66 / 13.61 / 12.66 s | 152 / 170 / 153 ms |

**About 12.5 s of wall around 0.15 s of work.** Wrapping costs essentially
nothing; paying for it as a separate process costs 12 s. On a prover that stays
up it disappears into the noise, which is the whole argument for one.


## What the numbers decided

**The accumulator earns its keep.** An accumulator node is **16.3x** cheaper
than an SSZ node. The accumulator tree is also depth 22 against the SSZ
registry's 40, so a membership path costs about **30x** less than proving the
same membership directly against the beacon state root. That answers the
question of whether a second tree is still worth an entire proof stage now that
`sha256f` is a precompile: it is, comfortably.

**BLS is the cost, not hashing.** One pairing check costs as much as ~80,000
accumulator nodes. The old cost model in `op_counter.rs` weighted SHA-256 at
29,000 and Poseidon at 250 — guesses from before either had a precompile — and
concluded that ~28M Poseidon hashes dominated the finality proof. With real
precompiles the ranking inverts completely: the entire accumulator multi-proof
for a slot is a rounding error next to a single attestation's signature check.

**Batching the pairing is the single biggest win.** The final exponentiation
costs 169M and is paid *once per multi-pairing* no matter how many pairs it
covers. Verifying attestations one at a time pays it every time:

| | per attestation | 64 attestations |
|---|---:|---:|
| one check each | 266,649,257 | 17,065,552,448 |
| one multi-pairing | 57,893,910 + shared | 3,913,965,587 |

**4.36x**, for free. `bls::verify_attestation_batch` does this, and the slot
proof uses it. Messages must be pairwise distinct or a rogue-key attack could
cancel one attestation against another; attestations in a slot carry different
`AttestationData`, and the check is enforced rather than assumed.

**Proofs must be batched.** The 293.6M floor is roughly one pairing check.
A proof that does less work than that is more than half overhead, which is an
argument for fewer, larger slot proofs rather than one per attestation.

## Decompressed public keys in the accumulator leaf

The leaf used to commit to the compressed 48-byte key, so every slot proof
decompressed every key it touched — at mainnet scale, every active validator,
once per epoch. It now commits to the decompressed G1 point, and decompression
happens in the epoch-diff proof instead, once per validator that actually
changed.

A first attempt at this went the other way: keep the compressed leaf, take the
uncompressed point from the witness, and verify it with an on-curve check
instead of decompressing. That saved only 7% (46,067 against 49,311), because
`sqrt_fp_bls12_381` **hints** the square root and verifies it with a single
squaring. Decompression was never the modular exponentiation it looks like, so
there was nothing to avoid. Measuring first is what caught it.

Committing the point works because the leaf hash is itself the binding: a point
that is not the committed one fails the accumulator check, so no per-attester
curve validation is needed at all.

The point is 768 bits, packed into thirteen 60-bit Goldilocks elements plus two
for the balance — fifteen in a sixteen-element state, so it is still **one
permutation**. The leaf goes from 3,460 to 3,979, and 49,311 of decompression
disappears:

| | per attester |
|---|---:|
| compressed leaf | 120,625 |
| point leaf | 71,833 |
| | **40.4% off** |

## A mainnet epoch

`scripts/mainnet_cost.py`, at 1,050,000 active validators and 8 aggregates per
slot — 32 slot proofs plus one justification:

| component | before | after | change |
|---|---:|---:|---:|
| accumulator hashing | 26.3B | 26.8B | +2.1% |
| public keys | 123.0B | 2.5B | −97.9% |
| pairings | 21.5B | 21.5B | — |
| per-proof floor | 9.7B | 9.7B | — |
| **total** | **180.5B** | **60.6B** | **−66.4%** |

Per attester: 120,625 → 6,407, **94.7% off**. The second half of that comes from
the aggregation change below.

## Aggregating with the raw precompile

`add_complete_safe_bls12_381` costs 67,854. The `bls12_381_curve_add` precompile
it wraps costs 2,428. **97% of the call is the wrapper**: it re-validates both
operands on every addition — two `is_on_curve` checks, four range comparisons,
and the array shuffling around them.

None of that is needed in the aggregation loop. The points come from accumulator
leaves that already commit to them, and the sum of on-curve points is on-curve.
Driving the precompile directly is **27.9x** cheaper and drops public keys from
the largest line item in the system to 4% of an epoch.

The precompile does have preconditions the wrapper was covering: `p1 != p2` and
`p1 != -p2`, which both mean a shared x-coordinate. Validator public keys are
distinct by construction, so a collision would need a partial sum to land exactly
on the next point or its negation — a discrete-log problem, not something a
prover can arrange. `aggregate_points` checks for it and rejects rather than
assuming it away.

## Complement proving: name the absentees

`scripts/complement_cost.py`, at 1,050,000 active validators and 99.7%
participation — so 32,812 to a committee and **98** of them absent.

A slot proof used to open an accumulator path for every attester. That is
proving the overwhelmingly common case tens of thousands of times, and at
mainnet participation it is 99.7% of the work:

| per slot | leaves | internal nodes | cost |
|---|---:|---:|---:|
| open every attester | 32,714 | 232,927 | 836.6M |
| open every absentee | 98 | 1,524 | **5.0M** |

**167x.** What replaces the openings is a per-slot `(summed public key, summed
effective balance)` pair, published by a committee proof and subtracted from:

```text
agg_pk  = committee.pubkey  − Σ(absentee pubkeys)
support = committee.balance − Σ(absentee balances)
```

The committee proof pays for the whole epoch at once — it opens every active
validator's leaf and aggregates every public key — and that is the only place
the old per-slot work goes:

| | | |
|---|---:|---:|
| open 1,050,000 leaves (2,462,373 internal nodes) | 11.65B | |
| aggregate 1,050,000 public keys | 2.55B | |
| per-proof floor | 0.29B | |
| **committee proof, once per epoch** | | **14.49B** |

Even paying that, the epoch gets cheaper, because 32 slot proofs stop opening a
scattered thirty-second of the tree each:

| | |
|---|---:|
| 32 slot proofs, enumerating attesters | 54.86B |
| 32 slot proofs, naming absentees | 14.11B |
| committee proof | 14.49B |
| **total** | **28.60B** (−47.9%) |

And the committee for epoch `N` is fixed by a RANDAO mix that stops moving two
epochs earlier, so it has a whole epoch — 384 seconds — of slack. It is off the
critical path by construction, not by scheduling luck. It also fits in that
slack: 125 µs per member over the 960,974 *active* validators is 169 s, one
chunk on one card. It did not always. See
[The committee proof was 94% framing](#the-committee-proof-was-94-framing).

### What it does to `T2 − T`

The marginal unit used to be one aggregate; it is now one slot, because a slot is
the smallest thing a committee aggregate can be the complement of. Measured
against the 26,813-attester aggregate that crossed the threshold on epoch
430529:

| | GPU warm, time model |
|---|---:|
| marginal aggregate, enumerated (26,813 attesters) | 40.0s |
| marginal slot, complemented (98 absentees, 3 messages) | **9.1s** |

**4.4x**, and what is left is almost entirely irreducible: the 7.18s stage floor
and the 0.64s final exponentiation are 86% of it, naming the absentees is 0.15s,
and the counted-set opening is gone — deduplication is now a 32-bit slot mask,
because a committee proof puts every validator in exactly one slot.

(The cost-unit version of this table read 1.42B against 0.57B, 22.2s against
9.6s. The ratio was understated because enumerating 26,813 attesters costs 878 µs
apiece and the model charged 6,407 cost units; the times were understated for the
opposite reason. Neither column should be quoted.)

## The committee proof was 94% framing

Measured in prover-seconds, on epoch 430529 as the schedule cuts it, this table
used to read **1,950 s of committee proof against 50 s of everything else** —
97%, five epochs of one card, and a card-count problem that wanted the proof cut
into six chunks across seven cards. Two things were wrong with it and both are
fixed:

**The model charged the whole registry.** Committees are formed from *active*
validators and those are the only leaves the proof opens: 960,974, not the
2,212,792 the registry holds. 2.3x, for free.

**The guest deserialised a witness it had already been handed.** A
`CommitteeMember` is fifteen `u64`s — index, twelve point limbs, balance, slot —
and Zisk maps the input into the guest's address space at an 8-byte-aligned
address. The guest was calling `bincode::deserialize` on it, which at a million
members means fifteen million bounds-checked field decodes into a 115 MB `Vec`
that reallocates its way there, on top of a 115 MB `to_vec` of the input the
guest never needed. Measured on the committee guest itself under `ziskemu -X`,
at 16,000 / 32,000 / 64,000 members, linear to five figures:

| | steps/member | cost units/member |
|---|---:|---:|
| bincode witness | 1,157.0 | 111,318 |
| flat witness, read in place | 328.0 | 36,473 |
| curve add takes the sum in place | **254.0** | **30,127** |

All three rows are v1.0.0-alpha. Re-measured on v1.1.0-alpha at the same three
sizes, the last row is **208.0 steps and 36,406 cost units** — 18.1% fewer steps
for 20.8% more units, which is the poseidon2 re-pricing and not a regression.
Priced at v1.0.0-alpha's constants a member now costs 26,958, or 10.5% less.

`crates/common/src/committee.rs` now defines the layout the host writes and the
guest indexes; nothing about what is proven changed, and the strictly-increasing
check that makes the slot buckets disjoint is still the same check in the same
pass.

The third row is the marshalling around the addition rather than the witness.
`SyscallPoint384` is `#[repr(C)] { x: [u64; 6], y: [u64; 6] }`, which is the
layout `G1Point` already has, so `bls::PointSum` was building two of them field
by field and copying the result back — 48 loads and 24 stores around a syscall
that is 1,896 cost units. Pointing the precompile at the running sum and at the
key where they lie is 74 steps a member, and the same saving lands on every key
a slot proof names.

At the attester sweep's rate for this work class that is 101 µs a member against
405 µs, and the proof as a whole:

| | seconds | share |
|---|---:|---:|
| committee proof | 146 | **74%** |
| stage floors, the epoch's own five proofs | 28.7 | 15% |
| distinct messages (64 of them) | 16.1 | 8% |
| final exponentiation | 0.64 | 0.3% |
| naming absentees | ~5 | 3% |
| | **196** | |

Three things follow:

1. **The fleet is one card.** 146 s of committee proof lands inside the 384 s
   epoch that owes it, in one chunk, on the card the deadline work already has
   idle. Chunking is still supported and still correct — bucket sums add and a
   validator lands in one index range — but nothing needs it.

2. **`T2 − T` is unchanged at 25.6 s and is now the whole question.** The
   epoch's own proofs are 47 s of prover time against 384 s of epoch. Buying
   cards buys nothing at all.

   No other guest is worth the same treatment, and that was checked rather
   than assumed. Every one of them still opens with `bincode::deserialize`,
   but a group-proof witness is 728 bytes and a stream-final witness 2,671:
   measured on the same fixture, dropping the input copy moved the group guest
   by **12 steps out of 1,175,370**. The named set a slot proof walks is about
   a hundred validators — 0.08 s of the 3.64 s floor — so a second wire format
   over the pipeline's most nested witness would buy about 1% of a proof.

3. **What is left of the committee proof is not framing any more.** Of the
   30,127 units a member cost on v1.0.0-alpha, the precompiles it exists to run
   — one leaf hash, one internal node, one curve addition — were 4,161, or 14%.
   On v1.1.0-alpha the same three are 13,609 of 36,406, or **37%**, because
   poseidon2 is now charged what it occupies. The rest is `acc::leaf`'s
   repacking of a 768-bit point into 60-bit Goldilocks windows and the
   multi-proof's scan bookkeeping. `scripts/committee_bench.py` attributes it,
   at 1,024 -> 2,048 members and depth 12:

   | | v1.0.0-alpha | share | v1.1.0-alpha | share |
   |---|---:|---:|---:|---:|
   | accumulator multi-proof | 10,801 | 36% | 13,016 | 36% |
   | leaf hash | 11,210 | 37% | 15,344 | 43% |
   | curve addition | 5,405 | 18% | 4,573 | 13% |
   | witness I/O, what is left of it | 1,281 | 4% | 1,336 | 4% |
   | balances, asserts, the 32-leaf tree | 1,219 | 4% | 1,826 | 5% |

   The curve addition is the only one of the five whose *price* barely moved
   (`ARITH_EQ_384_COST` rose 1.3%), so its **−15.4%** is real work removed by the
   new Main and Binary arithmetization. The marshalling this list exists to
   track — `MAIN` per member — fell from 17,272 to 14,144, exactly tracking the
   18.1% step reduction.

   Writing the packed point straight into the permutation state was measured and
   is **worth nothing** — 30,568 against 30,127, LLVM already elides the
   intermediate array. What does pay is arity: a 4-ary accumulator absorbs four
   digests in the permutation a 2-ary node spends on two, which takes the
   internal nodes from one a leaf to a third of one and measures **25,965 units
   a member, 13% off** (v1.1.0-alpha: 30,039 against 36,095, 17% off). It also
   halves the levels a scattered absentee opening
   hashes, against three auxiliaries a level instead of one. It is not landed:
   it changes the accumulator every other proof binds.

### Measuring a committee strategy in a minute

`scripts/committee_bench.py` runs `crates/committee-bench-guest` under
`ziskemu -X` over a witness `gen-committee-witness` builds at a size, an
accumulator depth and a registry-to-active ratio a person picks, and subtracts
two sizes so everything that does not scale cancels. Every candidate is a whole
verification checked against `committee::verify`'s own output by
`--selftest`, so an "optimisation" that changes the answer cannot be reported as
one. Marginal cost is flat to 1.2% from 256 to 8,192 members, and the
production guest at 16,000 / 32,000 / 64,000 reproduces the bench guest's
figure to 0.7%, which is what licenses the extrapolation to 961k.

Three questions it closed:

**Accumulator depth does not matter.** Per-member cost at depths 12, 16, 20 and
22 is 254 steps and 29,916 units, identical to the last unit — 208 steps and
36,095 on v1.1.0-alpha, equally flat. The committee
proof opens an index range, so the levels above it are a constant, not a term.
An `ACC_TREE_DEPTH` cheaper than 22 buys the committee proof nothing.

**Montgomery's batch inversion is a 3.75x pessimisation.** Sharing one inversion
across a level of a binary reduction is the classic win when an inversion costs
what a hundred multiplications cost. In Zisk it costs what *one* does:
`arith384_mod` and `bls12_381_curve_add` are the same `ARITH_EQ_384` operation
at 1,896 cost units (1,920 on v1.1.0-alpha, and the AIR behind it was rebuilt
from 2^18 x 135 to 2^20 x 80), and `inv_fp_bls12_381` is a hinted inverse plus one
multiplication to check it. A whole affine addition is one precompile; doing it
in software is ten, and batching the inversion makes it twelve. Measured:
**112,272 units a member against 29,916**, with 11.94 `arith384_mod` calls a
member where the precompile path has one.

**The inactive gaps are what is left to attack.** The registry holds 2,212,792
entries and the proof opens 960,974 of them, so the opened set is not one run.
With the inactive validators spread evenly, every factor of two of scatter costs
**one more internal node, 101 steps and 10,795 cost units a member**:

| active share of the registry | steps/member | cost units/member |
|---|---:|---:|
| all of it | 254 | 29,916 |
| 1 in 2 | 355 | 40,712 |
| 1 in 4 | 456 | 51,507 |

Mainnet's ratio is 2.30, so uniform scatter would be +43%. Real exits cluster at
low indices and pending validators at high ones, so the true figure is somewhere
below that and is an empirical question about a real state, not a modelling one
— `gen-committee-witness` takes the ratio as an argument for exactly that
reason. It is the largest remaining term and the only one that argues for
indexing the accumulator by active index rather than registry index.

## Composite: real slot proof

`crates/slot-proof-guest` built for `riscv64ima-zisk-zkvm-elf` and run on a
4-validator test witness:

```
STEPS        2,405,933
VARIABLE   282,009,180   (49.0%)
BASE       293,601,280   (51.0%)
TOTAL      575,610,460
```

At four validators this barely moves — the leaf change saves four
decompressions, about 197K against a 575M total. The saving is per attester, so
it only shows up at a scale this fixture does not reach; that is what
`scripts/mainnet_cost.py` is for. What the run does show is that the proof is
half floor and the accumulator work is 0.01% of the total.


## Streaming: what `T2 - T` costs

`T` is when the chain has published enough attestations to justify a checkpoint.
`T2` is when a proof of it exists. Everything else about proving cost is a
budget question; this is the only latency a bridge sees.

The pipeline is built so that the only thing between them is one proof:

| | fixed groups of 8 | streaming |
|---|---:|---:|
| proofs after the last attestation | 3 + wrap | 1 + wrap |
| last group's attestation work | 8 slots | 1 aggregate |
| final exponentiations in the epoch | one per group | **one** |
| attestations proven | the whole epoch | up to the threshold |

Four changes get there, and they are worth different amounts.

**Splitting the Miller loop from the final exponentiation.** A group proof
computes its Miller loops and publishes a commitment to the resulting Fp12
accumulator; the proof that closes the epoch multiplies them and runs one final
exponentiation. Worth 132,665,557 per group in *total* cost — about 1B across a
seven-group epoch. It is **not** what shortens the critical path: the final
proof verifies the marginal aggregate inline, so it needs a final exponentiation
either way. Groups that each finished their own pairing would have the same
`T2 - T` and cost ~2% more.

**Geometrically shrinking groups.** Groups of 12, 6, 3, 1, 1, 1 slots instead of
four groups of 8. This is the change that moves the critical path, and it moves
it by the most: eight slots of work become one aggregate's worth. On the real
mainnet epoch below the schedule chose groups of 37, 15, 10, 2, 1, 3 and 1
aggregates.

**Stopping at the threshold.** Measured accumulated weight, not a slot number,
with a margin above 2/3 that only the schedule knows — the circuit enforces
exactly 2/3, so a thin margin costs a retry and never soundness.

**Collapsing the tail.** One proof verifies the running aggregate, does the
marginal aggregate inline, runs the final exponentiation, checks the threshold
and emits the finalization. Saves three per-proof floors and, far more
importantly on a GPU, three prover invocations.

### Measured, on a real mainnet epoch

`cargo test --release --test ssz_file_tests test_ssz_file_streaming_finality --
--ignored`, epoch 430529, 2,212,730 validators, 37.17M ETH active:

```
units=115 proven=70 (39% skipped), groups=[37, 15, 10, 2, 1, 3, 1]
tail attesters=26813, attesting_balance=71.6% of stake
7 group proofs, 7 folds, 1 final proof
```

39% of the epoch's aggregates are never proven at all, and the proof that runs
after the last attestation covers one aggregate of 26,813 attesters.

### The number

`cargo test --release --test ssz_file_tests test_ssz_file_streaming_schedule --
--ignored --nocapture`, the same epoch, complement proving, the time model:

```
=== measured floor, 4-card budget: T = 252s, T2 = 278s, T2-T = 25.6s on 1 card(s) ===
  card 0     0.0s ->  169.0s   169.01s  Committee(0)
  card 0   228.0s ->  252.2s    24.22s  Group(0) slots [0..19]
  card 0   252.2s ->  261.8s     9.55s  Group(1) slots [20, 21]
  card 0   264.0s ->  277.5s    13.46s  Final    absorbs [0, 1], inline slot [22]
  card 0   277.5s ->  277.6s     0.16s  Wrap
```

**`T2 − T` is 25.6 s on one card.** The committee proof for the next epoch runs
first and finishes at 169 s, on the same card, 215 s before the epoch that owes
it ends; it is throughput work and never touches `T2`. Five proofs, two of them
groups, one slot inline. The 4-card budget is a budget: the schedule reports
what it needed, and it needed one at every budget from one to six.

| | seconds | why |
|---|---:|---|
| the crossing slot's group, waiting on its block | 12.0 | arrival, not proving |
| the final proof | 13.45 | one stage floor, one final exponentiation, one slot inline |
| the wrap | 0.16 | measured compression |
| | **25.6** | |

Two thirds of it is arrival time and a stage floor, and neither is bought with
cost units.

#### What this supersedes

| published | was | now | why it moved |
|---|---:|---:|---|
| `T2 − T`, streaming, GPU warm | 22.2 s | see below | computed from `293,601,280` and `67,452,592`, neither of which is a time |
| `T2 − T`, streaming, GPU cold | 60.3 s | 25.6 s + 13.5 s per invocation | the cold constant double-counted the floor |
| `T2 − T`, scheduled, "789M floor" | 36.1 s | **25.6 s** | 789M was a trace-*area* figure used as a time; the measured stage floor is 7.18 s, not 12.20 s |
| `T2 − T` at a 294M floor | 26.4 s | 23.3 s | same, for the smaller floor |
| critical path, cost units | 1.418B | — | retired: `streaming_cost.py` counted no `MAIN` execution, so it understated a group proof several-fold, and the units do not convert to seconds anyway |

The 22.2 s and the 25.6 s are not the same measurement of the same thing: the
first modelled one proof in isolation, the second is a scheduler placing five
proofs on cards against real arrival times. The isolated final proof is 9.1 s
under the time model (`scripts/streaming_cost.py`); the other 16.5 s is waiting
for the crossing slot's block and for the group ahead of it.

#### What it is sensitive to

All rows are Zisk v1.1.0-alpha, from
`test_ssz_file_streaming_schedule`. `T2 − T` is **5.5 s on one card**, against
9.1 s on two cards under v1.0.0-alpha's constants.

| | `T2 − T` | cards |
|---|---:|---:|
| stage floor 2.00 s (a hypothetical) | 3.9 s | 1 |
| stage floor 2.43 s (an empty guest) | 4.3 s | 1 |
| **stage floor 3.64 s (measured, v1.1.0-alpha)** | **5.5 s** | **1** |
| stage floor 4.84 s (v1.0.0-alpha's empty guest) | 6.7 s | 1 |
| stage floor 7.18 s (v1.0.0-alpha's measured floor) | 9.1 s | 1 |
| stage floor 12.20 s (the old 789M, as time) | 15.3 s | 1 |
| stage floor 20.00 s | 23.1 s | 1 |
| Fp2-tower rate 162M units/s (the slow bracket) | 5.9 s | 1 |
| Fp2-tower rate 400M units/s (the fast end) | 4.7 s | 1 |
| recursive verification 1 s per child | 6.5 s | 2 |
| recursive verification 5 s per child | 11.8 s | 2 |

`T2 − T` tracks the stage floor almost one for one, which is why halving the
floor is the whole of this release for zkasper's latency. The Fp2-tower rate,
the model's largest uncertainty, now moves it by 1.2 s across its entire
bracket, against 2.3 s before.

The trigger margin still dominates everything else. At 66–68% the epoch closes
on 22 slots and `T2 − T` is 5.5 s; at 69–70% it waits for a 23rd and pays
21.6 s. That cliff is a consensus decision, not a prover one, and v1.1.0-alpha
moves the far side of it from 25.6 s to 21.6 s without moving the cliff.

The whole Fp2-tower bracket moves `T2 − T` by 3 s, so the model's largest
uncertainty is not the answer's largest uncertainty. Recursion, which nothing
measured, is worth more.

**Warm and cold are different products, and the gap is 13.5s.** Measured over 87
warm proves, wall clock exceeds the prover's own `Proof generated` by
**13.49 s** — `INITIALIZING_PROOFMAN` is 7.74 s ± 0.71 of that and process start
and teardown are the rest. That is what a long-running prover saves per proof,
and it is the whole argument for `crates/witness-gen/src/prover.rs` taking
`&self`. Five cold invocations would put 67 s into a 25.6 s answer.

### The trigger margin is worth 16.5 s, and it is the user's call

[`StreamPolicy::threshold_numerator`] defaults to 70% while the circuit enforces
exactly 2/3. `T` is measured at 2/3 either way, so a margin that pushes the
crossing into the next slot shows up in full:

| margin | `T2 − T` | slots proven | balance | over 2/3 |
|---:|---:|---:|---:|---:|
| 67% | **9.1 s** | 22 | 68.52% | 1.85% |
| 68% | 9.1 s | 22 | 68.52% | 1.85% |
| 69% | 25.6 s | 23 | 71.63% | 4.97% |
| **70% (default)** | **25.6 s** | 23 | 71.63% | 4.97% |
| 72% | 34.7 s | 24 | 74.68% | 8.01% |
| 75% | 45.1 s | 25 | 77.78% | 11.12% |

**16.5 s**, and the case for spending it is that the margin's original purpose
is gone: with `slots_mask` a validator belongs to exactly one slot, so nothing
is double-counted, and `marginal_balance` is exact rather than estimated. What
is left is reorg risk on the crossing block, and a margin that turns out too
thin costs a retry rather than soundness — the circuit does not know what margin
the schedule used.

That is a consensus-facing default and it has not been changed here. It is
surfaced, with the number attached, for whoever owns that call.

## Composite: the streaming guests

Built for `riscv64ima-zisk-zkvm-elf` and run on the 4-validator test witness:

```
group proof   STEPS 1,180,802   VARIABLE 135,183,320   BASE 293,601,280   TOTAL 428,784,600
slot proof    STEPS 2,405,933   VARIABLE 282,009,180   BASE 293,601,280   TOTAL 575,610,460
```

On v1.1.0-alpha, same fixtures:

```
group proof   STEPS   329,675   VARIABLE  92,078,690   BASE 287,309,824   TOTAL 379,388,514
slot proof    STEPS   569,601   VARIABLE 180,840,309   BASE 287,309,824   TOTAL 468,150,133
```

Cost units fall 32% and 34%, but **executed steps fall 72% and 76%** — these are
the two most Fp2-tower-heavy stages in the pipeline and the new arithmetization
lands hardest on them.

Same attestations, same membership proof; the group proof is 146,825,860
cheaper because it does not finish the pairing. That is the final exponentiation
(132,665,557) plus the per-pair validation the direct Miller loop skips
(2 x 6,076,715), to within a rounding error.

The aggregation and stream-final guests cannot be measured this way: their
witnesses carry stub child proofs, and `verify_child` rejects an empty proof
inside a guest, so they panic — and a panicking guest does not return from
`ziskemu`. The justification and finalization guests have always had this
property; it is a property of the fixture, not of the circuits, and it goes away
with real child proofs.

## The warm prover, measured

Everything above is trace area, which is hardware-independent. This is the other
half: what a proof costs when the prover is a long-lived process rather than a
`cargo-zisk` invocation. Measured through `crates/witness-gen/src/zisk_prover.rs`
on a 20-core CPU box with no GPU, against the standard proving key, by
`tests/zisk_proof_tests.rs`:

```
initialise + ROM setup for two guests            31.25 s   (once, per process)
group proof   428,784,600 units    811.97 s  =  805.91 prove +  5.89 wrap
slot proof    575,610,460 units    850.08 s  =  841.78 prove +  8.22 wrap
switch from the group ELF to the slot ELF         0.36 s   (263 ms of it the guest)
```

Two things in that table are the point.

**The second proof used a different guest and paid nothing for it.** The client
keeps a map of set-up programs, so changing guest is an `Arc` swap of a cached
ROM plus a 32-byte read of that ROM's Merkle root. Subtract the guest's own
263 ms execution and the switch is under a tenth of a second. A pipeline of eight
stages therefore needs one prover, not eight — a fleet is sized by how many
proofs must be in flight at once, never by how many programs there are.

**The wrap never pays for a process.** `cargo-zisk wrap --minimal` measures 18.4 s
on a GPU of which 0.192 s is the compression; the rest is startup and device
allocation. In-process there is no startup, and what is left is the compression
itself — 5.89 s here, because compressing on a CPU really does cost seconds.

Do not fit a line to these two points. The box was shared with other work while
they were taken, and `scripts/gpu_bench.sh` explains why two points a few seconds
apart is not a measurement. They are here to show the shape, not the slope.

What they do not show is a streaming epoch proven end to end. That needs a GPU
and is what `scripts/gpu_bench.sh` is for; until it is run, the 22.2 s in
"Streaming: what `T2 - T` costs" is a model.

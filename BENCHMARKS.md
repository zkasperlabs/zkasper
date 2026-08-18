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

## `T2 - T`

`T` is the moment the chain has published enough attestations to justify a
checkpoint. `T2` is the moment a wrapped proof exists.

```sh
cargo test --release --test ssz_file_tests test_ssz_file_streaming_schedule -- --ignored --nocapture
```

On mainnet epoch 430529, 2,212,730 validators, the schedule needs **one GPU**
and puts `T2 - T` at **5.5 s**. It reports one GPU at every lane budget from one
to six, because the pipeline is deadline-bound and not throughput-bound: a group
proof cannot start before its blocks exist.

**This is a model over measured per-stage times. No streaming epoch has been
proven end to end.**

What it is sensitive to:

| | `T2 - T` | GPUs |
|---|---:|---:|
| stage floor 2.43 s (an empty guest) | 4.3 s | 1 |
| **stage floor 3.64 s (measured)** | **5.5 s** | **1** |
| stage floor 7.18 s (the v1.0.0-alpha floor) | 9.1 s | 1 |
| stage floor 20.00 s | 23.1 s | 1 |
| Fp2-tower rate 162M units/s (the slow bracket) | 5.9 s | 1 |
| Fp2-tower rate 400M units/s (the fast end) | 4.7 s | 1 |
| recursive verification 1 s per child | 6.5 s | 2 |
| recursive verification 5 s per child | 11.8 s | 2 |

`T2 - T` tracks the stage floor almost one for one. The Fp2-tower rate, which is
the largest uncertainty in the model, moves it by 1.2 s across its whole
bracket. Recursive verification, which nothing has measured, is worth more than
that.

**The trigger threshold dominates every prover term.** At 66 to 68% of the stake
the epoch closes on 22 slots and `T2 - T` is 5.5 s. At 69 to 70% it waits for a
23rd slot and pays 21.6 s. The default is 2/3 exactly, which is the rule the
circuit enforces.

**Warm and cold are different products.** The cold penalty is 5.80 s of process
start and GPU allocation per proof. That is what a long-running prover saves,
and it is why `crates/witness-gen/src/prover.rs` takes `&self`.

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

- **Recursive verification.** Both stages that exercise it can only be proved
  with it removed. Their fixtures carry stub child proofs, and a panicking guest
  never returns from `ziskemu`. It is a parameter with a default
  of zero, and it is not a zero.
- **BLS at mainnet scale.** One sweep over distinct message count closes the
  Fp2-tower bracket.
- **A streaming epoch, proven end to end.** `scripts/gpu_bench.sh` is what that
  needs. Until it runs, `T2 - T` is a model.

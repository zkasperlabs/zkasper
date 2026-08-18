# Measured Zisk costs

All numbers from `scripts/bench.py` against **zisk v1.0.0-alpha** (CPU build),
via `ziskemu -X`. Each primitive runs at two iteration counts inside a guest and
the results are subtracted, so program setup, input parsing and output
commitment cancel out and what remains is the marginal cost of one operation.

Re-run after any Zisk version bump — these are properties of the prover, not of
zkasper:

```sh
python3 scripts/bench.py --build
```

> **Recalibration, 2026-08-18.** The per-proof floor and the GPU throughput model
> in this file were re-measured on an RTX 5090 against Zisk v1.0.0-alpha over a
> 29-point sweep. `BASE = 293,601,280` is a compile-time constant in zisk that
> does not describe the shipped proving key, and every latency figure derived
> from it inherited the error. Numbers marked **superseded** below should not be
> quoted. See [The per-proof floor](#the-per-proof-floor-is-a-constant-that-does-not-describe-the-prover),
> raw data in `data/gpu_bench/`, and `python3 scripts/fit_gpu_bench.py`.

## Primitives

| primitive | cost | precompiles used |
|---|---:|---|
| `syscall_poseidon2` (raw) | 1,772 | `poseidon2` |
| `acc::compress` — accumulator node | 3,033 | `poseidon2` |
| `acc::leaf` — one validator | 3,979 | `poseidon2` |
| `sha256_pair` — one SSZ node | 50,662 | `sha256` ×2 |
| G1 decompress — one public key | 49,311 | `arith384_mod` |
| G1 add — `add_complete_safe_bls12_381` | 67,854 | `bls12_381_curve_add` |
| G1 add — raw `syscall_bls12_381_curve_add` | 2,428 | `bls12_381_curve_add` |
| hash-to-curve G2 | 18,594,521 | Fp2 tower |
| Miller loop, marginal pair | 33,222,822 | Fp2 tower |
| Miller loop, fixed per batch | 39,633,399 | Fp2 tower |
| final exponentiation | 132,665,557 | Fp2 tower |
| Fp12 multiply | 737,503 | Fp2 tower |
| `acc::commit_fp12` | 78,002 | `poseidon2` |
| G2 subgroup check | 8,219,617 | Fp2 tower |
| pairing check, 2 pairs (`pairing_check_safe`) | 248,054,847 | Fp2 tower |
| **per-proof floor (BASE)** | **293,601,280** *(superseded — see below)* | — |

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

Against the superseded `time = 19.5 s + units / 67,452,592`: the slope was 3.4%
low, and the 19.5 s was never a proving floor. It is **13.49 s of process start
and GPU allocation** plus about 5 s of actual floor, which is why it cannot be
added to a `proof_base` term without counting the floor twice.


## What one GPU actually holds

The prover does not allocate what the witness needs. It reads *free* VRAM at
startup and fills it. Every prove in the campaign logged the same thing on an
idle 32.61 GB RTX 5090, for workloads spanning 40x in cost:

```
Minimum free memory available for GPU usage: 30.609253 GB
GPU 0: Allocated 30.135334 GB (28.413327 GB unified + 1.722007 GB const pols)
Pinned host memory per GPU: 2.000000 GB
```

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

`gen-test-witness group-proof <out> <n-validators>` builds a fixture whose one
aggregate covers `n/2` attesters. Proved on the RTX 5090, 3 warm proves each,
`Proof generated` (raw data in `data/gpu_bench/attester_*.tsv`):

| attesters | STEPS | VARIABLE | `Proof generated` | effective units/s | steps/attester |
|---:|---:|---:|---:|---:|---:|
| 512 | 1,769,057 | 191,762,010 | 10.54 s ± 4.20 | 18,186,262 | 3,455 |
| 4,096 | 5,910,479 | 595,312,633 | 8.95 s ± 0.28 | 66,532,724 | 1,443 |
| 16,384 | 20,110,664 | 1,982,290,621 | 14.23 s ± 0.90 | 139,342,796 | 1,227 |
| 65,536 | 76,911,936 | 7,539,064,642 | 34.37 s ± 0.81 | 219,341,641 | 1,174 |
| 125,000 | 145,632,319 | 14,267,663,844 | 60.92 s ± 0.91 | 234,195,592 | 1,165 |
| 308,000 | 357,111,686 | 35,009,796,558 | 140.46 s | 249,243,910 | 1,159 |

Two things fall out, and they pull in opposite directions.

**The analytical cost model understates a group proof by 3.6x.** At 125,000
attesters `scripts/streaming_cost.py` accounts for 3.93B cost units; the guest
really costs 14.27B. The missing term is not cryptography. At 65,536 attesters
the emulator attributes **66.8% of the cost to `MAIN`** — plain interpreted
RISC-V — against 4.9% to precompiles:

```
MAIN         5,230,011,648  66.77%
OPCODES      1,045,722,377  13.35%
MEMORY         876,798,512  11.19%
PRECOMPILES    386,532,105   4.93%
```

That is **~1,159 executed steps per attester** — deserialising the witness and
walking the attester list — and the model counts none of it. It counts
`acc_leaf`, `acc_node` and BLS and nothing else.

**But the model's predicted *times* are close anyway**, because the second error
cancels the first. Effective throughput climbs from 18M units/s on a
floor-dominated proof to **249M units/s** at 308,000 attesters, against the
69.7M units/s measured on poseidon2 work. `MAIN`-heavy work proves about 3.5x
faster per cost unit than the calibration workload:

| | modelled | measured | error |
|---|---:|---:|---:|
| group of ~83,000 attesters | 43.3 s | ~42.2 s | −2.5% |
| group of 125,000 attesters | 58.7 s | 60.9 s | +3.8% |
| group of 308,000 attesters | 118.5 s | 140.5 s | **+18.5%** |

So the scheduling analysis built on those times survives — the largest group is
18% more expensive than assumed, which makes the deadline slightly harder, not
easier. What does not survive is the idea that a single cost-units-per-second
number describes this prover. It does not: the same constant is wrong by 3.5x in
one direction for `MAIN`-heavy guests and right only for the poseidon2 workload
it was fitted on.


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
angle: below an AIR-instance boundary, cost units buy very little time.

`aggregation` and `stream-final` **could not be proved as shipped**. Their
witnesses carry stub child proofs, `verify_child` rejects an empty proof inside
a guest, and the `assert!` around it panics - a panicking guest never returns
from `ziskemu`, so both time out rather than reporting a cost. This is a
property of the fixture, not of the circuits.

Rebuilding them with that one rejection removed (`verify_child` returning true
for an empty proof) makes them run, and gives a **lower bound** that excludes
all recursive verification:

| stage, recursion removed | STEPS | VARIABLE | TOTAL | wall, warm |
|---|---:|---:|---:|---:|
| aggregation | 34,002 | 3,309,296 | 296,910,576 | 20.0-20.9 s |
| stream-final | 2,376,988 | 275,264,815 | 568,866,095 | 21.7-22.1 s |

Aggregation without recursion is **3.3M cost units** - it is nothing but the
floor. Whatever an aggregation proof really costs is almost entirely the
recursive verification of its children, which is exactly the term this fixture
cannot exercise. Do not read these as stage costs; read them as evidence that
the interesting cost is the part that is missing.

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
epochs earlier, so the 14.49B has a whole epoch — 384 seconds — of slack. It is
off the critical path by construction, not by scheduling luck.

### What it does to `T2 − T`

The marginal unit used to be one aggregate; it is now one slot, because a slot is
the smallest thing a committee aggregate can be the complement of. Measured
against the 26,813-attester aggregate that crossed the threshold on epoch
430529:

| | cost | GPU warm |
|---|---:|---:|
| marginal aggregate, enumerated | 1.42B | 22.2s |
| marginal slot, complemented | **0.57B** | **9.6s** |

**2.5x**, and what is left is almost entirely irreducible: 0.294B of per-proof
floor and 0.133B of final exponentiation are 75% of it, the accumulator work is
0.005B, and the counted-set opening is gone — deduplication is now a 32-bit slot
mask, because a committee proof puts every validator in exactly one slot.

## Where the next win is

| | | share |
|---|---:|---:|
| committee proof | 14.5B | 51% |
| per-proof floor | 9.7B | 34% |
| pairings | 3.9B | 14% |
| slot accumulator work | 0.2B | 1% |

Two things worth measuring next:

1. **The committee proof is half the epoch and is trivially parallel.** Bucket
   sums add and a validator lands in one index range, so splitting it across
   *n* proofs needs only a fold that adds aggregates. Nothing else in the
   pipeline has that shape.

2. **The floor is 34% and it is pure overhead.** 34 proofs at 293,601,280 each.
   Fewer, larger proofs trade that against parallelism.

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

`scripts/streaming_cost.py`, measured constants, the marginal aggregate sized
from that run:

| | fixed groups of 8 | streaming |
|---|---:|---:|
| critical path | 8.597B | **1.418B** |
| CPU (333.4s + cost/1,244,523 per proof) | 7,908s | **1,473s** |
| GPU cold (19.52s per invocation) | 205.7s | **60.3s** *(superseded)* |
| GPU warm (allocation held open) | 129.6s | **22.2s** *(superseded)* |

**6.1x** in cost units, **5.8x** in GPU wall-clock.

> **Superseded.** Both GPU rows are computed from `293,601,280` and
> `67,452,592`, and both constants are wrong — see
> [The per-proof floor](#the-per-proof-floor-is-a-constant-that-does-not-describe-the-prover).
> The cost-unit column is also wrong in the other direction: measured against
> real group proofs, `streaming_cost.py` understates a group by **3.6x** because
> it counts no `MAIN` execution. The two errors partly cancel, so the *times* are
> closer than the *costs* — group proofs land within 4% of the model at 83k–125k
> attesters and 18.5% over it at 308k — but nothing here should be quoted as a
> measurement until the model is rebuilt on
> [the group-stage numbers](#the-group-stage-measured-against-attester-count).

**Warm and cold are different products, and the gap is 13.5s.** Measured over 87
warm proves, wall clock exceeds the prover's own `Proof generated` by
**13.49 s** — `INITIALIZING_PROOFMAN` is 7.74 s ± 0.71 of that and process start
and teardown are the rest. That is what a long-running prover saves per proof,
and it is the whole argument for `crates/witness-gen/src/prover.rs` taking
`&self`. The 19.52s previously quoted here was a regression intercept that also
absorbed the per-proof floor, so it cannot be added to a `proof_base` term
without counting the floor twice — which `scripts/streaming_cost.py` currently
does.

### Where the remaining 1.418B went

That measurement predates complement proving, and the thing it identified as the
next win is what complement proving is:

| | | share |
|---|---:|---:|
| accumulator membership, marginal aggregate | 0.709B | 50.0% |
| per-proof floor | 0.294B | 20.7% |
| hash-to-curve, Miller loops, subgroup check | 0.133B | 9.4% |
| final exponentiation | 0.133B | 9.4% |
| counted-set opening | 0.084B | 5.9% |
| public key aggregation | 0.065B | 4.6% |
| Fp12 multiply and commitment | 0.001B | 0.1% |

Half the critical path was opening 26,813 accumulator leaves for one aggregate.
Naming that slot's ~98 absentees instead drops it to 0.005B, and the counted-set
opening disappears with the counted set. 1.418B becomes 0.57B; see
**Complement proving** above.

## Composite: the streaming guests

Built for `riscv64ima-zisk-zkvm-elf` and run on the 4-validator test witness:

```
group proof   STEPS 1,180,802   VARIABLE 135,183,320   BASE 293,601,280   TOTAL 428,784,600
slot proof    STEPS 2,405,933   VARIABLE 282,009,180   BASE 293,601,280   TOTAL 575,610,460
```

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

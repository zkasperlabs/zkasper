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
| **per-proof floor (BASE)** | **293,601,280** | — |

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

## Where the next win is

With public keys handled, an epoch is:

| | | share |
|---|---:|---:|
| accumulator hashing | 26.8B | 44% |
| pairings | 21.5B | 35% |
| per-proof floor | 9.7B | 16% |
| public keys | 2.5B | 4% |

Three things worth measuring next, in rough order of size:

1. **Accumulator membership is proven 32 times over.** Each slot proof opens a
   different scattered 1/32 of the tree, which is the worst case for a
   multi-proof: the upper levels get rebuilt in every one of the 32 proofs.
   Proving membership once per epoch over the union of attesters — effectively
   rebuilding the whole tree once — is ~16.9B against 26.8B. It moves work from
   the slot proofs into the justification proof, which also makes the slot
   proofs cheaper to parallelise.

2. **Aggregate count drives the pairings.** The 21.5B assumes 8 aggregates per
   slot. Post-Electra a single aggregate can cover every committee in a slot, so
   this scales directly with how many a block actually carries — at one per slot
   it is 8.5B.

3. **The floor is 16% and it is pure overhead.** 33 proofs at 293,601,280 each.
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
| GPU cold (19.52s per invocation) | 205.7s | **60.3s** |
| GPU warm (allocation held open) | 129.6s | **22.2s** |

**6.1x** in cost units, **5.8x** in GPU wall-clock.

GPU figures use 67,452,592 cost units per second, measured on an RTX 5090
against Zisk 1.0.0-alpha, plus one wrap invocation at 0.192s of actual
compression.

**Warm and cold are different products.** The 19.52s "fixed cost" of a proof is
process startup and 30 GB of GPU allocation, not proving — the wrap measurement
makes this unmistakable: 18.4s wall-clock around 0.192s of work. Two cold
invocations are 39s of nothing, which is why the pipeline is only under 30
seconds on a prover that stays up. `crates/witness-gen/src/prover.rs` documents
this as a requirement of the trait rather than a deployment note.

### Where the remaining 1.418B is

| | | share |
|---|---:|---:|
| accumulator membership, marginal aggregate | 0.709B | 50.0% |
| per-proof floor | 0.294B | 20.7% |
| hash-to-curve, Miller loops, subgroup check | 0.133B | 9.4% |
| final exponentiation | 0.133B | 9.4% |
| counted-set opening | 0.084B | 5.9% |
| public key aggregation | 0.065B | 4.6% |
| Fp12 multiply and commitment | 0.001B | 0.1% |

The critical path is now dominated by opening 26,813 accumulator leaves for the
one aggregate that crosses the threshold — 0.602B of it internal nodes, 0.107B
leaves — and not by the pairing, which is what dominated before. Two things follow. A chain with smaller aggregates has a shorter
critical path for free, since the marginal unit is one aggregate and its size is
whatever the block builder chose. And the next real win is proving membership
for a *superset* of the likely marginal attesters before `T`, leaving the final
proof to select from it: that is the only remaining term that is large and not
irreducible.

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

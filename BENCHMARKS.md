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
| G1 add — aggregate one key | 67,854 | `bls12_381_curve_add` |
| hash-to-curve G2 | 18,594,336 | Fp2 tower |
| Miller loop (marginal) | 39,299,490 | Fp2 tower |
| final exponentiation | 169,455,773 | Fp2 tower |
| pairing check, 2 pairs | 248,054,754 | Fp2 tower |
| **per-proof floor (BASE)** | **293,601,280** | — |

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

| component | compressed leaf | point leaf | change |
|---|---:|---:|---:|
| accumulator hashing | 26.3B | 26.8B | +2.1% |
| public keys | 123.0B | 71.2B | −42.1% |
| pairings | 21.5B | 21.5B | — |
| per-proof floor | 9.7B | 9.7B | — |
| **total** | **180.5B** | **129.3B** | **−28.4%** |

## Where the next win is

At mainnet scale the ranking inverts once more. A pairing is the most expensive
*single* operation, but an epoch has ~256 aggregates and ~1.05M attesters, so
**G1 point addition is now the largest line item in the whole system** — 71.2B
against 21.5B for every pairing combined.

`add_complete_safe_bls12_381` works in affine coordinates, which needs a field
inversion per addition. Accumulating in projective coordinates, or summing
pairwise and batching the inversions with Montgomery's trick, would replace
~32K inversions per slot with a handful. That is the next thing worth measuring;
zisklib exposes only complete affine addition today, so it may need either
field-level access or an upstream addition.

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

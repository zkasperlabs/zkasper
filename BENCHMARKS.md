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
| `syscall_poseidon2` (raw) | 1,856 | `poseidon2` |
| `acc::compress` — accumulator node | 3,117 | `poseidon2` |
| `acc::leaf` — one validator | 3,460 | `poseidon2` |
| `sha256_pair` — one SSZ node | 50,746 | `sha256` ×2 |
| G1 decompress — one public key | 49,395 | `arith384_mod` |
| G1 add — aggregate one key | 67,938 | `bls12_381_curve_add` |
| hash-to-curve G2 | 18,594,420 | Fp2 tower |
| Miller loop (marginal) | 39,299,490 | Fp2 tower |
| final exponentiation | 169,455,857 | Fp2 tower |
| pairing check, 2 pairs | 248,054,838 | Fp2 tower |
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

## Where the next win is

Public key decompression is 49,395 and aggregation 67,938, so folding one
attester costs 117,333. Every validator attests once per epoch, so at mainnet
scale (~700K attesters) that is **~34.6 billion per epoch just to decompress
public keys** — around 28% of the total, and the largest single line item after
the pairings themselves.

The accumulator leaf currently commits to the compressed 48-byte key, so every
slot proof decompresses every key it touches. If the leaf committed to the
*decompressed* G1 point instead, decompression would happen once per validator
per epoch inside the epoch-diff proof (~200 mutations) rather than ~700K times
across the slot proofs. The leaf grows from 14 field elements to 26, so it needs
two permutations instead of one — about 6,500 extra per leaf, or ~4.5B per
epoch against ~34.6B saved. Net **~24%** off the whole epoch.

## Composite: real slot proof

`crates/slot-proof-guest` built for `riscv64ima-zisk-zkvm-elf` and run on a
4-validator test witness:

```
STEPS        2,407,985
VARIABLE   282,248,550   (49.0%)
BASE       293,601,280   (51.0%)
TOTAL      575,849,830
```

with 29 `poseidon2`, 39 `sha256`, and 27,454 BLS Fp2 operations. At this size the
proof is half floor and the accumulator work is 0.01% of the total — the shape
that motivates the leaf-format change above.

# The committee proof, and why the shuffle is proven in it

**This is settled design. It has been re-derived from scratch several times
because it was never written down. Read this before reopening it.**

## The shape

**One proof per epoch establishes the committee assignment *and* the per-slot
sums, and it is proved an epoch ahead.**

RANDAO fixes epoch E's assignment at the end of epoch **E-2**. So the assignment
for E is known a full epoch before E begins, and the proof of it has an entire
epoch of lead time. It is pure throughput work: it never touches the critical
path between `T` and `T2`.

That one proof publishes:

- the **shuffle**, proven -- each validator's assigned slot for epoch E, so the
  assignment is no longer prover-chosen witness;
- the **per-slot sums** it already computes -- one
  `(summed public key, summed effective balance)` per slot bucket.

Both consumers then take the complement against those sums: open the ~90
absentees rather than the ~30,000 attesters.

## Why the shuffle has to be in it

Not for finality's sake. Finality's denominator is **global** -- two thirds of
total active balance, summed over all 32 buckets -- so a prover-chosen partition
buys nothing there, and finality alone could leave the assignment as unproven
witness.

**FCR's denominator is the bucket.** A sub-minute confirmation cannot be stated
over total stake: one slot carries 1/32 of the validator set, so any total-stake
threshold high enough to be secure needs ~24 slots, about five minutes, and is
not a fast path. Sub-minute therefore requires per-slot committee weight -- and
the moment the threshold is a fraction of slot 1's committee, a prover who picks
the partition picks its own denominator. Concentrate the validators you control
into bucket 1, have them all vote, and any percentage clears with a small
fraction of total stake, with ordering, pairing and leaf binding all passing.

Proving the shuffle closes that, and it is the only thing that does.

## Why this is affordable

Three properties compose:

1. **Once per epoch, not per slot.** The assignment is fixed for all 32 slots of
   E, so one proof serves every confirmation in the epoch.
2. **A full epoch of lead time**, by construction, from the E-2 RANDAO fix. It
   is scheduled like the existing committee proof -- ahead, on its own lane --
   and never sits between `T` and `T2`.
3. **Fused with work already being done.** The committee proof already reads
   every validator leaf once per epoch and is 48% plain witness scan. The shuffle
   is computed over the same pass rather than added beside it.

## What each product takes from it

| | finality | FCR |
|---|---|---|
| per-slot sums, for complement proving | yes | yes |
| the proven assignment | not required, but free | **required** -- it is the denominator |
| denominator | 2/3 of total active balance | per-slot committee weight |

Finality does not need the assignment proven and is unharmed by it. FCR cannot
exist without it. It is one proof because splitting it would mean reading every
leaf twice.

## What it costs: 44.2 s an epoch

Measured, not modelled. `crates/shuffle-bench-guest` computes each validator's
assigned slot every way worth computing it, `V_SELFTEST` holds them all to a
transcription of `compute_shuffled_index`, and the results were proved on an
RTX 5090 over the **901,001-validator mainnet active set** -- the active set,
not the 2.34M registry, because that is what `get_active_validator_indices`
returns and what committees are formed from.

| how the assignment is computed | proved |
|---|---:|
| `compute_shuffled_index` per validator, as the spec writes it | 10,207 s |
| whole-set swap-or-not over a `u32` index array, what clients do | 115.3 s |
| the same permutation over 5-bit slot labels | 91.7 s |
| the same, bit-sliced into five bitplanes | **44.2 s** |

44.2 s in a 384 s epoch is **11.5% of one card**, once an epoch, with a full
epoch of lead time and zero marginal cost per slot proof.

Two corrections to what this note used to say:

- **The shuffle is not absorbed by the existing scan.** The 90 rounds are a pass
  over their own array. All the committee scan shares is reading the finished
  label out, which is 4.3 s of the 44.2 s -- 9.7%. The shuffle is additive, and
  the reason to fuse it into the committee proof is the stage floor and the
  recursive child it saves (39.3 s together), not the pass.
- **It is not hash work.** Once each round's source block is shared 256 ways the
  guest hashes 158,641 times an epoch, 6.1% of the cost. 60% of it is `Main`,
  one row per executed instruction, so instruction count is the only lever.

The campaign, the soundness bindings this drags in, and the sampled scheme that
was measured and rejected are in `zkasper-pm/technical/shuffle-proof-cost.md`.

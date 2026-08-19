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

## What is still open

The **cost** of the shuffle inside the proof -- 90 rounds of swap-or-not over
~2.34M validators -- and how much of it the existing scan absorbs. That number
decides the fleet, not the design.

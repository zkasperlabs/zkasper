# FCR: trust assumptions and accepted risks

Read this before you trust a zkasper **fast confirmation** proof.

The batch proof exists — `crates/fcr-proof-guest`, verified natively against
real signatures — but nothing has proved an FCR statement on a GPU, and the
committee proof it needs does not yet prove the shuffle. So everything below is
an assumption of a design that is partly built.
[architecture.md](architecture.md) holds the design.

An FCR confirmation claims one thing. **Over a run of slots, validators the
proven committee assignment placed in those slots cast head votes, worth more
effective balance than the specification's own threshold, for one block.** The accumulator commits to the validator set behind those balances,
and a chain of `parent_root` openings binds the descent.

This is a different product from the finality proof, with a different threshold,
different circuits and a different threat model.
[../finality/assumptions.md](../finality/assumptions.md) is that product's page,
and **nothing in it applies here unless this page says so.** What the two
genuinely share — the accumulator, the init point, the BLS arithmetic, native
mode and the on-chain wrap — is
[../shared/assumptions.md](../shared/assumptions.md).

Each entry says whether a broken assumption costs liveness (no proof) or
soundness (a false proof).

---

## 1. FCR requires the committee proof, and requires its shuffle proven

**This is the distinction that gets confused, so it is first, and it has been
settled more than once.** An earlier version of this page said the opposite —
that no FCR circuit consumes the committee proof — on the strength of a threshold
stated over total active balance rather than over a slot's committee weight. That
threshold is real and it is conservative, but it is **not a fast path**: one slot
carries 1/32 of the validator set, so a total-stake threshold high enough to be
secure needs about 24 slots, roughly five minutes. A page claiming one-slot
confirmation and a 75%-of-total threshold in the same breath was asking for
something arithmetically impossible.

**Sub-minute confirmation requires a per-slot committee denominator, and the
moment the denominator is a bucket, the bucket has to be proven.** See
[../shared/committee-and-shuffle.md](../shared/committee-and-shuffle.md), which
is the settled design: one proof per epoch establishes the assignment *and* the
per-slot sums, proved an epoch ahead off the E-2 RANDAO fix, measured at 44.2 s —
11.5% of one card, once an epoch, never on the critical path.

So the reuse list **includes** the committee proof, and the shuffle question is
FCR's as much as finality's. Finality does not need the assignment proven and is
unharmed by it; FCR cannot exist without it.

---

## 1a. The threshold is the spec's, unmodified

zkasper proves the rule `consensus-specs` writes, not one shaped to what is cheap
to prove. Thresholds derived for provability — budgeting the adversary's whole
stake as `0.5*M + beta*T + P/2` to survive an unproven assignment — are **not
adopted.** They buy soundness under a weaker circuit at the price of claiming a
safety property nobody has analysed, and a bridge that says "confirmed" on terms
Ethereum never defined is worth less than one that waits.

The consequence is that no threshold lives in a circuit at all. An FCR proof
publishes scalars — support, total active balance, the slot run, the committee
root, the head chain — and the verifier evaluates
`(maximum_support + proposer_score + 2*adversarial_weight - support_discount) / 2`
over them. A circuit that hard-coded the formula would need a rebuild, and a new
verification key, every time the specification moved.

---

## 2. `equivocation_score` is permanently zero

A circuit sees only on-chain state, so it can never reproduce
`store.equivocating_indices` of the fork-choice implementation. Any subset of
that set raises the confirmation threshold, so **zero is the most conservative
value available**. The term only moves the threshold once equivocating stake
reaches about 0.1% of the total, which mainnet has never approached.
`support_discount` stays zero for the same reason.

---

## 3. FCR assumes good network conditions

FCR is a fast path for the healthy case only. When the network breaks, zkasper
does not keep confirming with a degraded FCR proof. **It falls back to two-epoch
finality, which runs all the time anyway.**

Two consequences follow. Complement proving needs no low-participation fallback.
`support_discount` stays zero permanently, because a missed slot is exactly the
unhealthy case that finality takes back.

---

## 4. The wrong-slot attestation attack, and what closes it

**Confirmed, not theoretical, and it is the reason the shuffle is proven.**

**The attack this defends against, stated plainly.** The committee partition is
prover-chosen -- disjoint, because leaves are consumed in strictly increasing
validator-index order, but otherwise arbitrary. If a confirmation threshold were
a fraction of *slot 1's committee weight*, the prover would be choosing its own
denominator: concentrate the validators you control into bucket 1, have them all
vote, and any percentage clears with a small fraction of total stake. Ordering,
pairing and leaf binding all pass. **Finality is immune to this because its
denominator is global** -- two thirds of total active balance, summed over every
bucket, so moving stake between buckets changes nothing. A per-slot denominator
is not, and no threshold this project is willing to state fixes that — only
proving the assignment does.

On mainnet the attack needs **2.97% of stake** against the spec threshold at a
one-slot window, and an adversarial validator signing for a slot it was never
assigned to is **not slashable**: a double vote needs two attestations sharing a
target epoch, and this validator casts one. The attestation is invalid on the
wire, so it is never included and never leaves on-chain evidence.

**This is resolved, and the resolution is written down**: the shuffle is proven
once per epoch, inside the committee proof, an epoch ahead. RANDAO fixes epoch
E's assignment at the end of E-2, so it has a full epoch of lead time and never
touches the critical path, and the committee proof already reads every leaf once
per epoch. With the assignment proven the denominator is no longer prover-chosen,
so FCR can state a per-slot committee threshold and confirm inside a minute.
Complement proving then works for both products off the same sums. See
[../shared/committee-and-shuffle.md](../shared/committee-and-shuffle.md).

The cost is no longer open either: **44.2 s an epoch, measured** on the
901,001-validator mainnet active set, bit-sliced over five bitplanes. That is
11.5% of one card, once an epoch, with a full epoch of lead time.

**What the circuit does about it: nothing, and it cannot.**
`crates/fcr-proof-guest` binds one `committee_root` across a batch and asserts
each bucket's slot index against the `data.slot` of the message it is paired
with, which stops an *honest* validator being relocated. Neither check can tell a
proven partition from an invented one. Handing that circuit a committee root from
an unproven partition does not make it fail — it makes it lie.

---

## 5. What FCR inherits, and from where

- **[../shared/assumptions.md](../shared/assumptions.md) applies in full.** FCR
  opens balances out of the same accumulator, closes the same pairing equation,
  and would be wrapped by the same PLONK setup.
- **The accumulator's anchor rule is discharged by finality, not by FCR.** The
  rule that makes an accumulator commitment worth trusting is that every state
  root the accumulator passed through is later named by a **finalization** proof.
  An FCR confirmation names a block root and a slot; it names no state root and
  discharges nothing. A deployment that runs FCR without the finality pipeline
  behind it holds an unanchored accumulator.
- **No child program keys, by construction.** An FCR batch verifies its own
  signatures and runs its own final exponentiation; accumulation across batches
  is the verifier's, not a circuit's. So finality's "Which program a child proof
  came from" discipline has nothing to bite on here, and the unmeasured cost of
  in-guest `verify_zisk_proof` stays off the critical path. The VADCOP final key
  is one constant in `zkasper-common` either way.

---

## 6. A confirmation is a snapshot, not a standing claim

An FCR proof says "at slot S, block B was confirmed". It does not say that B
stays canonical. The full FCR reverts its confirmed root to the finalized root
when conditions change, and a proof cannot revert itself once it is on another
chain. Whether the verifier contract tracks confirmation validity windows, and
what a consumer does when a confirmed block is later reorged out, are open
questions of the design and are listed as such in
[architecture.md](architecture.md).

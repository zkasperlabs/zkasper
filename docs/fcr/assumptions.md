# FCR: trust assumptions and accepted risks

Read this before you trust a zkasper **fast confirmation** proof.

FCR is designed and **not built**. No `fcr` code exists in this repository.
[architecture.md](architecture.md) holds the design, so everything below is an
assumption of a design rather than of running code. Two standing decisions bound
it, and they are sections 2 and 3.

An FCR confirmation claims one thing. **At one slot, validators holding more
than 75% of the total active effective balance cast head votes that descend from
one block.** The accumulator commits to the validator set behind those balances,
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

## 1. FCR does not use the committee proof

**This is the distinction that gets confused, so it is first.** The committee
proof is a finality stage. It runs an epoch ahead, partitions the epoch's
validators into one bucket per slot, and publishes one
`(summed public key, summed effective balance)` pair per bucket. **No FCR
circuit consumes it, and the design does not need it.**

That is a deliberate consequence of the threshold. FCR states its threshold over
the **total active balance** rather than over a slot's committee weight,
precisely so that the circuit never has to know which validator was assigned to
which slot:

```
adversarial = byzantine_threshold_pct * total_active_balance / 100
threshold   = (total_active_balance + 2 * adversarial) / 2
```

With the default `byzantine_threshold_pct = 25` that is **more than 75% of total
active balance**. A slot's committee weight is always at most the total active
balance, so a threshold computed against the total is at least the true per-slot
threshold. It is conservative, and what it costs is participation headroom
rather than soundness. The derivation is in [architecture.md](architecture.md).

Two things follow, and both are easy to get backwards:

- **The reuse list excludes it.** What FCR takes from zkasper is the accumulator
  infrastructure, the BLS aggregate signature verification, the Poseidon
  multi-proof, the cross-slot dedup pattern and the witness-generator framework.
  The committee proof is not on that list, and neither is the epoch-ahead
  scheduling built around it.
- **The shuffle question is finality's, not FCR's.** "Is the shuffle necessary?
  Yes to compute, no to prove", in
  [../finality/assumptions.md](../finality/assumptions.md), is an argument about
  a proof that sums over per-slot buckets. FCR sums over head votes and never
  partitions validators by slot, so that argument neither applies to it nor is
  needed by it. Carrying a conclusion across in either direction is a mistake.

Per-slot committee weights would buy a tighter threshold, and
[architecture.md](architecture.md) prices three ways of obtaining them. All three
are V2, and **none is assumed by the design as written.**

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

## 4. The adversary budget is the whole stake, not a committee share

The design budgets the whole stake of the adversary rather than a per-slot
committee share. An unproven assignment lets a colluding prover place
adversarial stake into a one-slot window. The default byzantine threshold is
25%.

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
- **Child program keys are not baked, because no guest exists.** The discipline
  in finality's "Which program a child proof came from" is what an FCR build
  would have to follow before `fcr-confirm-guest` could trust an
  `fcr-slot-proof-guest` child.

---

## 6. A confirmation is a snapshot, not a standing claim

An FCR proof says "at slot S, block B was confirmed". It does not say that B
stays canonical. The full FCR reverts its confirmed root to the finalized root
when conditions change, and a proof cannot revert itself once it is on another
chain. Whether the verifier contract tracks confirmation validity windows, and
what a consumer does when a confirmed block is later reorged out, are open
questions of the design and are listed as such in
[architecture.md](architecture.md).

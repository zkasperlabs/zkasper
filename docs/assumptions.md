# Trust assumptions and accepted risks

Read this before you trust a zkasper proof.

A finalization proof claims one thing. **In each of two consecutive epochs, at
least 2/3 of the active effective balance attested to the target checkpoint.**
The accumulator commits to the validator set behind those balances. Everything
that claim rests on is listed here. Each entry says whether a broken assumption
costs liveness (no proof) or soundness (a false proof).

---

## 1. What a consumer must do

### The accumulator advances optimistically

The epoch-diff proof proves a registry delta between two claimed state roots. It
does not prove that the second state is the canonical successor of the first. A
prover can therefore branch the accumulator onto a fabricated validator set.

**A consumer must require that every state root the accumulator passed through
is later named by a finalization proof.** An attacker cannot forge that without
2/3 of the real validator set attesting to their fabricated state. A branched
accumulator therefore can never be confirmed, and the obligation to check sits
with the consumer.

The same argument is stated in `crates/common/src/types.rs`,
`crates/finalization-guest/src/lib.rs` and `crates/stream-final-guest/src/lib.rs`.
The Solidity verifier stores `latestFinalizedStateRoot` and does not yet
cross-check it against the diff chain.

The state root a finalization publishes is the one at the epoch's first slot,
opened out of the justified checkpoint's `state_roots`. It is not the finalized
block's own state root, and the two differ whenever that slot is empty: the
checkpoint is then an earlier block, and the boundary state is what the empty
slots advanced its post-state to. The published value is always the state the
accumulator was built from, which is what the rule above needs. The same opening
takes `block_roots` at that slot and requires it to be the finalized root, so the
checkpoint and the state come from one chain rather than two.

### The bootstrap state is the root of trust

Bootstrap builds the accumulator from one beacon state that the operator chose.
The verifier contract accepts the first bootstrap unconditionally. There is no
weak-subjectivity logic anywhere in the repository. Whoever deploys picks the
root of trust, and every later proof chains back to it.

---

## 2. What the circuits trust

### Committee assignment is unproven witness

**This is the subtlest assumption in the system, and it is deliberate.** The
committee proof does not compute the swap-or-not shuffle. The per-slot
assignment is plain witness, and the RANDAO seed is not bound in circuit.

What soundness needs from the assignment is only that the slot buckets are
**pairwise disjoint**. That is structural rather than assumed: leaves are
consumed in strictly increasing index order, so each validator is read once and
lands in exactly one bucket, whatever the witness claims.

Given disjointness, a wrong assignment cannot inflate anything. Write `U_s` for
the bucket the prover assigned to slot `s`, and `A_s` for the absentees it
names. The pairing forces `U_s \ A_s` to be exactly the validators who signed
the message of slot `s`, so the support of that slot is their balance. The
buckets are disjoint and each slot is counted at most once downstream, so a sum
over slots counts every validator at most once. A prover who fabricates the
shuffle gets a bucket whose members did not sign the message it is paired
against. That prover produces no proof at all.

**A wrong committee assignment is a liveness failure, not a soundness failure.**
That is why 90 rounds of swap-or-not over a million validators stay off the
prover entirely.

The public key side is pinned by the signature. The balance side is not, and
that part is got right by construction: the accumulator leaf is a single
Poseidon2 hash over `(pubkey, active_effective_balance)`, and `verify` sums both
totals from the same opened leaf in the same pass. A validator therefore cannot
contribute its key to one total and some other balance to the other.

**The one thing the pipeline must not do is mix buckets from two different
committee proofs of the same epoch.** Two partitions of the same validator set
overlap, and the disjointness argument is about one partition. Every proof
downstream therefore carries `CommitteeOutput::committee_root` and binds it.

The full argument is the module documentation of
`crates/common/src/committee.rs`. Read it before you change anything in that
file.

### The beacon node is trusted for the shuffle

The assignment comes straight off `/eth/v1/beacon/states/{id}/committees`, which
is the swap-or-not shuffle of the node itself. Nothing in the host recomputes
it, and nothing in the circuit checks it.

**A node that lies costs liveness only**, for the reason above: it produces
buckets that are disjoint but wrong, and the signatures then fail to verify.

### Public keys are not subgroup-checked

The consensus specification checks proof of possession once, at deposit time,
and skips the check when it verifies attestations. zkasper does the same. The
accumulator only ever holds keys that the beacon state already accepted. A check
in circuit costs one scalar multiplication per attester for no extra guarantee.
A component outside the r-torsion pairs to 1 against a G2 element of order r, so
it cannot affect the equation either.

The host does subgroup-check keys on ingest, because `blst` validates the
subgroup when it deserializes.

The other Miller loop inputs are covered as follows:

- **Public keys** are on-curve and canonical because they come out of an
  accumulator leaf that commits to them, and a sum of on-curve points is
  on-curve.
- **Message points** come from `hash_to_curve_g2`, which clears the cofactor, so
  they are in G2 by construction.
- **The signature sum** is the one input an attacker chooses freely, and it is
  subgroup-checked. Without that check a signature outside G2 satisfies the
  equation without a discrete logarithm.
- **Identity inputs** are rejected rather than skipped.

Individual signatures need no subgroup check of their own, because the equation
only ever involves their sum.

### Distinct validator public keys have no linear relation

Aggregation drives `syscall_bls12_381_curve_add` directly, which needs
`p1 != p2` and `p1 != -p2`. A collision needs a partial sum to land exactly on
the next point or its negation, which is a discrete-logarithm problem.
`aggregate_points` rejects the case rather than assuming it away.

Complement proving rests on the same assumption from the other side. The derived
aggregate key is a committee sum minus a non-negative sum of opened keys. No such
subtraction produces a key with a coefficient of two. A host that hands over
two overlapping aggregates of one message therefore gets a proof that does not
verify, not a proof that over-counts.

### Attestations over one message are merged, not rejected

Since Electra, `AttestationData.index` is pinned to 0 and committee identity
lives in `committee_bits`. Two aggregates in one block that cover different
committees therefore carry byte-identical `AttestationData`. Rejecting that case
rejects real mainnet blocks — measured, 4 of 34 slots in epoch 430529. The
circuit merges them instead. Merging is sound, because summing two aggregates
over the same message adds their public keys and their signatures in step.

---

## 3. Accepted risks

### The slashed-validator gap

`ValidatorData` carries no `slashed` field, and the SSZ field verifier treats
that leaf as opaque. A validator that is slashed mid-epoch keeps a far-future
`exit_epoch` for about 36 days. zkasper therefore counts it as active, and its
full effective balance goes into both the total and the committee aggregate.

The specification excludes slashed validators from the attesting balance that
justifies a checkpoint. zkasper does not. **This inflates support in the unsafe
direction, and an attacker can self-slash deliberately.**

**This is an accepted risk, carried knowingly.** It is recorded so that it is a
known gap rather than an undiscovered bug. Revisit it before any bridge secures
real value.

### The FFG source checkpoint is not constrained

The circuits assert that every attestation names the expected target epoch and
target root. They never compare `data_source_epoch` and `data_source_root`
against the checkpoint that the epoch builds on. The signature binds both
fields, and every attestation in one group must agree on them, but nothing pins
them to the justified checkpoint.

A zkasper proof therefore claims **that a supermajority attested to the
target**, which is weaker than the justification rule of the specification. The
protection against a mismatched source is the slashing rules of the protocol,
not the proof. Fix this before a bridge secures value.

### The batch justification divides by an unbound balance

`justification-guest` checks the 2/3 threshold against
`witness.total_active_balance`, which arrives as a free scalar. The guest holds
no `acc_root`, so it cannot recompute
`acc::commitment(acc_root, total_active_balance)`, and `JustificationOutput`
does not publish the balance either.

A prover on the batch path can therefore name a small total and clear the gate.
The streaming path does bind it: both `slot-proof-guest` and
`stream-final-guest` assert the commitment over `(acc_root,
total_active_balance)` before they use either. **Do not secure value with
`--mode batch`.**

### Native mode proves nothing cryptographically

`verify_child` accepts an empty proof on native targets, so that circuit logic
can run in tests without a prover. Inside a guest an empty proof is rejected.
`--prover native` is the default of the daemon, and it produces empty proofs. It
is a witness-only mode. Only `--prover zisk` produces proofs that a consumer can
verify.

### Reorg detection is the word of the node

The daemon learns about a reorg from the `chain_reorg` event of the beacon node.
A node that never emits one leaves the flag clear. The backstop is that the
daemon re-resolves the checkpoint root before it publishes, which asks the same
node again. A checkpoint that reorgs out is a retry and never a publication, and
that costs publication latency rather than a stale publication.

One slot carries about 3.1% of the stake, and the epoch that crosses the
threshold has about 1.85 points of headroom over 2/3. A one-slot reorg of the
crossing block therefore removes more stake than the headroom holds. Detection
is what guards this, not margin.

### Under-counting is safe and it happens

A committee member whose attestation has not arrived is an absentee. That
lowers the support of its slot and nothing else. The weight is therefore honest
at every instant, and waiting buys a cheaper proof rather than a valid one.

---

## 4. The fast confirmation rule

FCR is designed and **not built**. No `fcr` code exists in this repository.
[FCR_CIRCUIT_DESIGN.md](../FCR_CIRCUIT_DESIGN.md) holds the design. Two standing
decisions bound it.

### `equivocation_score` is permanently zero

A circuit sees only on-chain state, so it can never reproduce
`store.equivocating_indices` of the fork-choice implementation. Any subset of
that set raises the confirmation threshold, so **zero is the most conservative
value available**. The term only moves the threshold once equivocating stake
reaches about 0.1% of the total, which mainnet has never approached.
`support_discount` stays zero for the same reason.

### FCR assumes good network conditions

FCR is a fast path for the healthy case only. When the network breaks, zkasper
does not keep confirming with a degraded FCR proof. **It falls back to two-epoch
finality, which runs all the time anyway.**

Two consequences follow. Complement proving needs no low-participation fallback.
`support_discount` stays zero permanently, because a missed slot is exactly the
unhealthy case that finality takes back.

The design budgets the whole stake of the adversary rather than a per-slot
committee share. An unproven assignment lets a colluding prover place
adversarial stake into a one-slot window. The default byzantine threshold is
25%.

---

## 5. Measured, modelled, and not yet true

[BENCHMARKS.md](../BENCHMARKS.md) labels every constant. The summary:

**Measured** on an RTX 5090 against Zisk v1.1.0-alpha:

- the stage floor, the empty-guest floor, and the per-proof floor and slope
- the accumulator node cost, the wrap, and the cold penalty
- every precompile cost, and the VRAM behaviour

**Carried forward from Zisk v1.0.0-alpha**: the cost per opened validator and
the cost per committee member. The attester sweep cannot be reproduced, because
a group-proof witness is now a slot complement. Every constant that was
re-measured improved, so carrying these two forward can only make the schedule
look worse than it is.

**Modelled, not measured**:

- **`T2 - T` is 5.5 s in a model**, over measured per-stage times. **No
  streaming epoch has a real end-to-end proof yet.**
- **Recursive verification is a parameter with a default of zero.** Both stages
  that exercise it can only be proved with it removed. Their fixtures carry stub
  child proofs. It is not a zero, and at 1 s per child the schedule
  needs a second GPU.
- **The Fp2-tower rate is fitted**, with a bracket from 162M to 268M units per
  second. Nothing in the campaign runs BLS at mainnet scale.
- **The committee proof cost at mainnet scale is an extrapolation** from
  witnesses of 16,000 to 64,000 members.

**Cost units are not comparable across Zisk versions.** v1.1.0-alpha re-priced
`POSEIDON_COST` by 5.23x without changing the work. Compare wall clock, or
re-measure.

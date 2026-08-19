# Finality: trust assumptions and accepted risks

Read this before you trust a zkasper **finalization** proof.

A finalization proof claims one thing. **In each of two consecutive epochs, at
least 2/3 of the active effective balance attested to the target checkpoint.**
The accumulator commits to the validator set behind those balances. Everything
that claim rests on is either listed here or in
[../shared/assumptions.md](../shared/assumptions.md), which holds what this
proof shares with the fast confirmation rule: the accumulator, the init point,
the BLS arithmetic, native mode, and the on-chain wrap. **Neither page is
complete on its own.**

The fast confirmation rule is a different product with a different threshold and
different circuits. Nothing here applies to it unless
[../fcr/assumptions.md](../fcr/assumptions.md) says so.

Each entry says whether a broken assumption costs liveness (no proof) or
soundness (a false proof).

---

**The committee proof and the shuffle**: the assignment is proven once per
epoch, an epoch ahead, inside the committee proof -- see
[../shared/committee-and-shuffle.md](../shared/committee-and-shuffle.md).
Finality does not require it proven, for the reason in section 1; FCR does,
because its denominator is a bucket rather than the total. One proof serves both.

## 1. Is the shuffle necessary? Yes to compute, no to prove

**Settled. Do not reopen without new evidence** -- this gets asked repeatedly
because the two halves are easy to confuse for each other.

**Computing it: necessary.** The host must use the real swap-or-not shuffle. A
validator's signature is over AttestationData, which contains the **slot**, so a
bucket can only pair against a message its members actually signed. Feed the
circuit a made-up assignment and the multi-pairing fails and **no proof comes
out**. The shuffle is not optional anywhere in this system.

**Proving it: not necessary.** The circuit does not recompute the shuffle and
does not bind the RANDAO seed, and this costs nothing in soundness.

### The objection, stated plainly

*"Without checking the shuffle, a validator can fake attestations into whatever
slot they like."*

They can sign for a slot they were not assigned -- nothing prevents producing
that signature, and Ethereum would reject the attestation where this circuit
accepts it. **It gains them nothing**, because the quantity proved is a sum over
*validators*, not over slots:

- **Counting one validator twice is blocked by disjointness.** Leaves are
  consumed in strictly increasing index order, so each validator lands in exactly
  one bucket whatever the witness claims. Moving someone from bucket 5 to bucket
  7 adds no balance; it is the same validator, counted once either way.
- **Counting a validator who did not sign is blocked by the pairing.** It forces
  the bucket minus its absentees to be exactly the signers of that slot's
  message. Pad a bucket with a non-signer and the aggregate key comes out wrong;
  name them as an absentee and their balance is subtracted anyway.
- **Moving balance away from a key is blocked by the leaf.** One Poseidon2 hash
  over pubkey and active effective balance, summed in the same pass, so a
  validator cannot lend its key to one total and a different balance to the other.

The adversary's own stake counts once whichever bucket it sits in, and honest
stake is untouched. No arrangement of buckets inflates the total.

### What it means precisely

The proof establishes **"validators holding at least two thirds of active stake
signed this target"**. It does **not** establish "Ethereum's fork choice
justified this epoch under its own committee rule". Those coincide whenever
validators attest in their assigned slots, which honest validators always do. An
adversary attesting off-slot produces something Ethereum discards and this
circuit counts -- and still cannot inflate the total.

A consumer needing the second statement rather than the first would require the
shuffle bound in circuit, and this section would stop applying. **Nobody has
asked for that**, and it would put 90 rounds of swap-or-not over a million
validators on the prover.

---

## 2. What a consumer must do

The accumulator's two obligations — that every state root it passed through is
later named by a finalization proof, and that the init point is regenerated
rather than believed — are in
[../shared/assumptions.md](../shared/assumptions.md). This is what a
finalization proof adds to them.

### What a finalization publishes as the anchor state root

The state root a finalization publishes is the one at the epoch's first slot,
opened out of the justified checkpoint's `state_roots`. It is not the finalized
block's own state root, and the two differ whenever that slot is empty: the
checkpoint is then an earlier block, and the boundary state is what the empty
slots advanced its post-state to. The published value is always the state the
accumulator was built from, which is what the rule above needs. The same opening
takes `block_roots` at that slot and requires it to be the finalized root, so the
checkpoint and the state come from one chain rather than two.

### A justification proof is one link of a chain, and the flag is the claim

`justification-guest` folds an epoch's slot proofs a few at a time, each link
verifying its predecessor and the slot proofs added since. The links before the
last are valid proofs of a partial count, so **the existence of a justification
proof does not mean the epoch was justified**. What means it is
`JustificationOutput.justified`, which the circuit *computes* — from a
`total_active_balance` it rehashed against the accumulator commitment, so the
gate divides by the balance the accumulator commits to and not one the prover
named.

**A consumer must require that flag.** Both finalization circuits do, and so
does the daemon before it publishes a justification on its own. The API
publishes it beside the attesting balance in the proof's public inputs.

The same holds for the streaming path without a flag: `stream-final-guest`
asserts the supermajority itself, and only ever exists above it.

---

## 3. What the circuits trust

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

---

## 4. Accepted risks

### Which program a child proof came from: pinned, except at three edges

**This used to be open, and it is worth knowing that it was.** Every recursive
verification read the key it checked the child against **out of the witness**:
`slot_program_vk`, `committee_program_vk`, `justification_program_vk`,
`group_program_vk`, `aggregate_program_vk`, `epoch_diff_program_vk` and
`previous_program_vk` were all fields a prover filled in. `verify_child` required
the child proof to carry that key and to verify under it — which it did — but
nothing required the key to be *this pipeline's* guest. A prover could write a
guest of their own that emitted whatever `SlotProofOutput` they liked, prove it
honestly, hand the parent its key, and get a real proof out of the honest parent
circuit. The parent's own key was unchanged, so a verifier that pinned only the
top-level program accepted it.

**The keys are now constants of the guests.** They live in
`crates/*/src/child_vks.rs`, one module per guest that verifies something, and
`scripts/bake_child_vks.sh` writes them from the ELFs. A constant is part of the
circuit: change it and the guest's ELF changes, which changes the key every
parent of that guest holds. So the keys form a dependency graph, and the script
walks it in topological order — leaves, then aggregation, then justification,
then stream-final and finalization. One pass reaches a fixed point, because
nothing written at a later step can change an ELF built at an earlier one. That
is why the constants sit in the guest crates rather than in one shared module: a
shared module would put aggregation's key in a file aggregation itself compiles,
and the graph would have a cycle with no fixed point at all.

**Rebuilding is one command, and a mismatch fails at startup.** `cargo-zisk
build` on its own leaves guests whose constants describe the previous ELFs;
`./scripts/bake_child_vks.sh` builds and bakes together, and the four generated
files are committed with the ELFs they describe.
`zkasper_witness_gen::child_vks::check` compares every key a prover derives from
an ELF against the constant the guests hold — in `ZiskProver` where the ELF is
read, and again at the prover-server handshake — and refuses to start on a
disagreement. A guest that was never baked holds all zeros, which is no
program's key, so it refuses every child proof rather than accepting one from
anywhere. The failure direction is always "no proof", never "a proof of
something else".

**Three edges cannot be baked, because they are a program's own key.** A fold
chain verifies its predecessor under the key of the program doing the verifying,
and a program that contained its own key would change the ELF that derives it.
There is no fixed point to find. Those three edges — the justification fold, the
aggregation fold, and one epoch's stream final proof consuming the last — still
read their key from the witness, and each publishes it:
`JustificationOutput.program_vk`, `AggregateOutput.program_vk` and
`StreamFinalOutput.program_vk`. Every link requires its predecessor to have
published the same key, so a chain agrees on one program throughout; what ties
that agreed key to the real program is the consumer.

For two of the three the consumer is a circuit, and the binding is closed with
nothing left over:

- `finalization-guest` and `stream-final-guest` both bake the justification
  program's key and require `JustificationOutput.program_vk` to equal it.
- `stream-final-guest` bakes the aggregation program's key and requires
  `AggregateOutput.program_vk` to equal it.

**The third is the one obligation this scheme leaves outside the circuits.**
Nothing in this repository consumes a stream final proof except the next epoch's
stream final proof, so no guest is in a position to bake that key. **An on-chain
verifier must require `StreamFinalOutput.program_vk` to equal the program key it
already pins.** Without that comparison the proof it holds is genuine and the
epoch below it is whatever the prover chose. In the public outputs the key is
the last four words: at offset 44 of 52, in the `uint32` layout
`ZkasperVerifier.sol` reads. The contract has no stream-final entry point yet,
and adding one means adding that check with it.

The same obligation applies to any consumer that reads a justification proof on
its own rather than through a finalization — the API publishes them — since the
circuit that would have made the comparison is not in the picture.

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

## 5. Measured, modelled, and not yet true

[BENCHMARKS.md](../../BENCHMARKS.md) labels every constant. The summary:

**Measured** on an RTX 5090 against Zisk v1.1.0-alpha:

- the stage floor, the empty-guest floor, and the per-proof floor and slope
- the accumulator node cost, the wrap, and the cold penalty
- every precompile cost, and the VRAM behaviour
- **recursive verification, and it is not one price across guests.**
  `justification-guest` is **53.087 s per child**, linear from 2 children to 23,
  with an intercept that lands on the stage floor. The two guests on the
  streaming critical path are **35.629 s per child** — measured in production
  over 24 epoch-opening folds, whose child count is fixed by the guest source,
  sd 0.326 s. The model carried the justification figure for both until
  2026-08-19. It was carried as zero before anything could measure it, and it is
  larger than every other constant in the model put together.

**Carried forward from Zisk v1.0.0-alpha**: the cost per opened validator and
the cost per committee member. The attester sweep cannot be reproduced, because
a group-proof witness is now a slot complement. Every constant that was
re-measured improved, so carrying these two forward can only make the schedule
look worse than it is.

**Modelled, not measured**:

- **`T2 - T` is 83.1 s in a model** over measured per-stage times, on two GPUs.
  **No prover has run this shape.** It was 112.4 s while the final proof's inline
  tail was capped at four slots and the epoch's end had to be a group it then
  verified as a child; uncapping it removes that child but not the two the final
  proof cannot avoid — the running aggregate and the previous epoch's
  justification. Every measurement below was taken against the capped shape: a
  production stream-final proof took 148.2 s four times within ±1.1 s, and the
  folded path ran at 116.5 to 124.2 s. **The 67.8 s this document quoted until
  2026-08-19 is withdrawn**: the model charged the final proof one child too few
  and priced the rest at the justification guest's rate, and the two errors
  cancel only at three children. The capped shape had three and was right by
  accident; the uncapped shape has two and was 15.3 s optimistic. **The 5.5 s
  quoted before that was computed with recursion priced at zero and is also
  withdrawn.**
- **The Fp2-tower rate is fitted**, with a bracket from 162M to 268M units per
  second. Nothing in the campaign runs BLS at mainnet scale.
- **The committee proof cost at mainnet scale is an extrapolation** from
  witnesses of 16,000 to 64,000 members.

**Cost units are not comparable across Zisk versions.** v1.1.0-alpha re-priced
`POSEIDON_COST` by 5.23x without changing the work. Compare wall clock, or
re-measure.

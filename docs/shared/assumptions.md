# Shared trust assumptions

zkasper builds two proofs, and they are two products with two threat models:
the **finality proof** and the **fast confirmation rule proof**. This page holds
only what both rest on — the validator-set accumulator underneath them, the BLS
arithmetic they share, and the prover and the wrap that produce them. Nothing
here is specific to either claim.

Read it beside the product page you care about. Neither page is complete alone.

| product | what it claims | its assumptions |
|---|---|---|
| finality | in each of two consecutive epochs, at least 2/3 of the active effective balance attested to the target checkpoint | [../finality/assumptions.md](../finality/assumptions.md) |
| FCR | at one slot, head votes above an adversary-aware threshold all descend from one block | [../fcr/assumptions.md](../fcr/assumptions.md) |

Each entry below says whether a broken assumption costs liveness (no proof) or
soundness (a false proof).

---

## 1. The accumulator

Both proofs open validator balances out of the same Poseidon2 accumulator, and
both inherit everything that tree rests on.

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
What a finalization proof publishes as that state root, and why that is the
value this rule needs, is in
[../finality/assumptions.md](../finality/assumptions.md).

### The init point is the root of trust

The accumulator chain starts from an **init point**: a small JSON tuple of
`(chain, epoch, state_root, num_validators, total_active_balance, acc_root,
accumulator_commitment, state_to_validators_siblings)` that an operator gives
`zkasperd` on a fresh run. Whoever deploys picks it, the verifier contract
accepts the first commitment unconditionally, and there is no weak-subjectivity
logic anywhere in the repository. Every later proof chains back to that choice.

**This used to be a proof, and deleting the proof moved less than it looks.**
Bootstrap rebuilt Ethereum's depth-40 validators tree and the depth-22
accumulator over every validator in a beacon state and proved in-circuit that
the two agreed under a claimed `state_root`. It never proved the root was
canonical Ethereum — that was the operator's choice then, exactly as it is now,
and this section has always said so. What the proof gave a consumer was a way to
check the accumulator against the state root without redoing the work. Removing
it moves accumulator-correctness from *verify this proof* to *recompute it
yourself*, which anyone can do, because the accumulator is a deterministic
function of the validator list at that state. `zkasper-init-point` is that
recomputation, and it is the same code path the daemon runs.

Two things make the delta narrower still. On mainnet the bootstrap proof did not
exist: the witness over 2,338,764 validators serialized to 916 MB against a
512 MB frame cap, so the stage produced the empty proof of a witness-only run and
carried on. And nothing downstream ever verified it — the accumulator chain
begins at the operator's declared root of trust either way.

**What the daemon still checks, and refuses to start without.** `--init-point`
is read before the first beacon call and rejected unless
`acc::commitment(acc_root, total_active_balance)` equals
`accumulator_commitment`; a tuple that fails this names an accumulator nobody
holds. It then walks the registry at that epoch and refuses unless the validator
count, the total active balance, the accumulator root it rebuilds, and the state
root the supplied branch opens to all match the file. A wrong init point stops
the run at startup rather than producing proofs against an accumulator that does
not exist.

**What a consumer should do about it.** Take the deployment's published init
point, run `zkasper-init-point` against your own node at the same slot, and
compare the files byte for byte. Then apply the rule above: require every state
root the accumulator passed through — starting with the init point's — to be
named by a later finalization proof. That rule is what makes a trusted start
recoverable, and it matters more now than it did, because it is the only thing
that ties the declared starting state to the chain the validators actually
attested to.

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

---

## 2. The BLS arithmetic

Every proof that counts attesting balance closes the same pairing equation over
the same aggregate keys.

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

## 3. The prover and the wrap

### Native mode proves nothing cryptographically

`verify_child` accepts an empty proof on native targets, so that circuit logic
can run in tests without a prover. Inside a guest an empty proof is rejected.
`--prover native` is the default of the daemon, and it produces empty proofs. It
is a witness-only mode. Only `--prover zisk` produces proofs that a consumer can
verify.

### The proving system a child was proved under is pinned, and must be rederived

`zisklib::verify_zisk_proof` takes the key it checks a child's STARK against from
the **last four words of the child's own buffer**. That key is `rootC`, the
commitment to the constant polynomials, which for a circom-compiled circuit *are*
the gates and the wiring -- `proofman`'s generated `vadcop_final` and `recursive2`
verifiers are byte for byte the same code and differ only in that root. Left
witness-supplied it is a soundness hole with no floor: a prover compiles a circuit
with 69 unconstrained public signals, proves it, and every public value an honest
parent then binds -- the program key included -- is one they wrote. It was
witness-supplied until 2026-08-19.

`zkasper_common::recursion::VADCOP_FINAL_VK` pins it, and `verify_child` checks it
first. Both products inherit that from the shared crate; unlike the child program
keys, there is nothing per-guest to do, because the key belongs to a Zisk release
rather than to any ELF. The full account is in
[../finality/assumptions.md](../finality/assumptions.md), "Which proving system a
child proof was proved under".

**What a Zisk bump costs:** rederive the constant from
`provingKey/zisk/vadcop_final/vadcop_final.verkey.bin` of the new release. A stale
value costs liveness, never soundness -- it refuses every proof.

### The on-chain wrap reintroduces a trusted setup

The Zisk STARK is transparent. The PLONK wrap that puts a proof on chain is not.
It needs a structured reference string, distributed as `provingKeySnark` -- a
~21.9 GB `final.zkey` with the `recursivef` setup -- fetched from a Google Cloud
bucket and checked against a published MD5. Neither the Zisk tree nor `ziskup`
references a ceremony transcript, and nothing in the toolchain regenerates the
key. Anyone who verifies a wrapped zkasper proof therefore trusts a setup they
cannot audit and did not witness.

The SRS is universal, so the *statement* is not part of what is trusted. What the
key fixes is the circuit: `recursivef`, `final`, and the constant
`rootCVadcopFinal` that names the VADCOP final verification key. A different Zisk
release is a different key and a different on-chain verifier.

Nothing that runs today depends on this. The wrap is not on the live path, and
`zkasper-solana` expects Groth16, which Zisk v1.1.0-alpha cannot produce at all
-- its `SnarkProtocol` enum is `{ Fflonk, Plonk }`. The assumption is written
down now because it arrives with the wrap, not with the pipeline, and it is the
one trust assumption a reader would not predict from the rest of this page.

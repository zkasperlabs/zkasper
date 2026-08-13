# FCR Circuit Design — 1-Slot Finality Confirmation via ZK

Based on [Lighthouse PR #8951](https://github.com/sigp/lighthouse/pull/8951) (Fast Confirmation Rule).

## Motivation

zkasper currently proves **Casper FFG finality** (~13 minutes / 2 epochs). The Fast Confirmation
Rule (FCR) from the Lighthouse PR can confirm blocks as safe within **1 slot (~12 seconds)** by
analyzing LMD-GHOST attestation support against an adversary-aware safety threshold.

A ZK proof of FCR confirmation lets another network (bridge target) trust Ethereum blocks in ~12s
instead of waiting for full finality.

## Key differences from existing finality proof

| Aspect | Current finality proof | FCR confirmation proof |
|--------|------------------------|------------------------|
| What's proven | ≥2/3 of stake attested to FFG target | Head votes exceed safety threshold |
| Latency | ~13 min (2 epochs) | ~12 sec (1 slot) |
| Attestation semantics | Target (FFG) votes for checkpoint | Head (LMD-GHOST) votes for blocks |
| Chain awareness | None (just a checkpoint root) | Needs block ancestry proofs |
| Threshold | Simple: `balance * 3 >= total * 2` | Complex: adversary-aware safety bound |
| Security assumption | Byzantine fault tolerance 1/3 | Configurable `byzantine_threshold` (default 25%) |

## What can be reused from zkasper

- **Entire accumulator infrastructure**: bootstrap, epoch-diff, Poseidon tree — unchanged
- **BLS aggregate signature verification**: identical
- **Poseidon multi-proof**: same leaf format and multi-proof verification
- **Cross-slot dedup**: `counted_validators_commitment` pattern
- **Witness generator framework**: beacon API, attestation collection (minor mods)

## What's new

1. **Block ancestry verification** — prove each head vote descends from the confirmed block
2. **Safety threshold computation** — adversary-aware bound instead of 2/3
3. **LMD-GHOST vote filtering** — collect by `beacon_block_root` chain membership
4. **2 new guest crates**: `fcr-slot-proof-guest`, `fcr-confirm-guest`

## Architecture

```
                  ┌─────────────────┐
                  │   bootstrap     │  (existing, unchanged)
                  │   epoch-diff    │
                  └────────┬────────┘
                           │ accumulator_commitment
                           ▼
              ┌────────────────────────────┐
              │   fcr-slot-proof-guest     │  × N blocks in the slot range
              │   (per-block head votes)   │
              └────────────┬───────────────┘
                           │ FcrSlotProofOutput
                           ▼
              ┌────────────────────────────┐
              │   fcr-confirm-guest        │  aggregation + threshold check
              └────────────┬───────────────┘
                           │ FcrConfirmationOutput
                           ▼
              ┌────────────────────────────┐
              │   on-chain verifier        │
              │   (target network)         │
              └────────────────────────────┘
```

## Types

```rust
/// Proves a block header's parent_root field links to the next block in the ancestry chain.
/// BeaconBlockHeader SSZ layout: [slot, parent_root, state_root, body_root, proposer_index]
/// 5 fields → padded to 8 → depth-3 tree. parent_root is field index 1.
pub struct BlockAncestryStep {
    pub block_root: [u8; 32],
    /// SSZ siblings (3 levels) proving parent_root is field 1 in the header
    pub header_siblings: [[u8; 32]; 3],
    pub parent_root: [u8; 32],
}

/// LMD-GHOST attestation with ancestry proof back to the confirmed block.
pub struct FcrAttestationWitness {
    // Standard attestation data fields (same as AttestationWitness)
    pub data_slot: u64,
    pub data_index: u64,
    pub data_beacon_block_root: [u8; 32],  // the head vote
    pub data_source_epoch: u64,
    pub data_source_root: [u8; 32],
    pub data_target_epoch: u64,
    pub data_target_root: [u8; 32],
    pub signature: BlsSignature,
    pub attesting_validators: Vec<AttestingValidator>,

    /// Ancestry proof: data_beacon_block_root -> ... -> confirmed_block_root
    /// Empty if data_beacon_block_root == confirmed_block_root (direct vote).
    /// Typical depth: 0–2 blocks (most validators vote for the same head).
    pub ancestry_chain: Vec<BlockAncestryStep>,
}

/// Witness for FCR slot proof (one block's head attestations).
pub struct FcrSlotProofWitness {
    pub accumulator_commitment: [u8; 32],
    pub confirmed_block_root: [u8; 32],
    pub signing_domain: [u8; 32],

    pub poseidon_root: [u8; 32],
    pub total_active_balance: u64,
    pub attestations: Vec<FcrAttestationWitness>,
    pub poseidon_multi_proof: MerkleMultiProof,
}

/// Public outputs of an FCR slot proof.
pub struct FcrSlotProofOutput {
    pub accumulator_commitment: [u8; 32],
    pub confirmed_block_root: [u8; 32],
    pub attesting_balance: u64,
    pub counted_validators_commitment: [u8; 32],
    pub num_counted_validators: u64,
}

/// Witness for FCR confirmation (aggregate slot proofs + safety threshold).
pub struct FcrConfirmationWitness {
    pub accumulator_commitment: [u8; 32],
    pub total_active_balance: u64,
    pub confirmed_block_root: [u8; 32],
    pub confirmed_at_slot: u64,

    pub slot_proof_outputs: Vec<FcrSlotProofOutput>,
    pub slot_proof_proofs: Vec<Vec<u8>>,
    pub counted_indices_per_slot: Vec<Vec<u64>>,

    /// Safety parameter: max % of stake an adversary controls (default 25).
    pub byzantine_threshold_pct: u64,
}

/// Public outputs of FCR confirmation.
pub struct FcrConfirmationOutput {
    pub accumulator_commitment: [u8; 32],
    pub confirmed_block_root: [u8; 32],
    pub confirmed_at_slot: u64,
}
```

## Circuit logic

### FCR Slot Proof

```rust
fn verify_fcr_slot_proof(w: &FcrSlotProofWitness) -> FcrSlotProofOutput {
    // 1. Verify accumulator commitment
    assert_eq!(
        accumulator_commitment(&w.poseidon_root, w.total_active_balance),
        w.accumulator_commitment,
    );

    let mut attesting_balance = 0u64;
    let mut multi_proof_leaves = Vec::new();
    let mut counted_indices = Vec::new();

    for att in &w.attestations {
        // 2. Verify block ancestry: head vote descends from confirmed block
        verify_block_ancestry(
            &att.data_beacon_block_root,
            &w.confirmed_block_root,
            &att.ancestry_chain,
        );

        // 3. Process validators (identical to existing slot-proof logic)
        for v in &att.attesting_validators {
            if v.count_balance {
                attesting_balance += v.active_effective_balance;
                counted_indices.push(v.validator_index);
                multi_proof_leaves.push((
                    poseidon_leaf(&v.pubkey.0, v.active_effective_balance),
                    v.validator_index,
                ));
            }
        }
    }

    // 4. Poseidon multi-proof (identical to existing)
    multi_proof_leaves.sort_unstable_by_key(|&(_, idx)| idx);
    // ... dedup check, verify root ...

    // 5. BLS aggregate signatures (identical to existing)
    for att in &w.attestations {
        let data_root = attestation_data_root(/* fields */);
        let signing_root = compute_signing_root(&data_root, &w.signing_domain);
        verify_aggregate_signature(&pubkeys, &signing_root, &att.signature.0);
    }

    FcrSlotProofOutput { /* ... */ }
}
```

### Block ancestry verification

```rust
/// Verify that `head_root` descends from `confirmed_root` via a chain of parent_root links.
fn verify_block_ancestry(
    head_root: &[u8; 32],
    confirmed_root: &[u8; 32],
    chain: &[BlockAncestryStep],
) {
    if head_root == confirmed_root {
        assert!(chain.is_empty());
        return;
    }

    let mut current = *head_root;
    for step in chain {
        assert_eq!(current, step.block_root, "ancestry chain broken");

        // BeaconBlockHeader: 5 fields padded to 8, parent_root at index 1
        // Verify parent_root is field 1 in the SSZ hash-tree of this block header
        let leaf = step.parent_root;  // field 1 is already a 32-byte root
        let field_index = 1u64;
        let computed_root = compute_root(sha256_pair, &leaf, field_index, &step.header_siblings);
        assert_eq!(computed_root, step.block_root, "header SSZ proof invalid");

        current = step.parent_root;
    }
    assert_eq!(current, *confirmed_root, "ancestry doesn't reach confirmed block");
}
```

Cost: ~3 SHA-256 per hop. Typical depth 0–2, so 0–6 SHA-256 total. Negligible.

### FCR Confirmation (threshold check)

```rust
fn verify_fcr_confirmation(w: &FcrConfirmationWitness) -> FcrConfirmationOutput {
    // 1. Verify and aggregate slot proofs (same pattern as justification)
    let mut total_attesting = 0u64;
    for (i, out) in w.slot_proof_outputs.iter().enumerate() {
        verify_proof(&w.slot_proof_proofs[i], /* ... */);
        assert_eq!(out.accumulator_commitment, w.accumulator_commitment);
        assert_eq!(out.confirmed_block_root, w.confirmed_block_root);
        total_attesting += out.attesting_balance;
    }

    // 2. Cross-slot dedup (identical to justification)
    // ... merge sorted indices, assert uniqueness ...

    // 3. Safety threshold check (simplified — see "Committee refinement" below)
    //
    // From the FCR spec:
    //   threshold = (max_weight + proposer_boost + 2 * adversarial_weight - discount) / 2
    //
    // Simplified (no per-slot committee data, no proposer boost, no discount):
    //   adversarial_weight = byzantine_threshold_pct * total_active_balance / 100
    //   threshold = (total_active_balance + 2 * adversarial_weight) / 2
    //
    // This is a conservative bound: the actual per-slot committee weight is always
    // <= total_active_balance, so this threshold is >= the true threshold.
    let adversarial = w.total_active_balance * w.byzantine_threshold_pct / 100;
    let threshold = (w.total_active_balance + 2 * adversarial) / 2;

    assert!(
        total_attesting > threshold,
        "FCR: insufficient attestation support {} vs threshold {}",
        total_attesting, threshold,
    );

    FcrConfirmationOutput {
        accumulator_commitment: w.accumulator_commitment,
        confirmed_block_root: w.confirmed_block_root,
        confirmed_at_slot: w.confirmed_at_slot,
    }
}
```

## Threshold analysis

With `byzantine_threshold_pct = 25` and the simplified formula:

```
adversarial = 0.25 * total
threshold = (total + 0.50 * total) / 2 = 0.75 * total
```

So confirmation requires **>75% of total active balance** attesting to the confirmed block's chain.
This is more conservative than the per-slot FCR (~60-65% of committee weight) but still achievable
within 1 slot on a healthy network (typical participation is ~98%).

For comparison, full Casper finality requires 66.7% but over 2 epochs.

## Committee refinement (optional, tighter threshold)

The full FCR uses per-slot committee weights for a tighter threshold. To support this in ZK:

**Option A — Committee accumulator** (recommended for V2):
- Add a Poseidon tree that commits to `(validator_index, assigned_slot)` per epoch
- An epoch-diff style proof updates it when the shuffling seed changes
- FCR circuit reads committee assignments via multi-proof
- Tighter threshold: only count committee weight for the relevant slot range

**Option B — Prove from beacon state**:
- The beacon state caches committee assignments
- Verify via SSZ Merkle path from state_root
- Avoids recomputing RANDAO shuffle but requires deep state access

**Option C — Accept as trusted input** (fastest to implement, weaker):
- Committee assignments provided in witness, not verified in circuit
- Still useful when the bridge operator is trusted

## Witness generation changes

The existing `attestation_collector.rs` collects attestations by target checkpoint. For FCR:

1. **Collect by head vote**: instead of filtering `data_target_root == checkpoint_root`, filter
   attestations where `data_beacon_block_root` is a descendant of `confirmed_block_root`
2. **Build ancestry proofs**: for each unique `data_beacon_block_root`, construct the chain of
   `BeaconBlockHeader` SSZ proofs back to the confirmed block
3. **Use existing infrastructure**: the same Poseidon tree, multi-proof generation, and BLS
   verification pipeline applies

```rust
// New CLI command
zkasper-witness-gen fcr-confirm --beacon-url <URL> --block-root 0x... --slot <S>
```

## Cost estimate

For 1-slot confirmation with ~200K attesting validators:

| Operation | Count | Cost |
|-----------|-------|------|
| Poseidon multi-proof | 200K leaves × 40 levels | ~8M Poseidon (dominant) |
| BLS aggregate verify | ~32 attestations | ~32 pairing checks |
| Ancestry proofs | ~3 unique heads × 2 hops | ~18 SHA-256 (negligible) |
| Safety threshold | 1 mul + 1 div + 1 cmp | trivial |

**Total cost is essentially identical to the existing finality proof.** The FCR-specific additions
(ancestry proofs + threshold) add <0.001% overhead.

## On-chain verifier

```solidity
contract ZkasperFcrVerifier {
    bytes32 public accumulatorCommitment;
    // ... (bootstrap + epoch-diff same as existing) ...

    // NEW: submit FCR confirmation proof
    function submitFcrConfirmation(
        bytes calldata proof,
        bytes32 confirmedBlockRoot,
        uint64 confirmedAtSlot
    ) external {
        // Verify ZK proof
        require(verifier.verify(proof, publicOutputs), "invalid proof");

        // Verify accumulator matches stored state
        require(outputs.accumulatorCommitment == accumulatorCommitment, "stale accumulator");

        // Store confirmed block
        confirmedBlocks[confirmedBlockRoot] = confirmedAtSlot;
        emit BlockConfirmed(confirmedBlockRoot, confirmedAtSlot);
    }

    function isConfirmed(bytes32 blockRoot) external view returns (bool) {
        return confirmedBlocks[blockRoot] != 0;
    }
}
```

## Implementation order

1. Add FCR types to `common/types.rs`
2. Add `verify_block_ancestry` to `common/ssz.rs`
3. Create `fcr-slot-proof-guest/` (fork of `slot-proof-guest/` with ancestry check)
4. Create `fcr-confirm-guest/` (fork of `justification-guest/` with threshold check)
5. Extend witness-gen with `fcr-confirm` command (head vote collection + ancestry proofs)
6. Tests with mock data
7. (V2) Committee accumulator for tighter threshold

## Open questions

1. **Reversion handling**: The full FCR reverts `confirmed_root` to finalized when conditions change
   (e.g., epoch boundary, chain reorg). In ZK-bridge context, a confirmation is a snapshot: "at slot
   S, block B was confirmed." Should the verifier contract track confirmation validity windows?

2. **FFG guards**: The full FCR checks that no conflicting checkpoint can be justified. For a bridge,
   this may not be needed — if the confirmed block IS later reorged, the bridge can fall back to the
   existing finality proof as the canonical source of truth.

3. **Proposer boost**: Including proposer boost in the threshold requires knowing the proposer for
   the current slot. This is derivable from the beacon state (committee assignments). Worth adding
   in V2 with the committee accumulator.

4. **Byzantine threshold parameter**: Should this be hardcoded (25%) or configurable per-deployment?
   The on-chain verifier could enforce a minimum threshold.

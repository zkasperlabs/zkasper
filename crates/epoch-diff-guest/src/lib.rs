// Re-export verification functions for use by integration tests and other crates.

extern crate alloc;

use alloc::vec::Vec;
use zkasper_common::acc::Digest;
use zkasper_common::types::EpochDiffWitness;

/// Core epoch-diff verification logic. Returns (new_accumulator_commitment, new_poseidon_root, new_total_active_balance).
pub fn verify_epoch_diff(witness: &EpochDiffWitness) -> (Digest, Digest, u64) {
    verify_epoch_diff_with_depth(
        witness,
        zkasper_common::constants::VALIDATORS_TREE_DEPTH,
        zkasper_common::constants::ACC_TREE_DEPTH,
    )
}

/// Epoch-diff verification with configurable tree depths.
///
/// `ssz_depth`: depth of the SSZ validators data tree (40 per spec).
/// `acc_depth`: depth of the accumulator tree.
pub fn verify_epoch_diff_with_depth(
    witness: &EpochDiffWitness,
    ssz_depth: u32,
    acc_depth: u32,
) -> (Digest, Digest, u64) {
    use zkasper_common::acc;
    use zkasper_common::ssz::{
        compute_ssz_merkle_root, list_hash_tree_root, validator_hash_tree_root,
        validator_hash_tree_root_pair, verify_field_leaves, verify_field_leaves_no_pubkey_hash,
        verify_ssz_multi_proof,
    };

    // Verify Poseidon siblings length matches expected depth
    for mutation in &witness.mutations {
        assert_eq!(
            mutation.acc_siblings.len(),
            acc_depth as usize,
            "poseidon siblings length mismatch for validator {}",
            mutation.validator_index,
        );
    }

    let mut acc_root = witness.acc_root_1;
    let mut total_active_balance = witness.total_active_balance_1;
    let epoch_old = witness.epoch_1;
    let epoch_new = witness.epoch_2;

    // Phase 1: Per-mutation validation + Poseidon updates (sequential)
    // Collect SSZ leaves for multi-proof verification
    let mut old_ssz_leaves: Vec<([u8; 32], u64)> = Vec::with_capacity(witness.mutations.len());
    let mut new_ssz_leaves: Vec<([u8; 32], u64)> = Vec::with_capacity(witness.mutations.len());

    for mutation in &witness.mutations {
        let idx = mutation.validator_index;

        // Decompressed once per mutation and reused for both the old and the new
        // leaf. Public keys never change for an existing validator, which the
        // field-leaf checks below enforce, so one decompression covers both.
        let point = zkasper_common::bls::decompress_pubkey(&mutation.new_data.pubkey.0)
            .unwrap_or_else(|| panic!("validator {idx} has an invalid public key"));

        if mutation.is_new {
            // New validator: the old leaf is empty in both trees.
            old_ssz_leaves.push(([0u8; 32], idx));

            let computed_old_root = zkasper_common::merkle::compute_root(
                acc::compress,
                &acc::ZERO,
                idx,
                &mutation.acc_siblings,
            );
            assert_eq!(
                computed_old_root, acc_root,
                "accumulator root mismatch before new validator {}",
                idx
            );

            // -- Verify new field leaves + compute new HTR --
            verify_field_leaves(
                &mutation.new_data,
                &mutation.new_field_leaves,
                &mutation.new_pubkey_chunks,
            );
            let new_validator_root = validator_hash_tree_root(&mutation.new_field_leaves);
            new_ssz_leaves.push((new_validator_root, idx));
        } else {
            // -- Verify new field leaves (full, including pubkey hash) --
            verify_field_leaves(
                &mutation.new_data,
                &mutation.new_field_leaves,
                &mutation.new_pubkey_chunks,
            );

            // -- Verify old field leaves (skip pubkey hash — pubkey doesn't change) --
            verify_field_leaves_no_pubkey_hash(
                &mutation.old_data,
                &mutation.old_field_leaves,
                &mutation.old_pubkey_chunks,
            );
            // Ensure pubkey leaf matches (no SHA-256 — just comparison)
            assert_eq!(
                mutation.old_field_leaves[0], mutation.new_field_leaves[0],
                "pubkey leaf changed for existing validator {}",
                idx
            );

            // -- Compute old + new HTR, sharing work for identical subtrees --
            let (old_validator_root, new_validator_root) = validator_hash_tree_root_pair(
                &mutation.old_field_leaves,
                &mutation.new_field_leaves,
            );
            old_ssz_leaves.push((old_validator_root, idx));
            new_ssz_leaves.push((new_validator_root, idx));

            // -- Verify the accumulator leaf the mutation replaces --
            let old_active_balance = mutation.old_data.active_effective_balance(epoch_old);
            let old_acc_leaf = acc::leaf(&point, old_active_balance);
            let computed_old_root = zkasper_common::merkle::compute_root(
                acc::compress,
                &old_acc_leaf,
                idx,
                &mutation.acc_siblings,
            );
            assert_eq!(
                computed_old_root, acc_root,
                "accumulator root mismatch before mutation {}",
                idx
            );
        }

        // -- Write the new accumulator leaf --
        let new_active_balance = mutation.new_data.active_effective_balance(epoch_new);
        let new_acc_leaf = acc::leaf(&point, new_active_balance);
        acc_root = zkasper_common::merkle::compute_root(
            acc::compress,
            &new_acc_leaf,
            idx,
            &mutation.acc_siblings,
        );

        // -- Balance delta --
        let old_active_balance = if mutation.is_new {
            0
        } else {
            mutation.old_data.active_effective_balance(epoch_old)
        };
        total_active_balance = total_active_balance - old_active_balance + new_active_balance;
    }

    // Phase 2: SSZ multi-proof verification
    let ssz_data_root_1 =
        verify_ssz_multi_proof(&old_ssz_leaves, &witness.ssz_multi_proof_1, ssz_depth);
    let ssz_data_root_2 =
        verify_ssz_multi_proof(&new_ssz_leaves, &witness.ssz_multi_proof_2, ssz_depth);

    // -- Verify SSZ data tree roots link to state roots --
    let validators_field_index = zkasper_common::constants::BEACON_STATE_VALIDATORS_FIELD_INDEX;

    let validators_root_1 = list_hash_tree_root(&ssz_data_root_1, witness.validators_list_length_1);
    let computed_state_root_1 = compute_ssz_merkle_root(
        &validators_root_1,
        validators_field_index,
        &witness.state_to_validators_siblings_1,
    );
    assert_eq!(
        computed_state_root_1, witness.state_root_1,
        "state_root_1 mismatch"
    );

    let validators_root_2 = list_hash_tree_root(&ssz_data_root_2, witness.validators_list_length_2);
    let computed_state_root_2 = compute_ssz_merkle_root(
        &validators_root_2,
        validators_field_index,
        &witness.state_to_validators_siblings_2,
    );
    assert_eq!(
        computed_state_root_2, witness.state_root_2,
        "state_root_2 mismatch"
    );

    let commitment = zkasper_common::acc::commitment(&acc_root, total_active_balance);

    (commitment, acc_root, total_active_balance)
}

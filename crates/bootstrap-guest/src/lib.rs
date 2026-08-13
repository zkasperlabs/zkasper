// Re-export verification functions for use by integration tests and other crates.

use zkasper_common::acc;
use zkasper_common::acc::Digest;
use zkasper_common::ssz::{
    compute_ssz_merkle_root, list_hash_tree_root, validator_hash_tree_root, verify_field_leaves,
};
use zkasper_common::types::BootstrapWitness;

/// Core bootstrap verification logic. Returns (accumulator_commitment, acc_root, total_active_balance).
pub fn verify_bootstrap(witness: &BootstrapWitness) -> (Digest, Digest, u64) {
    verify_bootstrap_with_depth(
        witness,
        zkasper_common::constants::VALIDATORS_TREE_DEPTH,
        zkasper_common::constants::ACC_TREE_DEPTH,
    )
}

/// Bootstrap verification with configurable tree depths (for testing with small trees).
pub fn verify_bootstrap_with_depth(
    witness: &BootstrapWitness,
    ssz_depth: u32,
    acc_depth: u32,
) -> (Digest, Digest, u64) {
    let num_validators = witness.validators.len();
    let mut total_active_balance: u64 = 0;
    let mut validator_roots = Vec::with_capacity(num_validators);
    let mut acc_leaves = Vec::with_capacity(num_validators);

    for i in 0..num_validators {
        verify_field_leaves(
            &witness.validators[i],
            &witness.validator_field_chunks[i],
            &witness.validator_pubkey_chunks[i],
        );

        let root = validator_hash_tree_root(&witness.validator_field_chunks[i]);
        validator_roots.push(root);

        let active_balance = witness.validators[i].active_effective_balance(witness.epoch);
        let point = zkasper_common::bls::decompress_pubkey(&witness.validators[i].pubkey.0)
            .unwrap_or_else(|| panic!("validator {i} has an invalid public key"));
        let p_leaf = acc::leaf(&point, active_balance);
        acc_leaves.push(p_leaf);

        total_active_balance += active_balance;
    }

    let ssz_data_root = rebuild_tree(
        &validator_roots,
        zkasper_common::ssz::sha256_pair,
        ssz_depth,
    );
    let validators_root = list_hash_tree_root(&ssz_data_root, num_validators as u64);
    let computed_state_root = compute_ssz_merkle_root(
        &validators_root,
        zkasper_common::constants::BEACON_STATE_VALIDATORS_FIELD_INDEX,
        &witness.state_to_validators_siblings,
    );
    assert_eq!(
        computed_state_root, witness.state_root,
        "state root mismatch"
    );

    let acc_root = rebuild_tree(&acc_leaves, acc::compress, acc_depth);
    let commitment = acc::commitment(&acc_root, total_active_balance);

    (commitment, acc_root, total_active_balance)
}

/// Generic bottom-up Merkle tree rebuild with zero-hash padding.
///
/// Only builds the dense portion (next-power-of-2 above `leaves.len()`),
/// then chains through precomputed zero hashes for the remaining sparse levels.
fn rebuild_tree<T: Copy + Default>(leaves: &[T], hash_pair: impl Fn(&T, &T) -> T, depth: u32) -> T {
    let mut zero_hashes = vec![T::default(); (depth + 1) as usize];
    for d in 1..=depth as usize {
        zero_hashes[d] = hash_pair(&zero_hashes[d - 1], &zero_hashes[d - 1]);
    }

    if leaves.is_empty() {
        return zero_hashes[depth as usize];
    }

    // Only build levels up to the dense portion
    let dense_depth = (leaves.len() as u64)
        .next_power_of_two()
        .trailing_zeros()
        .max(1)
        .min(depth);
    let dense_capacity = 1usize << dense_depth;

    // Pad leaves to dense capacity with zeros
    let mut current_level = Vec::with_capacity(dense_capacity);
    current_level.extend_from_slice(leaves);
    current_level.resize(dense_capacity, T::default());

    // Build dense levels bottom-up
    for _d in 0..dense_depth as usize {
        let parent_count = current_level.len() / 2;
        let mut next_level = Vec::with_capacity(parent_count);
        for i in 0..parent_count {
            next_level.push(hash_pair(&current_level[i * 2], &current_level[i * 2 + 1]));
        }
        current_level = next_level;
    }

    // Chain through zero hashes for sparse levels
    let mut root = current_level[0];
    for d in dense_depth..depth {
        root = hash_pair(&root, &zero_hashes[d as usize]);
    }

    root
}

//! Test helpers for building synthetic witness data.

use alloc::vec;
use alloc::vec::Vec;

use crate::acc::{compress as acc_compress, Digest, ZERO};
use crate::ssz::{sha256_pair, u64_to_chunk};
use crate::types::*;

/// Create a dummy validator with deterministic data.
/// Deterministic validator fixture.
///
/// The public key is a real BLS key derived from `index`. It has to be: the
/// accumulator leaf commits to the decompressed point, so an arbitrary 48-byte
/// pattern is not a public key that can be decompressed at all.
pub fn make_validator(index: u8, balance_eth: u64) -> ValidatorData {
    ValidatorData {
        pubkey: BlsPubkey(make_pubkey(index)),
        effective_balance: balance_eth * 1_000_000_000,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }
}

/// A real compressed BLS public key, derived deterministically from `index`.
pub fn make_pubkey(index: u8) -> [u8; 48] {
    let mut ikm = [0u8; 32];
    ikm[0] = index;
    ikm[1] = index.wrapping_mul(7).wrapping_add(1);
    blst::min_pk::SecretKey::key_gen(&ikm, &[])
        .expect("key_gen")
        .sk_to_pk()
        .compress()
}

/// Build the 8 SSZ field leaves for a validator.
/// Leaves 1, 3, 4, 7 (opaque fields) are filled with deterministic junk.
pub fn make_field_leaves(data: &ValidatorData) -> [[u8; 32]; 8] {
    let pubkey_chunks = make_pubkey_chunks(data);
    let pubkey_leaf = sha256_pair(&pubkey_chunks[0], &pubkey_chunks[1]);

    let mut withdrawal_creds = [0u8; 32];
    withdrawal_creds[0] = 0x01; // ETH1 withdrawal prefix
    let slashed = [0u8; 32]; // not slashed
    let activation_eligibility = u64_to_chunk(0);
    let withdrawable_epoch = u64_to_chunk(u64::MAX);

    [
        pubkey_leaf,
        withdrawal_creds,
        u64_to_chunk(data.effective_balance),
        slashed,
        activation_eligibility,
        u64_to_chunk(data.activation_epoch),
        u64_to_chunk(data.exit_epoch),
        withdrawable_epoch,
    ]
}

/// Split pubkey into 2x32-byte SSZ chunks.
pub fn make_pubkey_chunks(data: &ValidatorData) -> [[u8; 32]; 2] {
    let mut chunk0 = [0u8; 32];
    let mut chunk1 = [0u8; 32];
    chunk0.copy_from_slice(&data.pubkey.0[..32]);
    chunk1[..16].copy_from_slice(&data.pubkey.0[32..48]);
    [chunk0, chunk1]
}

/// Build a sparse Merkle tree (SHA-256) from validator roots and return
/// (data_tree_root, siblings_per_leaf).
///
/// Only builds levels up to the dense portion (next-power-of-2 above leaf count),
/// then uses precomputed zero hashes for the sparse levels above.
pub fn build_ssz_tree(
    validator_roots: &[[u8; 32]],
    depth: u32,
) -> (
    [u8; 32],
    Vec<Vec<[u8; 32]>>, // siblings[leaf_index] = vec of siblings
) {
    // Precompute zero hashes
    let mut zero_hashes = vec![[0u8; 32]; (depth + 1) as usize];
    for d in 1..=depth as usize {
        zero_hashes[d] = sha256_pair(&zero_hashes[d - 1], &zero_hashes[d - 1]);
    }

    let dense_depth = if validator_roots.is_empty() {
        1u32
    } else {
        (validator_roots.len() as u64)
            .next_power_of_two()
            .trailing_zeros()
    }
    .max(1)
    .min(depth);
    let dense_capacity = 1usize << dense_depth;

    // Build dense levels
    let mut levels: Vec<Vec<[u8; 32]>> = Vec::new();
    let mut leaves = vec![[0u8; 32]; dense_capacity];
    for (i, root) in validator_roots.iter().enumerate() {
        leaves[i] = *root;
    }
    levels.push(leaves);

    for d in 0..dense_depth as usize {
        let prev = &levels[d];
        let parent_count = prev.len() / 2;
        let mut parents = Vec::with_capacity(parent_count);
        for i in 0..parent_count {
            parents.push(sha256_pair(&prev[i * 2], &prev[i * 2 + 1]));
        }
        levels.push(parents);
    }

    // Chain through zero hashes for sparse levels
    let mut root = levels[dense_depth as usize][0];
    for d in dense_depth..depth {
        root = sha256_pair(&root, &zero_hashes[d as usize]);
    }

    // Extract siblings for each leaf
    let mut all_siblings = Vec::new();
    for leaf_idx in 0..validator_roots.len() {
        let mut siblings = Vec::with_capacity(depth as usize);
        let mut idx = leaf_idx;
        // Dense levels: read from stored levels
        for level in levels.iter().take(dense_depth as usize) {
            let sibling_idx = idx ^ 1;
            siblings.push(level[sibling_idx]);
            idx >>= 1;
        }
        // Sparse levels: sibling is always the zero hash
        for d in dense_depth..depth {
            siblings.push(zero_hashes[d as usize]);
        }
        all_siblings.push(siblings);
    }

    (root, all_siblings)
}

/// Build a SHA-256 multi-proof for the given leaf indices in a sparse tree.
/// Returns `(data_tree_root, MerkleMultiProof)`.
pub fn build_ssz_tree_multi_proof(
    validator_roots: &[[u8; 32]],
    depth: u32,
    leaf_indices: &[u64],
) -> ([u8; 32], crate::types::SszMultiProof) {
    use alloc::collections::BTreeSet;

    // Precompute zero hashes
    let mut zero_hashes = vec![[0u8; 32]; (depth + 1) as usize];
    for d in 1..=depth as usize {
        zero_hashes[d] = sha256_pair(&zero_hashes[d - 1], &zero_hashes[d - 1]);
    }

    let dense_depth = if validator_roots.is_empty() {
        1u32
    } else {
        (validator_roots.len() as u64)
            .next_power_of_two()
            .trailing_zeros()
    }
    .max(1)
    .min(depth);
    let dense_capacity = 1usize << dense_depth;

    // Build dense levels
    let mut levels: Vec<Vec<[u8; 32]>> = Vec::new();
    let mut leaves = vec![[0u8; 32]; dense_capacity];
    for (i, root) in validator_roots.iter().enumerate() {
        leaves[i] = *root;
    }
    levels.push(leaves);

    for d in 0..dense_depth as usize {
        let prev = &levels[d];
        let parent_count = prev.len() / 2;
        let mut parents = Vec::with_capacity(parent_count);
        for i in 0..parent_count {
            parents.push(sha256_pair(&prev[i * 2], &prev[i * 2 + 1]));
        }
        levels.push(parents);
    }

    // Chain through zero hashes for sparse levels
    let mut root = levels[dense_depth as usize][0];
    for d in dense_depth..depth {
        root = sha256_pair(&root, &zero_hashes[d as usize]);
    }

    // Build auxiliaries: walk bottom-up, collect sibling nodes not in `known`
    let mut known_at_level: BTreeSet<u64> = leaf_indices.iter().copied().collect();
    let mut auxiliaries = Vec::new();

    for level in 0..depth {
        // Collect sorted parent indices
        let parent_indices: BTreeSet<u64> = known_at_level.iter().map(|&idx| idx / 2).collect();

        for &parent_idx in &parent_indices {
            let left_idx = parent_idx * 2;
            let right_idx = parent_idx * 2 + 1;

            if !known_at_level.contains(&left_idx) {
                let node = get_node_hash(&levels, &zero_hashes, level, left_idx, dense_depth);
                auxiliaries.push(node);
            }
            if !known_at_level.contains(&right_idx) {
                let node = get_node_hash(&levels, &zero_hashes, level, right_idx, dense_depth);
                auxiliaries.push(node);
            }
        }

        known_at_level = parent_indices;
    }

    (root, crate::types::SszMultiProof { auxiliaries })
}

/// Get a node hash from the tree at a given level and index.
fn get_node_hash(
    levels: &[Vec<[u8; 32]>],
    zero_hashes: &[[u8; 32]],
    level: u32,
    idx: u64,
    dense_depth: u32,
) -> [u8; 32] {
    if level < dense_depth {
        let level_data = &levels[level as usize];
        if (idx as usize) < level_data.len() {
            level_data[idx as usize]
        } else {
            zero_hashes[level as usize]
        }
    } else {
        // Sparse levels: only index 0 is the actual node, everything else is zero hash
        if idx == 0 {
            // This is the dense root chained through zero hashes — but since we're
            // collecting it as an auxiliary, we can read from levels[dense_depth][0]
            // chained up. Actually for sparse levels, index 1 (the sibling) is always
            // the zero hash at that level.
            if level == dense_depth {
                levels[dense_depth as usize][0]
            } else {
                // This shouldn't happen — the only node at index 0 in sparse levels
                // is an ancestor of all leaves, so it should always be in `known`.
                zero_hashes[level as usize]
            }
        } else {
            zero_hashes[level as usize]
        }
    }
}

/// Build a sparse accumulator Merkle tree from leaves and return
/// (root, siblings_per_leaf).
///
/// Only builds levels up to the dense portion (next-power-of-2 above leaf count),
/// then uses precomputed zero hashes for the sparse levels above.
pub fn build_acc_tree(acc_leaves: &[Digest], depth: u32) -> (Digest, Vec<Vec<Digest>>) {
    let mut zero_hashes = vec![ZERO; (depth + 1) as usize];
    for d in 1..=depth as usize {
        zero_hashes[d] = acc_compress(&zero_hashes[d - 1], &zero_hashes[d - 1]);
    }

    let dense_depth = if acc_leaves.is_empty() {
        1u32
    } else {
        (acc_leaves.len() as u64)
            .next_power_of_two()
            .trailing_zeros()
    }
    .max(1)
    .min(depth);
    let dense_capacity = 1usize << dense_depth;

    let mut levels: Vec<Vec<Digest>> = Vec::new();
    let mut leaves = vec![ZERO; dense_capacity];
    for (i, leaf) in acc_leaves.iter().enumerate() {
        leaves[i] = *leaf;
    }
    levels.push(leaves);

    for d in 0..dense_depth as usize {
        let prev = &levels[d];
        let parent_count = prev.len() / 2;
        let mut parents = Vec::with_capacity(parent_count);
        for i in 0..parent_count {
            parents.push(acc_compress(&prev[i * 2], &prev[i * 2 + 1]));
        }
        levels.push(parents);
    }

    // Chain through zero hashes for sparse levels
    let mut root = levels[dense_depth as usize][0];
    for d in dense_depth..depth {
        root = acc_compress(&root, &zero_hashes[d as usize]);
    }

    let mut all_siblings = Vec::new();
    for leaf_idx in 0..acc_leaves.len() {
        let mut siblings = Vec::with_capacity(depth as usize);
        let mut idx = leaf_idx;
        // Dense levels
        for level in levels.iter().take(dense_depth as usize) {
            let sibling_idx = idx ^ 1;
            siblings.push(level[sibling_idx]);
            idx >>= 1;
        }
        // Sparse levels
        for d in dense_depth..depth {
            siblings.push(zero_hashes[d as usize]);
        }
        all_siblings.push(siblings);
    }

    (root, all_siblings)
}

/// A justification of `target_epoch` that says the supermajority is behind it.
///
/// The closing link of a real chain publishes the balance and mask it counted;
/// nothing downstream reads either, so a fixture only has to set the flag.
pub fn justified_output(
    accumulator_commitment: Digest,
    target_epoch: u64,
    target_root: [u8; 32],
) -> JustificationOutput {
    JustificationOutput {
        accumulator_commitment,
        committee_root: ZERO,
        target_epoch,
        target_root,
        attesting_balance: 0,
        slots_mask: 0,
        justified: true,
    }
}

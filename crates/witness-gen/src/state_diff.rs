//! Diff two beacon state validator registries and produce SSZ Merkle proofs.

use std::collections::BTreeSet;

use rayon::prelude::*;
use zkasper_common::ssz::{sha256_pair, u64_to_chunk, validator_hash_tree_root};
use zkasper_common::types::{BlsPubkey, SszMultiProof, ValidatorData};

use crate::beacon_api::ValidatorResponse;

// ---------------------------------------------------------------------------
// Validator response → common types conversions
// ---------------------------------------------------------------------------

/// Convert a beacon API validator response into the minimal `ValidatorData`.
pub fn validator_response_to_data(v: &ValidatorResponse) -> ValidatorData {
    ValidatorData {
        pubkey: BlsPubkey(v.pubkey),
        effective_balance: v.effective_balance,
        activation_epoch: v.activation_epoch,
        exit_epoch: v.exit_epoch,
    }
}

/// Build the 8 SSZ field leaves for a validator from the full API response.
///
/// SSZ Validator container field layout (8 fields):
/// ```text
/// leaf[0] = sha256(pubkey[0..32] || pubkey[32..48]++zeros)
/// leaf[1] = withdrawal_credentials (32 bytes, opaque)
/// leaf[2] = le_pad32(effective_balance)
/// leaf[3] = le_pad32(slashed)
/// leaf[4] = le_pad32(activation_eligibility_epoch)
/// leaf[5] = le_pad32(activation_epoch)
/// leaf[6] = le_pad32(exit_epoch)
/// leaf[7] = le_pad32(withdrawable_epoch)
/// ```
pub fn validator_response_to_field_leaves(v: &ValidatorResponse) -> [[u8; 32]; 8] {
    let chunks = validator_response_to_pubkey_chunks(v);
    let pubkey_leaf = sha256_pair(&chunks[0], &chunks[1]);

    [
        pubkey_leaf,
        v.withdrawal_credentials,
        u64_to_chunk(v.effective_balance),
        u64_to_chunk(if v.slashed { 1 } else { 0 }),
        u64_to_chunk(v.activation_eligibility_epoch),
        u64_to_chunk(v.activation_epoch),
        u64_to_chunk(v.exit_epoch),
        u64_to_chunk(v.withdrawable_epoch),
    ]
}

/// Split a 48-byte pubkey into 2×32-byte SSZ chunks.
pub fn validator_response_to_pubkey_chunks(v: &ValidatorResponse) -> [[u8; 32]; 2] {
    let mut chunk0 = [0u8; 32];
    let mut chunk1 = [0u8; 32];
    chunk0.copy_from_slice(&v.pubkey[..32]);
    chunk1[..16].copy_from_slice(&v.pubkey[32..48]);
    [chunk0, chunk1]
}

// ---------------------------------------------------------------------------
// Registry diffing
// ---------------------------------------------------------------------------

/// Find indices of validators that changed between two registries.
///
/// A validator is considered "changed" if:
/// - Any SSZ field differs between old and new state, OR
/// - The validator's `active_effective_balance` changes due to epoch transition
///   (activation_epoch or exit_epoch falls in `(epoch_1, epoch_2]`).
///
/// New validators (present in `new` but not `old`) are also returned.
pub fn find_mutations(
    old_validators: &[ValidatorResponse],
    new_validators: &[ValidatorResponse],
    epoch_1: u64,
    epoch_2: u64,
) -> Vec<u64> {
    let mut changed = Vec::new();

    // Compare overlapping validators
    for i in 0..old_validators.len().min(new_validators.len()) {
        let old = &old_validators[i];
        let new = &new_validators[i];

        // SSZ field changes. Withdrawal credentials are in here because they
        // move on their own: a switch-to-compounding request flips 0x01 to 0x02
        // and a BLS-to-execution change flips 0x00 to 0x01, both without
        // touching a balance or an epoch. Leaving them out let a validator's
        // root go stale, and the registry root with it.
        let ssz_changed = old.effective_balance != new.effective_balance
            || old.withdrawal_credentials != new.withdrawal_credentials
            || old.activation_epoch != new.activation_epoch
            || old.exit_epoch != new.exit_epoch
            || old.slashed != new.slashed
            || old.activation_eligibility_epoch != new.activation_eligibility_epoch
            || old.withdrawable_epoch != new.withdrawable_epoch;

        // Epoch-boundary: is_active status changes between epoch_1 and epoch_2.
        // Use new_validators fields since they reflect the canonical state.
        let was_active = new.activation_epoch <= epoch_1 && epoch_1 < new.exit_epoch;
        let is_active = new.activation_epoch <= epoch_2 && epoch_2 < new.exit_epoch;
        let activity_changed = was_active != is_active;

        if ssz_changed || activity_changed {
            changed.push(i as u64);
        }
    }

    // New validators (registry grew)
    for i in old_validators.len()..new_validators.len() {
        changed.push(i as u64);
    }

    changed
}

// ---------------------------------------------------------------------------
// SSZ tree building
// ---------------------------------------------------------------------------

/// Build a sparse SHA-256 Merkle tree from validator roots and return
/// `(data_tree_root, SszMultiProof)` for the given leaf indices.
///
/// Only allocates the dense portion (2^ceil(log2(n)) leaves), then chains
/// zero hashes for the remaining depth. This allows depth=40 with millions
/// of validators without allocating 2^40 entries.
pub fn build_validators_ssz_tree(
    validator_roots: &[[u8; 32]],
    depth: u32,
    leaf_indices: &[u64],
) -> ([u8; 32], SszMultiProof) {
    // Precompute zero hashes
    let mut zero_hashes = vec![[0u8; 32]; (depth + 1) as usize];
    for d in 1..=depth as usize {
        zero_hashes[d] = sha256_pair(&zero_hashes[d - 1], &zero_hashes[d - 1]);
    }

    // Compute dense depth
    let dense_depth = if validator_roots.is_empty() {
        1u32
    } else {
        let n = validator_roots.len() as u64;
        n.next_power_of_two().trailing_zeros()
    }
    .max(1)
    .min(depth);

    let dense_capacity = 1usize << dense_depth;

    // Build dense levels bottom-up
    let mut levels: Vec<Vec<[u8; 32]>> = Vec::new();
    let mut leaves = vec![[0u8; 32]; dense_capacity];
    for (i, root) in validator_roots.iter().enumerate() {
        leaves[i] = *root;
    }
    levels.push(leaves);

    for d in 0..dense_depth as usize {
        let prev = &levels[d];
        let parents: Vec<[u8; 32]> = prev
            .par_chunks_exact(2)
            .map(|pair| sha256_pair(&pair[0], &pair[1]))
            .collect();
        levels.push(parents);
    }

    // Compute full root by chaining through zero hashes
    let mut root = levels[dense_depth as usize][0];
    for d in dense_depth..depth {
        root = sha256_pair(&root, &zero_hashes[d as usize]);
    }

    // Build multi-proof: collect auxiliary nodes bottom-up, left-to-right
    let mut known_at_level: BTreeSet<u64> = leaf_indices.iter().copied().collect();
    let mut auxiliaries = Vec::new();

    for level in 0..depth {
        let parent_indices: BTreeSet<u64> = known_at_level.iter().map(|&idx| idx / 2).collect();

        for &parent_idx in &parent_indices {
            let left_idx = parent_idx * 2;
            let right_idx = parent_idx * 2 + 1;

            if !known_at_level.contains(&left_idx) {
                auxiliaries.push(get_node_hash(
                    &levels,
                    &zero_hashes,
                    level,
                    left_idx,
                    dense_depth,
                ));
            }
            if !known_at_level.contains(&right_idx) {
                auxiliaries.push(get_node_hash(
                    &levels,
                    &zero_hashes,
                    level,
                    right_idx,
                    dense_depth,
                ));
            }
        }

        known_at_level = parent_indices;
    }

    (root, SszMultiProof { auxiliaries })
}

/// Look up a node hash from the built tree levels or zero hashes.
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
        // Sparse levels: sibling is always the zero hash (the only real node
        // at each sparse level is on the path from dense root to full root,
        // which is always in `known`).
        zero_hashes[level as usize]
    }
}

/// Build all validator roots from API responses.
pub fn build_validator_roots(validators: &[ValidatorResponse]) -> Vec<[u8; 32]> {
    validators
        .par_iter()
        .map(|v| validator_hash_tree_root(&validator_response_to_field_leaves(v)))
        .collect()
}

// ---------------------------------------------------------------------------
// State proof (BeaconState top-level tree)
// ---------------------------------------------------------------------------

/// The one slot a synthetic state records in its two ring buffers.
///
/// A real state records every slot it has passed; a synthetic one only has to
/// record the boundary a finalization will open out of it, which is the
/// preceding epoch's. The default is the all-zero history a bootstrap starts
/// from, and every state after it carries what the state before it produced —
/// the same induction the real chain runs, so the two agree slot for slot.
#[derive(Clone, Copy, Default, Debug)]
pub struct SlotHistory {
    pub slot: u64,
    pub block_root: [u8; 32],
    pub state_root: [u8; 32],
}

/// Build a synthetic BeaconState tree from a validators data tree root.
///
/// Everything but `validators`, `block_roots` and `state_roots` is a
/// deterministic placeholder. For production use with a real beacon node the
/// whole tree comes out of the SSZ state instead.
pub fn make_state_proof(
    data_tree_root: &[u8; 32],
    list_length: u64,
    history: &SlotHistory,
) -> ([u8; 32], Vec<[u8; 32]>) {
    use zkasper_common::constants::BEACON_STATE_VALIDATORS_FIELD_INDEX;

    let leaves = synthetic_state_leaves(data_tree_root, list_length, history);
    crate::ssz_state::build_state_tree_and_extract(
        &leaves,
        BEACON_STATE_VALIDATORS_FIELD_INDEX as usize,
    )
}

/// Open a synthetic state's ring buffers the way [`crate::ssz_state::parse_boundary_proof`]
/// opens a real one's.
pub fn make_boundary_proof(
    data_tree_root: &[u8; 32],
    list_length: u64,
    history: &SlotHistory,
) -> crate::ssz_state::BoundaryProof {
    let leaves = synthetic_state_leaves(data_tree_root, list_length, history);
    let (state_root, block_field_siblings) =
        crate::ssz_state::build_state_tree_and_extract(&leaves, BLOCK_ROOTS_FIELD);
    let (_, state_field_siblings) =
        crate::ssz_state::build_state_tree_and_extract(&leaves, STATE_ROOTS_FIELD);

    let mut block_roots_siblings = ring_siblings();
    let mut state_roots_siblings = ring_siblings();
    block_roots_siblings.extend(block_field_siblings);
    state_roots_siblings.extend(state_field_siblings);

    crate::ssz_state::BoundaryProof {
        state_root,
        block_root: history.block_root,
        boundary_state_root: history.state_root,
        block_roots_siblings,
        state_roots_siblings,
    }
}

const BLOCK_ROOTS_FIELD: usize = 5;
const STATE_ROOTS_FIELD: usize = 6;
const RING_DEPTH: usize = 13;

/// The 64 field leaves of a synthetic BeaconState.
fn synthetic_state_leaves(
    data_tree_root: &[u8; 32],
    list_length: u64,
    history: &SlotHistory,
) -> [[u8; 32]; 64] {
    use zkasper_common::constants::BEACON_STATE_VALIDATORS_FIELD_INDEX;
    use zkasper_common::ssz::list_hash_tree_root;

    let mut leaves = [[0u8; 32]; 64];
    for (i, leaf) in leaves.iter_mut().enumerate() {
        leaf[0] = i as u8;
        leaf[1] = 0xBE;
    }
    leaves[BLOCK_ROOTS_FIELD] = ring_root(history.slot, &history.block_root);
    leaves[STATE_ROOTS_FIELD] = ring_root(history.slot, &history.state_root);
    leaves[BEACON_STATE_VALIDATORS_FIELD_INDEX as usize] =
        list_hash_tree_root(data_tree_root, list_length);
    leaves
}

/// Root of a `Vector[Root, 8192]` holding `entry` at `slot` and zero elsewhere.
fn ring_root(slot: u64, entry: &[u8; 32]) -> [u8; 32] {
    zkasper_common::ssz::compute_ssz_merkle_root(
        entry,
        slot % zkasper_common::ssz::SLOTS_PER_HISTORICAL_ROOT,
        &ring_siblings(),
    )
}

/// The zero subtrees that surround the one entry such a vector holds.
fn ring_siblings() -> Vec<[u8; 32]> {
    let mut zeros = Vec::with_capacity(RING_DEPTH);
    let mut zero = [0u8; 32];
    for _ in 0..RING_DEPTH {
        zeros.push(zero);
        zero = sha256_pair(&zero, &zero);
    }
    zeros
}

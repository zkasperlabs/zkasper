//! SSZ BeaconState parsing for extracting the state-to-validators Merkle proof.
//!
//! Parses raw SSZ-encoded BeaconState bytes (Electra or Fulu), computes the
//! hash_tree_root of each top-level field, and returns the 6 Merkle siblings
//! needed to prove the validators field (index 11) against the state root.

use anyhow::{Context, Result};
use zkasper_common::ssz::{sha256_pair, SLOTS_PER_HISTORICAL_ROOT};
use zkasper_common::{ChainConfig, ConsensusFork};

/// Result of parsing the SSZ state: proof siblings + computed state root.
pub struct StateProof {
    /// Merkle siblings for validators (field 11) in the state tree.
    /// Length 6 (both Electra and Fulu: 37/38 fields → 64 leaves → depth 6).
    pub siblings: Vec<[u8; 32]>,
    /// The computed state root (should match the block header's state_root).
    pub state_root: [u8; 32],
}

// -----------------------------------------------------------------------
// BeaconState layout per fork
// -----------------------------------------------------------------------

/// Number of leaves in the state tree (next power of 2 above field count).
/// Both Electra (37 fields) and Fulu (38 fields) pad to 64 leaves.
const STATE_TREE_LEAVES: usize = 64;

/// State tree depth: ceil(log2(64)) = 6.
const STATE_TREE_DEPTH: usize = 6;

/// Indices of variable-size fields in the BeaconState (same for Electra and Fulu).
const VARIABLE_FIELD_INDICES: [usize; 12] = [7, 9, 11, 12, 15, 16, 21, 24, 27, 34, 35, 36];

/// The two ring buffers of slot history, and how many slots they hold.
const BLOCK_ROOTS_FIELD: usize = 5;
const STATE_ROOTS_FIELD: usize = 6;
const HISTORICAL_ROOT_COUNT: usize = SLOTS_PER_HISTORICAL_ROOT as usize;

/// Fixed-portion sizes for the first 37 fields (Electra). Fulu appends one more.
const FIELD_FIXED_SIZES_ELECTRA: [usize; 37] = [
    8,       // 0:  genesis_time (uint64)
    32,      // 1:  genesis_validators_root (Bytes32)
    8,       // 2:  slot (uint64)
    16,      // 3:  fork (Fork: 4+4+8)
    112,     // 4:  latest_block_header (BeaconBlockHeader: 8+8+32+32+32)
    262144,  // 5:  block_roots (Vector[Root, 8192])
    262144,  // 6:  state_roots (Vector[Root, 8192])
    4,       // 7:  historical_roots (offset)
    72,      // 8:  eth1_data (Eth1Data: 32+8+32)
    4,       // 9:  eth1_data_votes (offset)
    8,       // 10: eth1_deposit_index (uint64)
    4,       // 11: validators (offset)
    4,       // 12: balances (offset)
    2097152, // 13: randao_mixes (Vector[Root, 65536])
    65536,   // 14: slashings (Vector[Gwei, 8192])
    4,       // 15: previous_epoch_participation (offset)
    4,       // 16: current_epoch_participation (offset)
    1,       // 17: justification_bits (Bitvector[4])
    40,      // 18: previous_justified_checkpoint (Checkpoint: 8+32)
    40,      // 19: current_justified_checkpoint (Checkpoint: 8+32)
    40,      // 20: finalized_checkpoint (Checkpoint: 8+32)
    4,       // 21: inactivity_scores (offset)
    24624,   // 22: current_sync_committee (SyncCommittee: 512*48+48)
    24624,   // 23: next_sync_committee (SyncCommittee)
    4,       // 24: latest_execution_payload_header (offset)
    8,       // 25: next_withdrawal_index (uint64)
    8,       // 26: next_withdrawal_validator_index (uint64)
    4,       // 27: historical_summaries (offset)
    // --- Electra ---
    8, // 28: deposit_requests_start_index (uint64)
    8, // 29: deposit_balance_to_consume (Gwei)
    8, // 30: exit_balance_to_consume (Gwei)
    8, // 31: earliest_exit_epoch (Epoch)
    8, // 32: consolidation_balance_to_consume (Gwei)
    8, // 33: earliest_consolidation_epoch (Epoch)
    4, // 34: pending_deposits (offset)
    4, // 35: pending_partial_withdrawals (offset)
    4, // 36: pending_consolidations (offset)
];

/// Fulu adds field 37: proposer_lookahead (Vector[ValidatorIndex, 64]: 64*8).
const FULU_EXTRA_FIELD_SIZE: usize = 512;

fn field_count(fork: ConsensusFork) -> usize {
    match fork {
        ConsensusFork::Electra => 37,
        ConsensusFork::Fulu => 38,
    }
}

fn field_fixed_sizes(fork: ConsensusFork) -> Vec<usize> {
    let mut sizes = FIELD_FIXED_SIZES_ELECTRA.to_vec();
    if fork == ConsensusFork::Fulu {
        sizes.push(FULU_EXTRA_FIELD_SIZE);
    }
    sizes
}

// -----------------------------------------------------------------------
// Main entry point
// -----------------------------------------------------------------------

/// Parse raw SSZ BeaconState and compute the Merkle proof for the
/// `validators` field (index 11) against the state root.
///
/// `validators_htr` is the externally-computed hash_tree_root of the
/// validators list (from our pipeline's build_validator_roots +
/// build_validators_ssz_tree + list_hash_tree_root). This avoids
/// recomputing the most expensive field.
pub fn parse_state_proof(
    raw_ssz: &[u8],
    validators_htr: &[u8; 32],
    config: &ChainConfig,
    slot: u64,
) -> Result<StateProof> {
    let fork = config.fork_at_slot(slot);
    let count = field_count(fork);
    let field_data_ranges = parse_field_ranges(raw_ssz, fork)?;

    // Compute hash_tree_root for each field
    let mut field_htrs = [[0u8; 32]; STATE_TREE_LEAVES];

    for i in 0..count {
        if i == 11 {
            field_htrs[i] = *validators_htr;
            continue;
        }

        let (start, end) = field_data_ranges[i];
        let data = &raw_ssz[start..end];

        field_htrs[i] = compute_field_htr(i, data, config);
    }

    let (state_root, siblings) = build_state_tree_and_extract(&field_htrs, 11);

    Ok(StateProof {
        siblings,
        state_root,
    })
}

/// Parse raw SSZ BeaconState and compute the state root directly.
///
/// Unlike `parse_state_proof`, this computes the validators HTR internally
/// from the SSZ data — useful for offline validation without a separate validator list.
/// Returns `(state_root, num_validators)`.
#[allow(dead_code)]
pub fn compute_state_root(raw_ssz: &[u8], config: &ChainConfig) -> Result<([u8; 32], u64)> {
    let slot = extract_slot(raw_ssz);
    let fork = config.fork_at_slot(slot);
    let count = field_count(fork);
    let field_data_ranges = parse_field_ranges(raw_ssz, fork)?;

    // Compute validators HTR from the raw SSZ validators data
    let (val_start, val_end) = field_data_ranges[11];
    let validators_data = &raw_ssz[val_start..val_end];
    let num_validators = (validators_data.len() / SSZ_VALIDATOR_SIZE) as u64;
    let validators_htr = compute_validators_htr(validators_data, num_validators)?;

    // Compute all field HTRs
    let mut field_htrs = [[0u8; 32]; STATE_TREE_LEAVES];

    for i in 0..count {
        if i == 11 {
            field_htrs[i] = validators_htr;
            continue;
        }
        let (start, end) = field_data_ranges[i];
        field_htrs[i] = compute_field_htr(i, &raw_ssz[start..end], config);
    }

    let (state_root, _siblings) = build_state_tree_and_extract(&field_htrs, 11);
    Ok((state_root, num_validators))
}

/// What a state records about one slot it has passed.
pub struct BoundaryProof {
    /// Root of the state the entries were opened from.
    pub state_root: [u8; 32],
    /// `block_roots[slot % 8192]`: the last block at or before that slot.
    pub block_root: [u8; 32],
    /// `state_roots[slot % 8192]`: the state at the end of that slot.
    pub boundary_state_root: [u8; 32],
    /// Siblings for each, bottom-up: 13 through the vector, 6 through the state.
    pub block_roots_siblings: Vec<[u8; 32]>,
    pub state_roots_siblings: Vec<[u8; 32]>,
}

/// Open what this state records for `slot` out of its two ring buffers.
///
/// This is how the finalized epoch's boundary is read when its first slot is
/// empty: a skipped slot has no header to take a state root off, but every
/// state that passed the slot recorded one.
///
/// `validators_htr` is the one field expensive enough to be worth passing in;
/// without it the whole registry is hashed again.
pub fn parse_boundary_proof(
    raw_ssz: &[u8],
    validators_htr: Option<[u8; 32]>,
    config: &ChainConfig,
    slot: u64,
) -> Result<BoundaryProof> {
    let state_slot = extract_slot(raw_ssz);
    anyhow::ensure!(
        slot < state_slot && state_slot - slot <= SLOTS_PER_HISTORICAL_ROOT,
        "the state at slot {state_slot} does not record slot {slot}",
    );

    let fork = config.fork_at_slot(state_slot);
    let count = field_count(fork);
    let ranges = parse_field_ranges(raw_ssz, fork)?;
    let ring = (slot % SLOTS_PER_HISTORICAL_ROOT) as usize;

    let entry = |field: usize| {
        let (start, _) = ranges[field];
        let mut root = [0u8; 32];
        root.copy_from_slice(&raw_ssz[start + ring * 32..start + ring * 32 + 32]);
        root
    };
    let vector = |field: usize| {
        let (start, end) = ranges[field];
        vector_root_and_proof(&raw_ssz[start..end], HISTORICAL_ROOT_COUNT, ring)
    };
    let (block_roots_htr, mut block_roots_siblings) = vector(BLOCK_ROOTS_FIELD);
    let (state_roots_htr, mut state_roots_siblings) = vector(STATE_ROOTS_FIELD);

    let mut field_htrs = [[0u8; 32]; STATE_TREE_LEAVES];
    for (i, htr) in field_htrs.iter_mut().enumerate().take(count) {
        let (start, end) = ranges[i];
        *htr = match i {
            BLOCK_ROOTS_FIELD => block_roots_htr,
            STATE_ROOTS_FIELD => state_roots_htr,
            11 => match validators_htr {
                Some(known) => known,
                None => {
                    let data = &raw_ssz[start..end];
                    compute_validators_htr(data, (data.len() / SSZ_VALIDATOR_SIZE) as u64)?
                }
            },
            _ => compute_field_htr(i, &raw_ssz[start..end], config),
        };
    }

    let (state_root, block_field_siblings) =
        build_state_tree_and_extract(&field_htrs, BLOCK_ROOTS_FIELD);
    let (_, state_field_siblings) = build_state_tree_and_extract(&field_htrs, STATE_ROOTS_FIELD);
    block_roots_siblings.extend(block_field_siblings);
    state_roots_siblings.extend(state_field_siblings);

    Ok(BoundaryProof {
        state_root,
        block_root: entry(BLOCK_ROOTS_FIELD),
        boundary_state_root: entry(STATE_ROOTS_FIELD),
        block_roots_siblings,
        state_roots_siblings,
    })
}

/// Merkle root of a `Vector[Root, count]`, with the sibling path to one entry.
fn vector_root_and_proof(data: &[u8], count: usize, index: usize) -> ([u8; 32], Vec<[u8; 32]>) {
    let mut level: Vec<[u8; 32]> = (0..count)
        .map(|i| {
            let mut chunk = [0u8; 32];
            chunk.copy_from_slice(&data[i * 32..(i + 1) * 32]);
            chunk
        })
        .collect();

    let mut siblings = Vec::new();
    let mut idx = index;
    while level.len() > 1 {
        siblings.push(level[idx ^ 1]);
        level = level.chunks(2).map(|p| sha256_pair(&p[0], &p[1])).collect();
        idx >>= 1;
    }
    (level[0], siblings)
}

/// Read the slot (field 2) directly from raw SSZ — always at offset 40 (8 + 32).
fn extract_slot(raw_ssz: &[u8]) -> u64 {
    u64::from_le_bytes(raw_ssz[40..48].try_into().unwrap())
}

/// Compute `ceil_log2(EPOCHS_PER_ETH1_VOTING_PERIOD * slots_per_epoch)`.
/// Mainnet: ceil_log2(64 * 32) = 11, Gnosis: ceil_log2(64 * 16) = 10.
fn eth1_votes_limit_depth(config: &ChainConfig) -> u32 {
    let limit = 64 * config.slots_per_epoch; // EPOCHS_PER_ETH1_VOTING_PERIOD = 64
    u64::BITS - (limit - 1).leading_zeros()
}

/// Compute the hash_tree_root of a single BeaconState field by index.
fn compute_field_htr(i: usize, data: &[u8], config: &ChainConfig) -> [u8; 32] {
    match i {
        0 | 2 | 10 | 25 | 26 | 28 | 29 | 30 | 31 | 32 | 33 => htr_uint64(data),
        1 => htr_bytes32(data),
        3 => htr_fork(data),
        4 => htr_beacon_block_header(data),
        5 => htr_vector_roots(data, 8192),
        6 => htr_vector_roots(data, 8192),
        7 => htr_list_roots(data, 24),
        8 => htr_eth1_data(data),
        9 => htr_list_eth1_data(data, eth1_votes_limit_depth(config)),
        12 => htr_list_gwei(data, 40),
        13 => htr_vector_roots(data, 65536),
        14 => htr_vector_gwei(data, 8192),
        15 | 16 => htr_list_uint8(data, 40),
        17 => htr_bitvector4(data),
        18..=20 => htr_checkpoint(data),
        21 => htr_list_gwei(data, 40),
        22 | 23 => htr_sync_committee(data),
        // ExecutionPayloadHeader is unchanged from Deneb through Electra.
        // Electra moved requests to a separate ExecutionRequests in BeaconBlockBody.
        24 => htr_execution_payload_header_deneb(data),
        27 => htr_list_historical_summaries(data, 24),
        34 => htr_list_pending_deposits(data, 27),
        35 => htr_list_pending_partial_withdrawals(data, 27),
        36 => htr_list_pending_consolidations(data, 18),
        37 => htr_vector_gwei(data, 64),
        _ => unreachable!("unexpected field index {i}"),
    }
}

/// Extract the byte ranges of each field from a raw SSZ BeaconState.
fn parse_field_ranges(raw_ssz: &[u8], fork: ConsensusFork) -> Result<Vec<(usize, usize)>> {
    let sizes = field_fixed_sizes(fork);
    let count = field_count(fork);
    let fixed_size: usize = sizes.iter().sum();
    anyhow::ensure!(raw_ssz.len() >= fixed_size, "SSZ state too small");

    let mut cursor = 0usize;
    let mut field_data_ranges: Vec<(usize, usize)> = Vec::with_capacity(count);
    let mut variable_offsets: Vec<(usize, u32)> = Vec::new();

    for (i, &size) in sizes.iter().enumerate().take(count) {
        if VARIABLE_FIELD_INDICES.contains(&i) {
            let offset = u32::from_le_bytes(
                raw_ssz[cursor..cursor + 4]
                    .try_into()
                    .context("read variable offset")?,
            );
            variable_offsets.push((i, offset));
            field_data_ranges.push((0, 0));
        } else {
            field_data_ranges.push((cursor, cursor + size));
        }
        cursor += size;
    }

    variable_offsets.sort_by_key(|&(_, off)| off);
    for j in 0..variable_offsets.len() {
        let (field_idx, start) = variable_offsets[j];
        let start = start as usize;
        let end = if j + 1 < variable_offsets.len() {
            variable_offsets[j + 1].1 as usize
        } else {
            raw_ssz.len()
        };
        field_data_ranges[field_idx] = (start, end);
    }

    Ok(field_data_ranges)
}

/// Size of one SSZ Validator container in bytes.
#[allow(dead_code)]
const SSZ_VALIDATOR_SIZE: usize = 121;

/// Extract validators from raw SSZ state as `ValidatorResponse` structs.
#[allow(dead_code)]
pub fn extract_validators(
    raw_ssz: &[u8],
    config: &ChainConfig,
) -> Result<Vec<crate::beacon_api::ValidatorResponse>> {
    let fork = config.fork_at_slot(extract_slot(raw_ssz));
    let ranges = parse_field_ranges(raw_ssz, fork)?;
    let (val_start, val_end) = ranges[11];
    let data = &raw_ssz[val_start..val_end];
    let count = data.len() / SSZ_VALIDATOR_SIZE;

    let mut validators = Vec::with_capacity(count);
    for i in 0..count {
        let offset = i * SSZ_VALIDATOR_SIZE;
        let v = &data[offset..offset + SSZ_VALIDATOR_SIZE];

        let mut pubkey = [0u8; 48];
        pubkey.copy_from_slice(&v[0..48]);

        let mut withdrawal_credentials = [0u8; 32];
        withdrawal_credentials.copy_from_slice(&v[48..80]);

        validators.push(crate::beacon_api::ValidatorResponse {
            index: i as u64,
            pubkey,
            effective_balance: u64::from_le_bytes(v[80..88].try_into().unwrap()),
            slashed: v[88] != 0,
            activation_eligibility_epoch: u64::from_le_bytes(v[89..97].try_into().unwrap()),
            activation_epoch: u64::from_le_bytes(v[97..105].try_into().unwrap()),
            exit_epoch: u64::from_le_bytes(v[105..113].try_into().unwrap()),
            withdrawable_epoch: u64::from_le_bytes(v[113..121].try_into().unwrap()),
            withdrawal_credentials,
        });
    }
    Ok(validators)
}

/// Extract `genesis_validators_root` (field 1, Bytes32) from raw SSZ state.
///
/// Field 1 starts at byte offset 8 (after genesis_time which is 8 bytes).
pub fn extract_genesis_validators_root(raw_ssz: &[u8]) -> [u8; 32] {
    let mut root = [0u8; 32];
    root.copy_from_slice(&raw_ssz[8..40]);
    root
}

/// Extract `fork.current_version` (4 bytes) from raw SSZ state.
///
/// Field 3 (Fork) starts at byte offset 48 (8+32+8).
/// Fork layout: previous_version(4) + current_version(4) + epoch(8).
/// So current_version is at offset 52.
pub fn extract_fork_version(raw_ssz: &[u8]) -> [u8; 4] {
    let mut version = [0u8; 4];
    version.copy_from_slice(&raw_ssz[52..56]);
    version
}

/// Extract slot and state_root from raw SSZ state (fields 2 and embedded in the block header).
#[allow(dead_code)]
pub fn extract_header(
    raw_ssz: &[u8],
    config: &ChainConfig,
) -> Result<crate::beacon_api::HeaderResponse> {
    let fork = config.fork_at_slot(extract_slot(raw_ssz));
    let ranges = parse_field_ranges(raw_ssz, fork)?;

    // Field 2: slot (uint64 at known fixed offset)
    let (slot_start, _) = ranges[2];
    let slot = u64::from_le_bytes(raw_ssz[slot_start..slot_start + 8].try_into().unwrap());

    // Field 4: latest_block_header (BeaconBlockHeader: slot(8) + proposer_index(8) + parent_root(32) + state_root(32) + body_root(32))
    // But state_root in the header is zeroed! The actual state_root is computed.
    // We need to use the *computed* state root, not the one in the header.
    let (hdr_start, _) = ranges[4];
    let proposer_index =
        u64::from_le_bytes(raw_ssz[hdr_start + 8..hdr_start + 16].try_into().unwrap());
    let mut parent_root = [0u8; 32];
    parent_root.copy_from_slice(&raw_ssz[hdr_start + 16..hdr_start + 48]);
    let mut body_root = [0u8; 32];
    body_root.copy_from_slice(&raw_ssz[hdr_start + 80..hdr_start + 112]);

    Ok(crate::beacon_api::HeaderResponse {
        slot,
        proposer_index,
        state_root: [0u8; 32], // caller must set this from compute_fulu_state_root or external source
        parent_root,
        body_root,
    })
}

/// Compute validators list HTR from raw SSZ validator data.
///
/// Each SSZ Validator is 121 bytes:
///   pubkey(48) + withdrawal_credentials(32) + effective_balance(8) +
///   slashed(1) + activation_eligibility_epoch(8) + activation_epoch(8) +
///   exit_epoch(8) + withdrawable_epoch(8) = 121
#[allow(dead_code)]
fn compute_validators_htr(data: &[u8], num_validators: u64) -> Result<[u8; 32]> {
    let validator_size = 121usize;
    let count = num_validators as usize;

    // Compute each validator's HTR
    let mut roots: Vec<[u8; 32]> = Vec::with_capacity(count);
    for i in 0..count {
        let offset = i * validator_size;
        let v = &data[offset..offset + validator_size];

        // Build the 8 field leaves
        let pubkey_leaf = htr_bls_pubkey(&v[0..48]);
        let fields: [[u8; 32]; 8] = [
            pubkey_leaf,                // pubkey
            htr_bytes32(&v[48..80]),    // withdrawal_credentials
            pad_to_chunk(&v[80..88]),   // effective_balance
            pad_to_chunk(&v[88..89]),   // slashed (1 byte bool)
            pad_to_chunk(&v[89..97]),   // activation_eligibility_epoch
            pad_to_chunk(&v[97..105]),  // activation_epoch
            pad_to_chunk(&v[105..113]), // exit_epoch
            pad_to_chunk(&v[113..121]), // withdrawable_epoch
        ];
        roots.push(merkleize_fixed_fields(&fields));
    }

    // Merkleize to depth 40 (VALIDATORS_TREE_DEPTH)
    let data_root = merkleize_chunks(&roots, 40);
    Ok(mix_in_length(&data_root, num_validators))
}

// -----------------------------------------------------------------------
// State tree building
// -----------------------------------------------------------------------

/// Build a depth-6 tree from 64 field HTRs and extract siblings for the given index.
pub(crate) fn build_state_tree_and_extract(
    leaves: &[[u8; 32]; STATE_TREE_LEAVES],
    index: usize,
) -> ([u8; 32], Vec<[u8; 32]>) {
    let mut levels: Vec<Vec<[u8; 32]>> = Vec::with_capacity(STATE_TREE_DEPTH + 1);
    levels.push(leaves.to_vec());

    for d in 0..STATE_TREE_DEPTH {
        let prev = &levels[d];
        let parent_count = prev.len() / 2;
        let mut parents = Vec::with_capacity(parent_count);
        for i in 0..parent_count {
            parents.push(sha256_pair(&prev[i * 2], &prev[i * 2 + 1]));
        }
        levels.push(parents);
    }

    let root = levels[STATE_TREE_DEPTH][0];

    // Extract siblings
    let mut siblings = Vec::with_capacity(STATE_TREE_DEPTH);
    let mut idx = index;
    for level in levels.iter().take(STATE_TREE_DEPTH) {
        let sibling_idx = idx ^ 1;
        siblings.push(level[sibling_idx]);
        idx >>= 1;
    }

    (root, siblings)
}

// -----------------------------------------------------------------------
// Generic merkleize helper
// -----------------------------------------------------------------------

/// Merkleize a list of 32-byte chunks into a tree of the given depth.
/// Pads with zero hashes if fewer chunks than 2^depth.
///
/// Uses a sparse approach: only builds the dense portion (next power of 2
/// above the chunk count), then chains zero hashes for remaining depth.
/// This makes it efficient even for large depths (e.g. depth 40 with ~1M chunks).
pub fn merkleize_chunks(chunks: &[[u8; 32]], depth: u32) -> [u8; 32] {
    if depth == 0 {
        return if chunks.is_empty() {
            [0u8; 32]
        } else {
            chunks[0]
        };
    }

    // Precompute zero hashes
    let mut zero_hashes = vec![[0u8; 32]; (depth + 1) as usize];
    for d in 1..=depth as usize {
        zero_hashes[d] = sha256_pair(&zero_hashes[d - 1], &zero_hashes[d - 1]);
    }

    if chunks.is_empty() {
        return zero_hashes[depth as usize];
    }

    // Compute dense depth: only allocate next-power-of-2 above chunk count
    let dense_depth = (chunks.len() as u64)
        .next_power_of_two()
        .trailing_zeros()
        .max(1)
        .min(depth);
    let dense_capacity = 1usize << dense_depth;

    // Build dense leaves (pad with zeros)
    let mut current_level = vec![[0u8; 32]; dense_capacity];
    for (i, chunk) in chunks.iter().enumerate() {
        current_level[i] = *chunk;
    }

    // Build dense levels bottom-up
    for _d in 0..dense_depth as usize {
        let parent_count = current_level.len() / 2;
        let mut next_level = Vec::with_capacity(parent_count);
        for i in 0..parent_count {
            next_level.push(sha256_pair(
                &current_level[i * 2],
                &current_level[i * 2 + 1],
            ));
        }
        current_level = next_level;
    }

    // Chain zero hashes for remaining sparse depth
    let mut root = current_level[0];
    for d in dense_depth..depth {
        root = sha256_pair(&root, &zero_hashes[d as usize]);
    }

    root
}

// -----------------------------------------------------------------------
// Primitive HTR functions
// -----------------------------------------------------------------------

/// hash_tree_root of a uint64 (8 bytes LE padded to 32).
fn htr_uint64(data: &[u8]) -> [u8; 32] {
    let mut chunk = [0u8; 32];
    chunk[..8].copy_from_slice(&data[..8]);
    chunk
}

/// hash_tree_root of a Bytes32 (identity).
fn htr_bytes32(data: &[u8]) -> [u8; 32] {
    let mut chunk = [0u8; 32];
    chunk.copy_from_slice(&data[..32]);
    chunk
}

/// hash_tree_root of Bitvector[4] (1 byte padded to 32).
fn htr_bitvector4(data: &[u8]) -> [u8; 32] {
    let mut chunk = [0u8; 32];
    chunk[0] = data[0];
    chunk
}

/// Pad a fixed-size byte slice to a 32-byte SSZ chunk.
fn pad_to_chunk(data: &[u8]) -> [u8; 32] {
    let mut chunk = [0u8; 32];
    let len = data.len().min(32);
    chunk[..len].copy_from_slice(&data[..len]);
    chunk
}

/// hash_tree_root of a BLSPubkey (48 bytes → 2 chunks → sha256_pair).
fn htr_bls_pubkey(data: &[u8]) -> [u8; 32] {
    let mut chunk0 = [0u8; 32];
    let mut chunk1 = [0u8; 32];
    chunk0.copy_from_slice(&data[..32]);
    chunk1[..16].copy_from_slice(&data[32..48]);
    sha256_pair(&chunk0, &chunk1)
}

// -----------------------------------------------------------------------
// Container HTR functions
// -----------------------------------------------------------------------

/// hash_tree_root of Fork: { previous_version: Bytes4, current_version: Bytes4, epoch: uint64 }
/// 3 fields → 4-leaf tree (depth 2).
fn htr_fork(data: &[u8]) -> [u8; 32] {
    let fields = [
        pad_to_chunk(&data[0..4]),  // previous_version
        pad_to_chunk(&data[4..8]),  // current_version
        pad_to_chunk(&data[8..16]), // epoch (uint64 LE)
        [0u8; 32],                  // padding
    ];
    let n0 = sha256_pair(&fields[0], &fields[1]);
    let n1 = sha256_pair(&fields[2], &fields[3]);
    sha256_pair(&n0, &n1)
}

/// hash_tree_root of BeaconBlockHeader:
/// { slot, proposer_index, parent_root, state_root, body_root }
/// 5 fields → 8-leaf tree (depth 3).
fn htr_beacon_block_header(data: &[u8]) -> [u8; 32] {
    let fields: [[u8; 32]; 8] = [
        pad_to_chunk(&data[0..8]),   // slot
        pad_to_chunk(&data[8..16]),  // proposer_index
        htr_bytes32(&data[16..48]),  // parent_root
        htr_bytes32(&data[48..80]),  // state_root
        htr_bytes32(&data[80..112]), // body_root
        [0u8; 32],
        [0u8; 32],
        [0u8; 32],
    ];
    merkleize_fixed_fields(&fields)
}

/// hash_tree_root of Eth1Data:
/// { deposit_root: Bytes32, deposit_count: uint64, block_hash: Bytes32 }
/// 3 fields → 4-leaf tree (depth 2).
fn htr_eth1_data(data: &[u8]) -> [u8; 32] {
    let fields = [
        htr_bytes32(&data[0..32]),   // deposit_root
        pad_to_chunk(&data[32..40]), // deposit_count (uint64)
        htr_bytes32(&data[40..72]),  // block_hash
        [0u8; 32],
    ];
    let n0 = sha256_pair(&fields[0], &fields[1]);
    let n1 = sha256_pair(&fields[2], &fields[3]);
    sha256_pair(&n0, &n1)
}

/// hash_tree_root of Checkpoint: { epoch: uint64, root: Bytes32 }
/// 2 fields → 2-leaf tree (depth 1).
fn htr_checkpoint(data: &[u8]) -> [u8; 32] {
    let epoch = pad_to_chunk(&data[0..8]);
    let root = htr_bytes32(&data[8..40]);
    sha256_pair(&epoch, &root)
}

/// hash_tree_root of SyncCommittee:
/// { pubkeys: Vector[BLSPubkey, 512], aggregate_pubkey: BLSPubkey }
/// 2 fields → 2-leaf tree.
fn htr_sync_committee(data: &[u8]) -> [u8; 32] {
    // pubkeys: 512 BLSPubkeys, each 48 bytes = 24576 bytes
    // Each pubkey HTR = sha256(chunk0, chunk1)
    let mut pubkey_htrs: Vec<[u8; 32]> = Vec::with_capacity(512);
    for i in 0..512 {
        let offset = i * 48;
        pubkey_htrs.push(htr_bls_pubkey(&data[offset..offset + 48]));
    }
    // Vector[BLSPubkey, 512]: merkleize 512 leaves, depth = 9 (2^9 = 512)
    let pubkeys_root = merkleize_chunks(&pubkey_htrs, 9);

    // aggregate_pubkey: BLSPubkey at offset 24576
    let agg_root = htr_bls_pubkey(&data[24576..24624]);

    sha256_pair(&pubkeys_root, &agg_root)
}

/// hash_tree_root of ExecutionPayloadHeaderDeneb.
/// This is a container with 17 fields (one variable: extra_data).
/// 17 fields → 32-leaf tree (depth 5).
fn htr_execution_payload_header_deneb(data: &[u8]) -> [u8; 32] {
    // ExecutionPayloadHeaderDeneb fields (SSZ order):
    // Fixed fields and their sizes:
    //  0: parent_hash       Bytes32    32
    //  1: fee_recipient     Bytes20    20
    //  2: state_root        Bytes32    32
    //  3: receipts_root     Bytes32    32
    //  4: logs_bloom        ByteVector[256] 256
    //  5: prev_randao       Bytes32    32
    //  6: block_number      uint64     8
    //  7: gas_limit         uint64     8
    //  8: gas_used          uint64     8
    //  9: timestamp         uint64     8
    // 10: extra_data        ByteList[32]   offset (4)
    // 11: base_fee_per_gas  uint256    32
    // 12: block_hash        Bytes32    32
    // 13: transactions_root Root       32
    // 14: withdrawals_root  Root       32
    // 15: blob_gas_used     uint64     8
    // 16: excess_blob_gas   uint64     8

    let eph_fixed_sizes: [usize; 17] =
        [32, 20, 32, 32, 256, 32, 8, 8, 8, 8, 4, 32, 32, 32, 32, 8, 8];
    let _eph_fixed_total: usize = eph_fixed_sizes.iter().sum();

    // Parse fixed portion and find extra_data offset
    let mut cursor = 0usize;
    let mut fixed_ranges: Vec<(usize, usize)> = Vec::with_capacity(17);
    let mut extra_data_offset = 0u32;

    for (i, &size) in eph_fixed_sizes.iter().enumerate() {
        if i == 10 {
            // extra_data offset
            extra_data_offset =
                u32::from_le_bytes(data[cursor..cursor + 4].try_into().unwrap_or([0; 4]));
            fixed_ranges.push((0, 0)); // placeholder
        } else {
            fixed_ranges.push((cursor, cursor + size));
        }
        cursor += size;
    }

    // Resolve extra_data byte range
    let extra_data_start = extra_data_offset as usize;
    let extra_data_end = data.len();
    fixed_ranges[10] = (extra_data_start, extra_data_end);

    // Compute field HTRs
    let mut fields = [[0u8; 32]; 32]; // 17 fields + 15 padding

    for i in 0..17 {
        let (start, end) = fixed_ranges[i];
        let field_data = &data[start..end];

        fields[i] = match i {
            0 | 2 | 3 | 5 | 12 | 13 | 14 => {
                // Bytes32 / Root
                let mut chunk = [0u8; 32];
                chunk.copy_from_slice(&field_data[..32]);
                chunk
            }
            1 => {
                // Bytes20 (fee_recipient / ExecutionAddress)
                pad_to_chunk(field_data)
            }
            4 => {
                // ByteVector[256] (logs_bloom) — 256 bytes → 8 chunks → depth 3
                let mut chunks = [[0u8; 32]; 8];
                for j in 0..8 {
                    chunks[j].copy_from_slice(&field_data[j * 32..(j + 1) * 32]);
                }
                merkleize_fixed_fields(&chunks)
            }
            6 | 7 | 8 | 9 | 15 | 16 => {
                // uint64
                pad_to_chunk(field_data)
            }
            10 => {
                // extra_data: ByteList[32]
                // Pack bytes into chunks (32 bytes per chunk), merkleize to limit depth,
                // mix in length.
                // Limit = 32 bytes → 1 chunk → depth 0 for data tree
                let count = field_data.len();
                let mut chunk = [0u8; 32];
                let copy_len = count.min(32);
                chunk[..copy_len].copy_from_slice(&field_data[..copy_len]);
                // data_root = chunk (single chunk, depth 0 tree)
                let data_root = chunk;
                // mix in length
                let mut length_chunk = [0u8; 32];
                length_chunk[..8].copy_from_slice(&(count as u64).to_le_bytes());
                sha256_pair(&data_root, &length_chunk)
            }
            11 => {
                // uint256 (base_fee_per_gas) — 32 bytes, identity
                let mut chunk = [0u8; 32];
                chunk.copy_from_slice(&field_data[..32]);
                chunk
            }
            _ => unreachable!(),
        };
    }

    merkleize_chunks(&fields, 5)
}

/// hash_tree_root of HistoricalSummary:
/// { block_summary_root: Root, state_summary_root: Root }
fn htr_historical_summary(data: &[u8]) -> [u8; 32] {
    let block_root = htr_bytes32(&data[0..32]);
    let state_root = htr_bytes32(&data[32..64]);
    sha256_pair(&block_root, &state_root)
}

/// hash_tree_root of BLSSignature (96 bytes → 3 chunks → 4-leaf tree, depth 2).
fn htr_bls_signature(data: &[u8]) -> [u8; 32] {
    let mut chunk0 = [0u8; 32];
    let mut chunk1 = [0u8; 32];
    let mut chunk2 = [0u8; 32];
    chunk0.copy_from_slice(&data[..32]);
    chunk1.copy_from_slice(&data[32..64]);
    chunk2.copy_from_slice(&data[64..96]);
    let n0 = sha256_pair(&chunk0, &chunk1);
    let n1 = sha256_pair(&chunk2, &[0u8; 32]);
    sha256_pair(&n0, &n1)
}

/// hash_tree_root of PendingDeposit:
/// { pubkey: BLSPubkey, withdrawal_credentials: Bytes32, amount: Gwei,
///   signature: BLSSignature, slot: Slot }
/// 5 fields → 8-leaf tree (depth 3).
fn htr_pending_deposit(data: &[u8]) -> [u8; 32] {
    let fields: [[u8; 32]; 8] = [
        htr_bls_pubkey(&data[0..48]),      // pubkey (48B)
        htr_bytes32(&data[48..80]),        // withdrawal_credentials (32B)
        pad_to_chunk(&data[80..88]),       // amount (uint64, 8B)
        htr_bls_signature(&data[88..184]), // signature (96B)
        pad_to_chunk(&data[184..192]),     // slot (uint64, 8B)
        [0u8; 32],
        [0u8; 32],
        [0u8; 32],
    ];
    merkleize_fixed_fields(&fields)
}

/// hash_tree_root of PendingPartialWithdrawal:
/// { validator_index: ValidatorIndex, amount: Gwei, withdrawable_epoch: Epoch }
/// 3 fields → 4-leaf tree (depth 2).
fn htr_pending_partial_withdrawal(data: &[u8]) -> [u8; 32] {
    let fields = [
        pad_to_chunk(&data[0..8]),   // validator_index
        pad_to_chunk(&data[8..16]),  // amount
        pad_to_chunk(&data[16..24]), // withdrawable_epoch
        [0u8; 32],
    ];
    let n0 = sha256_pair(&fields[0], &fields[1]);
    let n1 = sha256_pair(&fields[2], &fields[3]);
    sha256_pair(&n0, &n1)
}

/// hash_tree_root of PendingConsolidation:
/// { source_index: ValidatorIndex, target_index: ValidatorIndex }
/// 2 fields → 2-leaf tree (depth 1).
fn htr_pending_consolidation(data: &[u8]) -> [u8; 32] {
    let source = pad_to_chunk(&data[0..8]);
    let target = pad_to_chunk(&data[8..16]);
    sha256_pair(&source, &target)
}

/// Merkleize exactly 8 fixed fields (depth 3).
fn merkleize_fixed_fields(fields: &[[u8; 32]; 8]) -> [u8; 32] {
    let n0 = sha256_pair(&fields[0], &fields[1]);
    let n1 = sha256_pair(&fields[2], &fields[3]);
    let n2 = sha256_pair(&fields[4], &fields[5]);
    let n3 = sha256_pair(&fields[6], &fields[7]);
    let n4 = sha256_pair(&n0, &n1);
    let n5 = sha256_pair(&n2, &n3);
    sha256_pair(&n4, &n5)
}

// -----------------------------------------------------------------------
// Vector HTR functions
// -----------------------------------------------------------------------

/// hash_tree_root of Vector[Root, N]: merkleize N 32-byte chunks.
fn htr_vector_roots(data: &[u8], count: usize) -> [u8; 32] {
    let mut chunks: Vec<[u8; 32]> = Vec::with_capacity(count);
    for i in 0..count {
        let mut chunk = [0u8; 32];
        chunk.copy_from_slice(&data[i * 32..(i + 1) * 32]);
        chunks.push(chunk);
    }
    let depth = (count as u64).next_power_of_two().trailing_zeros();
    merkleize_chunks(&chunks, depth)
}

/// hash_tree_root of Vector[Gwei, N]: pack 4 uint64s per 32-byte chunk, merkleize.
fn htr_vector_gwei(data: &[u8], count: usize) -> [u8; 32] {
    let num_chunks = count.div_ceil(4);
    let mut chunks: Vec<[u8; 32]> = Vec::with_capacity(num_chunks);
    for i in 0..num_chunks {
        let mut chunk = [0u8; 32];
        for j in 0..4 {
            let idx = i * 4 + j;
            if idx < count {
                let offset = idx * 8;
                chunk[j * 8..(j + 1) * 8].copy_from_slice(&data[offset..offset + 8]);
            }
        }
        chunks.push(chunk);
    }
    let depth = (num_chunks as u64).next_power_of_two().trailing_zeros();
    merkleize_chunks(&chunks, depth)
}

// -----------------------------------------------------------------------
// List HTR functions
// -----------------------------------------------------------------------

/// Mix in the list length: sha256(data_root || le_pad32(length)).
fn mix_in_length(data_root: &[u8; 32], length: u64) -> [u8; 32] {
    let mut length_chunk = [0u8; 32];
    length_chunk[..8].copy_from_slice(&length.to_le_bytes());
    sha256_pair(data_root, &length_chunk)
}

/// hash_tree_root of List[Root, 2^limit_log2]: each item 32 bytes.
fn htr_list_roots(data: &[u8], limit_log2: u32) -> [u8; 32] {
    let count = data.len() / 32;
    let mut chunks: Vec<[u8; 32]> = Vec::with_capacity(count);
    for i in 0..count {
        let mut chunk = [0u8; 32];
        chunk.copy_from_slice(&data[i * 32..(i + 1) * 32]);
        chunks.push(chunk);
    }
    let data_root = merkleize_chunks(&chunks, limit_log2);
    mix_in_length(&data_root, count as u64)
}

/// hash_tree_root of List[Eth1Data, 2^limit_log2]: each item 72 bytes.
fn htr_list_eth1_data(data: &[u8], limit_log2: u32) -> [u8; 32] {
    let item_size = 72;
    let count = data.len() / item_size;
    let mut htrs: Vec<[u8; 32]> = Vec::with_capacity(count);
    for i in 0..count {
        let offset = i * item_size;
        htrs.push(htr_eth1_data(&data[offset..offset + item_size]));
    }
    let data_root = merkleize_chunks(&htrs, limit_log2);
    mix_in_length(&data_root, count as u64)
}

/// hash_tree_root of List[uint64, 2^limit_log2]: pack 4 per chunk.
fn htr_list_gwei(data: &[u8], limit_log2: u32) -> [u8; 32] {
    let count = data.len() / 8;
    let num_chunks = count.div_ceil(4);
    let mut chunks: Vec<[u8; 32]> = Vec::with_capacity(num_chunks);
    for i in 0..num_chunks {
        let mut chunk = [0u8; 32];
        for j in 0..4 {
            let idx = i * 4 + j;
            if idx < count {
                let offset = idx * 8;
                chunk[j * 8..(j + 1) * 8].copy_from_slice(&data[offset..offset + 8]);
            }
        }
        chunks.push(chunk);
    }
    // For List[uint64, 2^limit_log2], the data tree has depth = limit_log2 - 2
    // because we pack 4 items per chunk (2^2 = 4), so chunk count limit = 2^(limit_log2-2).
    // Actually: max chunks = ceil(2^limit_log2 / 4) = 2^(limit_log2 - 2).
    let chunk_depth = limit_log2.saturating_sub(2);
    let data_root = merkleize_chunks(&chunks, chunk_depth);
    mix_in_length(&data_root, count as u64)
}

/// hash_tree_root of List[uint8, 2^limit_log2]: pack 32 per chunk.
fn htr_list_uint8(data: &[u8], limit_log2: u32) -> [u8; 32] {
    let count = data.len();
    let num_chunks = count.div_ceil(32);
    let mut chunks: Vec<[u8; 32]> = Vec::with_capacity(num_chunks);
    for i in 0..num_chunks {
        let mut chunk = [0u8; 32];
        let start = i * 32;
        let end = (start + 32).min(count);
        chunk[..end - start].copy_from_slice(&data[start..end]);
        chunks.push(chunk);
    }
    // max chunks = ceil(2^limit_log2 / 32) = 2^(limit_log2 - 5)
    let chunk_depth = limit_log2.saturating_sub(5);
    let data_root = merkleize_chunks(&chunks, chunk_depth);
    mix_in_length(&data_root, count as u64)
}

/// hash_tree_root of List[PendingDeposit, 2^limit_log2]: each item 192 bytes.
fn htr_list_pending_deposits(data: &[u8], limit_log2: u32) -> [u8; 32] {
    let item_size = 192;
    let count = data.len() / item_size;
    let mut htrs: Vec<[u8; 32]> = Vec::with_capacity(count);
    for i in 0..count {
        let offset = i * item_size;
        htrs.push(htr_pending_deposit(&data[offset..offset + item_size]));
    }
    let data_root = merkleize_chunks(&htrs, limit_log2);
    mix_in_length(&data_root, count as u64)
}

/// hash_tree_root of List[PendingPartialWithdrawal, 2^limit_log2]: each item 24 bytes.
fn htr_list_pending_partial_withdrawals(data: &[u8], limit_log2: u32) -> [u8; 32] {
    let item_size = 24;
    let count = data.len() / item_size;
    let mut htrs: Vec<[u8; 32]> = Vec::with_capacity(count);
    for i in 0..count {
        let offset = i * item_size;
        htrs.push(htr_pending_partial_withdrawal(
            &data[offset..offset + item_size],
        ));
    }
    let data_root = merkleize_chunks(&htrs, limit_log2);
    mix_in_length(&data_root, count as u64)
}

/// hash_tree_root of List[PendingConsolidation, 2^limit_log2]: each item 16 bytes.
fn htr_list_pending_consolidations(data: &[u8], limit_log2: u32) -> [u8; 32] {
    let item_size = 16;
    let count = data.len() / item_size;
    let mut htrs: Vec<[u8; 32]> = Vec::with_capacity(count);
    for i in 0..count {
        let offset = i * item_size;
        htrs.push(htr_pending_consolidation(&data[offset..offset + item_size]));
    }
    let data_root = merkleize_chunks(&htrs, limit_log2);
    mix_in_length(&data_root, count as u64)
}

/// hash_tree_root of List[HistoricalSummary, 2^limit_log2]: each item 64 bytes.
fn htr_list_historical_summaries(data: &[u8], limit_log2: u32) -> [u8; 32] {
    let item_size = 64;
    let count = data.len() / item_size;
    let mut htrs: Vec<[u8; 32]> = Vec::with_capacity(count);
    for i in 0..count {
        let offset = i * item_size;
        htrs.push(htr_historical_summary(&data[offset..offset + item_size]));
    }
    let data_root = merkleize_chunks(&htrs, limit_log2);
    mix_in_length(&data_root, count as u64)
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_htr_uint64() {
        let data = 42u64.to_le_bytes();
        let result = htr_uint64(&data);
        assert_eq!(u64::from_le_bytes(result[..8].try_into().unwrap()), 42);
        assert_eq!(&result[8..], &[0u8; 24]);
    }

    #[test]
    fn test_htr_bytes32() {
        let data = [0xABu8; 32];
        assert_eq!(htr_bytes32(&data), data);
    }

    #[test]
    fn test_htr_bitvector4() {
        let data = [0x0F];
        let result = htr_bitvector4(&data);
        assert_eq!(result[0], 0x0F);
        assert_eq!(&result[1..], &[0u8; 31]);
    }

    #[test]
    fn test_htr_fork() {
        // Fork with all zeros
        let data = [0u8; 16];
        let result = htr_fork(&data);
        // Should be sha256(sha256(zero, zero), sha256(zero, zero))
        let zero = [0u8; 32];
        let inner = sha256_pair(&zero, &zero);
        let expected = sha256_pair(&inner, &inner);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_htr_checkpoint() {
        let mut data = [0u8; 40];
        // epoch = 100
        data[..8].copy_from_slice(&100u64.to_le_bytes());
        // root = 0xFF..FF
        data[8..40].fill(0xFF);

        let epoch_chunk = pad_to_chunk(&data[0..8]);
        let root_chunk = htr_bytes32(&data[8..40]);
        let expected = sha256_pair(&epoch_chunk, &root_chunk);
        assert_eq!(htr_checkpoint(&data), expected);
    }

    #[test]
    fn test_merkleize_chunks_single() {
        let chunk = [1u8; 32];
        let result = merkleize_chunks(&[chunk], 0);
        assert_eq!(result, chunk);
    }

    #[test]
    fn test_merkleize_chunks_pair() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let result = merkleize_chunks(&[a, b], 1);
        assert_eq!(result, sha256_pair(&a, &b));
    }

    #[test]
    fn test_merkleize_chunks_with_padding() {
        // 1 chunk, depth 2 → should be: sha256(sha256(chunk, zero), sha256(zero, zero))
        let chunk = [1u8; 32];
        let zero = [0u8; 32];
        let result = merkleize_chunks(&[chunk], 2);

        let n0 = sha256_pair(&chunk, &zero);
        let n1 = sha256_pair(&zero, &zero);
        let expected = sha256_pair(&n0, &n1);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_mix_in_length() {
        let root = [1u8; 32];
        let result = mix_in_length(&root, 42);
        let mut length_chunk = [0u8; 32];
        length_chunk[..8].copy_from_slice(&42u64.to_le_bytes());
        assert_eq!(result, sha256_pair(&root, &length_chunk));
    }

    #[test]
    fn test_htr_bls_pubkey() {
        let mut data = [0u8; 48];
        data[0] = 0xAA;
        data[47] = 0xBB;
        let result = htr_bls_pubkey(&data);
        // Should be sha256(data[0..32], data[32..48]++zeros)
        let mut chunk0 = [0u8; 32];
        chunk0.copy_from_slice(&data[0..32]);
        let mut chunk1 = [0u8; 32];
        chunk1[..16].copy_from_slice(&data[32..48]);
        assert_eq!(result, sha256_pair(&chunk0, &chunk1));
    }

    #[test]
    fn test_state_tree_extracts_correct_siblings() {
        // Build a 64-leaf tree with known values (Fulu depth 6)
        let mut leaves = [[0u8; 32]; STATE_TREE_LEAVES];
        for (i, leaf) in leaves.iter_mut().enumerate() {
            leaf[0] = i as u8;
        }
        let (root, siblings) = build_state_tree_and_extract(&leaves, 11);
        assert_eq!(siblings.len(), STATE_TREE_DEPTH);

        // Verify proof: starting from leaf 11, applying siblings should give root
        let mut current = leaves[11];
        let mut idx = 11usize;
        for sib in &siblings {
            if idx & 1 == 0 {
                current = sha256_pair(&current, sib);
            } else {
                current = sha256_pair(sib, &current);
            }
            idx >>= 1;
        }
        assert_eq!(current, root);
    }

    #[test]
    fn test_htr_bls_signature() {
        let mut data = [0u8; 96];
        data[0] = 0xAA;
        data[95] = 0xBB;
        let result = htr_bls_signature(&data);
        // 96 bytes → 3 chunks of 32, 4th chunk is zero → depth 2 tree
        let mut c0 = [0u8; 32];
        c0.copy_from_slice(&data[..32]);
        let mut c1 = [0u8; 32];
        c1.copy_from_slice(&data[32..64]);
        let mut c2 = [0u8; 32];
        c2.copy_from_slice(&data[64..96]);
        let n0 = sha256_pair(&c0, &c1);
        let n1 = sha256_pair(&c2, &[0u8; 32]);
        assert_eq!(result, sha256_pair(&n0, &n1));
    }

    #[test]
    fn test_htr_pending_partial_withdrawal() {
        // All zeros
        let data = [0u8; 24];
        let result = htr_pending_partial_withdrawal(&data);
        let zero = [0u8; 32];
        let n0 = sha256_pair(&zero, &zero);
        let n1 = sha256_pair(&zero, &zero);
        assert_eq!(result, sha256_pair(&n0, &n1));
    }

    #[test]
    fn test_htr_pending_consolidation() {
        let mut data = [0u8; 16];
        data[..8].copy_from_slice(&42u64.to_le_bytes());
        data[8..16].copy_from_slice(&99u64.to_le_bytes());
        let result = htr_pending_consolidation(&data);
        let source = pad_to_chunk(&data[0..8]);
        let target = pad_to_chunk(&data[8..16]);
        assert_eq!(result, sha256_pair(&source, &target));
    }

    /// Test parsing a real SSZ state file from disk.
    ///
    /// Requires SSZ_STATE_PATH, EXPECTED_STATE_ROOT, and CHAIN env vars.
    /// Run with:
    /// ```sh
    /// SSZ_STATE_PATH=test_data/state_13776608.ssz \
    /// EXPECTED_STATE_ROOT=0x521d21fb0fffa1e7197ae149ae7c2d81bd66cd30be6cd5744f3a4f7105c5daef \
    /// CHAIN=mainnet \
    /// cargo test --lib ssz_state::tests::test_real_ssz_state -- --ignored
    /// ```
    #[test]
    #[ignore = "requires SSZ_STATE_PATH"]
    fn test_real_ssz_state() {
        let path = std::env::var("SSZ_STATE_PATH").expect("SSZ_STATE_PATH must be set");
        let expected_root_hex =
            std::env::var("EXPECTED_STATE_ROOT").expect("EXPECTED_STATE_ROOT must be set");

        let raw_ssz = std::fs::read(&path).expect("failed to read SSZ state file");
        eprintln!("loaded {} bytes from {}", raw_ssz.len(), path);

        let chain = std::env::var("CHAIN").unwrap_or_else(|_| "mainnet".to_string());
        let config = match chain.as_str() {
            "gnosis" => ChainConfig::GNOSIS,
            _ => ChainConfig::MAINNET,
        };
        let (state_root, num_validators) = compute_state_root(&raw_ssz, &config).unwrap();
        eprintln!("  computed state_root: 0x{}", hex::encode(state_root));
        eprintln!("  num_validators: {num_validators}");

        let expected_hex = expected_root_hex
            .strip_prefix("0x")
            .unwrap_or(&expected_root_hex);
        let expected_bytes = hex::decode(expected_hex).expect("invalid hex in EXPECTED_STATE_ROOT");
        let mut expected_root = [0u8; 32];
        expected_root.copy_from_slice(&expected_bytes);

        assert_eq!(
            state_root, expected_root,
            "computed state root does not match expected"
        );
        eprintln!("  state root matches!");
    }
}

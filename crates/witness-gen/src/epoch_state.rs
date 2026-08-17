use serde::{Deserialize, Serialize};

/// Cached state from a processed epoch, used to speed up the next epoch diff.
///
/// Avoids recomputing O(n) validator roots and re-parsing the SSZ state blob
/// when only O(k) validators changed.
#[derive(Clone, Serialize, Deserialize)]
pub struct EpochState {
    pub slot: u64,
    pub state_root: [u8; 32],
    pub state_to_validators_siblings: Vec<[u8; 32]>,
    /// Per-validator SHA-256 hash tree roots (one per validator).
    pub validator_roots: Vec<[u8; 32]>,
    /// Root of the validators data Merkle tree (before mix_in_length).
    pub ssz_data_root: [u8; 32],
    pub num_validators: u64,
}

impl EpochState {
    /// Create an empty EpochState (no cached data — forces slow path in epoch_diff).
    pub fn empty(slot: u64, num_validators: u64) -> Self {
        Self {
            slot,
            state_root: [0u8; 32],
            state_to_validators_siblings: vec![],
            validator_roots: vec![],
            ssz_data_root: [0u8; 32],
            num_validators,
        }
    }
}

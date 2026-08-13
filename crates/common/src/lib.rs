#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod acc;
pub mod bls;
pub mod merkle;
#[cfg(feature = "count-ops")]
pub mod op_counter;
pub mod recursion;
pub mod ssz;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
pub mod types;

/// Which consensus-layer fork a beacon state belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusFork {
    Electra,
    Fulu,
}

/// Network-specific configuration for beacon chain parameters.
#[derive(Debug, Clone)]
pub struct ChainConfig {
    pub slots_per_epoch: u64,
    pub validators_tree_depth: u32,
    pub acc_tree_depth: u32,
    pub beacon_state_validators_field_index: u64,
    /// First epoch at which the Fulu fork is active. `u64::MAX` means not scheduled.
    pub fulu_fork_epoch: u64,
}

impl ChainConfig {
    pub const MAINNET: Self = Self {
        slots_per_epoch: 32,
        validators_tree_depth: 40,
        acc_tree_depth: 22,
        beacon_state_validators_field_index: 11,
        fulu_fork_epoch: 0, // Fulu already active on mainnet test data
    };

    pub const GNOSIS: Self = Self {
        slots_per_epoch: 16,
        validators_tree_depth: 40,
        acc_tree_depth: 22,
        beacon_state_validators_field_index: 11,
        fulu_fork_epoch: u64::MAX, // Fulu not yet scheduled on Gnosis
    };

    /// Return the consensus fork active at `slot`.
    pub fn fork_at_slot(&self, slot: u64) -> ConsensusFork {
        let epoch = slot / self.slots_per_epoch;
        if epoch >= self.fulu_fork_epoch {
            ConsensusFork::Fulu
        } else {
            ConsensusFork::Electra
        }
    }
}

/// Beacon chain constants
pub mod constants {
    /// Depth of the SSZ validators data tree (capacity 2^40, per spec).
    pub const VALIDATORS_TREE_DEPTH: u32 = 40;

    /// Depth of the accumulator tree (capacity 2^22 = 4,194,304).
    /// Independent of the SSZ tree depth — only needs to hold the actual
    /// validator count (~2.2M as of 2025).
    pub const ACC_TREE_DEPTH: u32 = 22;

    /// Number of fields in a Validator container
    pub const VALIDATOR_FIELDS_COUNT: usize = 8;

    /// Generalized index of `validators` in BeaconState (field index 11, depth 6 for Fulu)
    pub const BEACON_STATE_VALIDATORS_FIELD_INDEX: u64 = 11;

    /// Slots per epoch
    pub const SLOTS_PER_EPOCH: u64 = 32;

    /// BLS domain type for beacon attester
    pub const DOMAIN_BEACON_ATTESTER: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

    /// Far future epoch sentinel
    pub const FAR_FUTURE_EPOCH: u64 = u64::MAX;
}

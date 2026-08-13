use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::acc::{Digest, G1Point};

/// Merkle multi-proof: the sibling nodes a leaf set does not itself determine.
///
/// Ordered bottom-up, and within a level in ascending parent order, left child
/// before right — the order [`crate::merkle::batch_root`] consumes them in.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MultiProof<T> {
    pub auxiliaries: Vec<T>,
}

/// Multi-proof over the SSZ (SHA-256) tree.
pub type SszMultiProof = MultiProof<[u8; 32]>;

/// Multi-proof over the accumulator (Poseidon2-Goldilocks) tree.
pub type AccMultiProof = MultiProof<Digest>;

/// 48-byte BLS public key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlsPubkey(#[serde(with = "BigArray")] pub [u8; 48]);

/// 96-byte BLS signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlsSignature(#[serde(with = "BigArray")] pub [u8; 96]);

/// Minimal validator data — only the fields needed for zkasper.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorData {
    pub pubkey: BlsPubkey,
    /// Effective balance in Gwei.
    pub effective_balance: u64,
    pub activation_epoch: u64,
    pub exit_epoch: u64,
}

impl ValidatorData {
    /// Whether this validator is active at the given epoch.
    pub fn is_active(&self, epoch: u64) -> bool {
        self.activation_epoch <= epoch && epoch < self.exit_epoch
    }

    /// Returns `effective_balance` if active, else 0.
    pub fn active_effective_balance(&self, epoch: u64) -> u64 {
        if self.is_active(epoch) {
            self.effective_balance
        } else {
            0
        }
    }
}

/// Casper FFG checkpoint (epoch + block root).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub epoch: u64,
    pub root: [u8; 32],
}

// ---------------------------------------------------------------------------
// Witness types
// ---------------------------------------------------------------------------

/// One changed validator between two consecutive epochs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorMutation {
    pub validator_index: u64,
    /// True if this validator is new (not present in the old state).
    /// When true, the old leaf in both SSZ and accumulator trees is all-zeros.
    pub is_new: bool,
    pub old_data: ValidatorData,
    pub new_data: ValidatorData,
    /// 8 field-level SSZ hash-tree leaves for the Validator container.
    pub old_field_leaves: [[u8; 32]; 8],
    pub new_field_leaves: [[u8; 32]; 8],
    /// Raw pubkey split into 2x32-byte SSZ chunks (to verify field_leaves[0]).
    pub old_pubkey_chunks: [[u8; 32]; 2],
    pub new_pubkey_chunks: [[u8; 32]; 2],
    /// Accumulator Merkle siblings (depth = ACC_TREE_DEPTH).
    pub acc_siblings: Vec<Digest>,
}

/// Witness for Proof 1: Epoch Diff.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochDiffWitness {
    // -- public inputs (bound by on-chain state) --
    pub state_root_1: [u8; 32],
    pub state_root_2: [u8; 32],
    pub acc_root_1: Digest,
    pub total_active_balance_1: u64,
    /// Epoch of state_root_1 (used for old is_active checks).
    pub epoch_1: u64,
    /// Epoch of state_root_2 (used for new is_active checks).
    pub epoch_2: u64,

    // -- SSZ proof: state_root -> validators data tree root --
    pub state_to_validators_siblings_1: Vec<[u8; 32]>,
    pub state_to_validators_siblings_2: Vec<[u8; 32]>,
    pub validators_list_length_1: u64,
    pub validators_list_length_2: u64,

    // -- mutations --
    pub mutations: Vec<ValidatorMutation>,

    // -- SSZ multi-proofs for validator trees --
    pub ssz_multi_proof_1: SszMultiProof,
    pub ssz_multi_proof_2: SszMultiProof,
}

/// Per-validator data carried inside an attestation witness.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestingValidator {
    pub validator_index: u64,
    /// Decompressed public key, matching what the accumulator leaf commits to.
    pub pubkey: G1Point,
    pub active_effective_balance: u64,
    /// Whether this validator's balance should be counted towards the
    /// attesting total. False when the same validator appears in an
    /// earlier attestation (prevents double-counting).
    pub count_balance: bool,
}

/// One aggregated attestation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationWitness {
    // -- Raw AttestationData fields (circuit recomputes hash_tree_root) --
    pub data_slot: u64,
    pub data_index: u64,
    pub data_beacon_block_root: [u8; 32],
    pub data_source_epoch: u64,
    pub data_source_root: [u8; 32],
    pub data_target_epoch: u64,
    pub data_target_root: [u8; 32],
    /// Aggregate BLS signature over the signing root.
    pub signature: BlsSignature,
    /// All validators that participated (bit set in aggregation_bits).
    pub attesting_validators: Vec<AttestingValidator>,
}

// ---------------------------------------------------------------------------
// Slot-level proving types
// ---------------------------------------------------------------------------

/// Public outputs of a slot proof.
///
/// After recursive verification, the justification circuit sees only these values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotProofOutput {
    pub accumulator_commitment: Digest,
    pub target_epoch: u64,
    pub target_root: [u8; 32],
    /// Sum of `active_effective_balance` for validators with `count_balance=true`.
    pub attesting_balance: u64,
    /// Sponge commitment over sorted counted validator indices.
    pub counted_validators_commitment: Digest,
    /// Number of counted validators (for commitment verification).
    pub num_counted_validators: u64,
}

/// Witness for a slot proof (one block's attestations).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlotProofWitness {
    // -- public inputs --
    pub accumulator_commitment: Digest,
    pub target_epoch: u64,
    pub target_root: [u8; 32],
    pub signing_domain: [u8; 32],

    // -- private witness --
    pub acc_root: Digest,
    pub total_active_balance: u64,
    pub attestations: Vec<AttestationWitness>,
    pub acc_multi_proof: AccMultiProof,
}

/// Public outputs of a justification proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JustificationOutput {
    pub accumulator_commitment: Digest,
    pub target_epoch: u64,
    pub target_root: [u8; 32],
}

/// Witness for a justification proof (aggregates slot proofs).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JustificationWitness {
    // -- public inputs --
    pub accumulator_commitment: Digest,
    pub target_epoch: u64,
    pub target_root: [u8; 32],
    pub total_active_balance: u64,

    /// Verification key of the slot-proof program. Bound into the justification
    /// output so the on-chain verifier can pin which program the slot proofs
    /// came from.
    pub slot_program_vk: crate::recursion::ProgramVk,

    // -- slot proof outputs, verified recursively --
    pub slot_proof_outputs: Vec<SlotProofOutput>,
    /// Zisk proof words per slot (empty in native testing mode).
    pub slot_proofs: Vec<Vec<u64>>,

    // -- dedup witness: per-slot sorted counted validator indices --
    pub counted_indices_per_slot: Vec<Vec<u64>>,
}

/// Public outputs of a finalization proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizationOutput {
    pub accumulator_commitment: Digest,
    pub finalized_epoch: u64,
    pub finalized_root: [u8; 32],
}

/// Witness for a finalization proof (pairs two consecutive justifications).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalizationWitness {
    pub accumulator_commitment: Digest,
    /// Verification key of the justification program.
    pub justification_program_vk: crate::recursion::ProgramVk,
    /// Justification outputs for epochs E and E+1.
    pub justification_outputs: Vec<JustificationOutput>,
    /// Zisk proof words for each justification (empty in native testing mode).
    pub justification_proofs: Vec<Vec<u64>>,
}

/// Witness for Bootstrap: one-time accumulator tree construction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BootstrapWitness {
    pub state_root: [u8; 32],
    pub epoch: u64,
    pub validators: Vec<ValidatorData>,
    /// SSZ proof from state_root to the validators data tree root.
    pub state_to_validators_siblings: Vec<[u8; 32]>,
    pub validators_list_length: u64,
    /// Per-validator: the 8 SSZ field-level hash-tree leaves.
    pub validator_field_chunks: Vec<[[u8; 32]; 8]>,
    /// Per-validator: raw pubkey split into 2x32-byte SSZ chunks.
    pub validator_pubkey_chunks: Vec<[[u8; 32]; 2]>,
}

// ---------------------------------------------------------------------------
// Public output encoding
// ---------------------------------------------------------------------------

use crate::recursion::PublicWriter;

impl SlotProofOutput {
    /// Bytes this proof commits to, and that the justification proof checks the
    /// child proof against.
    pub fn public_bytes(&self) -> Vec<u8> {
        PublicWriter::new()
            .digest(&self.accumulator_commitment)
            .u64(self.target_epoch)
            .bytes32(&self.target_root)
            .u64(self.attesting_balance)
            .digest(&self.counted_validators_commitment)
            .u64(self.num_counted_validators)
            .finish()
    }
}

impl JustificationOutput {
    pub fn public_bytes(&self) -> Vec<u8> {
        PublicWriter::new()
            .digest(&self.accumulator_commitment)
            .u64(self.target_epoch)
            .bytes32(&self.target_root)
            .finish()
    }
}

impl FinalizationOutput {
    pub fn public_bytes(&self) -> Vec<u8> {
        PublicWriter::new()
            .digest(&self.accumulator_commitment)
            .u64(self.finalized_epoch)
            .bytes32(&self.finalized_root)
            .finish()
    }
}

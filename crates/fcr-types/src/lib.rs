//! FCR witness and output types.
//!
//! Deliberately not in `zkasper-common`: every finality guest compiles that
//! crate, a guest's ELF decides its verification key, and a key that moves costs
//! a re-bake of every guest that verifies it. Nothing here is reachable from the
//! finality pipeline.

use serde::{Deserialize, Serialize};
use zkasper_common::acc::Digest;
use zkasper_common::recursion::PublicWriter;
use zkasper_common::types::{AccMultiProof, SlotComplementWitness};


/// A `BeaconBlockHeader`, at the five fields its root is built from.
///
/// Carried rather than trusted: the circuit recomputes the root, so the only
/// thing a host can choose is which header it hands over, and `parent_root`
/// pins that to the chain the batch before it left.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeaderWitness {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: [u8; 32],
    pub state_root: [u8; 32],
    pub body_root: [u8; 32],
}

/// One slot of an FCR batch: a complement, and the block its head votes are
/// counted against.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FcrSlotWitness {
    pub complement: SlotComplementWitness,
    /// The block proposed at this slot, or `None` when the slot was skipped and
    /// the canonical head is still the one the slot before it left.
    pub head_header: Option<BlockHeaderWitness>,
}

/// One FCR proof over a run of consecutive slots.
///
/// The batch is standalone — it verifies its own signatures rather than handing
/// a Miller accumulator upwards — because FCR accumulates in the verifier and
/// not in the circuit. Batching is what makes that affordable: the stage floor
/// is 75% of a one-slot proof, so three slots under one floor cost 10.78 s
/// against 27.27 s.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FcrBatchWitness {
    pub accumulator_commitment: Digest,
    pub acc_root: Digest,
    pub total_active_balance: u64,
    /// One committee root for the whole batch. Two committee proofs of one
    /// epoch are two partitions, and the disjointness argument holds for one.
    pub committee_root: Digest,
    pub acc_multi_proof: AccMultiProof,
    pub committee_multi_proof: AccMultiProof,
    pub signing_domain: [u8; 32],
    /// Canonical head at the slot before the batch's first, so that batches
    /// chain: this is the previous batch's `head_root` and `head_slot`.
    pub parent_head_root: [u8; 32],
    pub parent_head_slot: u64,
    pub slots: Vec<FcrSlotWitness>,
}

/// What an FCR batch proof establishes.
///
/// `support` is a sum, not a verdict. The threshold — tier A's
/// `0.5*M + beta*T + P/2` — is integer arithmetic on published scalars, so the
/// verifier evaluates it and this circuit never encodes a safety parameter it
/// would have to be rebuilt to change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FcrBatchOutput {
    pub accumulator_commitment: Digest,
    pub committee_root: Digest,
    /// Head the batch started from, and the head it ended at. A verifier joins
    /// batches by matching one to the other.
    pub parent_head_root: [u8; 32],
    pub head_root: [u8; 32],
    /// Slot of the last block proposed in the batch, so a verifier can tell a
    /// run of skipped slots from a batch that ended early.
    pub head_slot: u64,
    /// Effective balance that voted for the canonical head of its own slot,
    /// summed over the batch. Votes for anything else are dropped, not
    /// attributed, which under-counts and is therefore conservative.
    pub support: u64,
    /// Total active balance, republished so a verifier can evaluate the
    /// threshold. `accumulator_commitment` binds it but does not reveal it, and
    /// a verifier that tracks only the finality chain's commitments cannot
    /// invert a Poseidon hash to recover it.
    pub total_active_balance: u64,
    /// The contiguous run of slots this batch covers. `slot_count` is the `k` of
    /// `M(k)`, and a gap would let a prover drop a slot that carried little
    /// support and shrink the threshold by more than the support it lost — so
    /// the run is contiguous and the verifier joins batches by
    /// `first_slot + slot_count`.
    pub first_slot: u64,
    pub slot_count: u64,
}

impl FcrBatchOutput {
    pub fn public_bytes(&self) -> Vec<u8> {
        PublicWriter::new()
            .digest(&self.accumulator_commitment)
            .digest(&self.committee_root)
            .bytes32(&self.parent_head_root)
            .bytes32(&self.head_root)
            .u64(self.head_slot)
            .u64(self.support)
            .u64(self.total_active_balance)
            .u64(self.first_slot)
            .u64(self.slot_count)
            .finish()
    }
}

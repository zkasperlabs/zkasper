//! Assemble a JustificationWitness from slot proof outputs.

use zkasper_common::acc::Digest;
use zkasper_common::recursion::ProgramVk;
use zkasper_common::types::{CommitteeOutput, JustificationWitness, SlotProofOutput};

/// Build a JustificationWitness from slot proof results.
///
/// `slot_proofs` carries the serialized Zisk proof words per slot, empty when
/// running the circuit natively without a prover.
#[allow(clippy::too_many_arguments)]
pub fn build(
    slot_proof_outputs: Vec<SlotProofOutput>,
    slot_proofs: Vec<Vec<u64>>,
    accumulator_commitment: Digest,
    slot_program_vk: ProgramVk,
    committee_program_vk: ProgramVk,
    committee: CommitteeOutput,
    committee_proof: Vec<u64>,
    target_epoch: u64,
    target_root: [u8; 32],
    total_active_balance: u64,
    acc_root: Digest,
) -> JustificationWitness {
    JustificationWitness {
        accumulator_commitment,
        target_epoch,
        target_root,
        total_active_balance,
        acc_root,
        slot_program_vk,
        committee_program_vk,
        committee,
        committee_proof,
        slot_proof_outputs,
        slot_proofs,
    }
}

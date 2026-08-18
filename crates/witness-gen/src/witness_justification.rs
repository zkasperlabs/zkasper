//! Assemble a JustificationWitness from slot proof outputs.

use zkasper_common::acc::Digest;
use zkasper_common::recursion::ProgramVk;
use zkasper_common::types::{
    CommitteeOutput, JustificationOutput, JustificationWitness, SlotProofOutput,
};

/// The parts of a justification fold that do not change across an epoch.
#[derive(Clone, Debug)]
pub struct Context {
    pub accumulator_commitment: Digest,
    pub acc_root: Digest,
    pub target_epoch: u64,
    pub target_root: [u8; 32],
    pub total_active_balance: u64,
    pub slot_program_vk: ProgramVk,
    pub committee_program_vk: ProgramVk,
    pub justification_program_vk: ProgramVk,
}

/// Build one link of an epoch's justification chain.
///
/// `previous` is the fold this one extends, absent for the fold that opens the
/// epoch — which is the one that carries the committee proof, since every later
/// link inherits the root it publishes.
///
/// `slot_proofs` carries the serialized Zisk proof words per slot, empty when
/// running the circuit natively without a prover.
#[tracing::instrument(name = "witness", skip_all, fields(stage = "justification"))]
pub fn build(
    context: &Context,
    committee: Option<CommitteeOutput>,
    committee_proof: Vec<u64>,
    previous: Option<JustificationOutput>,
    previous_proof: Vec<u64>,
    slot_proof_outputs: Vec<SlotProofOutput>,
    slot_proofs: Vec<Vec<u64>>,
) -> JustificationWitness {
    JustificationWitness {
        accumulator_commitment: context.accumulator_commitment,
        target_epoch: context.target_epoch,
        target_root: context.target_root,
        total_active_balance: context.total_active_balance,
        acc_root: context.acc_root,
        slot_program_vk: context.slot_program_vk,
        committee_program_vk: context.committee_program_vk,
        justification_program_vk: context.justification_program_vk,
        committee,
        committee_proof,
        previous,
        previous_proof,
        slot_proof_outputs,
        slot_proofs,
    }
}

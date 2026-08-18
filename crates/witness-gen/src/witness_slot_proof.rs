//! Assemble SlotProofWitness values — one per attestation slot.

use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::{info, info_span};

use zkasper_common::acc;
use zkasper_common::types::SlotProofWitness;
use zkasper_common::ChainConfig;

use crate::acc_tree::AccTree;
use crate::beacon_api::BeaconApi;
use crate::committee::EpochCommittees;

/// Per-slot witness with what the justification witness builder needs.
pub struct SlotWitnessData {
    pub slot: u64,
    pub witness: SlotProofWitness,
    /// Committee balance minus absentees: what this slot adds to the epoch.
    pub marginal_balance: u64,
}

/// Build one SlotProofWitness per attestation slot that has attestations.
#[allow(clippy::too_many_arguments)]
pub async fn build_per_slot(
    api: &impl BeaconApi,
    config: &ChainConfig,
    acc_tree: &AccTree,
    committees: Arc<EpochCommittees>,
    target_epoch: u64,
    target_root: [u8; 32],
    total_active_balance: u64,
    signing_domain: [u8; 32],
) -> Result<Vec<SlotWitnessData>> {
    let _span = info_span!("slot_proofs", target_epoch).entered();

    let acc_root = acc_tree.root();
    let commitment = acc::commitment(&acc_root, total_active_balance);
    let committee_root = committees.root();

    let per_slot = crate::attestation_collector::collect_per_slot_for_checkpoint(
        api,
        config,
        committees.clone(),
        target_epoch,
        &target_root,
    )
    .await
    .context("collect per-slot complements")?;

    let mut result = Vec::with_capacity(per_slot.len());

    for complement in per_slot {
        let _span = info_span!("slot", slot = complement.slot).entered();

        let acc_multi_proof = acc_tree.build_multi_proof(&complement.named_indices);

        info!(
            absentees = complement.witness.absentees.len(),
            named = complement.named_indices.len(),
            auxiliaries = acc_multi_proof.auxiliaries.len(),
            "slot proof witness built",
        );

        result.push(SlotWitnessData {
            slot: complement.slot,
            marginal_balance: complement.marginal_balance,
            witness: SlotProofWitness {
                accumulator_commitment: commitment,
                committee_root,
                target_epoch,
                target_root,
                signing_domain,
                acc_root,
                total_active_balance,
                acc_multi_proof,
                committee_multi_proof: committees.multi_proof(&[complement.witness.slot_in_epoch]),
                slots: vec![complement.witness],
            },
        });
    }

    info!(slot_count = result.len(), "all slot proof witnesses built");

    Ok(result)
}

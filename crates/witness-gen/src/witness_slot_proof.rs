//! Assemble SlotProofWitness values — one per block slot.

use anyhow::{Context, Result};
use tracing::{info, info_span};

use zkasper_common::acc;
use zkasper_common::types::SlotProofWitness;
use zkasper_common::ChainConfig;

use crate::acc_tree::AccTree;
use crate::beacon_api::BeaconApi;

/// Per-slot witness with metadata needed by the justification witness builder.
pub struct SlotWitnessData {
    pub slot: u64,
    pub witness: SlotProofWitness,
    /// Sorted counted validator indices (for justification dedup witness).
    pub counted_indices: Vec<u64>,
}

/// Build one SlotProofWitness per block slot that contains matching attestations.
pub async fn build_per_slot(
    api: &impl BeaconApi,
    config: &ChainConfig,
    acc_tree: &AccTree,
    target_epoch: u64,
    target_root: [u8; 32],
    total_active_balance: u64,
    signing_domain: [u8; 32],
) -> Result<Vec<SlotWitnessData>> {
    let _span = info_span!("slot_proofs", target_epoch).entered();

    // Fetch validators at the epoch boundary
    let slot_str = (target_epoch * config.slots_per_epoch).to_string();
    let validators = api
        .get_validators(&slot_str)
        .await
        .context("fetch validators for slot proofs")?;

    let acc_root = acc_tree.root();
    let commitment = acc::commitment(&acc_root, total_active_balance);

    // Collect attestations grouped by block slot
    let per_slot = crate::attestation_collector::collect_per_slot_for_checkpoint(
        api,
        config,
        target_epoch,
        &target_root,
        &validators,
        target_epoch,
    )
    .await
    .context("collect per-slot attestations")?;

    let mut result = Vec::with_capacity(per_slot.len());

    for slot_data in per_slot {
        let _span = info_span!("slot", slot = slot_data.slot).entered();

        // Build Poseidon multi-proof for this slot's unique validators
        let multi_proof_indices: Vec<u64> = slot_data.all_validator_indices.clone();
        let acc_multi_proof = acc_tree.build_multi_proof(&multi_proof_indices);

        info!(
            attestations = slot_data.attestations.len(),
            validators = multi_proof_indices.len(),
            counted = slot_data.counted_indices.len(),
            auxiliaries = acc_multi_proof.auxiliaries.len(),
            "slot proof witness built",
        );

        let witness = SlotProofWitness {
            accumulator_commitment: commitment,
            target_epoch,
            target_root,
            signing_domain,
            acc_root,
            total_active_balance,
            attestations: slot_data.attestations,
            acc_multi_proof,
        };

        result.push(SlotWitnessData {
            slot: slot_data.slot,
            witness,
            counted_indices: slot_data.counted_indices,
        });
    }

    info!(slot_count = result.len(), "all slot proof witnesses built");

    Ok(result)
}

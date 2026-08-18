//! Assemble a BootstrapWitness for one-time Poseidon tree construction.

use anyhow::{Context, Result};
use rayon::prelude::*;
use tracing::{info, info_span};

use zkasper_common::types::BootstrapWitness;
use zkasper_common::ChainConfig;

use crate::acc_tree::AccTree;
use crate::beacon_api::BeaconApi;
use crate::epoch_state::EpochState;
use crate::ssz_state;
use crate::state_diff::{
    build_validator_roots, make_state_proof, validator_response_to_data,
    validator_response_to_field_leaves, validator_response_to_pubkey_chunks,
};

/// Build a BootstrapWitness and AccTree from a beacon state at `slot`.
///
/// `ssz_depth`: depth of the SSZ validators data tree (40 per spec).
/// `acc_depth`: depth of the Poseidon accumulator tree (22 for mainnet).
/// Returns `(witness, tree, epoch_state, total_active_balance, num_validators)`.
pub async fn build(
    api: &impl BeaconApi,
    config: &ChainConfig,
    slot: u64,
) -> Result<(BootstrapWitness, AccTree, EpochState, u64, u64)> {
    let ssz_depth = config.validators_tree_depth;
    let acc_depth = config.acc_tree_depth;
    let _span = info_span!("bootstrap", slot, ssz_depth, acc_depth).entered();
    let slot_str = slot.to_string();

    // Fetch header to get the state_root
    let header = api
        .get_header(&slot_str)
        .await
        .context("fetch block header")?;
    let state_root = header.state_root;
    let epoch = header.slot / config.slots_per_epoch;

    // Fetch all validators at this state
    let validators = {
        let _span = info_span!("fetch_validators").entered();
        let v = api
            .get_validators(&slot_str)
            .await
            .context("fetch validators")?;
        info!(count = v.len(), "fetched validators");
        v
    };
    let num_validators = validators.len() as u64;

    // Convert to common types + SSZ chunks
    let (validator_data, field_chunks, pubkey_chunks) = {
        let _span = info_span!("convert").entered();
        let data: Vec<_> = validators
            .par_iter()
            .map(validator_response_to_data)
            .collect();
        let fields: Vec<_> = validators
            .par_iter()
            .map(validator_response_to_field_leaves)
            .collect();
        let pubkeys: Vec<_> = validators
            .par_iter()
            .map(validator_response_to_pubkey_chunks)
            .collect();
        (data, fields, pubkeys)
    };

    // Build SSZ data tree root
    let validator_roots = {
        let _span = info_span!("validator_roots").entered();
        build_validator_roots(&validators)
    };

    let (ssz_data_root, _) = {
        let _span = info_span!("ssz_tree").entered();
        crate::state_diff::build_validators_ssz_tree(&validator_roots, ssz_depth, &[])
    };

    // Compute validators HTR (list_hash_tree_root = mix_in_length(data_root, len))
    let validators_htr = zkasper_common::ssz::list_hash_tree_root(&ssz_data_root, num_validators);

    // Try real state proof from SSZ state, fall back to synthetic
    let state_siblings = {
        let _span = info_span!("state_proof").entered();
        if let Some(raw_ssz) = api.get_state_ssz(&slot_str).await? {
            let proof = ssz_state::parse_state_proof(&raw_ssz, &validators_htr, config, slot)?;
            anyhow::ensure!(
                proof.state_root == state_root,
                "SSZ state root {:#x?} != header state root {:#x?}",
                &proof.state_root[..4],
                &state_root[..4],
            );
            proof.siblings
        } else {
            // Synthetic fallback for mock-based tests
            // A bootstrap is the base of the chain of synthetic states: nothing
            // came before it, so it records no boundary.
            let (computed_state_root, siblings) = make_state_proof(
                &ssz_data_root,
                num_validators,
                &crate::state_diff::SlotHistory::default(),
            );
            anyhow::ensure!(
                computed_state_root == state_root,
                "synthetic state root does not match header"
            );
            siblings
        }
    };

    // Build Poseidon tree
    let tree = {
        let _span = info_span!("acc_tree").entered();
        AccTree::build(&validator_data, epoch, acc_depth)
    };

    // Compute total active balance
    let total_active_balance: u64 = validator_data
        .iter()
        .map(|v| v.active_effective_balance(epoch))
        .sum();

    info!(num_validators, total_active_balance, "bootstrap complete");

    let epoch_state = EpochState {
        slot,
        state_root,
        state_to_validators_siblings: state_siblings.clone(),
        validator_roots,
        ssz_data_root,
        num_validators,
    };

    let witness = BootstrapWitness {
        state_root,
        epoch,
        validators: validator_data,
        state_to_validators_siblings: state_siblings,
        validators_list_length: num_validators,
        validator_field_chunks: field_chunks,
        validator_pubkey_chunks: pubkey_chunks,
    };

    Ok((
        witness,
        tree,
        epoch_state,
        total_active_balance,
        num_validators,
    ))
}

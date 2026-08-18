//! Assemble an EpochDiffWitness between two beacon states.

use anyhow::{Context, Result};
use tracing::{info, info_span, warn};

use zkasper_common::acc;
use zkasper_common::ssz::validator_hash_tree_root;
use zkasper_common::types::{BlsPubkey, EpochDiffWitness, ValidatorData, ValidatorMutation};
use zkasper_common::ChainConfig;

use crate::acc_tree::AccTree;
use crate::beacon_api::BeaconApi;
use crate::epoch_state::EpochState;
use crate::ssz_state;
use crate::state_diff::{
    build_validators_ssz_tree, find_mutations, make_state_proof, validator_response_to_data,
    validator_response_to_field_leaves, validator_response_to_pubkey_chunks, SlotHistory,
};

/// Build an EpochDiffWitness and update the AccTree in place.
///
/// Uses `old_state` (from the init point or the previous epoch diff) to avoid recomputing
/// O(n) validator roots and re-parsing the old SSZ state.
///
/// Returns `(witness, new_epoch_state, new_total_active_balance, new_num_validators)`.
#[tracing::instrument(name = "witness", skip_all, fields(stage = "epoch_diff", slot_2))]
pub async fn build(
    api: &impl BeaconApi,
    config: &ChainConfig,
    acc_tree: &mut AccTree,
    old_state: &EpochState,
    slot_2: u64,
    total_active_balance_1: u64,
) -> Result<(EpochDiffWitness, EpochState, u64, u64)> {
    let slot_1 = old_state.slot;
    let ssz_depth = config.validators_tree_depth;
    let slot_2_str = slot_2.to_string();
    let epoch_1 = slot_1 / config.slots_per_epoch;
    let epoch_2 = slot_2 / config.slots_per_epoch;

    // Fetch only new validators (old are cached in old_state)
    let validators_2 = {
        let _span = info_span!("fetch_validators").entered();
        let v = api
            .get_validators(&slot_2_str)
            .await
            .context("fetch validators at slot_2")?;
        info!(count = v.len(), "fetched validators");
        v
    };

    // We also need old validators for mutation field data — fetch from API
    // (these are lightweight to fetch from the file-backed API; the expensive
    // part was computing validator_roots which we skip via old_state)
    let validators_1 = {
        let _span = info_span!("fetch_old_validators").entered();
        api.get_validators(&slot_1.to_string())
            .await
            .context("fetch validators at slot_1")?
    };

    let num_validators_1 = old_state.num_validators;
    let num_validators_2 = validators_2.len() as u64;

    // Find which validators changed (including epoch-boundary activations/exits)
    let mutation_indices = find_mutations(&validators_1, &validators_2, epoch_1, epoch_2);
    anyhow::ensure!(
        !mutation_indices.is_empty(),
        "no mutations found between states"
    );
    info!(mutations = mutation_indices.len(), "found mutations");

    // Build SSZ trees: reuse old validator_roots if cached, else compute from scratch
    let (old_data_root, ssz_multi_proof_1, new_data_root, ssz_multi_proof_2, new_validator_roots) = {
        let _span = info_span!("ssz_trees").entered();

        let old_roots = if old_state.validator_roots.is_empty() {
            // No cache — compute from scratch (slow path)
            crate::state_diff::build_validator_roots(&validators_1)
        } else {
            old_state.validator_roots.clone()
        };

        // Old tree: build from roots (cached or freshly computed)
        let (old_data_root, old_proof) =
            build_validators_ssz_tree(&old_roots, ssz_depth, &mutation_indices);

        // New roots: clone old, update only mutations
        let mut new_roots = old_roots;
        new_roots.resize(validators_2.len(), [0u8; 32]);
        for &idx in &mutation_indices {
            let v = &validators_2[idx as usize];
            let leaves = validator_response_to_field_leaves(v);
            new_roots[idx as usize] = validator_hash_tree_root(&leaves);
        }

        let (new_data_root, new_proof) =
            build_validators_ssz_tree(&new_roots, ssz_depth, &mutation_indices);

        (
            old_data_root,
            old_proof,
            new_data_root,
            new_proof,
            new_roots,
        )
    };

    // State proofs: reuse old from cache, compute new from SSZ blob
    let (state_root_1, state_siblings_1, state_root_2, state_siblings_2) = {
        let _span = info_span!("state_proofs").entered();

        let old_validators_htr =
            zkasper_common::ssz::list_hash_tree_root(&old_data_root, num_validators_1);
        let new_validators_htr =
            zkasper_common::ssz::list_hash_tree_root(&new_data_root, num_validators_2);

        // Old state proof: use cache if available
        let (sr1, ss1) = if !old_state.state_to_validators_siblings.is_empty() {
            (
                old_state.state_root,
                old_state.state_to_validators_siblings.clone(),
            )
        } else if let Some(raw) = api.get_state_ssz(&slot_1.to_string()).await? {
            // The state-root endpoint answers for a skipped slot; a header does
            // not exist for one. Fixture sources return None and keep the header.
            let expected = match api.get_state_root(&slot_1.to_string()).await? {
                Some(root) => root,
                None => {
                    api.get_header(&slot_1.to_string())
                        .await
                        .context("fetch header at slot_1")?
                        .state_root
                }
            };
            let proof = ssz_state::parse_state_proof(&raw, &old_validators_htr, config, slot_1)?;
            anyhow::ensure!(
                proof.state_root == expected,
                "SSZ state root mismatch at slot_1"
            );
            (proof.state_root, proof.siblings)
        } else {
            make_state_proof(&old_data_root, num_validators_1, &SlotHistory::default())
        };

        // New state proof: always compute fresh
        let (sr2, ss2) = if let Some(raw) = api.get_state_ssz(&slot_2_str).await? {
            // An empty epoch boundary slot has no header but does have a state
            // root, and boundaries are skipped often enough that reading the
            // header wedges the daemon on the first one.
            let expected = match api.get_state_root(&slot_2_str).await? {
                Some(root) => root,
                None => {
                    api.get_header(&slot_2_str)
                        .await
                        .context("fetch header at slot_2")?
                        .state_root
                }
            };
            let proof = ssz_state::parse_state_proof(&raw, &new_validators_htr, config, slot_2)?;
            anyhow::ensure!(
                proof.state_root == expected,
                "SSZ state root mismatch at slot_2"
            );
            (proof.state_root, proof.siblings)
        } else {
            // Nothing downstream can tell this apart from a real state root, and
            // it is what anchors the accumulator chain to the beacon chain. A
            // node that stops serving the debug endpoint mid-run would otherwise
            // degrade silently, so say so on every epoch it happens.
            warn!(
                slot = slot_2,
                "the node does not serve the debug state endpoint; \
                 anchoring this epoch on a synthetic state root",
            );
            // A synthetic state still records the boundary before it, because
            // that is what the finalization of the epoch it opens will open.
            let block_root = match api.get_header(&slot_1.to_string()).await {
                Ok(header) => header.root(),
                Err(_) => [0u8; 32],
            };
            make_state_proof(
                &new_data_root,
                num_validators_2,
                &SlotHistory {
                    slot: slot_1,
                    block_root,
                    state_root: sr1,
                },
            )
        };

        (sr1, ss1, sr2, ss2)
    };

    // Build mutations — process sequentially for correct Poseidon siblings
    let acc_root_1 = acc_tree.root();
    let mutations = {
        let _span = info_span!("build_mutations").entered();
        let mut mutations = Vec::with_capacity(mutation_indices.len());

        for &idx in &mutation_indices {
            let is_new = (idx as usize) >= validators_1.len();

            let new_v = &validators_2[idx as usize];
            let new_data = validator_response_to_data(new_v);

            // Compute new Poseidon leaf and update tree — returns old siblings
            let new_active_balance = new_data.active_effective_balance(epoch_2);
            let point = crate::pubkey::decompress(&new_data.pubkey.0)
                .context("decompress validator public key")?;
            let new_poseidon_leaf = acc::leaf(&point, new_active_balance);
            let acc_siblings = acc_tree.update_leaf(idx, new_poseidon_leaf);

            if is_new {
                let zero_data = ValidatorData {
                    pubkey: BlsPubkey([0u8; 48]),
                    effective_balance: 0,
                    activation_epoch: 0,
                    exit_epoch: 0,
                };

                mutations.push(ValidatorMutation {
                    validator_index: idx,
                    is_new: true,
                    old_data: zero_data,
                    new_data,
                    old_field_leaves: [[0u8; 32]; 8],
                    new_field_leaves: validator_response_to_field_leaves(new_v),
                    old_pubkey_chunks: [[0u8; 32]; 2],
                    new_pubkey_chunks: validator_response_to_pubkey_chunks(new_v),
                    acc_siblings,
                });
            } else {
                let old_v = &validators_1[idx as usize];
                let old_data = validator_response_to_data(old_v);

                mutations.push(ValidatorMutation {
                    validator_index: idx,
                    is_new: false,
                    old_data,
                    new_data,
                    old_field_leaves: validator_response_to_field_leaves(old_v),
                    new_field_leaves: validator_response_to_field_leaves(new_v),
                    old_pubkey_chunks: validator_response_to_pubkey_chunks(old_v),
                    new_pubkey_chunks: validator_response_to_pubkey_chunks(new_v),
                    acc_siblings,
                });
            }
        }

        let new_count = mutations.iter().filter(|m| m.is_new).count();
        info!(
            changed = mutations.len() - new_count,
            new = new_count,
            "built mutations"
        );
        mutations
    };

    // Compute new total active balance
    let new_total_active_balance: u64 = validators_2
        .iter()
        .map(|v| {
            let d = validator_response_to_data(v);
            d.active_effective_balance(epoch_2)
        })
        .sum();

    info!(
        num_validators = num_validators_2,
        new_total_active_balance, "epoch diff complete"
    );

    let new_epoch_state = EpochState {
        slot: slot_2,
        state_root: state_root_2,
        state_to_validators_siblings: state_siblings_2.clone(),
        validator_roots: new_validator_roots,
        ssz_data_root: new_data_root,
        num_validators: num_validators_2,
    };

    let witness = EpochDiffWitness {
        state_root_1,
        state_root_2,
        acc_root_1,
        total_active_balance_1,
        epoch_1,
        epoch_2,
        state_to_validators_siblings_1: state_siblings_1,
        state_to_validators_siblings_2: state_siblings_2,
        validators_list_length_1: num_validators_1,
        validators_list_length_2: num_validators_2,
        mutations,
        ssz_multi_proof_1,
        ssz_multi_proof_2,
    };

    Ok((
        witness,
        new_epoch_state,
        new_total_active_balance,
        num_validators_2,
    ))
}

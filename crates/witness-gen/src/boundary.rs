//! The finalized epoch's boundary, opened out of the justified checkpoint.
//!
//! A checkpoint root is the last block at or *before* the epoch's first slot, so
//! an empty first slot leaves the boundary state with no header to read it off.
//! The state of the justified checkpoint has both values in its ring buffers,
//! and it is the one state after the boundary the proof already trusts.

use anyhow::{Context, Result};
use tracing::warn;
use zkasper_common::ssz::list_hash_tree_root;
use zkasper_common::types::BoundaryAnchor;
use zkasper_common::ChainConfig;

use crate::beacon_api::BeaconApi;
use crate::epoch_state::EpochState;
use crate::ssz_state;
use crate::state_diff::{self, SlotHistory};

/// Build the anchor that ties the finalized epoch's boundary to the justified
/// checkpoint the attesters signed.
///
/// `boundary_state_root` is the state the finalized epoch's accumulator was
/// built from — the epoch diff's `state_root_1` — and the whole point of the
/// opening is to prove the chain recorded exactly that at the boundary.
pub async fn build(
    api: &impl BeaconApi,
    config: &ChainConfig,
    justified_root: &[u8; 32],
    finalized_epoch: u64,
    finalized_root: &[u8; 32],
    boundary_state_root: &[u8; 32],
    current: &EpochState,
) -> Result<BoundaryAnchor> {
    // Addressed by root rather than by slot, which is what makes this work for a
    // justified epoch whose own first slot was skipped.
    let justified_header = api
        .get_header(&crate::artifacts::hex0x(justified_root))
        .await
        .context("fetch the header of the justified checkpoint block")?
        .fields();

    let boundary_slot = finalized_epoch * config.slots_per_epoch;
    let proof = match api
        .get_state_ssz(&justified_header.slot.to_string())
        .await?
    {
        Some(raw) => {
            // The registry only carries over when the checkpoint block sits on
            // the boundary slot, which is the state the epoch diff just parsed.
            let known = (current.slot == justified_header.slot)
                .then(|| list_hash_tree_root(&current.ssz_data_root, current.num_validators));
            ssz_state::parse_boundary_proof(&raw, known, config, boundary_slot)?
        }
        None => {
            warn!(
                slot = justified_header.slot,
                "the node does not serve the debug state endpoint; \
                 anchoring this boundary on a synthetic state",
            );
            state_diff::make_boundary_proof(
                &current.ssz_data_root,
                current.num_validators,
                &SlotHistory {
                    slot: boundary_slot,
                    block_root: *finalized_root,
                    state_root: *boundary_state_root,
                },
            )
        }
    };

    // Everything the circuit will assert, asserted here first, so an epoch that
    // cannot be proven says which of the three values disagreed.
    anyhow::ensure!(
        proof.state_root == justified_header.state_root,
        "the state at slot {} is not the one the justified checkpoint produced",
        justified_header.slot,
    );
    anyhow::ensure!(
        proof.block_root == *finalized_root,
        "the justified chain has a different checkpoint at slot {boundary_slot}",
    );
    anyhow::ensure!(
        proof.boundary_state_root == *boundary_state_root,
        "the accumulator was built from a different state than slot {boundary_slot} produced",
    );

    Ok(BoundaryAnchor {
        justified_header,
        block_roots_siblings: proof.block_roots_siblings,
        state_roots_siblings: proof.state_roots_siblings,
    })
}

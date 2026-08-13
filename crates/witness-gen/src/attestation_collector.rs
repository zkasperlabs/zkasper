//! Collect attestations for a target checkpoint and build AttestationWitness values.

use std::collections::{BTreeSet, HashMap};

use anyhow::{Context, Result};
use tracing::info;

use zkasper_common::types::{AttestationWitness, AttestingValidator, BlsSignature};
use zkasper_common::ChainConfig;

use crate::beacon_api::{AttestationResponse, BeaconApi, CommitteeResponse, ValidatorResponse};
use crate::state_diff::validator_response_to_data;

/// Collect attestations targeting a specific checkpoint.
///
/// Stops early once the unique attesting balance reaches 2/3 of `total_active_balance`.
/// Returns `(attestation_witnesses, unique_validator_indices)`.
///
/// Scans blocks in `[target_epoch * SLOTS_PER_EPOCH .. (target_epoch + 2) * SLOTS_PER_EPOCH)`
/// for attestations whose target matches `(target_epoch, target_root)`.
/// Per-slot attestation data.
pub struct SlotAttestations {
    pub slot: u64,
    pub attestations: Vec<AttestationWitness>,
    /// Sorted indices of validators with count_balance=true in this slot.
    pub counted_indices: Vec<u64>,
    /// All unique validator indices in this slot's attestations.
    pub all_validator_indices: Vec<u64>,
}

/// Collect attestations grouped by the block slot they were included in.
///
/// Unlike `collect_for_checkpoint`, does NOT early-stop at 2/3 (that's the
/// justification proof's job). Maintains cross-slot dedup for `count_balance`.
///
/// Returns one `SlotAttestations` per block slot that contained matching attestations.
pub async fn collect_per_slot_for_checkpoint(
    api: &impl BeaconApi,
    config: &ChainConfig,
    target_epoch: u64,
    target_root: &[u8; 32],
    validators: &[ValidatorResponse],
    epoch: u64,
) -> Result<Vec<SlotAttestations>> {
    let spe = config.slots_per_epoch;

    // Fetch committees for the target epoch
    let slot_str = (target_epoch * spe).to_string();
    let committees = api
        .get_committees(&slot_str, target_epoch)
        .await
        .context("fetch committees")?;

    let committee_map = build_committee_map(&committees);

    // Scan blocks, group matching attestations by block slot
    let scan_start = target_epoch * spe;
    let scan_end = (target_epoch + 2) * spe;

    let mut per_slot: Vec<(u64, Vec<AttestationResponse>)> = Vec::new();

    for slot in scan_start..scan_end {
        let block_id = slot.to_string();
        match api.get_block_attestations(&block_id).await {
            Ok(attestations) => {
                let matching: Vec<_> = attestations
                    .into_iter()
                    .filter(|att| {
                        att.data_target_epoch == target_epoch
                            && att.data_target_root == *target_root
                    })
                    .collect();
                if !matching.is_empty() {
                    per_slot.push((slot, matching));
                }
            }
            Err(_) => continue,
        }
    }

    // Build per-slot witnesses with cross-slot dedup
    let mut seen_validators: BTreeSet<u64> = BTreeSet::new();
    let mut result = Vec::with_capacity(per_slot.len());

    for (slot, slot_attestations) in &per_slot {
        let mut attestation_witnesses = Vec::with_capacity(slot_attestations.len());
        let mut slot_counted_indices: BTreeSet<u64> = BTreeSet::new();
        let mut slot_all_indices: BTreeSet<u64> = BTreeSet::new();

        for att in slot_attestations {
            let attesting_indices =
                resolve_attesting_validators(att, &committee_map).context("resolve attestors")?;

            let sorted_indices: BTreeSet<u64> = attesting_indices.into_iter().collect();
            if sorted_indices.is_empty() {
                continue;
            }

            let mut attesting_validators = Vec::with_capacity(sorted_indices.len());

            for &idx in &sorted_indices {
                let v_resp = validators
                    .get(idx as usize)
                    .context("validator index out of range")?;
                let v_data = validator_response_to_data(v_resp);
                let active_balance = v_data.active_effective_balance(epoch);
                let count_balance = seen_validators.insert(idx);

                if count_balance {
                    slot_counted_indices.insert(idx);
                }
                slot_all_indices.insert(idx);

                attesting_validators.push(AttestingValidator {
                    validator_index: idx,
                    pubkey: crate::pubkey::decompress(&v_resp.pubkey)
                        .context("decompress attester public key")?,
                    active_effective_balance: active_balance,
                    count_balance,
                });
            }

            attestation_witnesses.push(AttestationWitness {
                data_slot: att.data_slot,
                data_index: att.data_index,
                data_beacon_block_root: att.data_beacon_block_root,
                data_source_epoch: att.data_source_epoch,
                data_source_root: att.data_source_root,
                data_target_epoch: att.data_target_epoch,
                data_target_root: att.data_target_root,
                signature: BlsSignature(att.signature),
                attesting_validators,
            });
        }

        if !attestation_witnesses.is_empty() {
            result.push(SlotAttestations {
                slot: *slot,
                attestations: attestation_witnesses,
                counted_indices: slot_counted_indices.into_iter().collect(),
                all_validator_indices: slot_all_indices.into_iter().collect(),
            });
        }
    }

    info!(
        slots = result.len(),
        total_unique_validators = seen_validators.len(),
        "collected per-slot attestations",
    );

    Ok(result)
}

/// Build a committee lookup map from committee responses.
///
/// Key: (slot, committee_index) → Value: list of validator indices
fn build_committee_map(committees: &[CommitteeResponse]) -> HashMap<(u64, u64), Vec<u64>> {
    let mut map = HashMap::new();
    for c in committees {
        map.insert((c.slot, c.index), c.validators.clone());
    }
    map
}

/// Resolve which global validator indices are attesting in an attestation.
///
/// For Electra-style attestations (committee_bits present), iterates over set
/// bits in committee_bits to find which committees are included, then uses
/// aggregation_bits to pick validators within each committee.
///
/// For pre-Electra attestations, uses data_index as the committee index directly.
fn resolve_attesting_validators(
    att: &AttestationResponse,
    committee_map: &HashMap<(u64, u64), Vec<u64>>,
) -> Result<Vec<u64>> {
    let mut result = Vec::new();

    if att.committee_bits.is_empty() {
        // Pre-Electra: single committee identified by data_index
        let committee = committee_map
            .get(&(att.data_slot, att.data_index))
            .context("committee not found")?;

        for (bit_idx, &validator_idx) in committee.iter().enumerate() {
            if get_bit(&att.aggregation_bits, bit_idx) {
                result.push(validator_idx);
            }
        }
    } else {
        // Electra: committee_bits indicates which committees are included
        let mut aggregation_offset = 0;

        for committee_idx in 0..att.committee_bits.len() * 8 {
            if !get_bit(&att.committee_bits, committee_idx) {
                continue;
            }

            let committee = match committee_map.get(&(att.data_slot, committee_idx as u64)) {
                Some(c) => c,
                None => continue,
            };

            for (j, &validator_idx) in committee.iter().enumerate() {
                if get_bit(&att.aggregation_bits, aggregation_offset + j) {
                    result.push(validator_idx);
                }
            }

            aggregation_offset += committee.len();
        }
    }

    Ok(result)
}

/// Get bit at position `idx` from a little-endian bitfield.
fn get_bit(bitfield: &[u8], idx: usize) -> bool {
    let byte_idx = idx / 8;
    let bit_idx = idx % 8;
    if byte_idx >= bitfield.len() {
        return false;
    }
    (bitfield[byte_idx] >> bit_idx) & 1 == 1
}

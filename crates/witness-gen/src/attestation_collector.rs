//! Collect attestations for a target checkpoint and build AttestationWitness values.

use std::collections::{BTreeSet, HashMap};

use anyhow::{Context, Result};
use tracing::info;

use zkasper_common::types::{AttestationWitness, AttestingValidator, BlsSignature};
use zkasper_common::ChainConfig;

use crate::beacon_api::{AttestationResponse, BeaconApi, CommitteeResponse, ValidatorResponse};
use crate::state_diff::validator_response_to_data;

/// Per-slot attestation data.
pub struct SlotAttestations {
    pub slot: u64,
    pub attestations: Vec<AttestationWitness>,
    /// Sorted indices of validators with count_balance=true in this slot.
    pub counted_indices: Vec<u64>,
    /// All unique validator indices in this slot's attestations.
    pub all_validator_indices: Vec<u64>,
}

/// Incremental collector for one target checkpoint.
///
/// Attestations for a checkpoint arrive over the whole epoch, so the collector
/// is fed one block at a time rather than handed the finished epoch. It carries
/// the committee table and the running cross-slot `seen` set, which is what
/// makes the `count_balance` flag correct without a second pass, and what lets a
/// caller stop the moment the 2/3 threshold is crossed instead of scanning to
/// the end of the epoch.
///
/// Slots must be fed in ascending order: which slot gets to count a validator is
/// first-come, and the justification proof checks that the merged per-slot index
/// lists are strictly increasing.
pub struct SlotStream {
    target_epoch: u64,
    target_root: [u8; 32],
    /// Epoch each attester's `active_effective_balance` is evaluated at.
    balance_epoch: u64,
    committee_map: HashMap<(u64, u64), Vec<u64>>,
    seen_validators: BTreeSet<u64>,
}

impl SlotStream {
    /// Fetch the target epoch's committees and open a stream over them.
    pub async fn open(
        api: &impl BeaconApi,
        config: &ChainConfig,
        target_epoch: u64,
        target_root: [u8; 32],
        balance_epoch: u64,
    ) -> Result<Self> {
        let slot_str = (target_epoch * config.slots_per_epoch).to_string();
        let committees = api
            .get_committees(&slot_str, target_epoch)
            .await
            .context("fetch committees")?;

        Ok(Self {
            target_epoch,
            target_root,
            balance_epoch,
            committee_map: build_committee_map(&committees),
            seen_validators: BTreeSet::new(),
        })
    }

    /// Number of distinct validators counted so far, across every slot fed in.
    pub fn counted_so_far(&self) -> usize {
        self.seen_validators.len()
    }

    /// Feed one block's attestations.
    ///
    /// Returns `None` when the block carries nothing for this checkpoint, which
    /// covers both a skipped slot and a block whose attestations all target
    /// something else.
    pub fn ingest(
        &mut self,
        slot: u64,
        attestations: &[AttestationResponse],
        validators: &[ValidatorResponse],
    ) -> Result<Option<SlotAttestations>> {
        let matching = attestations.iter().filter(|att| {
            att.data_target_epoch == self.target_epoch && att.data_target_root == self.target_root
        });

        let mut attestation_witnesses = Vec::new();
        let mut slot_counted_indices: BTreeSet<u64> = BTreeSet::new();
        let mut slot_all_indices: BTreeSet<u64> = BTreeSet::new();

        for att in matching {
            let attesting_indices = resolve_attesting_validators(att, &self.committee_map)
                .context("resolve attestors")?;

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
                let active_balance = v_data.active_effective_balance(self.balance_epoch);
                let count_balance = self.seen_validators.insert(idx);

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

        if attestation_witnesses.is_empty() {
            return Ok(None);
        }

        Ok(Some(SlotAttestations {
            slot,
            attestations: attestation_witnesses,
            counted_indices: slot_counted_indices.into_iter().collect(),
            all_validator_indices: slot_all_indices.into_iter().collect(),
        }))
    }
}

/// Collect attestations grouped by the block slot they were included in.
///
/// Scans every block in `[target_epoch, target_epoch + 2)` with no early stop.
/// Continuous mode drives [`SlotStream`] directly so that it can stop at the
/// threshold; this stays for one-shot generation of a whole epoch's witnesses.
///
/// Returns one `SlotAttestations` per block slot that contained matching
/// attestations.
pub async fn collect_per_slot_for_checkpoint(
    api: &impl BeaconApi,
    config: &ChainConfig,
    target_epoch: u64,
    target_root: &[u8; 32],
    validators: &[ValidatorResponse],
    epoch: u64,
) -> Result<Vec<SlotAttestations>> {
    let spe = config.slots_per_epoch;
    let mut stream = SlotStream::open(api, config, target_epoch, *target_root, epoch).await?;

    let mut result = Vec::new();

    for slot in target_epoch * spe..(target_epoch + 2) * spe {
        let Ok(attestations) = api.get_block_attestations(&slot.to_string()).await else {
            continue;
        };
        if let Some(slot_data) = stream.ingest(slot, &attestations, validators)? {
            result.push(slot_data);
        }
    }

    info!(
        slots = result.len(),
        total_unique_validators = stream.counted_so_far(),
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

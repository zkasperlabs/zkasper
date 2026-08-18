//! Collect attestations for a target checkpoint and build slot complements.
//!
//! # Why slots are keyed by attestation, not by inclusion
//!
//! Complement proving works against a committee, and a committee belongs to the
//! slot the attestation is *for*, not the slot whose block carried it. An
//! attestation for slot `s` can be included anywhere in `s+1 ..= s+32`, so the
//! collector buckets by `AttestationData.slot` and a bucket closes when the
//! caller stops feeding it blocks.
//!
//! Closing a bucket early is safe and is the normal case: a committee member
//! whose attestation has not been seen is simply an absentee, which lowers that
//! slot's support and nothing else. The schedule wants that trade — waiting for
//! stragglers costs latency and buys a few basis points of weight.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::info;

use zkasper_common::types::{
    AttestationWitness, BlsSignature, OpenedValidator, SlotComplementWitness,
};
use zkasper_common::ChainConfig;

use crate::beacon_api::{AttestationResponse, BeaconApi};
use crate::committee::EpochCommittees;

/// One attestation slot, ready to be proven as a complement.
pub struct SlotComplement {
    /// The attestation slot, globally numbered.
    pub slot: u64,
    pub witness: SlotComplementWitness,
    /// What this slot adds to the epoch: committee balance minus absentees.
    pub marginal_balance: u64,
    /// Validator indices the witness names, sorted — absentees and enumerated
    /// signers together. These are the accumulator leaves it opens.
    pub named_indices: Vec<u64>,
}

/// One aggregate as the node published it, with its signers resolved.
struct Aggregate {
    attestation: AttestationWitness,
    signers: BTreeSet<u64>,
}

/// `AttestationData`, as the key that decides which aggregates share a message.
type DataKey = (u64, u64, [u8; 32], u64, [u8; 32], u64, [u8; 32]);

fn data_key(a: &AttestationWitness) -> DataKey {
    (
        a.data_slot,
        a.data_index,
        a.data_beacon_block_root,
        a.data_source_epoch,
        a.data_source_root,
        a.data_target_epoch,
        a.data_target_root,
    )
}

/// Incremental collector for one target checkpoint.
///
/// Attestations for a checkpoint arrive over the whole epoch, so the collector
/// is fed one block at a time rather than handed the finished epoch. It holds
/// the epoch's committees, which is what lets a slot be closed into a complement
/// the moment the caller stops expecting more of its attestations.
///
/// Blocks must be fed in ascending slot order.
pub struct SlotStream {
    target_epoch: u64,
    target_root: [u8; 32],
    slots_per_epoch: u64,
    committees: Arc<EpochCommittees>,
    /// Aggregates seen so far, keyed by the slot they attest to.
    pending: BTreeMap<u64, Vec<Aggregate>>,
}

impl SlotStream {
    pub fn new(
        config: &ChainConfig,
        committees: Arc<EpochCommittees>,
        target_epoch: u64,
        target_root: [u8; 32],
    ) -> Self {
        Self {
            target_epoch,
            target_root,
            slots_per_epoch: config.slots_per_epoch,
            committees,
            pending: BTreeMap::new(),
        }
    }

    pub fn committees(&self) -> &EpochCommittees {
        &self.committees
    }

    /// Feed one block's attestations.
    ///
    /// Only those targeting this checkpoint are kept, and they are filed under
    /// the slot they attest to rather than the block that carried them.
    ///
    /// Nothing here materialises a public key. Signers are held as indices, and
    /// the leaf preimages are read off the committee proof's members at
    /// [`Self::close`] — for the handful of validators a complement names, not
    /// for the tens of thousands it does not.
    pub fn ingest(&mut self, attestations: &[AttestationResponse]) -> Result<()> {
        for att in attestations {
            if att.data_target_epoch != self.target_epoch
                || att.data_target_root != self.target_root
            {
                continue;
            }

            let signers: BTreeSet<u64> = resolve_attesting_validators(att, &self.committees)
                .context("resolve attestors")?
                .into_iter()
                .collect();
            if signers.is_empty() {
                continue;
            }

            self.pending
                .entry(att.data_slot)
                .or_default()
                .push(Aggregate {
                    attestation: AttestationWitness {
                        data_slot: att.data_slot,
                        data_index: att.data_index,
                        data_beacon_block_root: att.data_beacon_block_root,
                        data_source_epoch: att.data_source_epoch,
                        data_source_root: att.data_source_root,
                        data_target_epoch: att.data_target_epoch,
                        data_target_root: att.data_target_root,
                        signature: BlsSignature(att.signature),
                        attesting_validators: Vec::new(),
                    },
                    signers,
                });
        }
        Ok(())
    }

    /// Close an attestation slot into the complement that proves it.
    ///
    /// Returns `None` for a slot with no attestations at all: there is no
    /// primary message for the derived key to pair against, and a slot that
    /// contributes nothing is better left uncounted than counted at zero.
    pub fn close(&mut self, slot: u64) -> Option<SlotComplement> {
        let complement = self.peek(slot)?;
        self.pending.remove(&slot);
        Some(complement)
    }

    /// What closing `slot` right now would produce, without closing it.
    ///
    /// The trigger runs this several times a second on the slot gossip is
    /// filling: every arrival moves a committee member out of `absentees` and
    /// into the derived key, so `marginal_balance` climbs and `named_indices`
    /// shrinks as the slot converges. Both are what the trigger is choosing
    /// between — weight it has against work it would pay for.
    pub fn peek(&self, slot: u64) -> Option<SlotComplement> {
        let aggregates = self.pending.get(&slot)?;
        let slot_in_epoch = slot % self.slots_per_epoch;
        let committee = self.committees.aggregate(slot_in_epoch)?.clone();
        let members = &self.committees.members[slot_in_epoch as usize];

        // Aggregates over one message have to be pairwise disjoint before their
        // signatures can be summed against one aggregate key, so overlapping
        // ones are dropped in favour of the larger. On a live chain the later
        // block's aggregate is a superset of the earlier one's, so this drops
        // duplicates rather than attesters.
        let mut by_message: BTreeMap<DataKey, (Vec<&Aggregate>, BTreeSet<u64>)> = BTreeMap::new();
        let mut order: Vec<&Aggregate> = aggregates.iter().collect();
        order.sort_by_key(|a| std::cmp::Reverse(a.signers.len()));
        for aggregate in order {
            let entry = by_message
                .entry(data_key(&aggregate.attestation))
                .or_default();
            if entry.1.intersection(&aggregate.signers).next().is_some() {
                continue;
            }
            entry.1.extend(&aggregate.signers);
            entry.0.push(aggregate);
        }

        // The message with the most signers is the one worth deriving; every
        // other message's signers are named, which is what makes them a minority
        // head vote rather than a cost.
        let primary_key = *by_message
            .iter()
            .max_by_key(|(_, (_, signers))| signers.len())?
            .0;
        let (primary_aggregates, primary_signers) = by_message.remove(&primary_key)?;

        // Each named aggregate carries its *own* signers, not its message's:
        // the guest folds aggregates over one message by adding their keys, so a
        // shared list would subtract the same validator once per aggregate.
        let mut named: BTreeSet<u64> = BTreeSet::new();
        let mut secondary: Vec<AttestationWitness> = Vec::new();
        for (aggregates, signers) in by_message.into_values() {
            named.extend(&signers);
            for aggregate in aggregates {
                secondary.push(AttestationWitness {
                    attesting_validators: aggregate
                        .signers
                        .iter()
                        .map(|&index| self.opened(index))
                        .collect::<Option<Vec<_>>>()?,
                    ..aggregate.attestation.clone()
                });
            }
        }

        // Everyone in the committee that no counted aggregate covers. A signer
        // outside the committee cannot happen on a well-formed chain, and if it
        // did the derived key would not match, so it is not special-cased.
        let absentees: Vec<OpenedValidator> = members
            .iter()
            .filter(|index| !primary_signers.contains(index) && !named.contains(index))
            .map(|&index| self.opened(index))
            .collect::<Option<Vec<_>>>()?;

        let marginal_balance = committee.balance
            - absentees
                .iter()
                .map(|v| v.active_effective_balance)
                .sum::<u64>();

        named.extend(absentees.iter().map(|v| v.validator_index));

        Some(SlotComplement {
            slot,
            marginal_balance,
            named_indices: named.iter().copied().collect(),
            witness: SlotComplementWitness {
                slot_in_epoch,
                committee,
                primary: primary_aggregates
                    .into_iter()
                    .map(|a| a.attestation.clone())
                    .collect(),
                secondary,
                absentees,
            },
        })
    }

    /// Drop a slot the caller has already taken a [`Self::peek`] of, so that
    /// later arrivals for it are not collected all over again.
    pub fn forget(&mut self, slot: u64) {
        self.pending.remove(&slot);
    }

    /// Attestation slots that have been fed and not yet closed.
    pub fn open_slots(&self) -> Vec<u64> {
        self.pending.keys().copied().collect()
    }

    /// The accumulator leaf preimage for one validator, read off the committee
    /// proof's members rather than decompressed again.
    fn opened(&self, index: u64) -> Option<OpenedValidator> {
        let member = self
            .committees
            .witness
            .members
            .binary_search_by_key(&index, |m| m.validator_index)
            .ok()?;
        let member = &self.committees.witness.members[member];
        Some(OpenedValidator {
            validator_index: member.validator_index,
            pubkey: member.pubkey,
            active_effective_balance: member.active_effective_balance,
        })
    }
}

/// Collect and close every attestation slot of a target epoch.
///
/// Scans every block in `[target_epoch, target_epoch + 2)` with no early stop.
/// Continuous mode drives [`SlotStream`] directly so that it can stop at the
/// threshold; this stays for one-shot generation of a whole epoch's witnesses.
pub async fn collect_per_slot_for_checkpoint(
    api: &impl BeaconApi,
    config: &ChainConfig,
    committees: Arc<EpochCommittees>,
    target_epoch: u64,
    target_root: &[u8; 32],
) -> Result<Vec<SlotComplement>> {
    let spe = config.slots_per_epoch;
    let mut stream = SlotStream::new(config, committees, target_epoch, *target_root);

    for slot in target_epoch * spe..(target_epoch + 2) * spe {
        let Ok(attestations) = api.get_block_attestations(&slot.to_string()).await else {
            continue;
        };
        stream.ingest(&attestations)?;
    }

    let mut result = Vec::new();
    for slot in target_epoch * spe..(target_epoch + 1) * spe {
        if let Some(complement) = stream.close(slot) {
            result.push(complement);
        }
    }

    info!(
        slots = result.len(),
        attesting_balance = result.iter().map(|s| s.marginal_balance).sum::<u64>(),
        "collected per-slot complements",
    );

    Ok(result)
}

/// Resolve which global validator indices are attesting in an attestation.
///
/// For Electra-style attestations (committee_bits present), iterates over set
/// bits in committee_bits to find which committees are included, then uses
/// aggregation_bits to pick validators within each committee.
///
/// For pre-Electra attestations, uses data_index as the committee index directly.
///
/// Both forms index into the epoch's committee table, which is also what the
/// committee proof partitioned — so an attester resolved here is a validator the
/// complement can subtract.
fn resolve_attesting_validators(
    att: &AttestationResponse,
    committees: &EpochCommittees,
) -> Result<Vec<u64>> {
    let mut result = Vec::new();

    // An Electra `SingleAttestation` names its one signer outright. It is still
    // checked against the committee, because a signer the committee proof did
    // not open is a leaf the complement cannot subtract.
    if let Some(single) = att.single_attester {
        let committee = committees
            .committee(att.data_slot, single.committee_index)
            .context("committee not found")?;
        if committee.contains(&single.attester_index) {
            result.push(single.attester_index);
        }
        return Ok(result);
    }

    if att.committee_bits.is_empty() {
        // Pre-Electra: a single committee identified by data_index.
        let committee = committees
            .committee(att.data_slot, att.data_index)
            .context("committee not found")?;
        for (bit, &validator_index) in committee.iter().enumerate() {
            if get_bit(&att.aggregation_bits, bit) {
                result.push(validator_index);
            }
        }
        return Ok(result);
    }

    let mut offset = 0;
    for committee_index in 0..att.committee_bits.len() * 8 {
        if !get_bit(&att.committee_bits, committee_index) {
            continue;
        }
        let Some(committee) = committees.committee(att.data_slot, committee_index as u64) else {
            continue;
        };
        for (j, &validator_index) in committee.iter().enumerate() {
            if get_bit(&att.aggregation_bits, offset + j) {
                result.push(validator_index);
            }
        }
        offset += committee.len();
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

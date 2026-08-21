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

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use blst::min_pk::{AggregateSignature, Signature};
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
    /// The same signature, decompressed once, so that a chosen cover can be
    /// summed into the single aggregate the guest is cheapest at.
    signature: Signature,
    signers: BTreeSet<u64>,
}

/// One committee's unaggregated attestations over one message, summed as they
/// arrive.
///
/// This is the primary path, and the one cover that is **divisible**: a
/// `SingleAttestation` names one validator, so any subset of what this bucket
/// holds can still be summed into a signature over exactly that subset. A
/// network aggregate cannot be cut that way, which is what makes the two behave
/// differently at [`SlotStream::peek`] — the aggregates are what a cover has to
/// choose between, and these are what fills whatever the choice missed.
///
/// The running total is kept alongside the individual signatures because it is
/// what the common case reads: the whole bucket, when no chosen aggregate
/// carries any of it. Summing as gossip arrives rather than at
/// [`SlotStream::close`] is also what keeps a slot's thirty thousand G2
/// decompressions off the critical path — they are paid on arrival, and only
/// the last few land after the threshold.
///
/// The bucket is a committee and not a message, because a network aggregate is
/// a committee's worth of signers and the two have to be comparable. Post-
/// Electra `AttestationData.index` is pinned to 0, so every committee of a slot
/// voting the same head shares one message.
struct Summed {
    /// The message, with `signature` left empty until it is read out.
    attestation: AttestationWitness,
    signature: blst::min_pk::AggregateSignature,
    /// Every signer, with the signature it arrived under, so that a subset of
    /// them can be summed on its own.
    signers: BTreeMap<u64, Signature>,
}

impl Summed {
    /// The running total, as an aggregate the rest of the collector can treat
    /// like any other.
    fn aggregate(&self) -> Aggregate {
        let signature = self.signature.to_signature();
        Aggregate {
            attestation: AttestationWitness {
                signature: BlsSignature(signature.to_bytes()),
                ..self.attestation.clone()
            },
            signature,
            signers: self.signers.keys().copied().collect(),
        }
    }

    /// The part of this bucket that `covered` does not already carry.
    ///
    /// `None` when it carries all of it. The whole-bucket case is answered from
    /// the running total, so the per-signature sum below is only ever paid for
    /// the handful of members a chosen aggregate missed.
    fn residual(&self, covered: &BTreeSet<u64>) -> Option<Aggregate> {
        if !self.signers.keys().any(|index| covered.contains(index)) {
            return Some(self.aggregate());
        }
        let mut sum: Option<AggregateSignature> = None;
        let mut signers = BTreeSet::new();
        for (&index, signature) in &self.signers {
            if covered.contains(&index) {
                continue;
            }
            match &mut sum {
                None => sum = Some(AggregateSignature::from_signature(signature)),
                Some(sum) => sum.add_signature(signature, false).ok()?,
            }
            signers.insert(index);
        }
        let signature = sum?.to_signature();
        Some(Aggregate {
            attestation: AttestationWitness {
                signature: BlsSignature(signature.to_bytes()),
                ..self.attestation.clone()
            },
            signature,
            signers,
        })
    }
}

/// Sum a message's chosen aggregates into the one the circuit derives a key for.
///
/// They are pairwise disjoint by construction, so their signatures add exactly
/// as the guest's derived key adds their public keys — and one aggregate is
/// what the guest is cheapest at, because every extra one is another G2
/// decompression inside the proof.
fn merge(aggregates: &[&Aggregate]) -> Option<AttestationWitness> {
    let (first, rest) = aggregates.split_first()?;
    let mut sum = AggregateSignature::from_signature(&first.signature);
    for aggregate in rest {
        sum.add_signature(&aggregate.signature, false).ok()?;
    }
    Some(AttestationWitness {
        signature: BlsSignature(sum.to_signature().to_bytes()),
        ..first.attestation.clone()
    })
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
    source_epoch: u64,
    source_root: [u8; 32],
    slots_per_epoch: u64,
    committees: Arc<EpochCommittees>,
    /// Network aggregates seen so far, keyed by the slot they attest to. The
    /// only covers a slot has to choose between, because they cannot be cut.
    pending: BTreeMap<u64, Vec<Aggregate>>,
    /// Unaggregated attestations, summed per message and committee as they
    /// arrive, keyed by the slot they attest to. The primary path.
    summed: BTreeMap<u64, BTreeMap<(DataKey, u64), Summed>>,
    /// Slots [`Self::forget`] has been called for.
    ///
    /// Dropping the maps is not enough to forget a slot: attestations for it
    /// keep arriving for several slots afterwards, and each one puts the slot
    /// back. The caller then takes it a second time, and the aggregation circuit
    /// rejects the epoch with "group proof N counts a slot that was already
    /// counted" — correctly, because the first group proof already fixed that
    /// slot's attester set and counting it twice counts its validators twice.
    closed: BTreeSet<u64>,
}

impl SlotStream {
    pub fn new(
        config: &ChainConfig,
        committees: Arc<EpochCommittees>,
        target_epoch: u64,
        target_root: [u8; 32],
        source_root: [u8; 32],
    ) -> Self {
        Self {
            target_epoch,
            target_root,
            source_epoch: target_epoch.saturating_sub(1),
            source_root,
            slots_per_epoch: config.slots_per_epoch,
            committees,
            pending: BTreeMap::new(),
            summed: BTreeMap::new(),
            closed: BTreeSet::new(),
        }
    }

    pub fn committees(&self) -> &EpochCommittees {
        &self.committees
    }

    /// Feed whatever has arrived, gossiped or included in a block.
    ///
    /// Only attestations targeting this checkpoint are kept, and they are filed
    /// under the slot they attest to rather than whatever carried them.
    ///
    /// An unaggregated attestation goes straight into its committee's running
    /// signature; an aggregate is held aside until [`Self::close`] chooses
    /// between it and whatever else covers the same members. A validator seen twice — the same
    /// attestation re-gossiped, or a single a later block also carried — is
    /// added once, because summing a signature twice still verifies and would
    /// quietly count the validator twice.
    ///
    /// Nothing here materialises a public key. Signers are held as indices, and
    /// the leaf preimages are read off the committee proof's members at
    /// [`Self::close`] — for the handful of validators a complement names, not
    /// for the tens of thousands it does not.
    pub fn ingest(&mut self, attestations: &[AttestationResponse]) -> Result<()> {
        for att in attestations {
            if att.data_target_epoch != self.target_epoch
                || att.data_target_root != self.target_root
                || att.data_source_epoch != self.source_epoch
                || att.data_source_root != self.source_root
            {
                continue;
            }
            if self.closed.contains(&att.data_slot) {
                continue;
            }

            let signers: BTreeSet<u64> = resolve_attesting_validators(att, &self.committees)
                .context("resolve attestors")?
                .into_iter()
                .collect();
            if signers.is_empty() {
                continue;
            }

            let attestation = AttestationWitness {
                data_slot: att.data_slot,
                data_index: att.data_index,
                data_beacon_block_root: att.data_beacon_block_root,
                data_source_epoch: att.data_source_epoch,
                data_source_root: att.data_source_root,
                data_target_epoch: att.data_target_epoch,
                data_target_root: att.data_target_root,
                signature: BlsSignature(att.signature),
                attesting_validators: Vec::new(),
            };

            match att.single_attester {
                Some(single) => {
                    self.sum_single(attestation, single.committee_index, single.attester_index)?
                }
                None => {
                    // A backstop the node published and we cannot read is one
                    // less cover to choose from, not a reason to fail the tick.
                    let Ok(signature) = Signature::from_bytes(&attestation.signature.0) else {
                        continue;
                    };
                    self.pending
                        .entry(att.data_slot)
                        .or_default()
                        .push(Aggregate {
                            attestation,
                            signature,
                            signers,
                        });
                }
            }
        }
        Ok(())
    }

    /// Add one unaggregated attestation to its committee's running signature.
    ///
    /// Takes the attester rather than a signer set because the signature is
    /// filed under it: a subset of the bucket is summed out of these, so a
    /// signature stored against a validator it does not sign for would produce
    /// a residual that pairs against the wrong key.
    fn sum_single(
        &mut self,
        attestation: AttestationWitness,
        committee_index: u64,
        attester: u64,
    ) -> Result<()> {
        let signature = Signature::from_bytes(&attestation.signature.0)
            .map_err(|e| anyhow!("a gossiped signature does not decompress: {e:?}"))?;

        match self
            .summed
            .entry(attestation.data_slot)
            .or_default()
            .entry((data_key(&attestation), committee_index))
        {
            Entry::Vacant(message) => {
                message.insert(Summed {
                    signature: AggregateSignature::from_signature(&signature),
                    attestation,
                    signers: BTreeMap::from([(attester, signature)]),
                });
            }
            Entry::Occupied(mut message) => {
                let running = message.get_mut();
                if running.signers.contains_key(&attester) {
                    return Ok(());
                }
                running
                    .signature
                    .add_signature(&signature, false)
                    .map_err(|e| anyhow!("summing a gossiped signature failed: {e:?}"))?;
                running.signers.insert(attester, signature);
            }
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
        self.forget(slot);
        Some(complement)
    }

    /// What closing `slot` right now would produce, without closing it.
    ///
    /// The trigger runs this several times a second on the slot gossip is
    /// filling: every arrival moves a committee member out of `absentees` and
    /// into the derived key, so `marginal_balance` climbs and `named_indices`
    /// shrinks as the slot converges. Both are what the trigger is choosing
    /// between — weight it has against work it would pay for.
    ///
    /// # What the cover may be
    ///
    /// A named leaf is a committee member the derived key does not cover, so
    /// `named_indices.len()` is exactly `committee size − primary coverage` and
    /// the only question this asks is how much of the committee one message's
    /// aggregates can be made to reach.
    ///
    /// Disjointness is the whole constraint, and it is proved here rather than
    /// assumed, because summing a validator's signature twice *verifies*:
    /// `sig + sig_v` checks out against `2·pk_v + rest`, so a double count is
    /// not caught downstream by anything. Nothing else is: the guest folds any
    /// number of aggregates over one message by adding their signatures, and it
    /// never sees this choice — a cover that is wrong produces a proof that
    /// fails to verify rather than one that lies.
    pub fn peek(&self, slot: u64) -> Option<SlotComplement> {
        let slot_in_epoch = slot % self.slots_per_epoch;
        let committee = self.committees.aggregate(slot_in_epoch)?.clone();
        let members = &self.committees.members[slot_in_epoch as usize];

        let summed = self.summed.get(&slot);
        let theirs = self.pending.get(&slot);
        if summed.is_none_or(|messages| messages.is_empty())
            && theirs.is_none_or(|aggregates| aggregates.is_empty())
        {
            return None;
        }

        // The network's aggregates, largest first and only where disjoint from
        // what is already counted. They are the only atoms in the slot: a
        // signature over a set of signers cannot be cut down to a subset of it,
        // so an aggregate overlapping one already taken is refused however much
        // more it carries. This is the one place a cover is *chosen*.
        let mut packed: BTreeMap<DataKey, BTreeSet<u64>> = BTreeMap::new();
        let mut chosen: Vec<(DataKey, &Aggregate)> = Vec::new();
        let mut order: Vec<&Aggregate> = theirs.into_iter().flatten().collect();
        order.sort_by_key(|a| std::cmp::Reverse(a.signers.len()));
        for aggregate in order {
            let key = data_key(&aggregate.attestation);
            let signers = packed.entry(key).or_default();
            if signers.intersection(&aggregate.signers).next().is_some() {
                continue;
            }
            signers.extend(&aggregate.signers);
            chosen.push((key, aggregate));
        }

        // Then every unaggregated attestation that packing missed. A single
        // names one validator, so ours are divisible where an aggregate is not,
        // and the part of a committee's sum that a chosen aggregate does not
        // carry can still be summed on its own. That makes the cover at least
        // the union of everything the node has heard, whatever the packing
        // chose — which is the property the old rule did not have. It weighed
        // our sums against the aggregates by size and threw away the loser
        // whole, so a slot on gossip alone kept whichever wave happened to be
        // ahead: 64% to 77% from the unaggregated feed against 99.7% from the
        // aggregates, and either could displace the other.
        let empty = BTreeSet::new();
        let ours: Vec<(DataKey, Aggregate)> = summed
            .into_iter()
            .flatten()
            .filter_map(|((key, _committee), summed)| {
                Some((*key, summed.residual(packed.get(key).unwrap_or(&empty))?))
            })
            .collect();

        let mut by_message: BTreeMap<DataKey, (Vec<&Aggregate>, BTreeSet<u64>)> = packed
            .into_iter()
            .map(|(key, signers)| (key, (Vec::new(), signers)))
            .collect();
        for (key, aggregate) in chosen {
            by_message.entry(key).or_default().0.push(aggregate);
        }
        // A residual is disjoint from the packing by construction and from
        // every other residual because committees partition the slot. It is
        // still proved rather than assumed: a validator counted twice is a
        // proof that fails, and nothing before this point would catch it.
        for (key, aggregate) in &ours {
            let entry = by_message.entry(*key).or_default();
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
                primary: vec![merge(&primary_aggregates)?],
                secondary,
                absentees,
            },
        })
    }

    /// Drop a slot the caller has already taken a [`Self::peek`] of, so that
    /// later arrivals for it are not collected all over again.
    pub fn forget(&mut self, slot: u64) {
        self.pending.remove(&slot);
        self.summed.remove(&slot);
        self.closed.insert(slot);
    }

    /// Network aggregates seen for `slot` so far.
    ///
    /// The trigger reads this rather than the count of attesters: a slot's
    /// gossip arrives in two pieces, and this says whether the second has
    /// started. See [`crate::streaming::Filling`].
    pub fn aggregates(&self, slot: u64) -> usize {
        self.pending.get(&slot).map_or(0, Vec::len)
    }

    /// Attestation slots that have been fed and not yet closed.
    pub fn open_slots(&self) -> Vec<u64> {
        let mut slots: Vec<u64> = self
            .pending
            .keys()
            .chain(self.summed.keys())
            .copied()
            .collect();
        slots.dedup();
        slots.sort_unstable();
        slots.dedup();
        slots
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
#[allow(clippy::too_many_arguments)]
pub async fn collect_per_slot_for_checkpoint(
    api: &impl BeaconApi,
    config: &ChainConfig,
    committees: Arc<EpochCommittees>,
    target_epoch: u64,
    target_root: &[u8; 32],
    source_root: &[u8; 32],
) -> Result<Vec<SlotComplement>> {
    let spe = config.slots_per_epoch;
    let mut stream = SlotStream::new(config, committees, target_epoch, *target_root, *source_root);

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

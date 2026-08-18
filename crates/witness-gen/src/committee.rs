//! Host side of the committee proof.
//!
//! Sums each slot's committee out of the accumulator, once per epoch, so that
//! every proof after it names absentees instead of attesters. See
//! [`zkasper_common::committee`] for what the circuit establishes.
//!
//! # Where the assignment comes from
//!
//! Straight off the beacon node's `/eth/v1/beacon/states/{id}/committees`, which
//! is the node's own swap-or-not shuffle over the epoch's active validators.
//! Nothing here recomputes it and nothing in the circuit checks it, because a
//! wrong assignment produces buckets whose members did not sign the message they
//! are paired against — a proof that cannot be built, rather than one that lies.
//! The 90 shuffle rounds over a million validators therefore stay on the host,
//! where they are the node's problem and cost nothing.

use std::collections::BTreeMap;

use anyhow::{ensure, Context, Result};
use rayon::prelude::*;

use zkasper_common::acc::{self, Digest, ZERO};
use zkasper_common::committee::{self, MAX_SLOTS, TREE_DEPTH};
use zkasper_common::types::{
    AccMultiProof, CommitteeAggregate, CommitteeMember, CommitteeOutput, CommitteeWitness,
    OpenedValidator,
};
use zkasper_common::ChainConfig;

use crate::acc_tree::AccTree;
use crate::beacon_api::{CommitteeResponse, ValidatorResponse};
use crate::state_diff::validator_response_to_data;

/// One epoch's committees, summed, with everything a slot proof needs to open
/// them.
pub struct EpochCommittees {
    /// Validator indices per slot within the epoch, sorted.
    pub members: Vec<Vec<u64>>,
    /// The node's raw table, `(slot, committee index) -> validators`, which is
    /// what an attestation's `committee_bits` and `aggregation_bits` index into.
    table: BTreeMap<(u64, u64), Vec<u64>>,
    /// Summed public key and balance per slot within the epoch.
    pub aggregates: Vec<Option<CommitteeAggregate>>,
    pub witness: CommitteeWitness,
    pub output: CommitteeOutput,
    /// `levels[0]` are the leaves, `levels[TREE_DEPTH]` the root.
    levels: Vec<Vec<Digest>>,
}

impl EpochCommittees {
    pub fn root(&self) -> Digest {
        self.levels[TREE_DEPTH as usize][0]
    }

    pub fn aggregate(&self, slot_in_epoch: u64) -> Option<&CommitteeAggregate> {
        self.aggregates.get(slot_in_epoch as usize)?.as_ref()
    }

    /// One committee of one slot, as the node reported it.
    pub fn committee(&self, slot: u64, index: u64) -> Option<&[u64]> {
        self.table.get(&(slot, index)).map(Vec::as_slice)
    }

    /// Opening of the committee tree for `slots`, which must be sorted and
    /// strictly increasing.
    ///
    /// Mirrors [`zkasper_common::merkle::batch_root`]'s scan, so the auxiliaries
    /// come out in the order it consumes them.
    pub fn multi_proof(&self, slots: &[u64]) -> AccMultiProof {
        let mut idx: Vec<u64> = slots.to_vec();
        let mut auxiliaries = Vec::new();
        let mut next: Vec<u64> = Vec::with_capacity(idx.len());

        for level in 0..TREE_DEPTH as usize {
            next.clear();
            let mut i = 0usize;
            while i < idx.len() {
                let k = idx[i];
                if k & 1 == 0 {
                    if i + 1 < idx.len() && idx[i + 1] == k + 1 {
                        i += 2;
                    } else {
                        auxiliaries.push(self.levels[level][(k + 1) as usize]);
                        i += 1;
                    }
                } else {
                    auxiliaries.push(self.levels[level][(k - 1) as usize]);
                    i += 1;
                }
                next.push(k >> 1);
            }
            std::mem::swap(&mut idx, &mut next);
        }

        AccMultiProof { auxiliaries }
    }
}

/// Sum every slot's committee out of the accumulator and assemble the proof's
/// witness.
///
/// `balance_epoch` is the epoch the accumulator's `active_effective_balance`
/// values were evaluated at, which is what the leaves commit to.
pub fn build(
    committees: &[CommitteeResponse],
    validators: &[ValidatorResponse],
    acc_tree: &AccTree,
    config: &ChainConfig,
    target_epoch: u64,
    balance_epoch: u64,
    total_active_balance: u64,
) -> Result<EpochCommittees> {
    ensure!(
        config.slots_per_epoch <= MAX_SLOTS,
        "committee tree holds {MAX_SLOTS} slots, chain has {} per epoch",
        config.slots_per_epoch,
    );

    // Slot within the epoch each validator attests at. A validator sits in
    // exactly one committee per epoch, so a second assignment is the node
    // contradicting itself rather than something to merge.
    let mut assignment: BTreeMap<u64, u64> = BTreeMap::new();
    let mut table: BTreeMap<(u64, u64), Vec<u64>> = BTreeMap::new();
    for response in committees {
        let slot_in_epoch = response.slot % config.slots_per_epoch;
        for &index in &response.validators {
            ensure!(
                assignment.insert(index, slot_in_epoch).is_none(),
                "validator {index} is in two committees of epoch {target_epoch}",
            );
        }
        table.insert((response.slot, response.index), response.validators.clone());
    }

    let mut members: Vec<Vec<u64>> = vec![Vec::new(); MAX_SLOTS as usize];
    let mut positions: Vec<Vec<usize>> = vec![Vec::new(); MAX_SLOTS as usize];
    let mut member_witnesses: Vec<CommitteeMember> = Vec::with_capacity(assignment.len());
    for (&validator_index, &slot_in_epoch) in &assignment {
        let response = validators.get(validator_index as usize).ok_or_else(|| {
            anyhow::anyhow!("committee names validator {validator_index}, which is not registered")
        })?;
        members[slot_in_epoch as usize].push(validator_index);
        positions[slot_in_epoch as usize].push(member_witnesses.len());
        member_witnesses.push(CommitteeMember {
            validator_index,
            pubkey: crate::pubkey::decompress(&response.pubkey)
                .with_context(|| format!("decompress validator {validator_index} public key"))?,
            active_effective_balance: validator_response_to_data(response)
                .active_effective_balance(balance_epoch),
            slot_in_epoch,
        });
    }

    // The same sums the circuit computes, over the same leaves. The host builds
    // them so the witness carries what the proof will publish, not so the proof
    // can trust them.
    let aggregates: Vec<Option<CommitteeAggregate>> = positions
        .par_iter()
        .map(|slot| {
            let mut sum = zkasper_common::bls::PointSum::default();
            let mut balance = 0u64;
            for &position in slot {
                sum.add(&member_witnesses[position].pubkey)?;
                balance += member_witnesses[position].active_effective_balance;
            }
            sum.get()
                .map(|pubkey| CommitteeAggregate { pubkey, balance })
        })
        .collect();

    let leaves: Vec<Digest> = aggregates
        .iter()
        .map(|slot| match slot {
            Some(aggregate) => committee::leaf(aggregate),
            None => ZERO,
        })
        .collect();

    let mut levels: Vec<Vec<Digest>> = vec![leaves];
    for d in 0..TREE_DEPTH as usize {
        let parents = levels[d]
            .chunks_exact(2)
            .map(|pair| acc::compress(&pair[0], &pair[1]))
            .collect();
        levels.push(parents);
    }

    let acc_root = acc_tree.root();
    let accumulator_commitment = acc::commitment(&acc_root, total_active_balance);
    let indices: Vec<u64> = member_witnesses.iter().map(|m| m.validator_index).collect();

    Ok(EpochCommittees {
        members,
        table,
        aggregates,
        witness: CommitteeWitness {
            accumulator_commitment,
            target_epoch,
            acc_root,
            total_active_balance,
            acc_multi_proof: acc_tree.build_multi_proof(&indices),
            members: member_witnesses,
        },
        output: CommitteeOutput {
            accumulator_commitment,
            target_epoch,
            committee_root: levels[TREE_DEPTH as usize][0],
        },
        levels,
    })
}

/// The accumulator leaf preimage for one validator, as a witness names it.
pub fn opened(
    index: u64,
    response: &ValidatorResponse,
    balance_epoch: u64,
) -> Result<OpenedValidator> {
    Ok(OpenedValidator {
        validator_index: index,
        pubkey: crate::pubkey::decompress(&response.pubkey)
            .with_context(|| format!("decompress validator {index} public key"))?,
        active_effective_balance: validator_response_to_data(response)
            .active_effective_balance(balance_epoch),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tree the host builds and the one the circuit recomputes from an
    /// opening are the same tree, or a slot proof could never open anything.
    #[test]
    fn leaves_and_root_agree_with_the_circuit() {
        let aggregates: Vec<Option<CommitteeAggregate>> = (0..MAX_SLOTS)
            .map(|s| {
                (s % 3 != 0).then(|| CommitteeAggregate {
                    pubkey: [s + 1; 12],
                    balance: 32_000_000_000 * (s + 1),
                })
            })
            .collect();

        let mut levels: Vec<Vec<Digest>> = vec![aggregates
            .iter()
            .map(|a| a.as_ref().map(committee::leaf).unwrap_or(ZERO))
            .collect()];
        for d in 0..TREE_DEPTH as usize {
            levels.push(
                levels[d]
                    .chunks_exact(2)
                    .map(|pair| acc::compress(&pair[0], &pair[1]))
                    .collect(),
            );
        }
        assert_eq!(levels[TREE_DEPTH as usize][0], committee::root(&aggregates));
    }
}

//! FCR batch proof: how much stake voted for the canonical head, slot by slot.
//!
//! # What this proves, and what it deliberately does not
//!
//! The statement is a sum, not a verdict:
//!
//! > against accumulator commitment `A` and committee root `R`, the committees
//! > of these slots cast `support` of effective balance for the chain that runs
//! > from `parent_head_root` to `head_root`.
//!
//! The threshold is not here, and no threshold of ours ever will be. zkasper
//! proves the rule Ethereum specifies rather than one shaped to what is cheap to
//! prove, so the verifier evaluates `consensus-specs`' own
//! `(maximum_support + proposer_score + 2*adversarial_weight - support_discount) / 2`
//! over the scalars below. A circuit that hard-coded a threshold would also have
//! to be rebuilt, and reverified, every time that formula moved.
//!
//! # What this rests on: the assignment must be proven
//!
//! The spec threshold's denominator is a **slot's committee weight**, and the
//! committee partition is otherwise the prover's to choose — disjoint, because
//! leaves are consumed in strictly increasing validator-index order, but
//! otherwise arbitrary. An adversarial validator can sign an attestation for a
//! slot it was never assigned to: that is not slashable, because a double vote
//! needs two attestations with one target epoch and this is one, and the
//! attestation is invalid on the wire so it never becomes on-chain evidence. A
//! prover that concentrates the stake it controls into one bucket therefore picks
//! its own denominator, and ordering, pairing and leaf binding all still pass.
//! On mainnet that forges a one-slot confirmation with **2.97% of stake**.
//!
//! Finality is immune because its denominator is global — two thirds of total
//! active balance, summed over every bucket — so moving stake between buckets
//! changes nothing. FCR is not.
//!
//! **`committee_root` must therefore be the root of a committee proof that proves
//! the shuffle**, not one that merely partitions. That is settled design, it is
//! measured at 44.2 s an epoch, and it is proved an epoch ahead off the E-2
//! RANDAO fix so it never touches the critical path. See
//! `docs/shared/committee-and-shuffle.md`. Handing this circuit a committee root
//! from an unproven partition does not make it fail — it makes it lie.
//!
//! # Why a batch is available, and when it is not
//!
//! A one-slot FCR proof is 75% stage floor: 9.09 s, of which 7.176 s is the floor
//! and 1.76 s is the work. Three slots under one floor cost 10.78 s against
//! 27.27 s as three proofs. A batch is therefore a latency-for-cost dial, and the
//! caller sets it: `slot_count` of 1 is the fast path the spec threshold is worth
//! having, and a larger batch trades confirmation granularity for prover time
//! where a consumer does not need every slot.
//!
//! # No recursion, by construction
//!
//! Batches are standalone: each runs its own final exponentiation and verifies
//! its own signatures. In-guest `verify_zisk_proof` has never been measured,
//! and at 3 s a chain that verified its predecessor in-circuit would fall
//! 0.43 s behind every slot for ever, which no number of cards fixes. Keeping
//! the accumulation in the verifier removes the unmeasured constant from the
//! critical path and leaves batches independent, so a chain that falls behind
//! can be caught up in parallel.

extern crate alloc;

use alloc::vec::Vec;
use zkasper_common::acc::{Digest, G1Point};
use zkasper_common::types::AttestationWitness;
use zkasper_fcr_types::{FcrBatchOutput, FcrBatchWitness};

/// Verify an FCR batch at the mainnet accumulator depth.
pub fn verify_fcr_batch(witness: &FcrBatchWitness) -> FcrBatchOutput {
    verify_fcr_batch_with_depth(witness, zkasper_common::constants::ACC_TREE_DEPTH)
}

/// The same, with a configurable accumulator tree depth.
pub fn verify_fcr_batch_with_depth(witness: &FcrBatchWitness, acc_depth: u32) -> FcrBatchOutput {
    use zkasper_common::acc;
    use zkasper_common::bls::{miller_accumulator, PointSum, SignedMessage};
    use zkasper_common::committee;

    assert_eq!(
        acc::commitment(&witness.acc_root, witness.total_active_balance),
        witness.accumulator_commitment,
        "accumulator commitment mismatch",
    );
    assert!(!witness.slots.is_empty(), "an FCR batch covers no slots");

    let mut support: u64 = 0;
    let mut opened: Vec<(Digest, u64)> = Vec::new();
    let mut committee_leaves: Vec<(Digest, u64)> = Vec::new();
    let mut aggregate_keys: Vec<Vec<G1Point>> = Vec::new();
    let mut signing_roots: Vec<[u8; 32]> = Vec::new();
    let mut signatures: Vec<Vec<[u8; 96]>> = Vec::new();

    let mut head_root = witness.parent_head_root;
    let mut head_slot = witness.parent_head_slot;
    let mut previous_slot: Option<u64> = None;

    for entry in &witness.slots {
        let slot = &entry.complement;

        // Contiguous, not merely increasing. The threshold is `0.5*M(k) + ...`
        // with `M(k) = (T / SLOTS_PER_EPOCH) * k`, so dropping a slot lowers the
        // bar by half a committee. A prover that omitted every slot whose
        // counted support fell below that — a slot the chain mostly voted a
        // different head at, which costs it nothing — would buy threshold slack
        // for free. Gaps between batches are the verifier's job, by
        // `first_slot + slot_count`; gaps inside one are this assertion's.
        if let Some(previous) = previous_slot {
            assert_eq!(
                slot.slot_in_epoch,
                previous + 1,
                "an FCR batch covers a contiguous run of slots; {} followed {previous}",
                slot.slot_in_epoch,
            );
        }
        previous_slot = Some(slot.slot_in_epoch);
        assert!(
            slot.slot_in_epoch < committee::MAX_SLOTS,
            "slot {} is past the {} a committee tree holds",
            slot.slot_in_epoch,
            committee::MAX_SLOTS,
        );
        committee_leaves.push((committee::leaf(&slot.committee), slot.slot_in_epoch));

        // The canonical head this slot's votes are counted against. A skipped
        // slot proposes nothing and leaves the head where it was; a block must
        // extend the head the slot before it left, so the batch proves a chain
        // rather than a set of unrelated roots.
        if let Some(header) = &entry.head_header {
            assert_eq!(
                header.parent_root, head_root,
                "the block at slot {} does not extend this batch's chain",
                header.slot,
            );
            assert!(
                header.slot > head_slot,
                "the block at slot {} does not advance past head slot {head_slot}",
                header.slot,
            );
            head_root = zkasper_common::ssz::block_header_root(
                header.slot,
                header.proposer_index,
                &header.parent_root,
                &header.state_root,
                &header.body_root,
            );
            head_slot = header.slot;
        }

        let (first, rest) = slot
            .primary
            .split_first()
            .expect("slot has no primary aggregate");
        for attestation in &slot.primary {
            assert!(
                attestation.attesting_validators.is_empty(),
                "the primary aggregate of slot {} names its signers, which is the \
                 work complement proving exists to avoid",
                slot.slot_in_epoch,
            );
        }
        for attestation in rest {
            assert!(
                same_data(first, attestation),
                "slot {} pairs one derived key against two messages",
                slot.slot_in_epoch,
            );
        }

        // The committee bucket and the message must name one slot, or honest
        // validators could be relocated into a window that needs their weight.
        assert_eq!(
            first.data_slot % zkasper_common::constants::SLOTS_PER_EPOCH,
            slot.slot_in_epoch,
            "slot {} is paired against a message for slot {}",
            slot.slot_in_epoch,
            first.data_slot,
        );
        if let Some(header) = &entry.head_header {
            assert_eq!(
                header.slot, first.data_slot,
                "the block proposed at slot {} is paired against a message for slot {}",
                header.slot, first.data_slot,
            );
        }

        let mut counted = slot.committee.balance;
        let mut primary_key = PointSum::from_point(slot.committee.pubkey);

        // Minority head votes. Their signers are named, so their keys leave the
        // derived sum — and, unlike the FFG pipeline, so do their balances: they
        // voted for a different head, and a vote for a different head is not
        // support for this one.
        for attestation in &slot.secondary {
            let mut keys = PointSum::default();
            for v in &attestation.attesting_validators {
                opened.push((
                    acc::leaf(&v.pubkey, v.active_effective_balance),
                    v.validator_index,
                ));
                primary_key
                    .sub(&v.pubkey)
                    .expect("public key aggregation hit a shared x-coordinate");
                keys.add(&v.pubkey)
                    .expect("public key aggregation hit a shared x-coordinate");
                counted = counted
                    .checked_sub(v.active_effective_balance)
                    .expect("minority head votes exceed the committee's balance");
            }
            push_message(
                core::slice::from_ref(attestation),
                keys.get().expect("secondary aggregate names no signers"),
                &witness.signing_domain,
                &mut aggregate_keys,
                &mut signing_roots,
                &mut signatures,
            );
        }

        for v in &slot.absentees {
            opened.push((
                acc::leaf(&v.pubkey, v.active_effective_balance),
                v.validator_index,
            ));
            primary_key
                .sub(&v.pubkey)
                .expect("public key aggregation hit a shared x-coordinate");
            counted = counted
                .checked_sub(v.active_effective_balance)
                .expect("absentee balances exceed the committee's");
        }

        push_message(
            &slot.primary,
            primary_key
                .get()
                .expect("committee aggregate is the identity"),
            &witness.signing_domain,
            &mut aggregate_keys,
            &mut signing_roots,
            &mut signatures,
        );

        // The drop rule. A vote whose head is not the canonical block at its own
        // slot is dropped rather than attributed: exact-root matching
        // under-counts, which is the conservative direction, and it keeps the
        // accumulation O(1). The signatures are still verified — the slot's
        // committee is still bound — only its weight is not claimed.
        if first.data_beacon_block_root == head_root {
            support += counted;
        }
    }

    opened.sort_unstable_by_key(|&(_, index)| index);
    for i in 1..opened.len() {
        assert!(
            opened[i].1 > opened[i - 1].1,
            "validator {} named twice",
            opened[i].1,
        );
    }

    if !opened.is_empty() {
        assert_eq!(
            zkasper_common::merkle::batch_root(
                acc::compress,
                &opened,
                &witness.acc_multi_proof.auxiliaries,
                acc_depth,
            ),
            witness.acc_root,
            "accumulator root mismatch",
        );
    } else {
        assert!(
            witness.acc_multi_proof.auxiliaries.is_empty(),
            "accumulator opening with nothing to open",
        );
    }

    assert_eq!(
        zkasper_common::merkle::batch_root(
            acc::compress,
            &committee_leaves,
            &witness.committee_multi_proof.auxiliaries,
            committee::TREE_DEPTH,
        ),
        witness.committee_root,
        "committee root mismatch",
    );

    let messages: Vec<SignedMessage> = (0..aggregate_keys.len())
        .map(|i| SignedMessage {
            pubkeys: &aggregate_keys[i],
            signing_root: &signing_roots[i],
            signatures: &signatures[i],
        })
        .collect();

    assert!(
        zkasper_common::bls::final_exp_is_one(
            &miller_accumulator(&messages).expect("BLS pairing inputs rejected"),
        ),
        "BLS aggregate signature verification failed",
    );

    FcrBatchOutput {
        accumulator_commitment: witness.accumulator_commitment,
        committee_root: witness.committee_root,
        parent_head_root: witness.parent_head_root,
        head_root,
        head_slot,
        support,
        total_active_balance: witness.total_active_balance,
        // Absolute, and asserted above to agree with the first bucket's index.
        first_slot: witness.slots[0].complement.primary[0].data_slot,
        slot_count: witness.slots.len() as u64,
    }
}

/// Whether two aggregates carry byte-identical `AttestationData`.
fn same_data(a: &AttestationWitness, b: &AttestationWitness) -> bool {
    a.data_slot == b.data_slot
        && a.data_index == b.data_index
        && a.data_beacon_block_root == b.data_beacon_block_root
        && a.data_source_epoch == b.data_source_epoch
        && a.data_source_root == b.data_source_root
        && a.data_target_epoch == b.data_target_epoch
        && a.data_target_root == b.data_target_root
}

/// Queue a message for the multi-pairing.
///
/// Unlike the FFG path this pins no checkpoint: FCR counts head votes, and which
/// head a vote is for is decided by `data_beacon_block_root` against the
/// canonical root of its slot, not by the source and target it also carries.
/// The signature covers the whole `AttestationData` either way, so nothing here
/// is taken on the host's word.
fn push_message(
    aggregates: &[AttestationWitness],
    aggregate_key: G1Point,
    signing_domain: &[u8; 32],
    aggregate_keys: &mut Vec<Vec<G1Point>>,
    signing_roots: &mut Vec<[u8; 32]>,
    signatures: &mut Vec<Vec<[u8; 96]>>,
) {
    let attestation = &aggregates[0];
    let data_root = zkasper_common::ssz::attestation_data_root(
        attestation.data_slot,
        attestation.data_index,
        &attestation.data_beacon_block_root,
        attestation.data_source_epoch,
        &attestation.data_source_root,
        attestation.data_target_epoch,
        &attestation.data_target_root,
    );

    aggregate_keys.push(alloc::vec![aggregate_key]);
    signing_roots.push(zkasper_common::bls::compute_signing_root(
        &data_root,
        signing_domain,
    ));
    signatures.push(aggregates.iter().map(|a| a.signature.0).collect());
}

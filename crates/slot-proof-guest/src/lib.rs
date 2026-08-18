extern crate alloc;

use alloc::vec::Vec;
use zkasper_common::acc::{Digest, G1Point};
use zkasper_common::bls::Fp12;
use zkasper_common::types::{
    AccMultiProof, AttestationWitness, GroupProofOutput, SlotComplementWitness, SlotProofOutput,
    SlotProofWitness,
};

/// What verifying a set of attestation slots establishes.
pub struct Attested {
    /// Sum over those slots of `committee balance − absentee balances`.
    pub attesting_balance: u64,
    /// Which slots of the epoch were counted, one bit each.
    pub slots_mask: u64,
    /// The Miller-loop half of the signature check over every attestation.
    ///
    /// The final exponentiation is *not* done here. Nothing is proven about
    /// these signatures until some proof runs it over the product of this and
    /// every other accumulator in the epoch.
    pub miller: Fp12,
}

/// Verify a single slot's attestations and produce a SlotProofOutput.
///
/// This is the whole-slot form: it finishes the pairing itself, so its output
/// stands alone. Streaming callers want [`verify_group_proof`] instead.
pub fn verify_slot_proof(witness: &SlotProofWitness) -> SlotProofOutput {
    verify_slot_proof_with_depth(witness, zkasper_common::constants::ACC_TREE_DEPTH)
}

/// Slot-proof verification with a configurable accumulator tree depth.
pub fn verify_slot_proof_with_depth(witness: &SlotProofWitness, acc_depth: u32) -> SlotProofOutput {
    let attested = attest(witness, acc_depth);

    assert!(
        zkasper_common::bls::final_exp_is_one(&attested.miller),
        "BLS aggregate signature verification failed",
    );

    SlotProofOutput {
        accumulator_commitment: witness.accumulator_commitment,
        committee_root: witness.committee_root,
        target_epoch: witness.target_epoch,
        target_root: witness.target_root,
        attesting_balance: attested.attesting_balance,
        slots_mask: attested.slots_mask,
    }
}

/// Verify a group of slots' attestations and stop before the final exponentiation.
///
/// A group proof is the streaming form of a slot proof. It does the same
/// membership and aggregation work over as many slots as the caller chose to
/// group together, and publishes a commitment to its Miller-loop accumulator
/// instead of a verdict on the signatures.
///
/// # Why the signatures are not checked here
///
/// The final exponentiation costs 132,665,557 against 33,222,822 for a Miller
/// loop, and one of them settles a product of any number of Miller loops.
/// Charging every group for its own would spend that once per group for no gain,
/// since the epoch's proof chain has to run one anyway over whatever the last
/// attestation contributes.
///
/// The consequence is that a group proof alone proves nothing about signatures.
/// It is a claim of the form "these are the committees of these slots, and *if*
/// the product of everyone's accumulators exponentiates to 1, this is their
/// attesting balance". The proof that closes the epoch is what discharges the
/// *if*, and it must cover every group whose balance it counts.
pub fn verify_group_proof(witness: &SlotProofWitness) -> GroupProofOutput {
    verify_group_proof_with_depth(witness, zkasper_common::constants::ACC_TREE_DEPTH)
}

/// Group-proof verification with a configurable accumulator tree depth.
pub fn verify_group_proof_with_depth(
    witness: &SlotProofWitness,
    acc_depth: u32,
) -> GroupProofOutput {
    let attested = attest(witness, acc_depth);

    GroupProofOutput {
        accumulator_commitment: witness.accumulator_commitment,
        committee_root: witness.committee_root,
        target_epoch: witness.target_epoch,
        target_root: witness.target_root,
        attesting_balance: attested.attesting_balance,
        slots_mask: attested.slots_mask,
        miller_commitment: zkasper_common::acc::commit_fp12(&attested.miller),
    }
}

/// Run a slot/group witness's checks and return what they established, Miller
/// accumulator included.
///
/// The accumulator never appears in a proof's public outputs — it is 576 bytes
/// against a 256-byte budget — so the host recomputes it here, natively, to feed
/// the parent proof as witness. Recomputing is safe: the parent checks it
/// against the commitment the child published, so a host that got it wrong
/// produces a proof that fails rather than one that lies.
pub fn attest(witness: &SlotProofWitness, acc_depth: u32) -> Attested {
    // Verify the accumulator commitment binds acc_root + total_active_balance
    assert_eq!(
        zkasper_common::acc::commitment(&witness.acc_root, witness.total_active_balance),
        witness.accumulator_commitment,
        "accumulator commitment mismatch",
    );

    verify_attestations(
        &witness.slots,
        &witness.acc_root,
        &witness.acc_multi_proof,
        &witness.committee_root,
        &witness.committee_multi_proof,
        witness.target_epoch,
        &witness.target_root,
        &witness.signing_domain,
        acc_depth,
    )
}

/// Verify attestation slots by complement and accumulate their pairings.
///
/// Shared by the slot proof, the group proof, and the marginal slot the final
/// proof of an epoch does inline — the last of which is the only place this work
/// sits on the critical path, so there is exactly one implementation of it.
///
/// # What is proven, and what proves it
///
/// A slot's committee arrives already summed, as a `(pubkey, balance)` pair
/// opened from the committee tree. What this function does with it is:
///
/// ```text
/// agg_pk  = committee.pubkey  − Σ(secondary signers) − Σ(absentees)
/// support = committee.balance − Σ(absentee balances)
/// ```
///
/// and then pairs `agg_pk` against the primary message. Nothing enumerates the
/// ~99.7% of the committee that attested, which is the entire saving: 90
/// openings for a mainnet slot instead of 29,940.
///
/// **The public keys are pinned by the pairing.** The multi-pairing forces
/// `agg_pk` to be the sum of the keys that actually signed the primary message.
/// A prover who omits a genuine absentee leaves `agg_pk` too large by that
/// validator's key; one who names an attester leaves it too small; one who names
/// a validator outside the committee leaves it something that is not a subset
/// sum of the committee at all. Each is an aggregate-signature forgery, so the
/// aggregation bitfield never has to enter the circuit and no per-attester
/// committee-membership check is needed. This is the same argument that used to
/// justify opening *every* attester rather than only the counted ones — a key
/// that is never opened is a key the prover chose freely — and it still holds,
/// because every key that goes into `agg_pk` is either opened here or summed
/// into `committee.pubkey` by the committee proof.
///
/// **The balances are not pinned by the pairing**, and are bound instead by the
/// accumulator leaf, which is one Poseidon2 hash over `(pubkey, balance)`
/// together. A validator cannot be subtracted from `agg_pk` at one balance and
/// from `support` at another, and the committee proof summed its two totals out
/// of the same leaves in the same pass. `checked_sub` below is the last line of
/// that defence: a balance sum that goes negative is rejected rather than
/// wrapping into an enormous one.
///
/// **Nothing is counted twice.** Within a group, every named validator index is
/// strictly increasing, so no validator is subtracted twice and no slot appears
/// twice. Across groups, the slot mask does the same job for slots — which is
/// enough, because a committee proof puts each validator in exactly one slot.
#[allow(clippy::too_many_arguments)]
pub fn verify_attestations(
    slots: &[SlotComplementWitness],
    acc_root: &Digest,
    acc_multi_proof: &AccMultiProof,
    committee_root: &Digest,
    committee_multi_proof: &AccMultiProof,
    target_epoch: u64,
    target_root: &[u8; 32],
    signing_domain: &[u8; 32],
    acc_depth: u32,
) -> Attested {
    use zkasper_common::acc;
    use zkasper_common::bls::{miller_accumulator, PointSum, SignedMessage};
    use zkasper_common::committee;

    let mut attesting_balance: u64 = 0;
    let mut slots_mask: u64 = 0;
    let mut opened: Vec<(acc::Digest, u64)> = Vec::new();
    let mut committee_leaves: Vec<(acc::Digest, u64)> = Vec::new();

    // One entry per attestation: its derived-or-enumerated aggregate key, the
    // root it signed, and the signature. `miller_accumulator` folds aggregates
    // over the same message together, so a slot whose primary and secondary
    // carry identical `AttestationData` costs one Miller loop, not two.
    let mut aggregate_keys: Vec<Vec<G1Point>> = Vec::new();
    let mut signing_roots: Vec<[u8; 32]> = Vec::new();
    let mut signatures: Vec<Vec<[u8; 96]>> = Vec::new();

    let mut previous_slot: Option<u64> = None;
    for slot in slots {
        if let Some(previous) = previous_slot {
            assert!(
                slot.slot_in_epoch > previous,
                "attestation slots must be strictly increasing: {} followed {previous}",
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
        slots_mask |= 1u64 << slot.slot_in_epoch;

        committee_leaves.push((committee::leaf(&slot.committee), slot.slot_in_epoch));

        let mut support = slot.committee.balance;
        let mut primary_key = PointSum::from_point(slot.committee.pubkey);

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
        // One derived key can only pair against one message, so every aggregate
        // it covers has to be over that message.
        for attestation in rest {
            assert!(
                same_data(first, attestation),
                "slot {} pairs one derived key against two messages",
                slot.slot_in_epoch,
            );
        }

        // Aggregates over a message other than the primary one: their signers
        // are named, so their keys leave the primary sum and form their own.
        // Their balances stay counted — they did attest to the target.
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
            }
            push_message(
                core::slice::from_ref(attestation),
                keys.get().expect("secondary aggregate names no signers"),
                target_epoch,
                target_root,
                signing_domain,
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
            support = support
                .checked_sub(v.active_effective_balance)
                .expect("absentee balances exceed the committee's");
        }

        push_message(
            &slot.primary,
            primary_key
                .get()
                .expect("committee aggregate is the identity"),
            target_epoch,
            target_root,
            signing_domain,
            &mut aggregate_keys,
            &mut signing_roots,
            &mut signatures,
        );

        attesting_balance += support;
    }

    // Every named validator, across every slot in the group, opened at once.
    // Strictly increasing after the sort is what stops a key being subtracted
    // twice — from one slot's absentees and another's, or from two aggregates.
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
                &acc_multi_proof.auxiliaries,
                acc_depth,
            ),
            *acc_root,
            "accumulator root mismatch",
        );
    } else {
        assert!(
            acc_multi_proof.auxiliaries.is_empty(),
            "accumulator opening with nothing to open",
        );
    }

    assert_eq!(
        zkasper_common::merkle::batch_root(
            acc::compress,
            &committee_leaves,
            &committee_multi_proof.auxiliaries,
            committee::TREE_DEPTH,
        ),
        *committee_root,
        "committee root mismatch",
    );

    let messages: Vec<SignedMessage> = (0..aggregate_keys.len())
        .map(|i| SignedMessage {
            pubkeys: &aggregate_keys[i],
            signing_root: &signing_roots[i],
            signatures: &signatures[i],
        })
        .collect();

    Attested {
        attesting_balance,
        slots_mask,
        miller: miller_accumulator(&messages).expect("BLS pairing inputs rejected"),
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

/// Check a message's checkpoint and queue it for the multi-pairing.
///
/// `aggregates` all carry the same `AttestationData`; their signatures sum into
/// one pairing term against `aggregate_key`.
#[allow(clippy::too_many_arguments)]
fn push_message(
    aggregates: &[AttestationWitness],
    aggregate_key: G1Point,
    target_epoch: u64,
    target_root: &[u8; 32],
    signing_domain: &[u8; 32],
    aggregate_keys: &mut Vec<Vec<G1Point>>,
    signing_roots: &mut Vec<[u8; 32]>,
    signatures: &mut Vec<Vec<[u8; 96]>>,
) {
    let attestation = &aggregates[0];
    assert_eq!(
        attestation.data_target_epoch, target_epoch,
        "attestation target_epoch mismatch",
    );
    assert_eq!(
        attestation.data_target_root, *target_root,
        "attestation target_root mismatch",
    );

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

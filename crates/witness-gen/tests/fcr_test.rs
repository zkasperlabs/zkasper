//! FCR batch proofs: what a head-vote count is allowed to claim.
//!
//! The FFG pipeline counts a target vote; this counts a head vote, and the two
//! differ in exactly one place that matters. A minority head vote still attests
//! the epoch's target, so the justification proof counts its balance. It is a
//! vote for a *different block*, so an FCR proof must not — and the rule it
//! obeys is to drop, never to attribute, because under-counting is the
//! conservative direction.

use zkasper_common::types::*;
use zkasper_common::{committee, ChainConfig};
use zkasper_fcr_proof_guest::verify_fcr_batch_with_depth;
use zkasper_fcr_types::*;
use zkasper_witness_gen::fixture::Epoch;

const ACC_DEPTH: u32 = 4;
const SLOTS: u64 = 4;
const PER_SLOT: usize = 4;
const BALANCE_GWEI: u64 = 32_000_000_000;
const EPOCH: u64 = 10;
/// The head the batch is asked to extend: whatever the batch before it left.
const PARENT_HEAD: [u8; 32] = [0x11; 32];

fn fixture() -> Epoch {
    Epoch::new(
        ChainConfig {
            acc_tree_depth: ACC_DEPTH,
            ..ChainConfig::MAINNET
        },
        EPOCH,
        SLOTS,
        PER_SLOT,
    )
}

fn header(epoch: &Epoch, slot_in_epoch: u64, parent_root: [u8; 32]) -> BlockHeaderWitness {
    BlockHeaderWitness {
        slot: epoch.slot(slot_in_epoch),
        proposer_index: slot_in_epoch,
        parent_root,
        state_root: [slot_in_epoch as u8 + 1; 32],
        body_root: [slot_in_epoch as u8 + 0x80; 32],
    }
}

fn root_of(h: &BlockHeaderWitness) -> [u8; 32] {
    zkasper_common::ssz::block_header_root(
        h.slot,
        h.proposer_index,
        &h.parent_root,
        &h.state_root,
        &h.body_root,
    )
}

fn attestation(
    epoch: &Epoch,
    slot_in_epoch: u64,
    head: [u8; 32],
    signers: &[u64],
    named: bool,
) -> AttestationWitness {
    AttestationWitness {
        data_slot: epoch.slot(slot_in_epoch),
        data_index: 0,
        data_beacon_block_root: head,
        data_source_epoch: EPOCH - 1,
        data_source_root: epoch.source_root,
        data_target_epoch: EPOCH,
        data_target_root: epoch.target_root,
        signature: BlsSignature(epoch.sign(signers, &epoch.signing_root(slot_in_epoch, head))),
        attesting_validators: if named {
            signers.iter().map(|&i| epoch.opened(i)).collect()
        } else {
            Vec::new()
        },
    }
}

/// One slot voting `head`, with `minority` voting `minority_head` instead.
fn slot_voting(
    epoch: &Epoch,
    slot_in_epoch: u64,
    head: [u8; 32],
    minority: &[u64],
    minority_head: [u8; 32],
) -> SlotComplementWitness {
    let members = &epoch.committees.members[slot_in_epoch as usize];
    let majority: Vec<u64> = members
        .iter()
        .copied()
        .filter(|i| !minority.contains(i))
        .collect();

    SlotComplementWitness {
        slot_in_epoch,
        committee: epoch.committees.aggregate(slot_in_epoch).unwrap().clone(),
        primary: vec![attestation(epoch, slot_in_epoch, head, &majority, false)],
        secondary: if minority.is_empty() {
            Vec::new()
        } else {
            vec![attestation(
                epoch,
                slot_in_epoch,
                minority_head,
                minority,
                true,
            )]
        },
        absentees: Vec::new(),
    }
}

/// A batch over `slots`, with the openings an honest host would have built.
fn batch(epoch: &Epoch, slots: Vec<FcrSlotWitness>) -> FcrBatchWitness {
    let mut named: Vec<u64> = slots
        .iter()
        .flat_map(|s| {
            s.complement
                .absentees
                .iter()
                .map(|v| v.validator_index)
                .chain(
                    s.complement
                        .secondary
                        .iter()
                        .flat_map(|a| a.attesting_validators.iter().map(|v| v.validator_index)),
                )
        })
        .collect();
    named.sort_unstable();

    FcrBatchWitness {
        accumulator_commitment: epoch.accumulator_commitment,
        acc_root: epoch.acc_root,
        total_active_balance: epoch.total_active_balance,
        committee_root: epoch.committees.root(),
        acc_multi_proof: epoch.tree.build_multi_proof(&named),
        committee_multi_proof: epoch.committees.multi_proof(
            &slots
                .iter()
                .map(|s| s.complement.slot_in_epoch)
                .collect::<Vec<_>>(),
        ),
        signing_domain: epoch.signing_domain,
        parent_head_root: PARENT_HEAD,
        parent_head_slot: epoch.slot(0) - 1,
        slots,
    }
}

/// The canonical three-slot chain: every slot proposes, every committee votes
/// for the block of its own slot.
fn three_slot_chain(epoch: &Epoch) -> (Vec<FcrSlotWitness>, [u8; 32]) {
    let mut parent = PARENT_HEAD;
    let mut slots = Vec::new();
    for slot_in_epoch in 0..3u64 {
        let h = header(epoch, slot_in_epoch, parent);
        parent = root_of(&h);
        slots.push(FcrSlotWitness {
            complement: slot_voting(epoch, slot_in_epoch, parent, &[], [0; 32]),
            head_header: Some(h),
        });
    }
    (slots, parent)
}

fn verify(w: &FcrBatchWitness) -> FcrBatchOutput {
    verify_fcr_batch_with_depth(w, ACC_DEPTH)
}

fn rejection(what: &str, f: impl FnOnce() + std::panic::UnwindSafe) -> String {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(f);
    std::panic::set_hook(previous);
    let payload = result.err().unwrap_or_else(|| panic!("{what}"));
    match payload.downcast::<String>() {
        Ok(message) => *message,
        Err(payload) => payload
            .downcast::<&'static str>()
            .map(|m| m.to_string())
            .unwrap_or_default(),
    }
}

// ---------------------------------------------------------------------------

/// Three slots under one proof: the whole committee of each votes for its own
/// block, so support is three committees and the batch ends on the third block.
#[test]
fn a_batch_counts_every_slot_that_voted_its_own_head() {
    let epoch = fixture();
    let (slots, expected_head) = three_slot_chain(&epoch);
    let out = verify(&batch(&epoch, slots));

    assert_eq!(out.support, 3 * PER_SLOT as u64 * BALANCE_GWEI);
    assert_eq!(out.head_root, expected_head);
    assert_eq!(out.head_slot, epoch.slot(2));
    assert_eq!(out.first_slot, epoch.slot(0));
    assert_eq!(out.slot_count, 3);
    assert_eq!(out.total_active_balance, epoch.total_active_balance);
    assert_eq!(out.parent_head_root, PARENT_HEAD);
}

/// A minority head vote is not support. Its signers are opened and subtracted
/// from the derived key exactly as the FFG path does — but where justification
/// still counts their balance, because they did attest the target, this must
/// not, because they attested a different block.
#[test]
fn a_minority_head_vote_is_dropped_not_counted() {
    let epoch = fixture();
    let (mut slots, _) = three_slot_chain(&epoch);
    let defector = epoch.committees.members[1][0];
    let canonical = slots[1].complement.primary[0].data_beacon_block_root;
    slots[1].complement = slot_voting(&epoch, 1, canonical, &[defector], [0x33; 32]);

    let out = verify(&batch(&epoch, slots));
    assert_eq!(
        out.support,
        3 * PER_SLOT as u64 * BALANCE_GWEI - BALANCE_GWEI
    );
}

/// A whole slot voting for something that is not its canonical block
/// contributes nothing. The signatures are still checked and the committee is
/// still bound; only the weight is not claimed.
#[test]
fn a_slot_that_votes_a_stale_head_contributes_nothing() {
    let epoch = fixture();
    let (mut slots, expected_head) = three_slot_chain(&epoch);
    slots[1].complement = slot_voting(&epoch, 1, [0x44; 32], &[], [0; 32]);

    let out = verify(&batch(&epoch, slots));
    assert_eq!(out.support, 2 * PER_SLOT as u64 * BALANCE_GWEI);
    assert_eq!(out.head_root, expected_head, "the chain is unaffected");
}

/// A skipped slot proposes nothing and leaves the head where it was, so its
/// committee's votes for the previous block still count.
#[test]
fn a_skipped_slot_still_votes_for_the_head_it_inherited() {
    let epoch = fixture();
    let first = header(&epoch, 0, PARENT_HEAD);
    let head = root_of(&first);
    let slots = vec![
        FcrSlotWitness {
            complement: slot_voting(&epoch, 0, head, &[], [0; 32]),
            head_header: Some(first),
        },
        FcrSlotWitness {
            complement: slot_voting(&epoch, 1, head, &[], [0; 32]),
            head_header: None,
        },
    ];

    let out = verify(&batch(&epoch, slots));
    assert_eq!(out.support, 2 * PER_SLOT as u64 * BALANCE_GWEI);
    assert_eq!(
        out.head_slot,
        epoch.slot(0),
        "no block was proposed at slot 1"
    );
}

/// A block that does not extend what the batch inherited is refused outright.
/// Without this a prover could publish a chain of its own and call it support.
#[test]
fn a_block_that_forks_off_the_inherited_head_is_refused() {
    let epoch = fixture();
    let (mut slots, _) = three_slot_chain(&epoch);
    let forged = header(&epoch, 0, [0x99; 32]);
    let head = root_of(&forged);
    slots[0] = FcrSlotWitness {
        complement: slot_voting(&epoch, 0, head, &[], [0; 32]),
        head_header: Some(forged),
    };
    let w = batch(&epoch, slots);

    let message = rejection("a forked chain verified", || {
        verify(&w);
    });
    assert!(message.contains("does not extend"), "{message}");
}

/// The committee bucket and the message it is paired against must name one
/// slot, or a committee's weight could be moved into a window that needs it.
#[test]
fn a_committee_cannot_be_paired_against_another_slots_message() {
    let epoch = fixture();
    let (slots, _) = three_slot_chain(&epoch);
    let mut w = batch(&epoch, slots);
    w.slots[1].complement.primary[0].data_slot = epoch.slot(2);

    let message = rejection("a relocated committee verified", || {
        verify(&w);
    });
    assert!(
        message.contains("is paired against a message for slot"),
        "{message}",
    );
}

/// Every slot in a batch binds one committee root. Two committee proofs of an
/// epoch are two partitions, and the disjointness argument is about one.
#[test]
fn the_batch_publishes_the_committee_root_it_opened() {
    let epoch = fixture();
    let (slots, _) = three_slot_chain(&epoch);
    assert_eq!(
        verify(&batch(&epoch, slots)).committee_root,
        epoch.committees.root()
    );
}

/// The public outputs fit, and that is not a given: the reason a batch reports
/// one sum rather than a scalar per slot is that per-slot reporting would cap
/// the batch at four before the cost curve stops paying.
#[test]
fn the_public_outputs_fit_the_proof() {
    let epoch = fixture();
    let (slots, _) = three_slot_chain(&epoch);
    let bytes = verify(&batch(&epoch, slots)).public_bytes();
    assert_eq!(bytes.len(), 168);
    assert!(bytes.len() <= zkasper_common::recursion::MAX_PUBLIC_BYTES);
}

/// `committee::MAX_SLOTS` still bounds the mask.
#[test]
fn a_slot_past_the_committee_tree_is_refused() {
    let epoch = fixture();
    let (slots, _) = three_slot_chain(&epoch);
    let mut w = batch(&epoch, slots);
    w.slots.truncate(1);
    w.slots[0].complement.slot_in_epoch = committee::MAX_SLOTS;

    let message = rejection("a slot past the tree verified", || {
        verify(&w);
    });
    assert!(message.contains("is past the"), "{message}");
}

/// A batch covers a contiguous run, and this is a soundness rule rather than a
/// tidiness one. The threshold is `0.5*M(k) + ...` with `M(k)` linear in `k`, so
/// dropping a slot lowers the bar by half a committee. A prover that omitted
/// every slot whose counted support fell below that — a slot the chain mostly
/// voted a different head at, which by the drop rule contributes nothing anyway
/// — would buy threshold slack for free.
#[test]
fn a_batch_cannot_omit_a_slot_that_carried_little_support() {
    let epoch = fixture();
    let (mut slots, _) = three_slot_chain(&epoch);
    // Slot 1 votes a stale head, so it already contributes nothing. Dropping it
    // costs the prover no support at all — and must still be refused.
    slots.remove(1);
    let w = batch(&epoch, slots);

    let message = rejection("a batch with a hole verified", || {
        verify(&w);
    });
    assert!(message.contains("contiguous run of slots"), "{message}");
}

/// The verifier can evaluate the specification's threshold from the publics
/// alone, with the specification's own code. It could not
/// before: `accumulator_commitment` is `poseidon(acc_root, total_active_balance)`
/// and a consumer that tracks only the finality chain's commitments holds the
/// hash, not the balance, so it had no `T` to put in `M(k) = (T / 32) * k`.
#[test]
fn the_publics_are_enough_to_evaluate_a_threshold() {
    let epoch = fixture();
    let (slots, _) = three_slot_chain(&epoch);
    let out = verify(&batch(&epoch, slots));

    assert_eq!(out.slot_count, 3);
    // The specification's own arithmetic, not a restatement of it.
    let maximum_support = fast_confirmation_core::estimate_committee_weight_between_slots(
        out.total_active_balance,
        out.first_slot,
        out.first_slot + out.slot_count - 1,
        SLOTS,
    )
    .unwrap();
    let threshold = fast_confirmation_core::safety_threshold(maximum_support, 0, 0, 0).unwrap();
    assert!(
        fast_confirmation_core::is_one_confirmed(false, out.support, threshold),
        "support {} against spec threshold {threshold}",
        out.support,
    );
}

// ---------------------------------------------------------------------------
// End to end: proofs in, a confirmation out, under the specification's own rule
// ---------------------------------------------------------------------------

/// Two batches, joined and judged.
///
/// This is the whole FCR path that exists today: the circuit publishes facts,
/// `zkasper-fcr-verifier` joins them into a window, and the threshold comes from
/// `fast_confirmation_core` — Lighthouse's own implementation, extracted to a
/// `no_std` crate. **No arithmetic in this repository decides the verdict.**
#[test]
fn two_batches_join_and_are_judged_by_lighthouses_own_rule() {
    use zkasper_fcr_verifier::{accumulate, is_confirmed, safety_threshold, Assignment, Params};

    let epoch = fixture();

    // Slots 0-1 under one proof, slots 2-3 under the next.
    let mut parent = PARENT_HEAD;
    let mut outputs = Vec::new();
    for chunk in [0..2u64, 2..4] {
        let mut slots = Vec::new();
        let first_parent = parent;
        for slot_in_epoch in chunk {
            let h = header(&epoch, slot_in_epoch, parent);
            parent = root_of(&h);
            slots.push(FcrSlotWitness {
                complement: slot_voting(&epoch, slot_in_epoch, parent, &[], [0; 32]),
                head_header: Some(h),
            });
        }
        let mut w = batch(&epoch, slots);
        w.parent_head_root = first_parent;
        w.parent_head_slot = epoch.slot(0) - 1;
        outputs.push(verify(&w));
    }

    let window = accumulate(&outputs).expect("the batches join");
    assert_eq!(window.first_slot, epoch.slot(0));
    assert_eq!(window.slot_count(), 4);
    assert_eq!(window.head_root, outputs[1].head_root);
    assert_eq!(
        window.support,
        4 * PER_SLOT as u64 * BALANCE_GWEI,
        "four full committees",
    );

    // The fixture's four validators are the whole set, so a window covering
    // every slot they are assigned to clears the specification's bar.
    let params = Params {
        slots_per_epoch: SLOTS,
        ..Params::default()
    };
    let parent_slot = epoch.slot(0) - 1;
    let current_slot = epoch.slot(4);
    let threshold = safety_threshold(&window, parent_slot, current_slot, &params).unwrap();

    // The fixture's committee root is a partition, not a proven assignment, and
    // the verifier refuses to confirm against one — which is the whole point of
    // the gate. `proven` is what the FCR-side committee guest will hand over
    // once it exists; nothing else in the judgement changes.
    assert_eq!(
        is_confirmed(
            &window,
            &Assignment::unproven(window.committee_root),
            parent_slot,
            current_slot,
            &params
        ),
        Err(zkasper_fcr_verifier::Error::AssignmentNotProven),
    );
    assert!(
        is_confirmed(
            &window,
            &Assignment::proven(window.committee_root),
            parent_slot,
            current_slot,
            &params
        )
        .unwrap(),
        "support {} against threshold {threshold}",
        window.support,
    );
}

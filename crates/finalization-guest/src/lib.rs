extern crate alloc;

use zkasper_common::types::{FinalizationOutput, FinalizationWitness};

/// Verify a finalization: two consecutive justification proofs, plus the epoch
/// diff that links the accumulators they were proved against.
pub fn verify_finalization(witness: &FinalizationWitness) -> FinalizationOutput {
    use zkasper_common::recursion::verify_child;

    assert_eq!(
        witness.justification_outputs.len(),
        2,
        "finalization requires exactly 2 justification outputs",
    );

    let just_e = &witness.justification_outputs[0];
    let just_e1 = &witness.justification_outputs[1];

    // Verify both justification proofs, bound to program and outputs.
    for (i, (proof, output)) in witness
        .justification_proofs
        .iter()
        .zip(witness.justification_outputs.iter())
        .enumerate()
    {
        assert!(
            verify_child(
                proof,
                &witness.justification_program_vk,
                &output.public_bytes()
            ),
            "justification proof {} failed recursive verification",
            i,
        );
    }

    // Epochs must be consecutive: E and E+1
    assert_eq!(
        just_e1.target_epoch,
        just_e.target_epoch + 1,
        "justification epochs not consecutive: {} and {}",
        just_e.target_epoch,
        just_e1.target_epoch,
    );

    // Relate the two accumulators with an epoch-diff proof.
    //
    // The accumulator leaf commits an *effective balance*, which the beacon
    // chain rewrites at every epoch transition, so the two justifications of a
    // finalizing pair are proved against different accumulators on any live
    // chain. Requiring them to be equal — as this circuit used to — is only
    // satisfiable when nothing moved, which is to say never.
    //
    // Verifying the diff that carries E's accumulator to E+1's is what makes
    // the pair meaningful. Without it a prover could pair a justification of E
    // against the real validator set with a justification of E+1 against a
    // fabricated one, and the output would look identical to an honest
    // finalization. With it, the two commitments are the endpoints of a single
    // proven registry transition.
    let diff = &witness.epoch_diff_output;
    assert!(
        verify_child(
            &witness.epoch_diff_proof,
            &witness.epoch_diff_program_vk,
            &diff.public_bytes(),
        ),
        "epoch diff proof failed recursive verification",
    );
    assert_eq!(
        diff.prev_accumulator_commitment, just_e.accumulator_commitment,
        "epoch diff does not start from the accumulator epoch E was justified against",
    );
    assert_eq!(
        diff.accumulator_commitment, just_e1.accumulator_commitment,
        "epoch diff does not end at the accumulator epoch E+1 was justified against",
    );

    // The diff's own epoch labels have to be the two epochs being paired.
    //
    // Those labels decide which validators the diff treats as active, so a
    // prover who mislabels them gets a different accumulator. They are pinned
    // here to the target epochs of the two justifications — and a target epoch
    // is signed over by every attester, so it is not something a prover picks.
    assert_eq!(
        diff.epoch_1, just_e.target_epoch,
        "epoch diff starts at epoch {} but epoch {} was justified",
        diff.epoch_1, just_e.target_epoch,
    );
    assert_eq!(
        diff.epoch_2, just_e1.target_epoch,
        "epoch diff ends at epoch {} but epoch {} was justified",
        diff.epoch_2, just_e1.target_epoch,
    );

    // Open the finalized block's header to recover its beacon state root.
    //
    // This is what anchors the accumulator chain. epoch-diff proves a registry
    // delta between two claimed state roots but never proves the second is the
    // canonical successor of the first, so a prover can branch the accumulator
    // onto a fabricated validator set. Publishing the state root of a block that
    // 2/3 of the real validator set attested to lets a consumer reject any
    // branch: an attacker would need a real supermajority to name their
    // fabricated state, which is the assumption the whole system already rests
    // on.
    let h = &witness.finalized_header;
    assert_eq!(
        zkasper_common::ssz::block_header_root(
            h.slot,
            h.proposer_index,
            &h.parent_root,
            &h.state_root,
            &h.body_root,
        ),
        just_e.target_root,
        "finalized header does not hash to the finalized root",
    );

    // ...and that state root must be the one the accumulator entered epoch E
    // with.
    //
    // `diff.state_root_1` is the state E's accumulator was built from, which —
    // because diffs chain end to start — is the same value the diff that
    // advanced *into* E published as its `state_root_2`. Pinning it to the
    // finalized header's state root is what makes the anchoring rule checkable
    // by a client: the state root a finalization names for epoch E is exactly
    // the one the accumulator chain passed through at E, so the two can be
    // compared without a third source.
    //
    // It also costs something, and the cost is worth stating. The two agree
    // only when the epoch's first slot holds a block, because that block's
    // post-state *is* the epoch-boundary state. When the slot is empty the
    // checkpoint root is an earlier block whose state root predates the epoch
    // transition, and this assertion rejects the pair. Failing to prove such an
    // epoch is the correct outcome: the alternative is a proof whose state root
    // names a different state than the accumulator used, which fails at every
    // consumer instead, silently and later.
    assert_eq!(
        diff.state_root_1, h.state_root,
        "epoch {}'s accumulator was built from a different state than the finalized block produced",
        just_e.target_epoch,
    );

    // Finalized epoch is E, root is E's target root
    FinalizationOutput {
        accumulator_commitment: just_e.accumulator_commitment,
        next_accumulator_commitment: just_e1.accumulator_commitment,
        finalized_epoch: just_e.target_epoch,
        finalized_root: just_e.target_root,
        finalized_state_root: h.state_root,
    }
}

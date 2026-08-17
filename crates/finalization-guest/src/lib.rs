extern crate alloc;

use zkasper_common::types::{FinalizationOutput, FinalizationWitness};

/// Verify a finalization: two consecutive justification proofs.
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

    // Both justifications must use the same accumulator commitment
    assert_eq!(
        just_e.accumulator_commitment, witness.accumulator_commitment,
        "justification 0 accumulator mismatch",
    );
    assert_eq!(
        just_e1.accumulator_commitment, witness.accumulator_commitment,
        "justification 1 accumulator mismatch",
    );

    // Epochs must be consecutive: E and E+1
    assert_eq!(
        just_e1.target_epoch,
        just_e.target_epoch + 1,
        "justification epochs not consecutive: {} and {}",
        just_e.target_epoch,
        just_e1.target_epoch,
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

    // Finalized epoch is E, root is E's target root
    FinalizationOutput {
        accumulator_commitment: witness.accumulator_commitment,
        finalized_epoch: just_e.target_epoch,
        finalized_root: just_e.target_root,
        finalized_state_root: h.state_root,
    }
}

//! The streaming pipeline, end to end, with real BLS signatures.
//!
//! Sixteen validators in eight committees of two, a tree depth of 4. Small
//! enough to run in a second and shaped exactly like a mainnet epoch: a
//! committee proof that sums every slot's committee out of the accumulator,
//! group proofs that never finish a pairing, a running aggregate that folds
//! them, and one final proof that does the marginal slot inline and settles
//! every signature in the epoch with a single final exponentiation.

mod common;

use common::{
    stream_fixture, StreamFixture as Fixture, STREAM_BALANCE_GWEI as BALANCE_GWEI,
    STREAM_EPOCH as EPOCH,
};

use zkasper_common::types::*;
use zkasper_witness_gen::attestation_collector::SlotComplement;
use zkasper_witness_gen::streaming::{self, StreamPolicy};

/// Small enough to run in a second. A guest ELF is compiled against the
/// production depth instead; see `zisk_proof_tests`.
const ACC_DEPTH: u32 = 4;

fn fixture() -> Fixture {
    stream_fixture(ACC_DEPTH)
}

/// Run `f` and return the message it panicked with.
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

fn run(fixture: &Fixture, plan: &streaming::StreamPlan) -> streaming::StreamRun {
    streaming::run_native(
        &fixture.context,
        &fixture.epoch.tree,
        &fixture.epoch.committees,
        &fixture.units,
        plan,
        fixture.previous.clone(),
        fixture.finalized_header.clone(),
    )
}

// ---------------------------------------------------------------------------

/// The whole pipeline, and what it publishes.
#[test]
fn streaming_pipeline_justifies_and_finalizes() {
    let fixture = fixture();
    let policy = StreamPolicy::default();
    let plan = streaming::plan(
        &fixture.units,
        fixture.context.total_active_balance,
        &policy,
    );

    assert!(plan.threshold_reached);
    // 70% of 16 validators is 11.2, so the 6th committee — the 12th validator —
    // is the one that crosses, and nothing after it is proven at all.
    assert_eq!(plan.tail, vec![5]);
    assert!(plan.groups.concat().iter().all(|&i| i < 5));

    let run = run(&fixture, &plan);

    assert_eq!(run.final_output.justified_epoch, EPOCH);
    assert_eq!(run.final_output.justified_root, fixture.context.target_root);
    assert_eq!(run.final_output.finalized_epoch, EPOCH - 1);
    assert_eq!(
        run.final_output.finalized_state_root,
        fixture.finalized_header.state_root,
    );
    // Both endpoints are published, and they are the epoch diff's — the registry
    // moves between epochs, so a consumer has to be able to check each against
    // the accumulator chain it follows.
    assert_eq!(
        run.final_output.next_accumulator_commitment,
        fixture.context.accumulator_commitment,
    );
    assert_eq!(
        run.final_output.accumulator_commitment,
        fixture.previous.accumulator_commitment(),
    );

    // Five committees of two, folded before the tail crossed the threshold.
    let aggregate = run.aggregate_outputs.last().unwrap();
    assert_eq!(aggregate.slots_mask, 0b11111);
    assert_eq!(aggregate.attesting_balance, 10 * BALANCE_GWEI);
}

/// The point of the whole design: a group proof succeeds without proving
/// anything about its signatures, and the epoch's single final exponentiation is
/// what catches a bad one.
#[test]
fn a_bad_signature_survives_its_group_proof_and_fails_the_final_one() {
    let mut fixture = fixture();

    // Re-sign slot 0's primary aggregate with the wrong key. Everything else
    // about it is untouched: the committee, its balance, its absentees.
    fixture.units[0].witness.primary[0].signature = BlsSignature(
        fixture
            .epoch
            .sign(&[15], &fixture.epoch.signing_root(0, [0u8; 32])),
    );

    let plan = streaming::plan(
        &fixture.units,
        fixture.context.total_active_balance,
        &StreamPolicy::default(),
    );

    // The group proof accepts it. It only ever claimed committee membership and
    // balances.
    let members: Vec<&SlotComplement> = plan.groups[0].iter().map(|&i| &fixture.units[i]).collect();
    let witness = streaming::group_witness(
        &fixture.context,
        &fixture.epoch.tree,
        &fixture.epoch.committees,
        &members,
    );
    let group = zkasper_slot_proof_guest::verify_group_proof_with_depth(&witness, ACC_DEPTH);
    assert_eq!(group.target_epoch, EPOCH);

    // The final proof does not.
    let message = rejection("a forged signature was accepted", || {
        run(&fixture, &plan);
    });
    assert!(
        message.contains("BLS aggregate signature verification failed"),
        "unexpected failure: {message}",
    );
}

/// A group's balance cannot be counted without its pairings: the two travel
/// together or the commitment check rejects them.
#[test]
fn a_groups_balance_cannot_be_counted_without_its_pairings() {
    let fixture = fixture();
    let plan = streaming::plan(
        &fixture.units,
        fixture.context.total_active_balance,
        &StreamPolicy::default(),
    );
    let run = run(&fixture, &plan);

    // Swap in the identity for the aggregate's Miller accumulator — the value a
    // prover would want if it hoped to count balances whose signatures it does
    // not have.
    let mut forged = run.final_witness.clone();
    forged.aggregate_miller = MillerAccumulator::default();

    let message = rejection("an unbacked Miller accumulator was accepted", || {
        zkasper_stream_final_guest::verify_stream_final_with_depth(&forged, ACC_DEPTH);
    });
    assert!(
        message.contains("Miller accumulator does not match its commitment"),
        "unexpected failure: {message}",
    );

    // And the untouched witness still verifies, so the rejection was about the
    // substitution and nothing else.
    zkasper_stream_final_guest::verify_stream_final_with_depth(&run.final_witness, ACC_DEPTH);
}

/// Counting a slot twice is counting its whole committee twice, because the
/// committee proof gave every validator exactly one slot. The fold that adds the
/// second one is where that stops.
#[test]
fn a_slot_cannot_be_counted_by_two_groups() {
    let fixture = fixture();

    let first: Vec<&SlotComplement> = vec![&fixture.units[0]];
    let witness = streaming::group_witness(
        &fixture.context,
        &fixture.epoch.tree,
        &fixture.epoch.committees,
        &first,
    );
    let attested = zkasper_slot_proof_guest::attest(&witness, ACC_DEPTH);
    let output = zkasper_slot_proof_guest::verify_group_proof_with_depth(&witness, ACC_DEPTH);

    let fold = streaming::aggregate_witness(
        &fixture.context,
        None,
        Vec::new(),
        zkasper_common::bls::FP12_ONE,
        vec![output.clone()],
        vec![Vec::new()],
        vec![attested.miller],
    );
    let aggregate = zkasper_aggregation_guest::verify_aggregate(&fold);
    assert_eq!(aggregate.slots_mask, 1);

    // Fold the very same group again. Its own proof is still valid; what is not
    // valid is counting that committee a second time.
    let again = streaming::aggregate_witness(
        &fixture.context,
        Some(aggregate),
        Vec::new(),
        attested.miller,
        vec![output],
        vec![Vec::new()],
        vec![attested.miller],
    );

    let message = rejection("a slot was counted twice", || {
        zkasper_aggregation_guest::verify_aggregate(&again);
    });
    assert!(
        message.contains("already counted"),
        "unexpected failure: {message}",
    );
}

/// The critical path is one proof deep, and it holds one slot.
///
/// This is the claim the whole design rests on, so it is asserted rather than
/// left to the benchmark script: whatever the epoch's size, what runs after the
/// last attestation is a single proof over a single committee's complement.
#[test]
fn only_one_proof_and_one_slot_sit_after_the_last_attestation() {
    let fixture = fixture();
    let plan = streaming::plan(
        &fixture.units,
        fixture.context.total_active_balance,
        &StreamPolicy::default(),
    );
    let run = run(&fixture, &plan);

    assert_eq!(run.final_witness.tail.len(), 1);
    // Nothing but the running aggregate is left to verify: every group was
    // already folded, so the final proof does one recursion for the epoch, one
    // for the previous epoch's justification, and no more.
    assert!(run.final_witness.groups.is_empty());
    assert!(run.final_witness.aggregate.is_some());
}

/// The proof chain has to hold together: an aggregate built against one
/// checkpoint cannot be spent on another.
#[test]
fn an_aggregate_from_another_checkpoint_is_rejected() {
    let fixture = fixture();
    let plan = streaming::plan(
        &fixture.units,
        fixture.context.total_active_balance,
        &StreamPolicy::default(),
    );
    let run = run(&fixture, &plan);

    let mut forged = run.final_witness.clone();
    forged.aggregate.as_mut().unwrap().target_root = [0xEE; 32];

    rejection("a foreign aggregate was accepted", || {
        zkasper_stream_final_guest::verify_stream_final_with_depth(&forged, ACC_DEPTH);
    });
}

/// Group proofs are independent of each other, so they can be proven in any
/// order or in parallel; only the folds are sequential.
#[test]
fn group_proofs_do_not_depend_on_each_other() {
    let fixture = fixture();
    let plan = streaming::plan(
        &fixture.units,
        fixture.context.total_active_balance,
        &StreamPolicy::default(),
    );

    let prove = |group: &Vec<usize>| {
        let members: Vec<&SlotComplement> = group.iter().map(|&i| &fixture.units[i]).collect();
        zkasper_slot_proof_guest::verify_group_proof_with_depth(
            &streaming::group_witness(
                &fixture.context,
                &fixture.epoch.tree,
                &fixture.epoch.committees,
                &members,
            ),
            ACC_DEPTH,
        )
    };

    let outputs: Vec<GroupProofOutput> = plan.groups.iter().map(prove).collect();
    let reversed: Vec<GroupProofOutput> = plan.groups.iter().rev().map(prove).collect();

    assert_eq!(
        outputs,
        reversed.into_iter().rev().collect::<Vec<_>>(),
        "a group proof depended on when it was run",
    );
}

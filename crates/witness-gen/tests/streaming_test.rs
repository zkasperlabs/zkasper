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
use zkasper_witness_gen::streaming::{self, Stage, StreamPolicy};

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

/// The same plan with every group folded rather than handed to the final proof.
///
/// A fold is a whole per-proof floor and buys nothing the final proof cannot do
/// itself, so the scheduler only ever emits one when it has time to spare — and
/// an eight-slot fixture does not. The tests that are about what a fold *binds*
/// need one anyway.
fn folded(plan: &streaming::StreamPlan) -> streaming::StreamPlan {
    streaming::StreamPlan {
        folds: (0..plan.groups.len()).map(|g| vec![g]).collect(),
        absorbed: Vec::new(),
        ..plan.clone()
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
        fixture.epoch.boundary.clone(),
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

    let run = run(&fixture, &folded(&plan));

    assert_eq!(run.final_output.justified_epoch, EPOCH);
    assert_eq!(run.final_output.justified_root, fixture.context.target_root);
    assert_eq!(run.final_output.finalized_epoch, EPOCH - 1);
    assert_eq!(
        run.final_output.finalized_state_root,
        fixture.epoch.previous_state_root,
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

/// An epoch whose first slot is empty finalizes like any other.
///
/// Its checkpoint is then the last block *before* the boundary, and the state
/// the accumulator was built from is what the empty slots advanced that block's
/// post-state to — a state no header names. Reading the anchor off the finalized
/// header, which is what this proof used to do, cannot see it at all: the two
/// values differ, and the epoch was rejected. Opening both out of the justified
/// checkpoint's ring buffers is what makes them separable.
#[test]
fn an_empty_first_slot_still_finalizes() {
    let fixture = common::stream_fixture_empty_boundary(ACC_DEPTH);
    let plan = streaming::plan(
        &fixture.units,
        fixture.context.total_active_balance,
        &StreamPolicy::default(),
    );
    let run = run(&fixture, &folded(&plan));

    assert_eq!(run.final_output.finalized_epoch, EPOCH - 1);
    assert_eq!(run.final_output.finalized_root, fixture.epoch.previous_root);

    // The anchor is the boundary state, not the checkpoint block's own, and the
    // two are genuinely different values here.
    assert_eq!(
        run.final_output.finalized_state_root,
        fixture.epoch.previous_state_root,
    );
    assert_ne!(
        fixture.epoch.previous_state_root,
        common::stream_fixture(ACC_DEPTH).epoch.previous_state_root,
    );
}

/// The anchor has to be the boundary the justified chain recorded, not one the
/// prover picked.
#[test]
fn an_accumulator_built_off_another_state_is_rejected() {
    let fixture = common::stream_fixture_empty_boundary(ACC_DEPTH);
    let plan = streaming::plan(
        &fixture.units,
        fixture.context.total_active_balance,
        &StreamPolicy::default(),
    );

    // Anchor the epoch on the checkpoint block's own state root — the value the
    // proof used to take, and the wrong one whenever the boundary is empty.
    let mut forged = fixture;
    forged.context.epoch_diff.state_root_1 = [0xAB; 32];

    let message = rejection("an accumulator off another state was accepted", || {
        run(&forged, &folded(&plan));
    });
    assert!(
        message.contains("built from a different state than the boundary"),
        "unexpected failure: {message}",
    );
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
    let run = run(&fixture, &folded(&plan));

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
/// last attestation is a single proof over a single committee's complement, and
/// the schedule puts nothing else there.
#[test]
fn only_one_proof_and_one_slot_sit_after_the_last_attestation() {
    let fixture = fixture();
    let schedule = streaming::schedule(
        &fixture.units,
        fixture.context.total_active_balance,
        &StreamPolicy::default(),
    );
    let run = run(&fixture, &schedule.plan);

    assert_eq!(run.final_witness.tail.len(), 1);

    let last = fixture.units[*schedule.plan.tail.last().unwrap()].slot;
    let arrival = (last - fixture.units[0].slot) as f64 * 12.0;
    let after: Vec<Stage> = schedule
        .proofs
        .iter()
        .filter(|p| p.start_s >= arrival)
        .map(|p| p.stage)
        .collect();
    assert_eq!(after, vec![Stage::Final, Stage::Wrap]);
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
    let run = run(&fixture, &folded(&plan));

    let mut forged = run.final_witness.clone();
    forged.aggregate.as_mut().unwrap().target_root = [0xEE; 32];

    rejection("a foreign aggregate was accepted", || {
        zkasper_stream_final_guest::verify_stream_final_with_depth(&forged, ACC_DEPTH);
    });
}

/// The first epoch of a run is justified by a chain of batch folds, and the
/// partial links of that chain are valid proofs of a partial count. The final
/// proof has to read the flag rather than take the proof's existence for the
/// claim, or a run would finalize an epoch a third of the stake voted for.
#[test]
fn a_partial_batch_justification_is_rejected() {
    let fixture = fixture();
    let plan = streaming::plan(
        &fixture.units,
        fixture.context.total_active_balance,
        &StreamPolicy::default(),
    );
    let run = run(&fixture, &folded(&plan));

    let mut forged = run.final_witness.clone();
    match &mut forged.previous_justification {
        PreviousJustification::Batch(output) => output.justified = false,
        PreviousJustification::Stream(_) => panic!("the fixture justifies with a batch fold"),
    }

    assert!(rejection("a partial justification was accepted", || {
        zkasper_stream_final_guest::verify_stream_final_with_depth(&forged, ACC_DEPTH);
    })
    .contains("partial fold"));
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

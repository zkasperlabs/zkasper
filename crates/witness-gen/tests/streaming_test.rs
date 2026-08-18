//! The streaming pipeline, end to end, with real BLS signatures.
//!
//! Sixteen validators, one aggregate per slot, a tree depth of 4. Small enough
//! to run in a second and shaped exactly like a mainnet epoch: group proofs that
//! never finish a pairing, a running aggregate that folds them, and one final
//! proof that does the marginal attestation inline and settles every signature
//! in the epoch with a single final exponentiation.

mod common;

use common::{
    stream_fixture, stream_sign as sign, StreamFixture as Fixture,
    STREAM_BALANCE_GWEI as BALANCE_GWEI, STREAM_EPOCH as EPOCH,
};

use zkasper_common::bls::compute_signing_root;
use zkasper_common::ssz::attestation_data_root;
use zkasper_common::types::*;
use zkasper_witness_gen::streaming::{self, DedupTree, StreamPolicy, StreamUnit};

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
        &fixture.tree,
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
    // 70% of 16 validators is 11.2, so the 6th aggregate — the 12th validator —
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

    // Twelve validators of sixteen, which is the 2/3 the circuit demands.
    let aggregate = run.aggregate_outputs.last().unwrap();
    assert_eq!(aggregate.num_counted_validators, 10);
    assert_eq!(aggregate.attesting_balance, 10 * BALANCE_GWEI);
}

/// The point of the whole design: a group proof succeeds without proving
/// anything about its signatures, and the epoch's single final exponentiation is
/// what catches a bad one.
#[test]
fn a_bad_signature_survives_its_group_proof_and_fails_the_final_one() {
    let mut fixture = fixture();

    // Re-sign unit 0 with the wrong key. Everything else about it is untouched:
    // the attesters, their balances, their accumulator leaves.
    let data_root = attestation_data_root(
        0,
        0,
        &[0; 32],
        EPOCH - 1,
        &[0x01; 32],
        EPOCH,
        &fixture.context.target_root,
    );
    let signing_root = compute_signing_root(&data_root, &fixture.context.signing_domain);
    fixture.units[0].attestation.signature =
        BlsSignature(sign(&[&fixture.keys[15]], &signing_root));

    let plan = streaming::plan(
        &fixture.units,
        fixture.context.total_active_balance,
        &StreamPolicy::default(),
    );

    // The group proof accepts it. It only ever claimed membership and balances.
    let members: Vec<&StreamUnit> = plan.groups[0].iter().map(|&i| &fixture.units[i]).collect();
    let witness = streaming::group_witness(&fixture.context, &fixture.tree, &members);
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

/// Counting a validator in two different groups is what the counted-set tree
/// exists to stop, and it stops it at the fold that adds the second one.
#[test]
fn a_validator_cannot_be_counted_by_two_groups() {
    let fixture = fixture();
    let dedup_depth = fixture.context.dedup_depth();
    let mut dedup_tree = DedupTree::new(dedup_depth);

    let first: Vec<&StreamUnit> = vec![&fixture.units[0]];
    let witness = streaming::group_witness(&fixture.context, &fixture.tree, &first);
    let attested = zkasper_slot_proof_guest::attest(&witness, ACC_DEPTH);
    let output = zkasper_slot_proof_guest::verify_group_proof_with_depth(&witness, ACC_DEPTH);
    let counted = streaming::counted_indices(&first);

    let fold = streaming::aggregate_witness(
        &fixture.context,
        &mut dedup_tree,
        None,
        Vec::new(),
        zkasper_common::bls::FP12_ONE,
        vec![output.clone()],
        vec![Vec::new()],
        vec![attested.miller],
        vec![counted.clone()],
    );
    let aggregate = zkasper_aggregation_guest::verify_aggregate_with_depth(&fold, dedup_depth);

    // Fold the very same group again. Its own proof is still valid; what is not
    // valid is counting those validators a second time.
    let again = streaming::aggregate_witness(
        &fixture.context,
        &mut dedup_tree.clone(),
        Some(aggregate.clone()),
        Vec::new(),
        attested.miller,
        vec![output],
        vec![Vec::new()],
        vec![attested.miller],
        vec![counted],
    );

    let message = rejection("a validator was counted twice", || {
        zkasper_aggregation_guest::verify_aggregate_with_depth(&again, dedup_depth);
    });
    assert!(
        message.contains("counted twice"),
        "unexpected failure: {message}",
    );
}

/// The critical path is one proof deep, and it holds one unit.
///
/// This is the claim the whole design rests on, so it is asserted rather than
/// left to the benchmark script: whatever the epoch's size, what runs after the
/// last attestation is a single proof over a single aggregate.
#[test]
fn only_one_proof_and_one_unit_sit_after_the_last_attestation() {
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

    let outputs: Vec<GroupProofOutput> = plan
        .groups
        .iter()
        .map(|group| {
            let members: Vec<&StreamUnit> = group.iter().map(|&i| &fixture.units[i]).collect();
            let witness = streaming::group_witness(&fixture.context, &fixture.tree, &members);
            zkasper_slot_proof_guest::verify_group_proof_with_depth(&witness, ACC_DEPTH)
        })
        .collect();

    let reversed: Vec<GroupProofOutput> = plan
        .groups
        .iter()
        .rev()
        .map(|group| {
            let members: Vec<&StreamUnit> = group.iter().map(|&i| &fixture.units[i]).collect();
            let witness = streaming::group_witness(&fixture.context, &fixture.tree, &members);
            zkasper_slot_proof_guest::verify_group_proof_with_depth(&witness, ACC_DEPTH)
        })
        .collect();

    assert_eq!(
        outputs,
        reversed.into_iter().rev().collect::<Vec<_>>(),
        "a group proof depended on when it was run",
    );
}

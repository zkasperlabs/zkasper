mod common;

use common::{make_header, validator_data_to_response, MockBeaconApi};

use zkasper_common::ChainConfig;

const TEST_CONFIG: ChainConfig = ChainConfig {
    slots_per_epoch: 32,
    validators_tree_depth: 2,
    acc_tree_depth: 2,
    beacon_state_validators_field_index: 11,
    fulu_fork_epoch: 0,
};
/// Small tree depth for tests (2^2 = 4 leaves)
const TEST_DEPTH: u32 = 2;
use zkasper_common::acc;
use zkasper_common::test_utils::make_validator;
use zkasper_common::types::{
    CommitteeOutput, EpochDiffOutput, FinalizationWitness, JustificationOutput,
    JustificationWitness, SlotProofOutput, ValidatorData,
};

use zkasper_witness_gen::beacon_api::ValidatorResponse;
use zkasper_witness_gen::child_vks;
use zkasper_witness_gen::state_diff::{find_mutations, SlotHistory};

// -----------------------------------------------------------------------
// state_diff unit tests
// -----------------------------------------------------------------------

#[test]
fn test_find_mutations_balance_change() {
    let v0 = make_response(0, 32);
    let v1_old = make_response(1, 32);
    let v1_new = make_response(1, 16);
    let v2 = make_response(2, 32);

    let old = vec![v0.clone(), v1_old, v2.clone()];
    let new = vec![v0, v1_new, v2];

    let changed = find_mutations(&old, &new, 100, 100);
    assert_eq!(changed, vec![1]);
}

#[test]
fn test_find_mutations_new_validators() {
    let v0 = make_response(0, 32);
    let v1 = make_response(1, 32);
    let v2 = make_response(2, 32);

    let old = vec![v0.clone(), v1.clone()];
    let new = vec![v0, v1, v2];

    let changed = find_mutations(&old, &new, 100, 100);
    assert_eq!(changed, vec![2]);
}

#[test]
fn test_find_mutations_no_changes() {
    let v0 = make_response(0, 32);
    let v1 = make_response(1, 32);

    let old = vec![v0.clone(), v1.clone()];
    let new = vec![v0, v1];

    let changed = find_mutations(&old, &new, 100, 100);
    assert!(changed.is_empty());
}

#[test]
fn test_find_mutations_activation_change() {
    let v0 = make_response(0, 32);
    let mut v0_new = make_response(0, 32);
    v0_new.exit_epoch = 100; // validator exiting

    let old = vec![v0];
    let new = vec![v0_new];

    let changed = find_mutations(&old, &new, 100, 100);
    assert_eq!(changed, vec![0]);
}

#[test]
fn test_find_mutations_withdrawal_credentials_change() {
    // A switch-to-compounding request rewrites the first byte of the
    // credentials and nothing else. Mainnet epoch 469594 died on exactly this:
    // validator 1339600 went 0x01 to 0x02, no other field moved, and the
    // registry root the daemon carried forward stopped matching the chain's.
    let v0 = make_response(0, 32);
    let mut v0_new = make_response(0, 32);
    v0_new.withdrawal_credentials[0] = 0x02;

    let old = vec![v0];
    let new = vec![v0_new];

    let changed = find_mutations(&old, &new, 100, 100);
    assert_eq!(changed, vec![0]);
}

#[test]
fn test_credentials_change_keeps_registry_root_honest() {
    use zkasper_common::ssz::list_hash_tree_root;
    use zkasper_witness_gen::state_diff::{
        build_validator_roots, build_validators_ssz_tree, validator_response_to_field_leaves,
    };

    let old: Vec<ValidatorResponse> = (0..4).map(|i| make_response(i, 32)).collect();
    let mut new = old.clone();
    new[2].withdrawal_credentials[0] = 0x02;

    let registry_root = |vs: &[ValidatorResponse]| {
        let (data_root, _) =
            build_validators_ssz_tree(&build_validator_roots(vs), TEST_DEPTH, &[0]);
        list_hash_tree_root(&data_root, vs.len() as u64)
    };

    // What the daemon carries forward: the old roots, patched only where
    // find_mutations pointed. It has to land on the root a full recompute gives,
    // because the circuit checks that root against the beacon state's own.
    let mut roots = build_validator_roots(&old);
    for &i in &find_mutations(&old, &new, 100, 100) {
        roots[i as usize] = zkasper_common::ssz::validator_hash_tree_root(
            &validator_response_to_field_leaves(&new[i as usize]),
        );
    }
    let (data_root, _) = build_validators_ssz_tree(&roots, TEST_DEPTH, &[0]);

    assert_ne!(registry_root(&old), registry_root(&new));
    assert_eq!(
        list_hash_tree_root(&data_root, new.len() as u64),
        registry_root(&new),
    );
}

#[test]
fn test_find_mutations_epoch_boundary_activation() {
    // Validator activates at epoch 101 — no SSZ field changes between states
    let mut v = make_response(0, 32);
    v.activation_epoch = 101;
    v.exit_epoch = u64::MAX;

    let old = vec![v.clone()];
    let new = vec![v];

    // Same epoch: not detected
    let changed = find_mutations(&old, &new, 100, 100);
    assert!(changed.is_empty());

    // Spans activation: detected
    let changed = find_mutations(&old, &new, 100, 101);
    assert_eq!(changed, vec![0]);
}

#[test]
fn test_find_mutations_epoch_boundary_exit() {
    // Validator exits at epoch 101 — no SSZ field changes between states
    let mut v = make_response(0, 32);
    v.activation_epoch = 0;
    v.exit_epoch = 101;

    let old = vec![v.clone()];
    let new = vec![v];

    // Same epoch: not detected
    let changed = find_mutations(&old, &new, 100, 100);
    assert!(changed.is_empty());

    // Spans exit: detected
    let changed = find_mutations(&old, &new, 100, 101);
    assert_eq!(changed, vec![0]);
}

// -----------------------------------------------------------------------
// DB tests
// -----------------------------------------------------------------------

#[test]
fn test_db_save_and_load() {
    use zkasper_witness_gen::acc_tree::AccTree;
    use zkasper_witness_gen::db::Db;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let db = Db::new(&db_path);

    let validators: Vec<_> = (0..4).map(|i| make_validator(i, 32)).collect();
    let tree = AccTree::build(&validators, 100, 2);
    let expected_root = tree.root();

    db.save(&tree, 100, 128_000_000_000, 4).unwrap();

    let (loaded_tree, epoch, balance, count) = db.load().unwrap().expect("should load");
    assert_eq!(loaded_tree.root(), expected_root);
    assert_eq!(epoch, 100);
    assert_eq!(balance, 128_000_000_000);
    assert_eq!(count, 4);
}

#[test]
fn test_db_load_nonexistent() {
    use zkasper_witness_gen::db::Db;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("nonexistent.db");
    let db = Db::new(&db_path);

    assert!(db.load().unwrap().is_none());
}

// -----------------------------------------------------------------------
// Init point round-trip test
// -----------------------------------------------------------------------

/// Taking an init point and opening it again has to agree, because that is the
/// whole of what replaced the bootstrap proof: `open` recomputes the
/// accumulator from the registry and refuses anything that does not match.
#[tokio::test]
async fn test_init_point_round_trip() {
    let slot = 3200u64; // epoch 100
    let epoch = slot / TEST_CONFIG.slots_per_epoch;

    let validators: Vec<ValidatorData> = (0..4).map(|i| make_validator(i, 32)).collect();
    let responses: Vec<ValidatorResponse> = validators
        .iter()
        .enumerate()
        .map(|(i, v)| validator_data_to_response(v, i as u64))
        .collect();

    let mut mock = MockBeaconApi::new();
    let header = make_header(slot, &responses, TEST_DEPTH, &SlotHistory::default());
    mock.validators.insert(slot.to_string(), responses.clone());
    mock.headers.insert(slot.to_string(), header);

    let (init, snapshot) = zkasper_witness_gen::init_point::take(&mock, &TEST_CONFIG, "test", slot)
        .await
        .unwrap();

    assert_eq!(init.num_validators, 4);
    assert_eq!(init.total_active_balance, 4 * 32_000_000_000);
    assert_eq!(init.epoch, epoch);
    assert_eq!(init.acc_root, snapshot.tree.root());
    assert_eq!(
        init.accumulator_commitment,
        acc::commitment(&init.acc_root, init.total_active_balance),
    );
    init.check().unwrap();

    let reopened = zkasper_witness_gen::init_point::open(&mock, &TEST_CONFIG, "test", &init)
        .await
        .expect("the init point describes the accumulator the registry builds");
    assert_eq!(reopened.tree.root(), snapshot.tree.root());
    assert_eq!(reopened.state.acc_commitment, init.accumulator_commitment);
    assert_eq!(reopened.epoch_state.state_root, init.state_root);

    // Every field `open` checks has to be load-bearing, or a wrong init point
    // would start a run against an accumulator nobody holds.
    for wrong in [
        {
            let mut w = init.clone();
            w.num_validators += 1;
            w
        },
        {
            let mut w = init.clone();
            w.acc_root[0] ^= 1;
            w.accumulator_commitment = acc::commitment(&w.acc_root, w.total_active_balance);
            w
        },
        {
            let mut w = init.clone();
            w.state_root[0] ^= 1;
            w
        },
    ] {
        assert!(
            zkasper_witness_gen::init_point::open(&mock, &TEST_CONFIG, "test", &wrong)
                .await
                .is_err(),
            "open accepted an init point that does not describe this registry",
        );
    }
}

// -----------------------------------------------------------------------
// Epoch diff round-trip test
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_epoch_diff_round_trip() {
    let slot_1 = 3200u64; // epoch 100
    let slot_2 = 3232u64; // epoch 101

    // 4 validators, validator 1 changes balance from 32 -> 16 ETH
    let validators_1: Vec<ValidatorData> = (0..4).map(|i| make_validator(i, 32)).collect();
    let mut validators_2 = validators_1.clone();
    validators_2[1].effective_balance = 16_000_000_000;

    let responses_1: Vec<ValidatorResponse> = validators_1
        .iter()
        .enumerate()
        .map(|(i, v)| validator_data_to_response(v, i as u64))
        .collect();
    let responses_2: Vec<ValidatorResponse> = validators_2
        .iter()
        .enumerate()
        .map(|(i, v)| validator_data_to_response(v, i as u64))
        .collect();

    let mut mock = MockBeaconApi::new();
    let header_1 = make_header(slot_1, &responses_1, TEST_DEPTH, &SlotHistory::default());
    let header_2 = make_header(slot_2, &responses_2, TEST_DEPTH, &SlotHistory::default());
    mock.validators
        .insert(slot_1.to_string(), responses_1.clone());
    mock.validators
        .insert(slot_2.to_string(), responses_2.clone());
    mock.headers.insert(slot_1.to_string(), header_1);
    mock.headers.insert(slot_2.to_string(), header_2);

    // The init point builds the AccTree the diff moves.
    let (init, snapshot) =
        zkasper_witness_gen::init_point::take(&mock, &TEST_CONFIG, "test", slot_1)
            .await
            .unwrap();
    let (mut tree, epoch_state, total_active_balance_1) = (
        snapshot.tree.clone(),
        snapshot.epoch_state.clone(),
        init.total_active_balance,
    );

    let old_root = tree.root();

    // Then epoch diff
    let (witness, _new_epoch_state, new_total_active_balance, new_num_validators) =
        zkasper_witness_gen::witness_epoch_diff::build(
            &mock,
            &TEST_CONFIG,
            &mut tree,
            &epoch_state,
            slot_2,
            total_active_balance_1,
        )
        .await
        .unwrap();

    assert_eq!(new_num_validators, 4);
    let expected_balance = 3 * 32_000_000_000 + 16_000_000_000;
    assert_eq!(new_total_active_balance, expected_balance);
    assert_ne!(tree.root(), old_root);

    // Verify with epoch-diff guest verification function
    let output =
        zkasper_epoch_diff_guest::verify_epoch_diff_with_depth(&witness, TEST_DEPTH, TEST_DEPTH);

    assert_eq!(output.acc_root, tree.root());
    assert_eq!(output.total_active_balance, new_total_active_balance);

    assert_eq!(
        output.accumulator_commitment,
        acc::commitment(&output.acc_root, output.total_active_balance),
    );
    // Both endpoints are published, so the diff can be chained onto the one it
    // started from.
    assert_eq!(
        output.prev_accumulator_commitment,
        acc::commitment(&witness.acc_root_1, witness.total_active_balance_1),
    );
    assert_eq!(output.epoch_1, witness.epoch_1);
    assert_eq!(output.epoch_2, witness.epoch_2);
    assert_eq!(output.state_root_1, witness.state_root_1);
    assert_eq!(output.state_root_2, witness.state_root_2);
}

// -----------------------------------------------------------------------
// Full pipeline: init point -> epoch diff
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_full_pipeline_init_point_then_epoch_diff() {
    let slot_1 = 3200u64;
    let slot_2 = 3232u64;

    // 4 validators, validator 0: exits at epoch 101, validator 3: balance 32 -> 24
    let validators_1: Vec<ValidatorData> = (0..4).map(|i| make_validator(i, 32)).collect();
    let mut validators_2 = validators_1.clone();
    validators_2[0].exit_epoch = 101; // will be inactive at epoch 101
    validators_2[3].effective_balance = 24_000_000_000;

    let responses_1: Vec<ValidatorResponse> = validators_1
        .iter()
        .enumerate()
        .map(|(i, v)| validator_data_to_response(v, i as u64))
        .collect();
    let responses_2: Vec<ValidatorResponse> = validators_2
        .iter()
        .enumerate()
        .map(|(i, v)| validator_data_to_response(v, i as u64))
        .collect();

    let mut mock = MockBeaconApi::new();
    let header_1 = make_header(slot_1, &responses_1, TEST_DEPTH, &SlotHistory::default());
    let header_2 = make_header(slot_2, &responses_2, TEST_DEPTH, &SlotHistory::default());
    mock.validators
        .insert(slot_1.to_string(), responses_1.clone());
    mock.validators
        .insert(slot_2.to_string(), responses_2.clone());
    mock.headers.insert(slot_1.to_string(), header_1);
    mock.headers.insert(slot_2.to_string(), header_2);

    // Start from an init point
    let (init, snapshot) =
        zkasper_witness_gen::init_point::take(&mock, &TEST_CONFIG, "test", slot_1)
            .await
            .unwrap();
    let (tree, total_active_balance, num_validators) = (
        snapshot.tree,
        init.total_active_balance,
        init.num_validators,
    );
    assert_eq!(init.acc_root, tree.root());

    // Save + load via DB
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let db = zkasper_witness_gen::db::Db::new(&db_path);
    db.save(&tree, 100, total_active_balance, num_validators)
        .unwrap();

    let (mut loaded_tree, _cursor_epoch, loaded_balance, _loaded_count) =
        db.load().unwrap().expect("should load");
    assert_eq!(loaded_tree.root(), tree.root());

    // Epoch diff (no cached EpochState from DB — uses slow path)
    let old_state = zkasper_witness_gen::EpochState::empty(slot_1, num_validators);
    let (epoch_diff_witness, _new_epoch_state, new_balance, _new_count) =
        zkasper_witness_gen::witness_epoch_diff::build(
            &mock,
            &TEST_CONFIG,
            &mut loaded_tree,
            &old_state,
            slot_2,
            loaded_balance,
        )
        .await
        .unwrap();

    // Verify epoch diff
    let diff = zkasper_epoch_diff_guest::verify_epoch_diff_with_depth(
        &epoch_diff_witness,
        TEST_DEPTH,
        TEST_DEPTH,
    );

    assert_eq!(diff.acc_root, loaded_tree.root());
    assert_eq!(diff.total_active_balance, new_balance);

    // epoch 101: v0 exits (0 ETH active), v1=32, v2=32, v3=24
    let expected = 32_000_000_000 + 32_000_000_000 + 24_000_000_000;
    assert_eq!(new_balance, expected);
}

// -----------------------------------------------------------------------
// Justification round-trip test (directly constructed slot proof outputs)
// -----------------------------------------------------------------------

/// Root of the committee tree these hand-built slot proofs counted against.
///
/// The value is arbitrary; what the circuit checks is that every slot proof and
/// the committee proof name the same one, so that the slot masks below
/// deduplicate against a single partition of the validator set.
const COMMITTEE_ROOT: acc::Digest = [3u64; 4];

/// The checkpoint these fixtures' attestations name as their FFG source. Only
/// its consistency across a fold chain matters here; the finalization tests
/// pin it to the checkpoint being finalized, in `finalization_witness`.
const SOURCE_EPOCH: u64 = 99;
const SOURCE_ROOT: [u8; 32] = [6u8; 32];

fn committee_output(accumulator_commitment: acc::Digest, target_epoch: u64) -> CommitteeOutput {
    CommitteeOutput {
        accumulator_commitment,
        target_epoch,
        committee_root: COMMITTEE_ROOT,
    }
}

#[test]
fn test_justification_round_trip() {
    let acc_root = [42u64; 4];
    let total_active_balance: u64 = 4 * 32_000_000_000;
    let commitment = acc::commitment(&acc_root, total_active_balance);
    let target_epoch = 100u64;
    let target_root = [7u8; 32];

    // Two slot proofs over disjoint slots of one committee proof, each covering
    // half the validator set: 128 ETH in all, a supermajority.
    let slot_proof_outputs = vec![
        SlotProofOutput {
            source_epoch: SOURCE_EPOCH,
            source_root: SOURCE_ROOT,
            accumulator_commitment: commitment,
            committee_root: COMMITTEE_ROOT,
            target_epoch,
            target_root,
            attesting_balance: 2 * 32_000_000_000,
            slots_mask: 0b01,
        },
        SlotProofOutput {
            source_epoch: SOURCE_EPOCH,
            source_root: SOURCE_ROOT,
            accumulator_commitment: commitment,
            committee_root: COMMITTEE_ROOT,
            target_epoch,
            target_root,
            attesting_balance: 2 * 32_000_000_000,
            slots_mask: 0b10,
        },
    ];

    let witness = JustificationWitness {
        source_epoch: SOURCE_EPOCH,
        source_root: SOURCE_ROOT,
        justification_program_vk: child_vks::JUSTIFICATION,
        accumulator_commitment: commitment,
        acc_root,
        target_epoch,
        target_root,
        total_active_balance,
        committee: Some(committee_output(commitment, target_epoch)),
        committee_proof: vec![],
        previous: None,
        previous_proof: vec![],
        slot_proof_outputs,
        slot_proofs: vec![vec![], vec![]], // empty proofs (stub verifier)
    };

    let output = zkasper_justification_guest::verify_justification(&witness);

    assert_eq!(output.accumulator_commitment, commitment);
    assert_eq!(output.target_epoch, target_epoch);
    assert_eq!(output.target_root, target_root);
}

/// The two-thirds gate divides by `total_active_balance`. If that number were
/// free, a prover would set it low enough that any attesting balance cleared the
/// bar. It is only safe because the accumulator commits to it.
#[test]
#[should_panic(expected = "accumulator commitment mismatch")]
fn test_justification_rejects_an_understated_active_balance() {
    let acc_root = [42u64; 4];
    let total_active_balance: u64 = 4 * 32_000_000_000;
    let commitment = acc::commitment(&acc_root, total_active_balance);
    let target_epoch = 100u64;
    let target_root = [7u8; 32];

    // One slot attests, a quarter of the stake — nowhere near two thirds.
    let slot_proof_outputs = vec![SlotProofOutput {
        source_epoch: SOURCE_EPOCH,
        source_root: SOURCE_ROOT,
        accumulator_commitment: commitment,
        committee_root: COMMITTEE_ROOT,
        target_epoch,
        target_root,
        attesting_balance: 32_000_000_000,
        slots_mask: 0b1,
    }];

    let witness = JustificationWitness {
        source_epoch: SOURCE_EPOCH,
        source_root: SOURCE_ROOT,
        justification_program_vk: child_vks::JUSTIFICATION,
        accumulator_commitment: commitment,
        acc_root,
        target_epoch,
        target_root,
        // The lie: claim the network is a quarter of its real size, so one slot
        // looks like the whole of it.
        total_active_balance: 32_000_000_000,
        committee: Some(committee_output(commitment, target_epoch)),
        committee_proof: vec![],
        previous: None,
        previous_proof: vec![],
        slot_proof_outputs,
        slot_proofs: vec![vec![]],
    };

    zkasper_justification_guest::verify_justification(&witness);
}

#[test]
#[should_panic(expected = "counts a slot that was already counted")]
fn test_justification_rejects_a_slot_counted_twice() {
    let acc_root = [42u64; 4];
    let total_active_balance: u64 = 4 * 32_000_000_000;
    let commitment = acc::commitment(&acc_root, total_active_balance);
    let target_epoch = 100u64;
    let target_root = [7u8; 32];

    // Both proofs count slot 1. The committee proof puts every validator in
    // exactly one slot, so a slot counted twice is a validator counted twice.
    let slot_proof_outputs = vec![
        SlotProofOutput {
            source_epoch: SOURCE_EPOCH,
            source_root: SOURCE_ROOT,
            accumulator_commitment: commitment,
            committee_root: COMMITTEE_ROOT,
            target_epoch,
            target_root,
            attesting_balance: 2 * 32_000_000_000,
            slots_mask: 0b011,
        },
        SlotProofOutput {
            source_epoch: SOURCE_EPOCH,
            source_root: SOURCE_ROOT,
            accumulator_commitment: commitment,
            committee_root: COMMITTEE_ROOT,
            target_epoch,
            target_root,
            attesting_balance: 2 * 32_000_000_000,
            slots_mask: 0b110,
        },
    ];

    let witness = JustificationWitness {
        source_epoch: SOURCE_EPOCH,
        source_root: SOURCE_ROOT,
        justification_program_vk: child_vks::JUSTIFICATION,
        accumulator_commitment: commitment,
        acc_root,
        target_epoch,
        target_root,
        total_active_balance,
        committee: Some(committee_output(commitment, target_epoch)),
        committee_proof: vec![],
        previous: None,
        previous_proof: vec![],
        slot_proof_outputs,
        slot_proofs: vec![vec![], vec![]],
    };

    zkasper_justification_guest::verify_justification(&witness);
}

/// A fold that has not reached two thirds is a valid proof of a partial count,
/// and says so.
///
/// It has to be: the chain would have no middle otherwise. What must not happen
/// is a consumer treating it as a justification, which is what
/// [`test_finalization_rejects_a_partial_justification`] covers.
#[test]
fn test_justification_below_two_thirds_is_not_justified() {
    let acc_root = [42u64; 4];
    let total_active_balance: u64 = 4 * 32_000_000_000; // 128 ETH total
    let commitment = acc::commitment(&acc_root, total_active_balance);
    let target_epoch = 100u64;
    let target_root = [7u8; 32];

    // One slot carrying one validator (32 ETH) — not enough for 2/3 of 128 ETH
    let witness = JustificationWitness {
        source_epoch: SOURCE_EPOCH,
        source_root: SOURCE_ROOT,
        justification_program_vk: child_vks::JUSTIFICATION,
        accumulator_commitment: commitment,
        acc_root,
        target_epoch,
        target_root,
        total_active_balance,
        committee: Some(committee_output(commitment, target_epoch)),
        committee_proof: vec![],
        previous: None,
        previous_proof: vec![],
        slot_proof_outputs: vec![SlotProofOutput {
            source_epoch: SOURCE_EPOCH,
            source_root: SOURCE_ROOT,
            accumulator_commitment: commitment,
            committee_root: COMMITTEE_ROOT,
            target_epoch,
            target_root,
            attesting_balance: 32_000_000_000,
            slots_mask: 0b1,
        }],
        slot_proofs: vec![vec![]],
    };

    let output = zkasper_justification_guest::verify_justification(&witness);

    assert!(!output.justified);
    assert_eq!(output.attesting_balance, 32_000_000_000);
    assert_eq!(output.slots_mask, 0b1);
}

// -----------------------------------------------------------------------
// The justification chain
// -----------------------------------------------------------------------

/// One link's witness, extending `previous` with one slot.
fn justification_link(
    acc_root: acc::Digest,
    total_active_balance: u64,
    previous: Option<JustificationOutput>,
    slot: SlotProofOutput,
) -> JustificationWitness {
    let commitment = acc::commitment(&acc_root, total_active_balance);
    JustificationWitness {
        source_epoch: SOURCE_EPOCH,
        source_root: SOURCE_ROOT,
        justification_program_vk: child_vks::JUSTIFICATION,
        accumulator_commitment: commitment,
        acc_root,
        target_epoch: slot.target_epoch,
        target_root: slot.target_root,
        total_active_balance,
        committee: previous
            .is_none()
            .then(|| committee_output(commitment, slot.target_epoch)),
        committee_proof: vec![],
        previous,
        previous_proof: vec![],
        slot_proof_outputs: vec![slot],
        slot_proofs: vec![vec![]],
    }
}

fn slot_output(commitment: acc::Digest, mask: u64, balance: u64) -> SlotProofOutput {
    SlotProofOutput {
        source_epoch: SOURCE_EPOCH,
        source_root: SOURCE_ROOT,
        accumulator_commitment: commitment,
        committee_root: COMMITTEE_ROOT,
        target_epoch: 100,
        target_root: [7u8; 32],
        attesting_balance: balance,
        slots_mask: mask,
    }
}

/// Four slots folded one at a time reach the same claim as four folded at once.
///
/// This is the whole point of the change: the epoch's cost is the same work in
/// proofs of bounded size, and nothing about what is proven moves.
#[test]
fn test_justification_chain_matches_a_single_fold() {
    let acc_root = [42u64; 4];
    let total_active_balance: u64 = 4 * 32_000_000_000;
    let commitment = acc::commitment(&acc_root, total_active_balance);
    let slots: Vec<SlotProofOutput> = (0..4)
        .map(|i| slot_output(commitment, 1 << i, 32_000_000_000))
        .collect();

    let mut chained = None;
    for slot in slots.clone() {
        chained = Some(zkasper_justification_guest::verify_justification(
            &justification_link(acc_root, total_active_balance, chained, slot),
        ));
    }
    let chained = chained.expect("four links");

    let at_once = zkasper_justification_guest::verify_justification(&JustificationWitness {
        source_epoch: SOURCE_EPOCH,
        source_root: SOURCE_ROOT,
        slot_proof_outputs: slots,
        slot_proofs: vec![vec![]; 4],
        ..justification_link(
            acc_root,
            total_active_balance,
            None,
            slot_output(commitment, 0, 0),
        )
    });

    assert_eq!(chained, at_once);
    assert!(chained.justified);
    assert_eq!(chained.attesting_balance, total_active_balance);
    assert_eq!(chained.slots_mask, 0b1111);
}

/// Deduplication has to hold across links, not only inside one.
///
/// A validator sits in exactly one slot of one committee proof, so a slot the
/// chain already counted is a validator counted twice.
#[test]
#[should_panic(expected = "counts a slot that was already counted")]
fn test_justification_chain_rejects_a_slot_an_earlier_link_counted() {
    let acc_root = [42u64; 4];
    let total_active_balance: u64 = 4 * 32_000_000_000;
    let commitment = acc::commitment(&acc_root, total_active_balance);

    let first = zkasper_justification_guest::verify_justification(&justification_link(
        acc_root,
        total_active_balance,
        None,
        slot_output(commitment, 0b01, 2 * 32_000_000_000),
    ));

    zkasper_justification_guest::verify_justification(&justification_link(
        acc_root,
        total_active_balance,
        Some(first),
        slot_output(commitment, 0b01, 2 * 32_000_000_000),
    ));
}

/// A link may only extend a link of its own epoch.
#[test]
#[should_panic(expected = "previous justification target_epoch mismatch")]
fn test_justification_chain_rejects_a_previous_link_from_another_epoch() {
    let acc_root = [42u64; 4];
    let total_active_balance: u64 = 4 * 32_000_000_000;
    let commitment = acc::commitment(&acc_root, total_active_balance);

    let mut previous = zkasper_justification_guest::verify_justification(&justification_link(
        acc_root,
        total_active_balance,
        None,
        slot_output(commitment, 0b01, 32_000_000_000),
    ));
    previous.target_epoch = 99;

    zkasper_justification_guest::verify_justification(&justification_link(
        acc_root,
        total_active_balance,
        Some(previous),
        slot_output(commitment, 0b10, 32_000_000_000),
    ));
}

/// A link inherits the committee root rather than re-choosing it, so a slot
/// proof counted against another partition of the same epoch is rejected even
/// though this link verifies no committee proof of its own.
#[test]
#[should_panic(expected = "committee mismatch")]
fn test_justification_chain_rejects_a_slot_from_another_partition() {
    let acc_root = [42u64; 4];
    let total_active_balance: u64 = 4 * 32_000_000_000;
    let commitment = acc::commitment(&acc_root, total_active_balance);

    let first = zkasper_justification_guest::verify_justification(&justification_link(
        acc_root,
        total_active_balance,
        None,
        slot_output(commitment, 0b01, 32_000_000_000),
    ));

    let mut stray = slot_output(commitment, 0b10, 32_000_000_000);
    stray.committee_root = [9u64; 4];
    zkasper_justification_guest::verify_justification(&justification_link(
        acc_root,
        total_active_balance,
        Some(first),
        stray,
    ));
}

/// Every link rehashes the commitment, so the balance the gate divides by stays
/// the accumulator's however long the chain gets.
#[test]
#[should_panic(expected = "accumulator commitment mismatch")]
fn test_justification_chain_rejects_a_restated_active_balance() {
    let acc_root = [42u64; 4];
    let total_active_balance: u64 = 4 * 32_000_000_000;
    let commitment = acc::commitment(&acc_root, total_active_balance);

    let first = zkasper_justification_guest::verify_justification(&justification_link(
        acc_root,
        total_active_balance,
        None,
        slot_output(commitment, 0b01, 32_000_000_000),
    ));

    // The lie: a later link claims a smaller network, so one more slot clears
    // the gate. The commitment it must rehash to is the one the chain carries.
    let mut witness = justification_link(
        acc_root,
        total_active_balance,
        Some(first),
        slot_output(commitment, 0b10, 32_000_000_000),
    );
    witness.total_active_balance = 2 * 32_000_000_000;
    zkasper_justification_guest::verify_justification(&witness);
}

// -----------------------------------------------------------------------
// Finalization round-trip test
// -----------------------------------------------------------------------

/// Two accumulators, one epoch apart, and the diff that links them.
///
/// Epoch E+1 is justified against a different accumulator than epoch E — the
/// beacon chain rewrites effective balances at every transition — so a
/// finalization witness needs the epoch diff that carries one to the other.
fn linked_accumulators() -> (acc::Digest, acc::Digest, EpochDiffOutput) {
    let acc_root = [42u64; 4];
    let balance_e: u64 = 4 * 32_000_000_000;
    let balance_e1: u64 = balance_e - 1_000_000_000;
    let commitment_e = acc::commitment(&acc_root, balance_e);
    let commitment_e1 = acc::commitment(&acc_root, balance_e1);

    let diff = EpochDiffOutput {
        prev_accumulator_commitment: commitment_e,
        // Matches the finalized block's state root: the accumulator for epoch E
        // is built from the state that block produced.
        state_root_1: fin().boundary_state_root,
        epoch_1: 100,
        accumulator_commitment: commitment_e1,
        acc_root,
        total_active_balance: balance_e1,
        state_root_2: [0xCDu8; 32],
        epoch_2: 101,
    };
    (commitment_e, commitment_e1, diff)
}

fn finalization_witness(
    just_e: JustificationOutput,
    mut just_e1: JustificationOutput,
    epoch_diff_output: EpochDiffOutput,
) -> FinalizationWitness {
    just_e1.source_epoch = just_e.target_epoch;
    just_e1.source_root = just_e.target_root;
    FinalizationWitness {
        boundary: fin().anchor,
        justification_outputs: vec![just_e, just_e1],
        justification_proofs: vec![vec![], vec![]], // empty proofs (stub verifier)
        epoch_diff_output,
        epoch_diff_proof: vec![],
    }
}

/// A partial link is a valid proof of a partial count, so the finalization has
/// to read the flag rather than take the proof's existence for the claim.
#[test]
#[should_panic(expected = "not a supermajority")]
fn test_finalization_rejects_a_partial_justification() {
    let (commitment_e, commitment_e1, diff) = linked_accumulators();

    let mut just_e = zkasper_common::test_utils::justified_output(
        child_vks::JUSTIFICATION,
        commitment_e,
        100,
        fin_root(),
    );
    just_e.justified = false;
    let just_e1 = zkasper_common::test_utils::justified_output(
        child_vks::JUSTIFICATION,
        commitment_e1,
        101,
        fin().justified_root,
    );

    zkasper_finalization_guest::verify_finalization(&finalization_witness(just_e, just_e1, diff));
}

#[test]
fn test_finalization_round_trip() {
    let (commitment_e, commitment_e1, diff) = linked_accumulators();

    let just_e = zkasper_common::test_utils::justified_output(
        child_vks::JUSTIFICATION,
        commitment_e,
        100,
        fin_root(),
    );
    let just_e1 = zkasper_common::test_utils::justified_output(
        child_vks::JUSTIFICATION,
        commitment_e1,
        101,
        fin().justified_root,
    );

    let output = zkasper_finalization_guest::verify_finalization(&finalization_witness(
        just_e, just_e1, diff,
    ));

    assert_eq!(output.accumulator_commitment, commitment_e);
    assert_eq!(output.next_accumulator_commitment, commitment_e1);
    assert_eq!(output.finalized_epoch, 100);
    assert_eq!(output.finalized_root, fin_root());
    assert_eq!(output.finalized_state_root, fin().boundary_state_root);
}

/// An epoch whose first slot is empty finalizes like any other.
///
/// Its checkpoint is the block two slots earlier, so the boundary state is not
/// that block's post-state — the empty slots advanced it. The finalization
/// therefore names a state root no header carries, which is what opening the
/// justified checkpoint's `state_roots` is for. Reading it off the finalized
/// header, as this proof used to, rejected the pair instead.
#[test]
fn test_finalization_across_an_empty_first_slot() {
    let empty = boundary(3198, [0xEEu8; 32]);
    assert_ne!(
        empty.boundary_state_root,
        fin().boundary_state_root,
        "the empty case has to differ from the block's own state root",
    );

    let (commitment_e, commitment_e1, mut diff) = linked_accumulators();
    diff.state_root_1 = empty.boundary_state_root;

    let mut just_e1 = zkasper_common::test_utils::justified_output(
        child_vks::JUSTIFICATION,
        commitment_e1,
        101,
        empty.justified_root,
    );
    just_e1.source_epoch = 100;
    just_e1.source_root = empty.finalized_root;

    let output = zkasper_finalization_guest::verify_finalization(&FinalizationWitness {
        boundary: empty.anchor,
        justification_outputs: vec![
            zkasper_common::test_utils::justified_output(
                child_vks::JUSTIFICATION,
                commitment_e,
                100,
                empty.finalized_root,
            ),
            just_e1,
        ],
        justification_proofs: vec![vec![], vec![]],
        epoch_diff_output: diff,
        epoch_diff_proof: vec![],
    });

    assert_eq!(output.finalized_epoch, 100);
    assert_eq!(output.finalized_root, empty.finalized_root);
    assert_eq!(output.finalized_state_root, empty.boundary_state_root);
}

/// A finalized root the justified chain does not have at the boundary is not a
/// checkpoint of that chain, whatever a justification proof says about it.
#[test]
#[should_panic(expected = "not the block at the boundary of the justified chain")]
fn test_finalization_rejects_a_checkpoint_from_another_chain() {
    let (commitment_e, commitment_e1, diff) = linked_accumulators();

    // A real header root, from a block the justified chain never had there.
    let just_e = zkasper_common::test_utils::justified_output(
        child_vks::JUSTIFICATION,
        commitment_e,
        100,
        boundary(3198, [0xEEu8; 32]).finalized_root,
    );
    let just_e1 = zkasper_common::test_utils::justified_output(
        child_vks::JUSTIFICATION,
        commitment_e1,
        101,
        fin().justified_root,
    );

    zkasper_finalization_guest::verify_finalization(&finalization_witness(just_e, just_e1, diff));
}

/// The opening only means anything against the checkpoint the attesters signed.
#[test]
#[should_panic(expected = "justified header does not hash to the justified root")]
fn test_finalization_rejects_a_boundary_opened_off_another_state() {
    let (commitment_e, commitment_e1, diff) = linked_accumulators();

    let just_e = zkasper_common::test_utils::justified_output(
        child_vks::JUSTIFICATION,
        commitment_e,
        100,
        fin_root(),
    );
    // The epoch was justified for one checkpoint; the anchor hangs off another
    // one's state.
    let just_e1 = zkasper_common::test_utils::justified_output(
        child_vks::JUSTIFICATION,
        commitment_e1,
        101,
        boundary(3198, [0xEEu8; 32]).justified_root,
    );

    zkasper_finalization_guest::verify_finalization(&finalization_witness(just_e, just_e1, diff));
}

#[test]
#[should_panic(expected = "justification epochs not consecutive")]
fn test_finalization_rejects_non_consecutive_epochs() {
    let (commitment_e, commitment_e1, diff) = linked_accumulators();

    let just_e = zkasper_common::test_utils::justified_output(
        child_vks::JUSTIFICATION,
        commitment_e,
        100,
        fin_root(),
    );
    // Epoch 102 instead of 101 — not consecutive!
    let just_e2 = zkasper_common::test_utils::justified_output(
        child_vks::JUSTIFICATION,
        commitment_e1,
        102,
        fin().justified_root,
    );

    zkasper_finalization_guest::verify_finalization(&finalization_witness(just_e, just_e2, diff));
}

#[test]
#[should_panic(expected = "epoch diff does not start from the accumulator")]
fn test_finalization_rejects_a_diff_from_another_accumulator() {
    let (_, commitment_e1, diff) = linked_accumulators();

    // Epoch E was justified against an accumulator this diff never touched —
    // exactly the pairing of two unrelated branches the diff is there to stop.
    let just_e = zkasper_common::test_utils::justified_output(
        child_vks::JUSTIFICATION,
        [99u64; 4],
        100,
        fin_root(),
    );
    let just_e1 = zkasper_common::test_utils::justified_output(
        child_vks::JUSTIFICATION,
        commitment_e1,
        101,
        fin().justified_root,
    );

    zkasper_finalization_guest::verify_finalization(&finalization_witness(just_e, just_e1, diff));
}

#[test]
#[should_panic(expected = "epoch diff does not end at the accumulator")]
fn test_finalization_rejects_a_diff_to_another_accumulator() {
    let (commitment_e, _, diff) = linked_accumulators();

    let just_e = zkasper_common::test_utils::justified_output(
        child_vks::JUSTIFICATION,
        commitment_e,
        100,
        fin_root(),
    );
    let just_e1 = zkasper_common::test_utils::justified_output(
        child_vks::JUSTIFICATION,
        [99u64; 4],
        101,
        fin().justified_root,
    );

    zkasper_finalization_guest::verify_finalization(&finalization_witness(just_e, just_e1, diff));
}

#[test]
#[should_panic(expected = "epoch diff starts at epoch")]
fn test_finalization_rejects_a_diff_labelled_with_other_epochs() {
    let (commitment_e, commitment_e1, mut diff) = linked_accumulators();
    diff.epoch_1 = 7;
    diff.epoch_2 = 8;

    let just_e = zkasper_common::test_utils::justified_output(
        child_vks::JUSTIFICATION,
        commitment_e,
        100,
        fin_root(),
    );
    let just_e1 = zkasper_common::test_utils::justified_output(
        child_vks::JUSTIFICATION,
        commitment_e1,
        101,
        fin().justified_root,
    );

    zkasper_finalization_guest::verify_finalization(&finalization_witness(just_e, just_e1, diff));
}

#[test]
#[should_panic(expected = "built from a different state than the boundary")]
fn test_finalization_rejects_an_accumulator_built_off_another_state() {
    let (commitment_e, commitment_e1, mut diff) = linked_accumulators();
    diff.state_root_1 = [0x77u8; 32];

    let just_e = zkasper_common::test_utils::justified_output(
        child_vks::JUSTIFICATION,
        commitment_e,
        100,
        fin_root(),
    );
    let just_e1 = zkasper_common::test_utils::justified_output(
        child_vks::JUSTIFICATION,
        commitment_e1,
        101,
        fin().justified_root,
    );

    zkasper_finalization_guest::verify_finalization(&finalization_witness(just_e, just_e1, diff));
}

// -----------------------------------------------------------------------
// Full pipeline: justification → finalization (from constructed data)
// -----------------------------------------------------------------------

#[test]
fn test_full_justification_to_finalization_pipeline() {
    let (commitment_e, commitment_e1, diff) = linked_accumulators();

    // Build justification for epoch 100
    let epoch_100_root = fin_root();
    let just_witness_100 = JustificationWitness {
        source_epoch: SOURCE_EPOCH,
        source_root: SOURCE_ROOT,
        justification_program_vk: child_vks::JUSTIFICATION,
        accumulator_commitment: commitment_e,
        acc_root: diff.acc_root,
        target_epoch: 100,
        target_root: epoch_100_root,
        total_active_balance: diff.total_active_balance + 1_000_000_000,
        committee: Some(committee_output(commitment_e, 100)),
        committee_proof: vec![],
        previous: None,
        previous_proof: vec![],
        slot_proof_outputs: vec![SlotProofOutput {
            source_epoch: SOURCE_EPOCH,
            source_root: SOURCE_ROOT,
            accumulator_commitment: commitment_e,
            committee_root: COMMITTEE_ROOT,
            target_epoch: 100,
            target_root: epoch_100_root,
            attesting_balance: diff.total_active_balance + 1_000_000_000,
            slots_mask: 0b1111, // one proof covering the epoch's four slots
        }],
        slot_proofs: vec![vec![]],
    };

    let output_100 = zkasper_justification_guest::verify_justification(&just_witness_100);
    assert_eq!(output_100.target_epoch, 100);

    // Build justification for epoch 101, against the accumulator the diff
    // produced rather than the one epoch 100 used.
    let epoch_101_root = fin().justified_root;
    let just_witness_101 = JustificationWitness {
        source_epoch: SOURCE_EPOCH,
        source_root: SOURCE_ROOT,
        justification_program_vk: child_vks::JUSTIFICATION,
        accumulator_commitment: commitment_e1,
        acc_root: diff.acc_root,
        target_epoch: 101,
        target_root: epoch_101_root,
        total_active_balance: diff.total_active_balance,
        committee: Some(committee_output(commitment_e1, 101)),
        committee_proof: vec![],
        previous: None,
        previous_proof: vec![],
        slot_proof_outputs: vec![SlotProofOutput {
            source_epoch: SOURCE_EPOCH,
            source_root: SOURCE_ROOT,
            accumulator_commitment: commitment_e1,
            committee_root: COMMITTEE_ROOT,
            target_epoch: 101,
            target_root: epoch_101_root,
            attesting_balance: diff.total_active_balance,
            slots_mask: 0b1111,
        }],
        slot_proofs: vec![vec![]],
    };

    let output_101 = zkasper_justification_guest::verify_justification(&just_witness_101);
    assert_eq!(output_101.target_epoch, 101);

    // Finalization: pair two consecutive justifications
    let finalization_output = zkasper_finalization_guest::verify_finalization(
        &finalization_witness(output_100, output_101, diff),
    );

    assert_eq!(finalization_output.accumulator_commitment, commitment_e);
    assert_eq!(
        finalization_output.next_accumulator_commitment,
        commitment_e1
    );
    assert_eq!(finalization_output.finalized_epoch, 100);
    assert_eq!(finalization_output.finalized_root, epoch_100_root);
}

// -----------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------

fn make_response(index: u8, balance_eth: u64) -> ValidatorResponse {
    let v = make_validator(index, balance_eth);
    validator_data_to_response(&v, index as u64)
}

/// Fixed header used by finalization tests, plus the root it hashes to.
/// The circuit opens the header and checks it against the finalized root, so
/// tests must derive the root rather than invent one.
/// Epoch 100's boundary, as epoch 101's checkpoint state records it.
struct Boundary {
    /// Root of the last block at or before slot 3200.
    finalized_root: [u8; 32],
    /// State at the end of slot 3200, which the accumulator was built from.
    boundary_state_root: [u8; 32],
    /// Root of epoch 101's checkpoint block, which the opening hangs off.
    justified_root: [u8; 32],
    anchor: zkasper_common::types::BoundaryAnchor,
}

/// `previous_block_slot` is where epoch 100's checkpoint block actually sits:
/// the boundary itself when it holds a block, an earlier slot when it is empty.
fn boundary(previous_block_slot: u64, boundary_state_root: [u8; 32]) -> Boundary {
    let finalized_root = zkasper_common::ssz::block_header_root(
        previous_block_slot,
        7,
        &[0x06u8; 32],
        &[0xABu8; 32],
        &[0x09u8; 32],
    );
    let opened = zkasper_witness_gen::state_diff::make_boundary_proof(
        &[0u8; 32],
        0,
        &SlotHistory {
            slot: 3200,
            block_root: finalized_root,
            state_root: boundary_state_root,
        },
    );
    let justified_header = zkasper_common::types::BlockHeaderFields {
        slot: 3232,
        proposer_index: 3,
        parent_root: [0x0Au8; 32],
        state_root: opened.state_root,
        body_root: [0x0Bu8; 32],
    };
    Boundary {
        finalized_root,
        boundary_state_root,
        justified_root: zkasper_common::ssz::block_header_root(
            justified_header.slot,
            justified_header.proposer_index,
            &justified_header.parent_root,
            &justified_header.state_root,
            &justified_header.body_root,
        ),
        anchor: zkasper_common::types::BoundaryAnchor {
            justified_header,
            block_roots_siblings: opened.block_roots_siblings,
            state_roots_siblings: opened.state_roots_siblings,
        },
    }
}

/// The ordinary case: the epoch's first slot holds a block, so the boundary
/// state is that block's post-state.
fn fin() -> Boundary {
    boundary(3200, [0xABu8; 32])
}

fn fin_root() -> [u8; 32] {
    fin().finalized_root
}

/// A justification chain that names another program is not this pipeline's
/// justification, whatever its links verified against.
///
/// This is the check that closes the fold chain. A link verifies its
/// predecessor under a key it carries in the witness, because a program cannot
/// contain its own key; requiring the finished chain to have carried the key
/// this guest was compiled with is what says every link below was the real
/// program.
#[test]
#[should_panic(expected = "pinned to a different program")]
fn test_finalization_rejects_a_justification_chain_from_another_program() {
    let (commitment_e, commitment_e1, diff) = linked_accumulators();

    let mut just_e = zkasper_common::test_utils::justified_output(
        child_vks::JUSTIFICATION,
        commitment_e,
        100,
        fin_root(),
    );
    just_e.program_vk = [0xAA; 4];
    let just_e1 = zkasper_common::test_utils::justified_output(
        child_vks::JUSTIFICATION,
        commitment_e1,
        101,
        fin().justified_root,
    );

    zkasper_finalization_guest::verify_finalization(&finalization_witness(just_e, just_e1, diff));
}

/// And one link down: a fold whose predecessor names another program is a fold
/// over somebody else's circuit.
#[test]
#[should_panic(expected = "produced by a different program")]
fn test_justification_rejects_a_predecessor_from_another_program() {
    let acc_root = [42u64; 4];
    let total_active_balance: u64 = 4 * 32_000_000_000;
    let commitment = acc::commitment(&acc_root, total_active_balance);

    let mut previous = zkasper_justification_guest::verify_justification(&justification_link(
        acc_root,
        total_active_balance,
        None,
        slot_output(commitment, 0b01, 32_000_000_000),
    ));
    previous.program_vk = [0xAA; 4];

    zkasper_justification_guest::verify_justification(&justification_link(
        acc_root,
        total_active_balance,
        Some(previous),
        slot_output(commitment, 0b10, 32_000_000_000),
    ));
}

// -----------------------------------------------------------------------
// The FFG link
// -----------------------------------------------------------------------

/// A finalization is a *link*, not two unrelated supermajorities.
///
/// Epoch E+1 has to have been justified *from* E. Without that clause the proof
/// says only that two thirds attested to E and two thirds attested to E+1, and
/// two thirds can then abandon E by voting `(E-1 -> E+7)`: the source epochs are
/// equal so there is no surround, the target epochs differ so there is no double
/// vote, and nobody is slashable. With the link, abandoning E takes a surround
/// vote and costs a third of the stake.
#[test]
#[should_panic(expected = "epoch 101 was justified from a different checkpoint of epoch 100")]
fn test_finalization_rejects_a_justification_from_another_checkpoint() {
    let (commitment_e, commitment_e1, diff) = linked_accumulators();

    let just_e = zkasper_common::test_utils::justified_output(
        child_vks::JUSTIFICATION,
        commitment_e,
        100,
        fin_root(),
    );
    let just_e1 = zkasper_common::test_utils::justified_output(
        child_vks::JUSTIFICATION,
        commitment_e1,
        101,
        fin().justified_root,
    );

    let mut witness = finalization_witness(just_e, just_e1, diff);
    // A supermajority for E+1 that named some other checkpoint of epoch 100.
    witness.justification_outputs[1].source_root = [0x11; 32];

    zkasper_finalization_guest::verify_finalization(&witness);
}

/// The same, by epoch: a justification of E+1 whose source is an older epoch is
/// the two-epoch rule, which this circuit does not implement and must not be
/// made to look like the one-epoch rule.
#[test]
#[should_panic(expected = "epoch 101 was justified from epoch 99 rather than from 100")]
fn test_finalization_rejects_a_justification_from_an_older_epoch() {
    let (commitment_e, commitment_e1, diff) = linked_accumulators();

    let just_e = zkasper_common::test_utils::justified_output(
        child_vks::JUSTIFICATION,
        commitment_e,
        100,
        fin_root(),
    );
    let just_e1 = zkasper_common::test_utils::justified_output(
        child_vks::JUSTIFICATION,
        commitment_e1,
        101,
        fin().justified_root,
    );

    let mut witness = finalization_witness(just_e, just_e1, diff);
    witness.justification_outputs[1].source_epoch = 99;

    zkasper_finalization_guest::verify_finalization(&witness);
}

/// A fold chain has to agree on the source as well as the target, or a chain
/// could count `(E-1 -> E)` votes in one link and `(E-2 -> E)` votes in the
/// next and call the sum a supermajority for either link.
#[test]
#[should_panic(expected = "slot proof 0 source_root mismatch")]
fn test_justification_rejects_a_slot_proof_from_another_source() {
    let acc_root = [42u64; 4];
    let total_active_balance: u64 = 4 * 32_000_000_000;
    let commitment = acc::commitment(&acc_root, total_active_balance);

    let mut slot = slot_output(commitment, 0b01, 2 * 32_000_000_000);
    slot.source_root = [0x33; 32];

    zkasper_justification_guest::verify_justification(&justification_link(
        acc_root,
        total_active_balance,
        None,
        slot,
    ));
}

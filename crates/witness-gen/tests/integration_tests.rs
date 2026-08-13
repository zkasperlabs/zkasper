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
use zkasper_common::types::ValidatorData;

use zkasper_witness_gen::beacon_api::ValidatorResponse;
use zkasper_witness_gen::state_diff::find_mutations;

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
// Bootstrap round-trip test
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_bootstrap_round_trip() {
    let slot = 3200u64; // epoch 100
    let epoch = slot / TEST_CONFIG.slots_per_epoch;

    let validators: Vec<ValidatorData> = (0..4).map(|i| make_validator(i, 32)).collect();
    let responses: Vec<ValidatorResponse> = validators
        .iter()
        .enumerate()
        .map(|(i, v)| validator_data_to_response(v, i as u64))
        .collect();

    let mut mock = MockBeaconApi::new();
    let header = make_header(slot, &responses, TEST_DEPTH);
    mock.validators.insert(slot.to_string(), responses.clone());
    mock.headers.insert(slot.to_string(), header);

    let (witness, tree, _epoch_state, total_active_balance, num_validators) =
        zkasper_witness_gen::witness_bootstrap::build(&mock, &TEST_CONFIG, slot)
            .await
            .unwrap();

    assert_eq!(num_validators, 4);
    assert_eq!(total_active_balance, 4 * 32_000_000_000);
    assert_eq!(witness.epoch, epoch);
    assert_eq!(witness.validators.len(), 4);

    // Verify with bootstrap guest verification function
    let (commitment, acc_root, balance) =
        zkasper_bootstrap_guest::verify_bootstrap_with_depth(&witness, TEST_DEPTH, TEST_DEPTH);

    assert_eq!(acc_root, tree.root());
    assert_eq!(balance, total_active_balance);

    let expected_commitment = acc::commitment(&acc_root, total_active_balance);
    assert_eq!(commitment, expected_commitment);
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
    let header_1 = make_header(slot_1, &responses_1, TEST_DEPTH);
    let header_2 = make_header(slot_2, &responses_2, TEST_DEPTH);
    mock.validators
        .insert(slot_1.to_string(), responses_1.clone());
    mock.validators
        .insert(slot_2.to_string(), responses_2.clone());
    mock.headers.insert(slot_1.to_string(), header_1);
    mock.headers.insert(slot_2.to_string(), header_2);

    // First bootstrap to build the AccTree
    let (_, mut tree, epoch_state, total_active_balance_1, _) =
        zkasper_witness_gen::witness_bootstrap::build(&mock, &TEST_CONFIG, slot_1)
            .await
            .unwrap();

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
    let (commitment, acc_root, balance) =
        zkasper_epoch_diff_guest::verify_epoch_diff_with_depth(&witness, TEST_DEPTH, TEST_DEPTH);

    assert_eq!(acc_root, tree.root());
    assert_eq!(balance, new_total_active_balance);

    let expected_commitment = acc::commitment(&acc_root, balance);
    assert_eq!(commitment, expected_commitment);
}

// -----------------------------------------------------------------------
// Full pipeline: bootstrap -> epoch diff
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_full_pipeline_bootstrap_then_epoch_diff() {
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
    let header_1 = make_header(slot_1, &responses_1, TEST_DEPTH);
    let header_2 = make_header(slot_2, &responses_2, TEST_DEPTH);
    mock.validators
        .insert(slot_1.to_string(), responses_1.clone());
    mock.validators
        .insert(slot_2.to_string(), responses_2.clone());
    mock.headers.insert(slot_1.to_string(), header_1);
    mock.headers.insert(slot_2.to_string(), header_2);

    // Bootstrap
    let (bootstrap_witness, tree, _epoch_state, total_active_balance, num_validators) =
        zkasper_witness_gen::witness_bootstrap::build(&mock, &TEST_CONFIG, slot_1)
            .await
            .unwrap();

    // Verify bootstrap
    let (_bootstrap_commitment, bootstrap_poseidon_root, bootstrap_balance) =
        zkasper_bootstrap_guest::verify_bootstrap_with_depth(
            &bootstrap_witness,
            TEST_DEPTH,
            TEST_DEPTH,
        );
    assert_eq!(bootstrap_poseidon_root, tree.root());
    assert_eq!(bootstrap_balance, total_active_balance);

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
    let (_diff_commitment, diff_poseidon_root, diff_balance) =
        zkasper_epoch_diff_guest::verify_epoch_diff_with_depth(
            &epoch_diff_witness,
            TEST_DEPTH,
            TEST_DEPTH,
        );

    assert_eq!(diff_poseidon_root, loaded_tree.root());
    assert_eq!(diff_balance, new_balance);

    // epoch 101: v0 exits (0 ETH active), v1=32, v2=32, v3=24
    let expected = 32_000_000_000 + 32_000_000_000 + 24_000_000_000;
    assert_eq!(new_balance, expected);
}

// -----------------------------------------------------------------------
// counted_validators_commitment unit tests
// -----------------------------------------------------------------------

#[test]
fn test_counted_validators_commitment_deterministic() {
    use zkasper_common::acc;

    let indices = vec![0, 1, 2, 3];
    let a = acc::commit_indices(&indices);
    let b = acc::commit_indices(&indices);
    assert_eq!(a, b);
    assert_ne!(a, zkasper_common::acc::ZERO);
}

#[test]
fn test_counted_validators_commitment_empty() {
    use zkasper_common::acc;

    // An empty list still absorbs its length, so it must not collide with a
    // list that happens to contain a zero index.
    assert_eq!(acc::commit_indices(&[]), acc::commit_indices(&[]));
    assert_ne!(acc::commit_indices(&[]), acc::commit_indices(&[0]));
}

#[test]
fn test_counted_validators_commitment_order_matters() {
    use zkasper_common::acc;

    let a = acc::commit_indices(&[0, 1, 2]);
    let b = acc::commit_indices(&[2, 1, 0]);
    assert_ne!(a, b);
}

#[test]
fn test_counted_validators_commitment_different_lengths() {
    use zkasper_common::acc;

    let a = acc::commit_indices(&[0, 1]);
    let b = acc::commit_indices(&[0, 1, 2]);
    assert_ne!(a, b);
}

// -----------------------------------------------------------------------
// Justification round-trip test (directly constructed slot proof outputs)
// -----------------------------------------------------------------------

#[test]
fn test_justification_round_trip() {
    use zkasper_common::acc;
    use zkasper_common::types::{JustificationWitness, SlotProofOutput};

    let acc_root = [42u64; 4];
    let total_active_balance: u64 = 4 * 32_000_000_000;
    let commitment = acc::commitment(&acc_root, total_active_balance);
    let target_epoch = 100u64;
    let target_root = [7u8; 32];

    // Simulate 2 slot proofs with disjoint validator sets.
    // Slot 0: validators [0, 1] — each 32 ETH
    // Slot 1: validators [2, 3] — each 32 ETH
    // Total attesting: 128 ETH = total_active_balance → supermajority

    let slot0_indices = vec![0u64, 1];
    let slot1_indices = vec![2u64, 3];

    let slot0_commitment = acc::commit_indices(&slot0_indices);
    let slot1_commitment = acc::commit_indices(&slot1_indices);

    let slot_proof_outputs = vec![
        SlotProofOutput {
            accumulator_commitment: commitment,
            target_epoch,
            target_root,
            attesting_balance: 2 * 32_000_000_000,
            counted_validators_commitment: slot0_commitment,
            num_counted_validators: 2,
        },
        SlotProofOutput {
            accumulator_commitment: commitment,
            target_epoch,
            target_root,
            attesting_balance: 2 * 32_000_000_000,
            counted_validators_commitment: slot1_commitment,
            num_counted_validators: 2,
        },
    ];

    let witness = JustificationWitness {
        slot_program_vk: [0; 4],
        accumulator_commitment: commitment,
        target_epoch,
        target_root,
        total_active_balance,
        slot_proof_outputs,
        slot_proofs: vec![vec![], vec![]], // empty proofs (stub verifier)
        counted_indices_per_slot: vec![slot0_indices, slot1_indices],
    };

    let output = zkasper_justification_guest::verify_justification(&witness);

    assert_eq!(output.accumulator_commitment, commitment);
    assert_eq!(output.target_epoch, target_epoch);
    assert_eq!(output.target_root, target_root);
}

#[test]
#[should_panic(expected = "cross-slot duplicate validator")]
fn test_justification_rejects_cross_slot_duplicate() {
    use zkasper_common::acc;
    use zkasper_common::types::{JustificationWitness, SlotProofOutput};

    let acc_root = [42u64; 4];
    let total_active_balance: u64 = 4 * 32_000_000_000;
    let commitment = acc::commitment(&acc_root, total_active_balance);
    let target_epoch = 100u64;
    let target_root = [7u8; 32];

    // Both slots count validator 1 — should be rejected
    let slot0_indices = vec![0u64, 1];
    let slot1_indices = vec![1u64, 2]; // validator 1 duplicated!

    let slot0_commitment = acc::commit_indices(&slot0_indices);
    let slot1_commitment = acc::commit_indices(&slot1_indices);

    let slot_proof_outputs = vec![
        SlotProofOutput {
            accumulator_commitment: commitment,
            target_epoch,
            target_root,
            attesting_balance: 2 * 32_000_000_000,
            counted_validators_commitment: slot0_commitment,
            num_counted_validators: 2,
        },
        SlotProofOutput {
            accumulator_commitment: commitment,
            target_epoch,
            target_root,
            attesting_balance: 2 * 32_000_000_000,
            counted_validators_commitment: slot1_commitment,
            num_counted_validators: 2,
        },
    ];

    let witness = JustificationWitness {
        slot_program_vk: [0; 4],
        accumulator_commitment: commitment,
        target_epoch,
        target_root,
        total_active_balance,
        slot_proof_outputs,
        slot_proofs: vec![vec![], vec![]],
        counted_indices_per_slot: vec![slot0_indices, slot1_indices],
    };

    // This should panic due to cross-slot duplicate
    zkasper_justification_guest::verify_justification(&witness);
}

#[test]
#[should_panic(expected = "insufficient attesting balance")]
fn test_justification_rejects_insufficient_balance() {
    use zkasper_common::acc;
    use zkasper_common::types::{JustificationWitness, SlotProofOutput};

    let acc_root = [42u64; 4];
    let total_active_balance: u64 = 4 * 32_000_000_000; // 128 ETH total
    let commitment = acc::commitment(&acc_root, total_active_balance);
    let target_epoch = 100u64;
    let target_root = [7u8; 32];

    // Only 1 slot with 1 validator (32 ETH) — not enough for 2/3 of 128 ETH
    let indices = vec![0u64];
    let slot_commitment = acc::commit_indices(&indices);

    let slot_proof_outputs = vec![SlotProofOutput {
        accumulator_commitment: commitment,
        target_epoch,
        target_root,
        attesting_balance: 32_000_000_000,
        counted_validators_commitment: slot_commitment,
        num_counted_validators: 1,
    }];

    let witness = JustificationWitness {
        slot_program_vk: [0; 4],
        accumulator_commitment: commitment,
        target_epoch,
        target_root,
        total_active_balance,
        slot_proof_outputs,
        slot_proofs: vec![vec![]],
        counted_indices_per_slot: vec![indices],
    };

    zkasper_justification_guest::verify_justification(&witness);
}

// -----------------------------------------------------------------------
// Finalization round-trip test
// -----------------------------------------------------------------------

#[test]
fn test_finalization_round_trip() {
    use zkasper_common::acc;
    use zkasper_common::types::{FinalizationWitness, JustificationOutput};

    let acc_root = [42u64; 4];
    let total_active_balance: u64 = 4 * 32_000_000_000;
    let commitment = acc::commitment(&acc_root, total_active_balance);

    let just_e = JustificationOutput {
        accumulator_commitment: commitment,
        target_epoch: 100,
        target_root: [7u8; 32],
    };

    let just_e1 = JustificationOutput {
        accumulator_commitment: commitment,
        target_epoch: 101,
        target_root: [8u8; 32],
    };

    let witness = FinalizationWitness {
        justification_program_vk: [0; 4],
        accumulator_commitment: commitment,
        justification_outputs: vec![just_e.clone(), just_e1],
        justification_proofs: vec![vec![], vec![]], // empty proofs (stub verifier)
    };

    let output = zkasper_finalization_guest::verify_finalization(&witness);

    assert_eq!(output.accumulator_commitment, commitment);
    assert_eq!(output.finalized_epoch, 100);
    assert_eq!(output.finalized_root, [7u8; 32]);
}

#[test]
#[should_panic(expected = "justification epochs not consecutive")]
fn test_finalization_rejects_non_consecutive_epochs() {
    use zkasper_common::acc;
    use zkasper_common::types::{FinalizationWitness, JustificationOutput};

    let acc_root = [42u64; 4];
    let total_active_balance: u64 = 4 * 32_000_000_000;
    let commitment = acc::commitment(&acc_root, total_active_balance);

    let just_e = JustificationOutput {
        accumulator_commitment: commitment,
        target_epoch: 100,
        target_root: [7u8; 32],
    };

    // Epoch 102 instead of 101 — not consecutive!
    let just_e2 = JustificationOutput {
        accumulator_commitment: commitment,
        target_epoch: 102,
        target_root: [8u8; 32],
    };

    let witness = FinalizationWitness {
        justification_program_vk: [0; 4],
        accumulator_commitment: commitment,
        justification_outputs: vec![just_e, just_e2],
        justification_proofs: vec![vec![], vec![]],
    };

    zkasper_finalization_guest::verify_finalization(&witness);
}

#[test]
#[should_panic(expected = "justification 1 accumulator mismatch")]
fn test_finalization_rejects_accumulator_mismatch() {
    use zkasper_common::acc;
    use zkasper_common::types::{FinalizationWitness, JustificationOutput};

    let acc_root = [42u64; 4];
    let total_active_balance: u64 = 4 * 32_000_000_000;
    let commitment = acc::commitment(&acc_root, total_active_balance);

    let just_e = JustificationOutput {
        accumulator_commitment: commitment,
        target_epoch: 100,
        target_root: [7u8; 32],
    };

    // Different accumulator commitment
    let just_e1 = JustificationOutput {
        accumulator_commitment: [99u64; 4], // mismatch!
        target_epoch: 101,
        target_root: [8u8; 32],
    };

    let witness = FinalizationWitness {
        justification_program_vk: [0; 4],
        accumulator_commitment: commitment,
        justification_outputs: vec![just_e, just_e1],
        justification_proofs: vec![vec![], vec![]],
    };

    zkasper_finalization_guest::verify_finalization(&witness);
}

// -----------------------------------------------------------------------
// Full pipeline: justification → finalization (from constructed data)
// -----------------------------------------------------------------------

#[test]
fn test_full_justification_to_finalization_pipeline() {
    use zkasper_common::acc;
    use zkasper_common::types::{FinalizationWitness, JustificationWitness, SlotProofOutput};

    let acc_root = [42u64; 4];
    let total_active_balance: u64 = 4 * 32_000_000_000;
    let commitment = acc::commitment(&acc_root, total_active_balance);

    // Build justification for epoch 100
    let epoch_100_root = [7u8; 32];
    let indices_100 = vec![0u64, 1, 2, 3]; // all 4 validators
    let commitment_100 = acc::commit_indices(&indices_100);

    let just_witness_100 = JustificationWitness {
        slot_program_vk: [0; 4],
        accumulator_commitment: commitment,
        target_epoch: 100,
        target_root: epoch_100_root,
        total_active_balance,
        slot_proof_outputs: vec![SlotProofOutput {
            accumulator_commitment: commitment,
            target_epoch: 100,
            target_root: epoch_100_root,
            attesting_balance: total_active_balance,
            counted_validators_commitment: commitment_100,
            num_counted_validators: 4,
        }],
        slot_proofs: vec![vec![]],
        counted_indices_per_slot: vec![indices_100],
    };

    let output_100 = zkasper_justification_guest::verify_justification(&just_witness_100);
    assert_eq!(output_100.target_epoch, 100);

    // Build justification for epoch 101
    let epoch_101_root = [8u8; 32];
    let indices_101 = vec![0u64, 1, 2, 3];
    let commitment_101 = acc::commit_indices(&indices_101);

    let just_witness_101 = JustificationWitness {
        slot_program_vk: [0; 4],
        accumulator_commitment: commitment,
        target_epoch: 101,
        target_root: epoch_101_root,
        total_active_balance,
        slot_proof_outputs: vec![SlotProofOutput {
            accumulator_commitment: commitment,
            target_epoch: 101,
            target_root: epoch_101_root,
            attesting_balance: total_active_balance,
            counted_validators_commitment: commitment_101,
            num_counted_validators: 4,
        }],
        slot_proofs: vec![vec![]],
        counted_indices_per_slot: vec![indices_101],
    };

    let output_101 = zkasper_justification_guest::verify_justification(&just_witness_101);
    assert_eq!(output_101.target_epoch, 101);

    // Finalization: pair two consecutive justifications
    let finalization_witness = FinalizationWitness {
        justification_program_vk: [0; 4],
        accumulator_commitment: commitment,
        justification_outputs: vec![output_100, output_101],
        justification_proofs: vec![vec![], vec![]],
    };

    let finalization_output =
        zkasper_finalization_guest::verify_finalization(&finalization_witness);

    assert_eq!(finalization_output.accumulator_commitment, commitment);
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

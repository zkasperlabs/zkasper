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
    let header = make_header(slot, &responses, TEST_DEPTH, &SlotHistory::default());
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
    let header_1 = make_header(slot_1, &responses_1, TEST_DEPTH, &SlotHistory::default());
    let header_2 = make_header(slot_2, &responses_2, TEST_DEPTH, &SlotHistory::default());
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
    let header_1 = make_header(slot_1, &responses_1, TEST_DEPTH, &SlotHistory::default());
    let header_2 = make_header(slot_2, &responses_2, TEST_DEPTH, &SlotHistory::default());
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
            accumulator_commitment: commitment,
            committee_root: COMMITTEE_ROOT,
            target_epoch,
            target_root,
            attesting_balance: 2 * 32_000_000_000,
            slots_mask: 0b01,
        },
        SlotProofOutput {
            accumulator_commitment: commitment,
            committee_root: COMMITTEE_ROOT,
            target_epoch,
            target_root,
            attesting_balance: 2 * 32_000_000_000,
            slots_mask: 0b10,
        },
    ];

    let witness = JustificationWitness {
        slot_program_vk: [0; 4],
        committee_program_vk: [0; 4],
        accumulator_commitment: commitment,
        acc_root,
        target_epoch,
        target_root,
        total_active_balance,
        committee: committee_output(commitment, target_epoch),
        committee_proof: vec![],
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
        accumulator_commitment: commitment,
        committee_root: COMMITTEE_ROOT,
        target_epoch,
        target_root,
        attesting_balance: 32_000_000_000,
        slots_mask: 0b1,
    }];

    let witness = JustificationWitness {
        slot_program_vk: [0; 4],
        committee_program_vk: [0; 4],
        accumulator_commitment: commitment,
        acc_root,
        target_epoch,
        target_root,
        // The lie: claim the network is a quarter of its real size, so one slot
        // looks like the whole of it.
        total_active_balance: 32_000_000_000,
        committee: committee_output(commitment, target_epoch),
        committee_proof: vec![],
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
            accumulator_commitment: commitment,
            committee_root: COMMITTEE_ROOT,
            target_epoch,
            target_root,
            attesting_balance: 2 * 32_000_000_000,
            slots_mask: 0b011,
        },
        SlotProofOutput {
            accumulator_commitment: commitment,
            committee_root: COMMITTEE_ROOT,
            target_epoch,
            target_root,
            attesting_balance: 2 * 32_000_000_000,
            slots_mask: 0b110,
        },
    ];

    let witness = JustificationWitness {
        slot_program_vk: [0; 4],
        committee_program_vk: [0; 4],
        accumulator_commitment: commitment,
        acc_root,
        target_epoch,
        target_root,
        total_active_balance,
        committee: committee_output(commitment, target_epoch),
        committee_proof: vec![],
        slot_proof_outputs,
        slot_proofs: vec![vec![], vec![]],
    };

    zkasper_justification_guest::verify_justification(&witness);
}

#[test]
#[should_panic(expected = "insufficient attesting balance")]
fn test_justification_rejects_insufficient_balance() {
    let acc_root = [42u64; 4];
    let total_active_balance: u64 = 4 * 32_000_000_000; // 128 ETH total
    let commitment = acc::commitment(&acc_root, total_active_balance);
    let target_epoch = 100u64;
    let target_root = [7u8; 32];

    // One slot carrying one validator (32 ETH) — not enough for 2/3 of 128 ETH
    let witness = JustificationWitness {
        slot_program_vk: [0; 4],
        committee_program_vk: [0; 4],
        accumulator_commitment: commitment,
        acc_root,
        target_epoch,
        target_root,
        total_active_balance,
        committee: committee_output(commitment, target_epoch),
        committee_proof: vec![],
        slot_proof_outputs: vec![SlotProofOutput {
            accumulator_commitment: commitment,
            committee_root: COMMITTEE_ROOT,
            target_epoch,
            target_root,
            attesting_balance: 32_000_000_000,
            slots_mask: 0b1,
        }],
        slot_proofs: vec![vec![]],
    };

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
    just_e1: JustificationOutput,
    epoch_diff_output: EpochDiffOutput,
) -> FinalizationWitness {
    FinalizationWitness {
        justification_program_vk: [0; 4],
        epoch_diff_program_vk: [0; 4],
        boundary: fin().anchor,
        justification_outputs: vec![just_e, just_e1],
        justification_proofs: vec![vec![], vec![]], // empty proofs (stub verifier)
        epoch_diff_output,
        epoch_diff_proof: vec![],
    }
}

#[test]
fn test_finalization_round_trip() {
    let (commitment_e, commitment_e1, diff) = linked_accumulators();

    let just_e = JustificationOutput {
        accumulator_commitment: commitment_e,
        target_epoch: 100,
        target_root: fin_root(),
    };
    let just_e1 = JustificationOutput {
        accumulator_commitment: commitment_e1,
        target_epoch: 101,
        target_root: fin().justified_root,
    };

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

    let output = zkasper_finalization_guest::verify_finalization(&FinalizationWitness {
        justification_program_vk: [0; 4],
        epoch_diff_program_vk: [0; 4],
        boundary: empty.anchor,
        justification_outputs: vec![
            JustificationOutput {
                accumulator_commitment: commitment_e,
                target_epoch: 100,
                target_root: empty.finalized_root,
            },
            JustificationOutput {
                accumulator_commitment: commitment_e1,
                target_epoch: 101,
                target_root: empty.justified_root,
            },
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

    let just_e = JustificationOutput {
        accumulator_commitment: commitment_e,
        target_epoch: 100,
        // A real header root, from a block the justified chain never had there.
        target_root: boundary(3198, [0xEEu8; 32]).finalized_root,
    };
    let just_e1 = JustificationOutput {
        accumulator_commitment: commitment_e1,
        target_epoch: 101,
        target_root: fin().justified_root,
    };

    zkasper_finalization_guest::verify_finalization(&finalization_witness(just_e, just_e1, diff));
}

/// The opening only means anything against the checkpoint the attesters signed.
#[test]
#[should_panic(expected = "justified header does not hash to the justified root")]
fn test_finalization_rejects_a_boundary_opened_off_another_state() {
    let (commitment_e, commitment_e1, diff) = linked_accumulators();

    let just_e = JustificationOutput {
        accumulator_commitment: commitment_e,
        target_epoch: 100,
        target_root: fin_root(),
    };
    let just_e1 = JustificationOutput {
        accumulator_commitment: commitment_e1,
        target_epoch: 101,
        // The epoch was justified for one checkpoint; the anchor hangs off
        // another one's state.
        target_root: boundary(3198, [0xEEu8; 32]).justified_root,
    };

    zkasper_finalization_guest::verify_finalization(&finalization_witness(just_e, just_e1, diff));
}

#[test]
#[should_panic(expected = "justification epochs not consecutive")]
fn test_finalization_rejects_non_consecutive_epochs() {
    let (commitment_e, commitment_e1, diff) = linked_accumulators();

    let just_e = JustificationOutput {
        accumulator_commitment: commitment_e,
        target_epoch: 100,
        target_root: fin_root(),
    };
    // Epoch 102 instead of 101 — not consecutive!
    let just_e2 = JustificationOutput {
        accumulator_commitment: commitment_e1,
        target_epoch: 102,
        target_root: fin().justified_root,
    };

    zkasper_finalization_guest::verify_finalization(&finalization_witness(just_e, just_e2, diff));
}

#[test]
#[should_panic(expected = "epoch diff does not start from the accumulator")]
fn test_finalization_rejects_a_diff_from_another_accumulator() {
    let (_, commitment_e1, diff) = linked_accumulators();

    // Epoch E was justified against an accumulator this diff never touched —
    // exactly the pairing of two unrelated branches the diff is there to stop.
    let just_e = JustificationOutput {
        accumulator_commitment: [99u64; 4],
        target_epoch: 100,
        target_root: fin_root(),
    };
    let just_e1 = JustificationOutput {
        accumulator_commitment: commitment_e1,
        target_epoch: 101,
        target_root: fin().justified_root,
    };

    zkasper_finalization_guest::verify_finalization(&finalization_witness(just_e, just_e1, diff));
}

#[test]
#[should_panic(expected = "epoch diff does not end at the accumulator")]
fn test_finalization_rejects_a_diff_to_another_accumulator() {
    let (commitment_e, _, diff) = linked_accumulators();

    let just_e = JustificationOutput {
        accumulator_commitment: commitment_e,
        target_epoch: 100,
        target_root: fin_root(),
    };
    let just_e1 = JustificationOutput {
        accumulator_commitment: [99u64; 4],
        target_epoch: 101,
        target_root: fin().justified_root,
    };

    zkasper_finalization_guest::verify_finalization(&finalization_witness(just_e, just_e1, diff));
}

#[test]
#[should_panic(expected = "epoch diff starts at epoch")]
fn test_finalization_rejects_a_diff_labelled_with_other_epochs() {
    let (commitment_e, commitment_e1, mut diff) = linked_accumulators();
    diff.epoch_1 = 7;
    diff.epoch_2 = 8;

    let just_e = JustificationOutput {
        accumulator_commitment: commitment_e,
        target_epoch: 100,
        target_root: fin_root(),
    };
    let just_e1 = JustificationOutput {
        accumulator_commitment: commitment_e1,
        target_epoch: 101,
        target_root: fin().justified_root,
    };

    zkasper_finalization_guest::verify_finalization(&finalization_witness(just_e, just_e1, diff));
}

#[test]
#[should_panic(expected = "built from a different state than the boundary")]
fn test_finalization_rejects_an_accumulator_built_off_another_state() {
    let (commitment_e, commitment_e1, mut diff) = linked_accumulators();
    diff.state_root_1 = [0x77u8; 32];

    let just_e = JustificationOutput {
        accumulator_commitment: commitment_e,
        target_epoch: 100,
        target_root: fin_root(),
    };
    let just_e1 = JustificationOutput {
        accumulator_commitment: commitment_e1,
        target_epoch: 101,
        target_root: fin().justified_root,
    };

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
        slot_program_vk: [0; 4],
        committee_program_vk: [0; 4],
        accumulator_commitment: commitment_e,
        acc_root: diff.acc_root,
        target_epoch: 100,
        target_root: epoch_100_root,
        total_active_balance: diff.total_active_balance + 1_000_000_000,
        committee: committee_output(commitment_e, 100),
        committee_proof: vec![],
        slot_proof_outputs: vec![SlotProofOutput {
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
        slot_program_vk: [0; 4],
        committee_program_vk: [0; 4],
        accumulator_commitment: commitment_e1,
        acc_root: diff.acc_root,
        target_epoch: 101,
        target_root: epoch_101_root,
        total_active_balance: diff.total_active_balance,
        committee: committee_output(commitment_e1, 101),
        committee_proof: vec![],
        slot_proof_outputs: vec![SlotProofOutput {
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

//! End-to-end test: bootstrap → slot proofs → justification → finalization → epoch diff.
//!
//! Uses 4 validators with real BLS signatures from deterministic secret keys.
//! Small tree depths (2) for fast execution.

mod common;

use common::{make_header, validator_data_to_response, MockBeaconApi};

use zkasper_common::acc;
use zkasper_common::bls::{compute_domain, compute_signing_root, DOMAIN_BEACON_ATTESTER};
use zkasper_common::ssz::attestation_data_root;
use zkasper_common::types::*;
use zkasper_common::ChainConfig;
use zkasper_witness_gen::acc_tree::AccTree;
use zkasper_witness_gen::beacon_api::{CommitteeResponse, ValidatorResponse};
use zkasper_witness_gen::committee::EpochCommittees;

const TEST_CONFIG: ChainConfig = ChainConfig {
    slots_per_epoch: 4,
    validators_tree_depth: 2,
    acc_tree_depth: 2,
    beacon_state_validators_field_index: 11,
    fulu_fork_epoch: 0,
};

const TEST_DEPTH: u32 = 2;

// ---------------------------------------------------------------------------
// BLS key generation helpers
// ---------------------------------------------------------------------------

fn generate_test_keys(n: usize) -> Vec<(blst::min_pk::SecretKey, [u8; 48])> {
    (0..n)
        .map(|i| {
            let mut ikm = [0u8; 32];
            ikm[0] = i as u8;
            ikm[1] = 0xAB; // ensure min 32 bytes entropy
            let sk = blst::min_pk::SecretKey::key_gen(&ikm, &[]).unwrap();
            let pk = sk.sk_to_pk();
            let pk_bytes: [u8; 48] = pk.to_bytes();
            (sk, pk_bytes)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Committees and complements
// ---------------------------------------------------------------------------

/// Sum the epoch's committees out of the accumulator.
///
/// Two committees of two, which is the smallest shape that still partitions the
/// validator set — and a partition is all the committee proof needs it to be.
fn committees(
    validators: &[ValidatorData],
    responses: &[ValidatorResponse],
    tree: &AccTree,
    epoch: u64,
    total_active_balance: u64,
) -> EpochCommittees {
    let table: Vec<CommitteeResponse> = (0..validators.len() as u64 / 2)
        .map(|slot| CommitteeResponse {
            slot: epoch * TEST_CONFIG.slots_per_epoch + slot,
            index: 0,
            validators: vec![slot * 2, slot * 2 + 1],
        })
        .collect();

    zkasper_witness_gen::committee::build(
        &table,
        responses,
        tree,
        &TEST_CONFIG,
        epoch,
        epoch,
        total_active_balance,
    )
    .unwrap()
}

/// One slot's complement, with the whole committee attesting.
///
/// Nothing is named, so nothing is opened against the accumulator: the aggregate
/// public key the signature is checked against is the committee's own, and the
/// support is the committee's own balance.
#[allow(clippy::too_many_arguments)]
fn complement(
    keys: &[(blst::min_pk::SecretKey, [u8; 48])],
    committees: &EpochCommittees,
    slot_in_epoch: u64,
    epoch: u64,
    target_root: [u8; 32],
    source_epoch: u64,
    source_root: [u8; 32],
    signing_domain: [u8; 32],
) -> SlotComplementWitness {
    let data_slot = epoch * TEST_CONFIG.slots_per_epoch + slot_in_epoch;
    let signing_root = compute_signing_root(
        &attestation_data_root(
            data_slot,
            0,
            &[0u8; 32],
            source_epoch,
            &source_root,
            epoch,
            &target_root,
        ),
        &signing_domain,
    );

    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    let signatures: Vec<blst::min_pk::Signature> = committees.members[slot_in_epoch as usize]
        .iter()
        .map(|&i| keys[i as usize].0.sign(&signing_root, dst, &[]))
        .collect();
    let refs: Vec<&blst::min_pk::Signature> = signatures.iter().collect();

    SlotComplementWitness {
        slot_in_epoch,
        committee: committees.aggregate(slot_in_epoch).unwrap().clone(),
        primary: vec![AttestationWitness {
            data_slot,
            data_index: 0,
            data_beacon_block_root: [0u8; 32],
            data_source_epoch: source_epoch,
            data_source_root: source_root,
            data_target_epoch: epoch,
            data_target_root: target_root,
            signature: BlsSignature(
                blst::min_pk::AggregateSignature::aggregate(&refs, true)
                    .unwrap()
                    .to_signature()
                    .to_bytes(),
            ),
            attesting_validators: Vec::new(),
        }],
        secondary: Vec::new(),
        absentees: Vec::new(),
    }
}

/// The witness for one slot proof over one committee's complement.
#[allow(clippy::too_many_arguments)]
fn slot_witness(
    committees: &EpochCommittees,
    slot: SlotComplementWitness,
    accumulator_commitment: acc::Digest,
    acc_root: acc::Digest,
    total_active_balance: u64,
    target_epoch: u64,
    target_root: [u8; 32],
    signing_domain: [u8; 32],
) -> SlotProofWitness {
    SlotProofWitness {
        accumulator_commitment,
        committee_root: committees.root(),
        target_epoch,
        target_root,
        signing_domain,
        acc_root,
        total_active_balance,
        acc_multi_proof: AccMultiProof::default(),
        committee_multi_proof: committees.multi_proof(&[slot.slot_in_epoch]),
        slots: vec![slot],
    }
}

// ---------------------------------------------------------------------------
// Full E2E test
// ---------------------------------------------------------------------------

/// Bootstrap, justify epoch E, move the accumulator with an epoch diff that
/// actually changes an effective balance, justify E+1 against the accumulator
/// that diff produced, and finalize the pair.
///
/// The balance change is the point. Effective balances are rewritten at every
/// epoch transition, so on a live chain the two justifications of a finalizing
/// pair are never proved against the same accumulator. A test where nothing
/// moves would pass against a finalization circuit that simply required the two
/// commitments to be equal, which is the bug this shape exists to catch.
#[test]
fn test_e2e_full_pipeline() {
    // 1. Generate 4 BLS key pairs
    let keys = generate_test_keys(4);
    let balance_gwei = 32_000_000_000u64;

    // 2. Create validator data with real pubkeys
    let validators: Vec<ValidatorData> = keys
        .iter()
        .map(|(_, pk)| ValidatorData {
            pubkey: BlsPubkey(*pk),
            effective_balance: balance_gwei,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
        })
        .collect();

    let total_active_balance = 4 * balance_gwei;

    // 3. Compute signing domain (synthetic fork version + genesis validators root)
    let fork_version = [0x04, 0x00, 0x00, 0x00]; // Electra
    let genesis_validators_root = [0xAA; 32];
    let signing_domain = compute_domain(
        &DOMAIN_BEACON_ATTESTER,
        &fork_version,
        &genesis_validators_root,
    );

    // 4. Build the accumulator tree
    let epoch_e = 10u64;
    let epoch_e1 = epoch_e + 1;
    let acc_tree = AccTree::build(&validators, epoch_e, TEST_DEPTH);
    let acc_root = acc_tree.root();
    let commitment = acc::commitment(&acc_root, total_active_balance);

    let source_root = [0x01u8; 32];

    // =========================================================
    // Step A: Bootstrap at slot E*4
    // =========================================================
    let bootstrap_slot = epoch_e * TEST_CONFIG.slots_per_epoch;

    let responses: Vec<_> = validators
        .iter()
        .enumerate()
        .map(|(i, v)| validator_data_to_response(v, i as u64))
        .collect();

    let mut mock = MockBeaconApi::new();
    let header_e = make_header(bootstrap_slot, &responses, TEST_DEPTH);
    // Epoch E's checkpoint is the block at its first slot, so its root is that
    // header's own root. The finalization circuit opens the header and checks
    // it against the root the attesters signed.
    let target_root_e = common::header_root(&header_e);
    mock.validators
        .insert(bootstrap_slot.to_string(), responses.clone());
    mock.headers
        .insert(bootstrap_slot.to_string(), header_e.clone());

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (bootstrap_witness, tree, _epoch_state, boot_balance, boot_count) = rt
        .block_on(zkasper_witness_gen::witness_bootstrap::build(
            &mock,
            &TEST_CONFIG,
            bootstrap_slot,
        ))
        .unwrap();

    assert_eq!(boot_count, 4);
    assert_eq!(boot_balance, total_active_balance);

    // Verify bootstrap
    let (boot_commitment, boot_poseidon_root, boot_total_balance) =
        zkasper_bootstrap_guest::verify_bootstrap_with_depth(
            &bootstrap_witness,
            TEST_DEPTH,
            TEST_DEPTH,
        );

    assert_eq!(boot_poseidon_root, tree.root());
    assert_eq!(boot_poseidon_root, acc_root);
    assert_eq!(boot_total_balance, total_active_balance);
    assert_eq!(boot_commitment, commitment);

    eprintln!("✓ Bootstrap verified");

    // =========================================================
    // Step B: Slot proofs for epoch E (2 committees, both fully attesting)
    // =========================================================
    let committees_e = committees(
        &validators,
        &responses,
        &tree,
        epoch_e,
        total_active_balance,
    );

    let outputs_e: Vec<SlotProofOutput> = (0..2)
        .map(|slot_in_epoch| {
            zkasper_slot_proof_guest::verify_slot_proof_with_depth(
                &slot_witness(
                    &committees_e,
                    complement(
                        &keys,
                        &committees_e,
                        slot_in_epoch,
                        epoch_e,
                        target_root_e,
                        epoch_e.saturating_sub(1),
                        source_root,
                        signing_domain,
                    ),
                    commitment,
                    acc_root,
                    total_active_balance,
                    epoch_e,
                    target_root_e,
                    signing_domain,
                ),
                TEST_DEPTH,
            )
        })
        .collect();

    assert_eq!(outputs_e[0].accumulator_commitment, commitment);
    assert_eq!(outputs_e[0].target_epoch, epoch_e);
    assert_eq!(outputs_e[0].target_root, target_root_e);
    assert_eq!(outputs_e[0].attesting_balance, 2 * balance_gwei);
    assert_eq!(outputs_e[0].slots_mask, 0b01);
    assert_eq!(outputs_e[1].attesting_balance, 2 * balance_gwei);
    assert_eq!(outputs_e[1].slots_mask, 0b10);

    eprintln!("✓ Slot proofs (epoch E) verified");

    // =========================================================
    // Step C: Justification for epoch E
    // =========================================================
    let just_e_witness = JustificationWitness {
        slot_program_vk: [0; 4],
        committee_program_vk: [0; 4],
        committee: committees_e.output.clone(),
        committee_proof: vec![], // stub proof
        accumulator_commitment: commitment,
        acc_root,
        target_epoch: epoch_e,
        target_root: target_root_e,
        total_active_balance,
        slot_proof_outputs: outputs_e,
        slot_proofs: vec![vec![], vec![]], // stub proofs
    };

    let just_e_output = zkasper_justification_guest::verify_justification(&just_e_witness);

    assert_eq!(just_e_output.accumulator_commitment, commitment);
    assert_eq!(just_e_output.target_epoch, epoch_e);
    assert_eq!(just_e_output.target_root, target_root_e);

    eprintln!("✓ Justification (epoch E) verified");

    // =========================================================
    // Step D: Epoch diff E → E+1 (validator 0's balance: 32 → 16 ETH)
    // =========================================================
    let slot_e1_0 = epoch_e1 * TEST_CONFIG.slots_per_epoch;

    let mut validators_e1 = validators.clone();
    validators_e1[0].effective_balance = 16_000_000_000;
    let total_active_balance_e1 = 16_000_000_000 + 3 * balance_gwei;

    let responses_e1: Vec<_> = validators_e1
        .iter()
        .enumerate()
        .map(|(i, v)| validator_data_to_response(v, i as u64))
        .collect();

    let header_e1 = make_header(slot_e1_0, &responses_e1, TEST_DEPTH);
    let target_root_e1 = common::header_root(&header_e1);
    mock.validators
        .insert(slot_e1_0.to_string(), responses_e1.clone());
    mock.headers.insert(slot_e1_0.to_string(), header_e1);

    let old_state = zkasper_witness_gen::EpochState::empty(bootstrap_slot, 4);
    let mut tree_e1 = tree.clone();

    let (epoch_diff_witness, _new_epoch_state, new_balance, new_count) = rt
        .block_on(zkasper_witness_gen::witness_epoch_diff::build(
            &mock,
            &TEST_CONFIG,
            &mut tree_e1,
            &old_state,
            slot_e1_0,
            total_active_balance,
        ))
        .unwrap();

    assert_eq!(new_count, 4);
    assert_eq!(new_balance, total_active_balance_e1);

    let diff = zkasper_epoch_diff_guest::verify_epoch_diff_with_depth(
        &epoch_diff_witness,
        TEST_DEPTH,
        TEST_DEPTH,
    );

    let acc_root_e1 = tree_e1.root();
    let commitment_e1 = diff.accumulator_commitment;

    assert_eq!(diff.acc_root, acc_root_e1);
    assert_eq!(diff.total_active_balance, new_balance);
    assert_eq!(diff.epoch_1, epoch_e);
    assert_eq!(diff.epoch_2, epoch_e1);
    // The diff starts from the accumulator epoch E was justified against, and
    // arrives at a different one — the whole reason finalization needs it.
    assert_eq!(diff.prev_accumulator_commitment, commitment);
    assert_ne!(commitment_e1, commitment);
    assert_eq!(
        commitment_e1,
        acc::commitment(&acc_root_e1, new_balance),
        "commitment must bind the new root and balance",
    );
    // And it is built from the state the finalized block produced.
    assert_eq!(diff.state_root_1, header_e.state_root);

    eprintln!(
        "✓ Epoch diff verified: balance {} → {}",
        total_active_balance, new_balance
    );

    // =========================================================
    // Step E: Slot proofs for epoch E+1, against the new accumulator
    // =========================================================
    assert_eq!(
        AccTree::build(&validators_e1, epoch_e1, TEST_DEPTH).root(),
        acc_root_e1,
        "the diff's incremental update must match a tree rebuilt from scratch",
    );

    let committees_e1 = committees(
        &validators_e1,
        &responses_e1,
        &tree_e1,
        epoch_e1,
        new_balance,
    );

    let outputs_e1: Vec<SlotProofOutput> = (0..2)
        .map(|slot_in_epoch| {
            zkasper_slot_proof_guest::verify_slot_proof_with_depth(
                &slot_witness(
                    &committees_e1,
                    complement(
                        &keys,
                        &committees_e1,
                        slot_in_epoch,
                        epoch_e1,
                        target_root_e1,
                        epoch_e,
                        target_root_e,
                        signing_domain,
                    ),
                    commitment_e1,
                    acc_root_e1,
                    new_balance,
                    epoch_e1,
                    target_root_e1,
                    signing_domain,
                ),
                TEST_DEPTH,
            )
        })
        .collect();

    // Validator 0 now carries 16 ETH, so its committee's balance moved with it.
    assert_eq!(
        outputs_e1[0].attesting_balance,
        16_000_000_000 + balance_gwei
    );

    eprintln!("✓ Slot proofs (epoch E+1) verified");

    // =========================================================
    // Step F: Justification for epoch E+1
    // =========================================================
    let just_e1_witness = JustificationWitness {
        slot_program_vk: [0; 4],
        committee_program_vk: [0; 4],
        committee: committees_e1.output.clone(),
        committee_proof: vec![],
        accumulator_commitment: commitment_e1,
        acc_root: acc_root_e1,
        target_epoch: epoch_e1,
        target_root: target_root_e1,
        total_active_balance: new_balance,
        slot_proof_outputs: outputs_e1,
        slot_proofs: vec![vec![], vec![]],
    };

    let just_e1_output = zkasper_justification_guest::verify_justification(&just_e1_witness);

    assert_eq!(just_e1_output.accumulator_commitment, commitment_e1);
    assert_eq!(just_e1_output.target_epoch, epoch_e1);

    eprintln!("✓ Justification (epoch E+1) verified");

    // =========================================================
    // Step G: Finalization across the epoch boundary
    // =========================================================
    let finalization_witness = FinalizationWitness {
        justification_program_vk: [0; 4],
        epoch_diff_program_vk: [0; 4],
        finalized_header: header_e.fields(),
        justification_outputs: vec![just_e_output, just_e1_output],
        justification_proofs: vec![vec![], vec![]],
        epoch_diff_output: diff,
        epoch_diff_proof: vec![],
    };

    let finalization_output =
        zkasper_finalization_guest::verify_finalization(&finalization_witness);

    assert_eq!(finalization_output.accumulator_commitment, commitment);
    assert_eq!(
        finalization_output.next_accumulator_commitment,
        commitment_e1
    );
    assert_eq!(finalization_output.finalized_epoch, epoch_e);
    assert_eq!(finalization_output.finalized_root, target_root_e);
    assert_eq!(
        finalization_output.finalized_state_root,
        header_e.state_root
    );

    eprintln!(
        "✓ Finalization verified across an epoch boundary: epoch={}, root=0x{}",
        epoch_e,
        hex::encode(target_root_e)
    );

    // =========================================================
    // Accumulator commitment chain
    // =========================================================
    assert_eq!(boot_commitment, commitment);
    assert_eq!(
        epoch_diff_witness.acc_root_1, acc_root,
        "epoch diff should start from bootstrap's poseidon root"
    );
    assert_eq!(
        epoch_diff_witness.total_active_balance_1, total_active_balance,
        "epoch diff should start from bootstrap's total balance"
    );

    eprintln!("✓ Full E2E pipeline passed!");
    eprintln!("  Bootstrap → Slot proofs (epoch E) → Justification E → Epoch diff → Slot proofs (epoch E+1) → Justification E+1 → Finalization");
}

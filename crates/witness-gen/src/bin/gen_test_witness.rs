//! Generate test witness binary files for Zisk proof testing.
//!
//! Usage: cargo run --bin gen-test-witness -- <proof-type> <output-path>
//!   proof-type: epoch-diff | slot-proof | justification | finalization

use std::collections::HashMap;

use zkasper_common::acc;
use zkasper_common::constants::FAR_FUTURE_EPOCH;
use zkasper_common::test_utils::make_validator;
use zkasper_common::types::*;
use zkasper_common::ChainConfig;

use zkasper_witness_gen::beacon_api::{BeaconApi, HeaderResponse, ValidatorResponse};
use zkasper_witness_gen::child_vks;
use zkasper_witness_gen::fixture::Epoch;
use zkasper_witness_gen::state_diff::{
    build_validator_roots, build_validators_ssz_tree, make_state_proof,
};

// Use MAINNET config so the guest binary (which uses default production depths) works.
const CONFIG: ChainConfig = ChainConfig::MAINNET;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn validator_data_to_response(data: &ValidatorData, index: u64) -> ValidatorResponse {
    ValidatorResponse {
        index,
        pubkey: data.pubkey.0,
        effective_balance: data.effective_balance,
        activation_epoch: data.activation_epoch,
        exit_epoch: data.exit_epoch,
        withdrawal_credentials: {
            let mut wc = [0u8; 32];
            wc[0] = 0x01;
            wc
        },
        slashed: false,
        activation_eligibility_epoch: 0,
        withdrawable_epoch: FAR_FUTURE_EPOCH,
    }
}

fn make_header(slot: u64, validators: &[ValidatorResponse]) -> HeaderResponse {
    let validator_roots = build_validator_roots(validators);
    let (ssz_data_root, _) =
        build_validators_ssz_tree(&validator_roots, CONFIG.validators_tree_depth, &[]);
    let (state_root, _) = make_state_proof(
        &ssz_data_root,
        validators.len() as u64,
        &zkasper_witness_gen::state_diff::SlotHistory::default(),
    );
    HeaderResponse {
        slot,
        proposer_index: 0,
        state_root,
        parent_root: [0u8; 32],
        body_root: [0u8; 32],
    }
}

/// In-memory mock beacon API
struct MockBeaconApi {
    validators: HashMap<String, Vec<ValidatorResponse>>,
    headers: HashMap<String, HeaderResponse>,
}

#[async_trait::async_trait]
impl BeaconApi for MockBeaconApi {
    async fn get_validators(&self, state_id: &str) -> anyhow::Result<Vec<ValidatorResponse>> {
        self.validators
            .get(state_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no validators for {state_id}"))
    }
    async fn get_block_attestations(
        &self,
        _block_id: &str,
    ) -> anyhow::Result<Vec<zkasper_witness_gen::beacon_api::AttestationResponse>> {
        Ok(vec![])
    }
    async fn get_committees(
        &self,
        _state_id: &str,
        _epoch: u64,
    ) -> anyhow::Result<Vec<zkasper_witness_gen::beacon_api::CommitteeResponse>> {
        Ok(vec![])
    }
    async fn get_header(&self, block_id: &str) -> anyhow::Result<HeaderResponse> {
        self.headers
            .get(block_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no header for {block_id}"))
    }
    async fn get_state_ssz(&self, _state_id: &str) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(None)
    }

    async fn get_state_root(&self, _state_id: &str) -> anyhow::Result<Option<[u8; 32]>> {
        // No independent state root here; the caller reads the header instead.
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Epoch diff
// ---------------------------------------------------------------------------

fn gen_epoch_diff(output_path: &str) {
    let slot_1 = 3200u64;
    let slot_2 = 3232u64;

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

    let mut mock = MockBeaconApi {
        validators: HashMap::new(),
        headers: HashMap::new(),
    };
    let header_1 = make_header(slot_1, &responses_1);
    let header_2 = make_header(slot_2, &responses_2);
    mock.validators.insert(slot_1.to_string(), responses_1);
    mock.validators.insert(slot_2.to_string(), responses_2);
    mock.headers.insert(slot_1.to_string(), header_1);
    mock.headers.insert(slot_2.to_string(), header_2);

    let rt = tokio::runtime::Runtime::new().unwrap();

    let (init, mut snapshot) = rt
        .block_on(zkasper_witness_gen::init_point::take(
            &mock, &CONFIG, "test", slot_1,
        ))
        .unwrap();

    let (witness, _, _, _) = rt
        .block_on(zkasper_witness_gen::witness_epoch_diff::build(
            &mock,
            &CONFIG,
            &mut snapshot.tree,
            &snapshot.epoch_state,
            slot_2,
            init.total_active_balance,
        ))
        .unwrap();

    let bytes = bincode::serialize(&witness).unwrap();
    std::fs::write(output_path, &bytes).unwrap();
    eprintln!(
        "wrote epoch-diff witness: {} bytes -> {output_path}",
        bytes.len()
    );
}

// ---------------------------------------------------------------------------
// Slot proof
// ---------------------------------------------------------------------------

/// Two committees, `per_slot` validators each.
///
/// Small by default, but the shape is the real one: a committee summed out of
/// the accumulator, a derived aggregate key, and an absentee opened against a
/// leaf. The size is a parameter so a bench can generate a witness at whatever
/// scale it wants to measure.
fn fixture(per_slot: usize) -> Epoch {
    Epoch::new(CONFIG, 100, 2, per_slot)
}

/// Build the witness for one slot's complement.
fn slot_witness(fixture: &Epoch, slot_in_epoch: u64, absent: &[u64]) -> SlotProofWitness {
    let complement = fixture.complement(slot_in_epoch, absent);
    SlotProofWitness {
        accumulator_commitment: fixture.accumulator_commitment,
        committee_root: fixture.committees.root(),
        target_epoch: fixture.epoch,
        target_root: fixture.target_root,
        signing_domain: fixture.signing_domain,
        acc_root: fixture.acc_root,
        total_active_balance: fixture.total_active_balance,
        acc_multi_proof: fixture.tree.build_multi_proof(&complement.named_indices),
        committee_multi_proof: fixture.committees.multi_proof(&[slot_in_epoch]),
        slots: vec![complement.witness],
    }
}

fn gen_slot_proof(output_path: &str) {
    let fixture = fixture(2);
    let witness = slot_witness(&fixture, 0, &[1]);

    let bytes = bincode::serialize(&witness).unwrap();
    std::fs::write(output_path, &bytes).unwrap();
    eprintln!(
        "wrote slot-proof witness: {} bytes -> {output_path}",
        bytes.len()
    );
}

// ---------------------------------------------------------------------------
// Committee
// ---------------------------------------------------------------------------

/// A whole epoch of committees, which is the one witness whose size is the
/// validator set rather than the absentees — and therefore the only one whose
/// framing was ever worth measuring.
///
/// `n_validators` is spread over all the epoch's slots, so the shape is
/// mainnet's: one bucket per slot, every index opened exactly once, and the
/// opened set one contiguous range.
fn gen_committee(output_path: &str, n_validators: usize) {
    let slots = CONFIG.slots_per_epoch;
    let fixture = Epoch::new(CONFIG, 100, slots, n_validators.div_ceil(slots as usize));

    let bytes = zkasper_common::committee::to_bytes(&zkasper_common::committee::encode(
        &fixture.committees.witness,
    ));
    std::fs::write(output_path, &bytes).unwrap();
    eprintln!(
        "wrote committee witness: {} members, {} bytes -> {output_path}",
        fixture.committees.witness.members.len(),
        bytes.len(),
    );
}

// ---------------------------------------------------------------------------
// Justification
// ---------------------------------------------------------------------------

fn gen_justification(output_path: &str) {
    let fixture = fixture(2);

    let outputs: Vec<SlotProofOutput> = (0..2)
        .map(|slot| {
            zkasper_slot_proof_guest::verify_slot_proof_with_depth(
                &slot_witness(&fixture, slot, &[]),
                CONFIG.acc_tree_depth,
            )
        })
        .collect();

    let witness = JustificationWitness {
        accumulator_commitment: fixture.accumulator_commitment,
        acc_root: fixture.acc_root,
        target_epoch: fixture.epoch,
        target_root: fixture.target_root,
        total_active_balance: fixture.total_active_balance,
        justification_program_vk: child_vks::JUSTIFICATION,
        committee: Some(fixture.committees.output.clone()),
        committee_proof: Vec::new(),
        // The link that opens an epoch, which is the only one whose witness can
        // be written without a real child proof to extend.
        previous: None,
        previous_proof: Vec::new(),
        slot_proof_outputs: outputs,
        slot_proofs: vec![vec![], vec![]], // native mode: no real child proofs
    };

    let bytes = bincode::serialize(&witness).unwrap();
    std::fs::write(output_path, &bytes).unwrap();
    eprintln!(
        "wrote justification witness: {} bytes -> {output_path}",
        bytes.len()
    );
}

// ---------------------------------------------------------------------------
// Finalization
// ---------------------------------------------------------------------------

fn gen_finalization(output_path: &str) {
    let data = fixture(2);
    let epoch_e = data.epoch - 1;
    let epoch_e1 = data.epoch;
    // The finalized root is the checkpoint at epoch E's boundary, and the state
    // root that anchors the accumulator is what E+1's checkpoint state records
    // for that slot — two different things whenever the slot is empty.
    let target_root_e = data.previous_root;
    let target_root_e1 = data.target_root;

    // Epoch E+1 is justified against a *different* accumulator: one validator's
    // effective balance moved over the epoch transition, which is the normal
    // case on a live chain. The epoch diff below is what ties the two together.
    let commitment_e1 = acc::commitment(&data.acc_root, data.total_active_balance - 1_000_000_000);
    let epoch_diff_output = EpochDiffOutput {
        prev_accumulator_commitment: data.accumulator_commitment,
        state_root_1: data.previous_state_root,
        epoch_1: epoch_e,
        accumulator_commitment: commitment_e1,
        acc_root: data.acc_root,
        total_active_balance: data.total_active_balance - 1_000_000_000,
        state_root_2: [0xCDu8; 32],
        epoch_2: epoch_e1,
    };

    let just_e = zkasper_common::test_utils::justified_output(
        child_vks::JUSTIFICATION,
        data.accumulator_commitment,
        epoch_e,
        target_root_e,
    );
    let just_e1 = zkasper_common::test_utils::justified_output(
        child_vks::JUSTIFICATION,
        commitment_e1,
        epoch_e1,
        target_root_e1,
    );

    let witness = FinalizationWitness {
        boundary: data.boundary,
        justification_outputs: vec![just_e, just_e1],
        justification_proofs: vec![vec![], vec![]], // stub proofs
        epoch_diff_output,
        epoch_diff_proof: vec![],
    };

    let bytes = bincode::serialize(&witness).unwrap();
    std::fs::write(output_path, &bytes).unwrap();
    eprintln!(
        "wrote finalization witness: {} bytes -> {output_path}",
        bytes.len()
    );
}

// ---------------------------------------------------------------------------
// Streaming: group, aggregation, final
// ---------------------------------------------------------------------------

/// Run the streaming pipeline over two aggregates and keep every witness it fed
/// to a circuit.
///
/// The three streaming witnesses have to agree with each other — a group's
/// Miller accumulator is bound by the aggregate that folds it, and the
/// aggregate's counted-set root by the proof that closes the epoch — so they are
/// generated from one run rather than assembled separately.
fn gen_stream(output_path: &str, stage: &str, n_validators: usize) {
    use zkasper_common::types::{EpochDiffOutput, PreviousJustification};
    use zkasper_witness_gen::streaming::{self, StreamPolicy};

    let data = fixture(n_validators / 2);
    let epoch = data.epoch;
    let target_root = data.target_root;

    // The epoch this one finalizes, and the diff that carried the accumulator
    // from there to here.
    let previous_commitment =
        acc::commitment(&data.acc_root, data.total_active_balance - 1_000_000_000);

    let context = streaming::StreamContext {
        accumulator_commitment: data.accumulator_commitment,
        acc_root: data.acc_root,
        total_active_balance: data.total_active_balance,
        target_epoch: epoch,
        target_root,
        signing_domain: data.signing_domain,
        aggregate_program_vk: child_vks::AGGREGATE,
        stream_program_vk: zkasper_common::recursion::UNSET_VK,
        epoch_diff: EpochDiffOutput {
            prev_accumulator_commitment: previous_commitment,
            state_root_1: data.previous_state_root,
            epoch_1: epoch - 1,
            accumulator_commitment: data.accumulator_commitment,
            acc_root: data.acc_root,
            total_active_balance: data.total_active_balance,
            state_root_2: [0xCDu8; 32],
            epoch_2: epoch,
        },
        epoch_diff_proof: Vec::new(),
        committee: data.committees.output.clone(),
        committee_proof: Vec::new(),
        acc_depth: CONFIG.acc_tree_depth,
    };

    // Two slots, half the validators each: the first is a group, the second
    // carries the epoch over the threshold and is proven inline by the final
    // proof.
    let units: Vec<_> = (0..2).map(|slot| data.complement(slot, &[])).collect();

    let plan = streaming::plan(&units, data.total_active_balance, &StreamPolicy::default());
    let run = streaming::run_native(
        &context,
        &data.tree,
        &data.committees,
        &units,
        &plan,
        PreviousJustification::Batch(zkasper_common::test_utils::justified_output(
            child_vks::JUSTIFICATION,
            previous_commitment,
            epoch - 1,
            data.previous_root,
        )),
        data.boundary.clone(),
    );

    let bytes = match stage {
        "group-proof" => bincode::serialize(&run.group_witnesses[0]).unwrap(),
        "aggregation" => bincode::serialize(&run.aggregate_witnesses[0]).unwrap(),
        "stream-final" => bincode::serialize(&run.final_witness).unwrap(),
        other => panic!("unknown streaming stage {other}"),
    };
    std::fs::write(output_path, &bytes).unwrap();
    eprintln!(
        "wrote {stage} witness: {} bytes -> {output_path}",
        bytes.len()
    );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 && args.len() != 4 {
        eprintln!(
            "usage: gen-test-witness <epoch-diff|slot-proof|committee|justification|\
             finalization|group-proof|aggregation|stream-final> <output-path> [n-validators]"
        );
        std::process::exit(1);
    }

    match args[1].as_str() {
        "epoch-diff" => gen_epoch_diff(&args[2]),
        "slot-proof" => gen_slot_proof(&args[2]),
        "committee" => gen_committee(
            &args[2],
            args.get(3)
                .map(|a| a.parse().expect("n-validators must be an integer"))
                .unwrap_or(64),
        ),
        "justification" => gen_justification(&args[2]),
        "finalization" => gen_finalization(&args[2]),
        stage @ ("group-proof" | "aggregation" | "stream-final") => gen_stream(
            &args[2],
            stage,
            args.get(3)
                .map(|a| a.parse().expect("n-validators must be an integer"))
                .unwrap_or(4),
        ),
        other => {
            eprintln!("unknown proof type: {other}");
            std::process::exit(1);
        }
    }
}

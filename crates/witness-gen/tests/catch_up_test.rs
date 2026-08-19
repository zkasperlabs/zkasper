//! The first epoch of a run, met the way a fresh daemon meets it.
//!
//! Every other orchestrator test moves the head a slot at a time, which is the
//! steady state and not how a run starts. A run starts on an epoch that is
//! already history: the whole epoch is on chain before the daemon opens it, so
//! the batch pipeline ingests all of it inside one tick, and the 2/3 threshold
//! crosses part-way through that burst rather than several ticks later. That is
//! also the only path a run can start on — a streaming epoch consumes the
//! previous epoch's justification, and the first epoch has none — so this is the
//! epoch whose cost decides whether a run gets started at all.
//!
//! What it costs is the number of children on the critical path, not the number
//! of slots behind them: recursion is [`JUSTIFICATION_RECURSION_S`] a child,
//! MEASURED, and linear. Twenty-two slots proven one at a time are twenty-two
//! children and a justification that outruns the node's state window; the same
//! slots in groups of [`DEFAULT_SLOT_GROUP_WIDTH`] are two. So every assertion
//! here counts children.

mod common;

use std::path::Path;
use std::time::Duration;

use common::SyntheticChain;

use zkasper_common::ChainConfig;
use zkasper_witness_gen::orchestrator::{
    Orchestrator, OrchestratorConfig, Pipeline, DEFAULT_SLOT_GROUP_WIDTH,
};
use zkasper_witness_gen::prover::NativeProver;
use zkasper_witness_gen::streaming::ProverModel;

/// Mainnet's epoch, over a validator set small enough to sign in a test.
///
/// The slot count is the one that matters and it is mainnet's: 32 slots with one
/// attester each crosses 2/3 at the 22nd attestation slot, exactly where mainnet
/// does. Every count below is a function of that 22.
const CATCH_UP_CONFIG: ChainConfig = ChainConfig {
    slots_per_epoch: 32,
    validators_tree_depth: 5,
    acc_tree_depth: 5,
    beacon_state_validators_field_index: 11,
    fulu_fork_epoch: 0,
};
const SPE: u64 = CATCH_UP_CONFIG.slots_per_epoch;
const VALIDATORS: usize = 32;
const EPOCH: u64 = 10;

/// Seconds `justification-guest` spends verifying one child.
///
/// Not [`ProverModel::recursion_verify_s`], which is the price in the streaming
/// guests. A child is not one price across guests: 35.629 s in
/// `aggregation-guest` and `stream-final-guest`, 53.087 s here. MEASURED by
/// `recursion_cost_curve` at two, three and four children, and by mainnet epoch
/// 469424 verifying 23 in 1,224 s in production. `BENCHMARKS.md` has both.
const JUSTIFICATION_RECURSION_S: f64 = 53.087;

fn config(dir: &Path, pipeline: Pipeline) -> OrchestratorConfig {
    OrchestratorConfig {
        db_path: dir.join("zkasperd.db"),
        output_dir: dir.join("out"),
        poll_interval: Duration::ZERO,
        pipeline,
        ..OrchestratorConfig::new(CATCH_UP_CONFIG, "test")
    }
}

/// Files in `dir` whose name starts with `prefix`, sorted.
fn artifacts(dir: &Path, prefix: &str) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("the epoch wrote a directory")
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(prefix) && name.ends_with(".bin"))
        .collect();
    names.sort();
    names
}

/// Prove the first epoch of a run out of a chain that is already past it, and
/// return the epoch's artifact directory.
async fn prove_the_first_epoch(dir: &Path, pipeline: Pipeline) -> std::path::PathBuf {
    let chain = SyntheticChain::new(CATCH_UP_CONFIG, VALIDATORS, EPOCH, EPOCH + 1);
    assert_eq!(
        chain.slots_to_threshold(EPOCH),
        22,
        "the fixture stopped being mainnet-shaped",
    );

    // The head is a whole epoch past the one being proven: nothing is waited
    // for, and the aggregator sees every slot it will ever see in one tick.
    let mock = chain.mock((EPOCH + 1) * SPE + 2);
    let config = OrchestratorConfig {
        init_point: Some(
            zkasper_witness_gen::init_point::generate(&mock, &CATCH_UP_CONFIG, "test", EPOCH * SPE)
                .await
                .expect("the node serves the epoch the run starts on"),
        ),
        ..config(dir, pipeline)
    };
    let mut daemon = Orchestrator::open(mock, config, Box::new(NativeProver::new(CATCH_UP_CONFIG)))
        .await
        .expect("orchestrator opens");

    let tick = daemon.tick().await.expect("the first epoch is proven");

    assert_eq!(
        tick.justified,
        Some(EPOCH),
        "one tick is the whole of a catch-up epoch",
    );
    assert_eq!(
        tick.slots_proved.len() as u64,
        chain.slots_to_threshold(EPOCH),
        "the epoch stops at the slot that crosses 2/3, and proves every slot up to it",
    );

    dir.join("out").join(format!("epoch-{EPOCH:09}"))
}

/// The catch-up epoch is proven in groups, and folded into one link.
///
/// This is the test the live run failed and the steady-state tests could not:
/// they move the head a slot per tick and never hold `slot_group_width` slots at
/// once, so a pipeline that proved every slot on its own would pass them all.
/// Here the slots arrive together, which is when grouping is both possible and
/// load-bearing.
#[tokio::test]
async fn test_the_first_epoch_of_a_run_is_proven_in_groups() {
    let dir = tempfile::tempdir().unwrap();
    let epoch_dir = prove_the_first_epoch(dir.path(), Pipeline::Batch).await;

    // Two children, not twenty-two. Twenty-two attestation slots at a bound of
    // eleven is two groups: one proven inside the loop when the eleventh slot
    // closed, one at the close taking what crossed the threshold.
    let groups = artifacts(&epoch_dir, "slot_proof_");
    assert_eq!(
        groups,
        vec![
            format!("slot_proof_{}.bin", EPOCH * SPE),
            format!(
                "slot_proof_{}.bin",
                EPOCH * SPE + DEFAULT_SLOT_GROUP_WIDTH as u64
            ),
        ],
        "the epoch's slots should be two groups named after the slot each opens",
    );

    // One link. Two slot proofs and a committee proof fit inside a single
    // justification, so the chain never has to form — and when it does, the
    // fold width bounds it rather than the epoch's length.
    assert_eq!(
        artifacts(&epoch_dir, "justification_"),
        vec!["justification_0.bin".to_string()],
        "two slot proofs fit in one link; a chain here means the fold ran early",
    );
}

/// What that epoch costs, in the only unit the prover charges in.
///
/// The critical path of the first epoch is its justification, and a
/// justification is a floor plus a recursion per child — MEASURED at
/// [`JUSTIFICATION_RECURSION_S`] and linear from 2 children to 23. So the child
/// count above is the cost, and this states it as seconds rather than leaving a
/// reader to multiply.
///
/// It has to fit inside the node's state window, not just inside an epoch. This
/// node serves 3-4 epochs of state, and a first epoch that took ~25 minutes
/// asked for a state the node had already migrated — which is not slow, it is a
/// run that never starts.
#[tokio::test]
async fn test_the_first_epoch_fits_inside_an_epoch() {
    let dir = tempfile::tempdir().unwrap();
    let epoch_dir = prove_the_first_epoch(dir.path(), Pipeline::Batch).await;

    // The closing link verifies every slot proof of the epoch plus the
    // committee proof that opened it.
    let children = artifacts(&epoch_dir, "slot_proof_").len() + 1;
    let model = ProverModel::default();
    let justification_s = model.stage_floor_s + children as f64 * JUSTIFICATION_RECURSION_S;

    assert_eq!(children, 3, "two groups and the committee proof");
    assert!(
        justification_s < 200.0,
        "the justification models at {justification_s:.0} s over {children} children; \
         one child per slot would be {:.0} s",
        model.stage_floor_s + 23.0 * JUSTIFICATION_RECURSION_S,
    );
    // A mainnet epoch is 384 s. The justification is the largest single stage of
    // the first epoch and the one that grew with the epoch before it was
    // bounded, so it alone has to leave room for the committee proof beside it.
    assert!(
        justification_s < 384.0 / 2.0,
        "the first epoch has to fit inside an epoch, and the state window behind it",
    );
}

/// A streaming run starts on the same epoch, and pays the same batch cost.
///
/// `--mode streaming` is what production runs, and its first epoch is not
/// streamed: there is no previous justification to consume. A regression that
/// only reached the batch path would therefore still be a regression on every
/// production start, so the streaming configuration is pinned to the same
/// counts.
#[tokio::test]
async fn test_a_streaming_run_starts_on_the_grouped_batch_path() {
    let dir = tempfile::tempdir().unwrap();
    let epoch_dir = prove_the_first_epoch(dir.path(), Pipeline::Streaming).await;

    assert_eq!(
        artifacts(&epoch_dir, "slot_proof_").len(),
        2,
        "a streaming run's first epoch is a batch epoch, and groups like one",
    );
    assert_eq!(artifacts(&epoch_dir, "justification_").len(), 1);
}

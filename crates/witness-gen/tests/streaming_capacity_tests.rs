//! What folding costs when the prover has no room, and what it saves when it does.
//!
//! # The invariant
//!
//! A group is folded before the threshold **if and only if** the daemon reached
//! the epoch before the threshold crossed. There is no third case: the fold
//! lives in the `!fire` branch of the streaming pipeline, so an epoch that is
//! already past its threshold on the tick it opens goes straight down the fire
//! path and the final proof absorbs its whole backlog as one recursion child.
//!
//! That is not a gate that fails to open — it is the correct decision, because
//! folding after `T` is never a win: the fold is itself a proof over the group,
//! and the final proof then verifies the aggregate instead of the group, so the
//! child count on the critical path is unchanged and the fold's own cost is
//! added to it. What makes folding pay is running it *before* `T`, against
//! attestations that have already arrived, which is only possible if the epoch
//! is open before its own threshold slot.
//!
//! # Why this is worth a test
//!
//! A daemon whose prover is saturated closes each epoch about as fast as the
//! chain produces one, so it never gains the lead it needs to open an epoch
//! early, and `folded_groups` is 0 for every epoch it ever proves. The suite
//! passed in that state, because the only streaming latency test drove the head
//! one slot at a time — which silently grants the daemon all the capacity in the
//! world. These two tests pin both halves of the relationship so that the
//! difference between them stays visible.
//!
//! # `wait_millis` is not idle time
//!
//! The manifest's `wait_millis` is `fired - crossed`, and the late group proof
//! runs between those two timestamps. So on the behind path it is not a window
//! that could absorb a fold — it *is* the group proof, already on the critical
//! path. [`test_a_daemon_behind_the_threshold_folds_nothing`] pins that with a
//! prover that takes a known time to prove a group, and its twin pins that the
//! same prover does not show up in `wait_millis` when the daemon is at the head.

mod common;

use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use common::{MockBeaconApi, SyntheticChain};

use zkasper_common::bls::Fp12;
use zkasper_common::recursion::ProgramVk;
use zkasper_common::types::{
    AggregateOutput, AggregateWitness, CommitteeOutput, CommitteeWitness, EpochDiffOutput,
    EpochDiffWitness, FinalizationOutput, FinalizationWitness, GroupProofOutput,
    JustificationOutput, JustificationWitness, SlotProofOutput, SlotProofWitness,
    StreamFinalOutput, StreamFinalWitness,
};
use zkasper_common::ChainConfig;

use zkasper_witness_gen::orchestrator::{Orchestrator, OrchestratorConfig, Pipeline};
use zkasper_witness_gen::prover::{NativeProver, Proof, Prover, Stage};

const TEST_CONFIG: ChainConfig = ChainConfig {
    slots_per_epoch: 8,
    validators_tree_depth: 2,
    acc_tree_depth: 2,
    beacon_state_validators_field_index: 11,
    fulu_fork_epoch: 0,
};
const SPE: u64 = TEST_CONFIG.slots_per_epoch;

const FIRST_EPOCH: u64 = 10;
const LAST_EPOCH: u64 = 13;
const VALIDATORS: usize = 4;

/// Cumulative balance crosses 2/3 of 128 ETH at the third attesting validator.
const SLOTS_TO_THRESHOLD: u64 = 3;

/// How long the test prover takes to prove one group.
///
/// Long enough to be unambiguous against a millisecond clock, short enough that
/// two tests paying it a few times stay quick. Nothing else in either test
/// sleeps, so any `wait_millis` at or above this can only be a group proof.
const GROUP_PROVE: Duration = Duration::from_millis(400);

/// A prover that takes measurable time to prove a group, and no time to do
/// anything else.
///
/// Everything else delegates to [`NativeProver`], so the epoch still composes
/// exactly as it does in the other tests — the only thing added is a cost on
/// the one stage whose placement relative to `T` is what these tests are about.
struct SlowGroupProver(NativeProver);

impl SlowGroupProver {
    fn new(config: ChainConfig) -> Self {
        Self(NativeProver::new(config))
    }
}

impl Prover for SlowGroupProver {
    fn name(&self) -> &'static str {
        "native (group proofs deliberately slow)"
    }

    fn program_vk(&self, stage: Stage) -> ProgramVk {
        self.0.program_vk(stage)
    }

    fn prove_epoch_diff(&self, witness: &EpochDiffWitness) -> Result<(EpochDiffOutput, Proof)> {
        self.0.prove_epoch_diff(witness)
    }

    fn prove_committee(&self, witness: &CommitteeWitness) -> Result<(CommitteeOutput, Proof)> {
        self.0.prove_committee(witness)
    }

    fn prove_slot(&self, witness: &SlotProofWitness) -> Result<(SlotProofOutput, Proof)> {
        self.0.prove_slot(witness)
    }

    fn prove_justification(
        &self,
        witness: &JustificationWitness,
    ) -> Result<(JustificationOutput, Proof)> {
        self.0.prove_justification(witness)
    }

    fn prove_finalization(
        &self,
        witness: &FinalizationWitness,
    ) -> Result<(FinalizationOutput, Proof)> {
        self.0.prove_finalization(witness)
    }

    fn prove_group(&self, witness: &SlotProofWitness) -> Result<(GroupProofOutput, Fp12, Proof)> {
        std::thread::sleep(GROUP_PROVE);
        self.0.prove_group(witness)
    }

    fn prove_aggregate(&self, witness: &AggregateWitness) -> Result<(AggregateOutput, Proof)> {
        self.0.prove_aggregate(witness)
    }

    fn prove_stream_final(
        &self,
        witness: &StreamFinalWitness,
    ) -> Result<(StreamFinalOutput, Proof)> {
        self.0.prove_stream_final(witness)
    }
}

fn chain() -> SyntheticChain {
    SyntheticChain::new(TEST_CONFIG, VALIDATORS, FIRST_EPOCH, LAST_EPOCH)
}

/// A daemon that has justified epoch 10 the batch way and is sitting on 11,
/// which it will stream.
async fn streaming_daemon(dir: &Path, chain: &SyntheticChain) -> Orchestrator<MockBeaconApi> {
    let mock = chain.mock((FIRST_EPOCH + 1) * SPE);
    let config = OrchestratorConfig {
        pipeline: Pipeline::Streaming,
        db_path: dir.join("zkasperd.db"),
        output_dir: dir.join("out"),
        poll_interval: Duration::ZERO,
        init_point: Some(
            zkasper_witness_gen::init_point::generate(
                &mock,
                &TEST_CONFIG,
                "test",
                FIRST_EPOCH * SPE,
            )
            .await
            .expect("the node serves the epoch the run starts on"),
        ),
        ..OrchestratorConfig::new(TEST_CONFIG, "test")
    };
    let mut daemon = Orchestrator::open(mock, config, Box::new(SlowGroupProver::new(TEST_CONFIG)))
        .await
        .expect("orchestrator opens");

    daemon.catch_up().await.unwrap();
    assert_eq!(daemon.state().cursor_epoch, FIRST_EPOCH + 1);
    assert_eq!(daemon.state().justified_through, Some(FIRST_EPOCH));
    daemon
}

fn latency(dir: &Path) -> serde_json::Value {
    let status: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("out").join("status.json")).unwrap())
            .unwrap();
    status["recent_latencies"][0].clone()
}

fn epoch_dir(dir: &Path, epoch: u64) -> std::path::PathBuf {
    dir.join("out").join(format!("epoch-{epoch:09}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A daemon that reaches the epoch only after its threshold has already crossed
/// folds nothing, and the final proof absorbs the whole backlog as one child.
///
/// This is the production shape when the prover is saturated: the epoch is
/// opened so late that the very first evaluation of the trigger already holds
/// enough stake to justify, so the pipeline fires on that tick and the `!fire`
/// branch — the only place a fold happens — never runs at all.
///
/// It also pins what `wait_millis` is made of. The late group proof runs between
/// the threshold timestamp and the fired timestamp, so the "wait" is occupied by
/// proving, not idle: it could not absorb a fold because it *is* the group
/// proof.
#[tokio::test]
async fn test_a_daemon_behind_the_threshold_folds_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let chain = chain();
    let mut daemon = streaming_daemon(dir.path(), &chain).await;

    let stream_epoch = FIRST_EPOCH + 1;
    let boundary = stream_epoch * SPE;

    // The whole difference from the test below: the head jumps straight past the
    // threshold, so the epoch opens with its backlog already complete. A daemon
    // whose prover is saturated arrives exactly like this, an epoch or more
    // behind the chain.
    daemon
        .api()
        .set_head(chain.header_at(boundary + SLOTS_TO_THRESHOLD));
    let ticks = daemon.catch_up().await.unwrap();

    assert_eq!(
        ticks.iter().filter_map(|t| t.justified).collect::<Vec<_>>(),
        vec![stream_epoch],
        "the epoch still gets justified — being behind costs latency, not correctness",
    );

    let latency = latency(dir.path());
    assert_eq!(latency["epoch"], stream_epoch);
    assert_eq!(
        latency["folded_groups"], 0,
        "an epoch opened past its own threshold has no tick on which to fold",
    );
    assert_eq!(
        latency["late_groups"], 1,
        "so the final proof absorbs the backlog as a recursion child instead",
    );
    assert_eq!(latency["tail"], 1, "one attestation on the critical path");

    // Nothing was folded, so no aggregate was ever written; the backlog was
    // proven once, as a single group, on the firing tick.
    let epoch_dir = epoch_dir(dir.path(), stream_epoch);
    assert!(
        epoch_dir.join("group_0.bin").exists(),
        "the backlog is proven as one group",
    );
    assert!(
        !epoch_dir.join("aggregate_0.bin").exists(),
        "nothing was folded, so there is no aggregate",
    );

    // The group proof sits between `T` and `fired`, which is the whole of
    // `wait_millis` here. This is the measurement that says the window cannot
    // absorb a fold: it is already full.
    let wait = latency["wait_millis"].as_u64().expect("wait_millis");
    assert!(
        wait >= GROUP_PROVE.as_millis() as u64,
        "wait_millis ({wait} ms) should contain the late group proof \
         ({} ms), because that proof runs between T and the fired timestamp",
        GROUP_PROVE.as_millis(),
    );
    let t2_minus_t = latency["t2_minus_t_millis"].as_u64().expect("t2_minus_t");
    assert!(
        t2_minus_t >= wait,
        "T2 - T ({t2_minus_t} ms) covers the wait ({wait} ms) and the final proof",
    );
}

/// A daemon that reaches the epoch before its threshold folds every group it
/// has, and the final proof verifies the aggregate rather than a group.
///
/// The head advances a slot at a time, which is what having spare capacity looks
/// like from the pipeline's side: each slot closes on its own tick, is proven,
/// and is folded before the next one arrives — so when the threshold crosses the
/// only work left is the marginal attestation.
///
/// The contrast with the test above is the point. Same chain, same prover, same
/// threshold; the only variable is whether the daemon got there in time.
#[tokio::test]
async fn test_a_daemon_at_the_head_folds_every_group_before_the_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let chain = chain();
    let mut daemon = streaming_daemon(dir.path(), &chain).await;

    let stream_epoch = FIRST_EPOCH + 1;
    let boundary = stream_epoch * SPE;

    // A slot at a time. The head leads the last counted slot by one, because a
    // slot's attestations are carried by the block after it.
    let mut ticks = Vec::new();
    for slot in boundary..=boundary + SLOTS_TO_THRESHOLD {
        daemon.api().set_head(chain.header_at(slot));
        ticks.extend(daemon.catch_up().await.unwrap());
    }

    assert_eq!(
        ticks.iter().filter_map(|t| t.justified).collect::<Vec<_>>(),
        vec![stream_epoch],
    );

    let latency = latency(dir.path());
    assert_eq!(latency["epoch"], stream_epoch);
    assert_eq!(
        latency["folded_groups"], 2,
        "every slot that closed before the threshold was folded on the tick it closed",
    );
    assert_eq!(
        latency["late_groups"], 0,
        "a daemon at the head has nothing left to fold when the threshold crosses",
    );
    assert_eq!(latency["tail"], 1, "one attestation on the critical path");

    let epoch_dir = epoch_dir(dir.path(), stream_epoch);
    assert!(
        epoch_dir.join("aggregate_0.bin").exists() && epoch_dir.join("aggregate_1.bin").exists(),
        "both folds ran, and ran before the threshold",
    );

    // The same prover that put 400 ms into `wait_millis` on the behind path puts
    // none into it here, because no group proof runs after `T`. That difference
    // is the entire value of folding: not that the group proof is cheaper, but
    // that it is off the critical path.
    let wait = latency["wait_millis"].as_u64().expect("wait_millis");
    assert!(
        wait < GROUP_PROVE.as_millis() as u64,
        "wait_millis ({wait} ms) must not contain a group proof ({} ms) — \
         every group was proven and folded before the threshold crossed",
        GROUP_PROVE.as_millis(),
    );
}

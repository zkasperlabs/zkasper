//! What folding costs when the prover has no room, and what it saves when it does.
//!
//! # The invariant
//!
//! A group is folded before the threshold **if and only if** the daemon reached
//! the epoch before the threshold crossed. There is no third case: the fold
//! lives in the `!fire` branch of the streaming pipeline, so an epoch that is
//! already past its threshold on the tick it opens goes straight down the fire
//! path and the final proof carries its whole backlog inline.
//!
//! That is not a gate that fails to open — it is the correct decision, because
//! folding after `T` is never a win: the fold is itself a proof over the group,
//! and the final proof then verifies the aggregate instead of the group, so the
//! child count on the critical path is unchanged and the fold's own cost is
//! added to it. What makes folding pay is running it *before* `T`, against
//! attestations that have already arrived, which is only possible if the epoch
//! is open before its own threshold slot.
//!
//! The backlog used to become a group proof on the fire path and then a
//! recursion child of the final proof — 36 s on a mainnet card. It goes inline
//! now, because that is what the plan's tail asks for and the fire path stopped
//! overriding it: the same attestations, as complement work rather than as a
//! child.
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
//! # `wait_millis` is not idle time, and no longer claims to be
//!
//! `wait_millis` is `fired - crossed`, and the late group proof used to run
//! between those two timestamps: the fired stamp was taken at the top of
//! `close`, which the fire path reaches only after proving the backlog. So the
//! manifest reported a 141 s group proof as a 141 s trigger hold — against a cap
//! of 10 s, into a histogram whose top bucket is 12 s — and three separate
//! analyses read it as the trigger waiting.
//!
//! The stamp is now taken where the trigger actually fires, and the group proof
//! is reported as `late_group_millis` beside it. The two tests below pin the
//! split from both sides, and [`test_the_reported_wait_never_exceeds_what_the_tail_is_worth`]
//! pins the bound that makes `wait_millis` readable at all: a wait can never be
//! worth more than the tail it is waiting for.

mod common;

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

use zkasper_witness_gen::beacon_api::HeaderResponse;
use zkasper_witness_gen::orchestrator::{Orchestrator, OrchestratorConfig, Pipeline};
use zkasper_witness_gen::prover::{NativeProver, Proof, Prover, Stage};
use zkasper_witness_gen::streaming::ProverModel;

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

/// How long the test prover takes to fold one group into the aggregate.
///
/// Longer than [`GROUP_PROVE`] on purpose. A fold started after the chain has
/// crossed is the whole of what
/// [`test_a_group_that_lands_on_a_justifiable_epoch_is_not_folded_first`]
/// measures, so it has to be separable from the group proof that preceded it by
/// more than a scheduling jitter.
const FOLD_PROVE: Duration = Duration::from_millis(1200);

/// What the chain does while a group proof is running.
///
/// The daemon can only be blind to a crossing while it is proving, so a test
/// about that blindness needs the head to move *inside* a proof. The prover
/// moves it itself rather than a second task racing the loop, which makes the
/// ordering exact: the head is up one full trigger interval before the proof it
/// moved during can land.
#[derive(Clone, Default)]
struct CrossDuringGroup(Arc<Mutex<Option<Crossing>>>);

struct Crossing {
    head: Arc<Mutex<Option<HeaderResponse>>>,
    header: HeaderResponse,
    /// Unix ms at which the head moved: the earliest the daemon could have seen
    /// the chain cross, and so what its observation is measured against.
    crossed_unix_millis: Option<u64>,
}

impl CrossDuringGroup {
    /// Move the head the next time a group is proven, and not again.
    fn arm(&self, head: Arc<Mutex<Option<HeaderResponse>>>, header: HeaderResponse) {
        *self.0.lock().unwrap() = Some(Crossing {
            head,
            header,
            crossed_unix_millis: None,
        });
    }

    fn take(&self) {
        let mut armed = self.0.lock().unwrap();
        let Some(crossing) = armed.as_mut() else {
            return;
        };
        if crossing.crossed_unix_millis.is_some() {
            return;
        }
        *crossing.head.lock().unwrap() = Some(crossing.header.clone());
        crossing.crossed_unix_millis = Some(now_unix_millis());
    }

    fn crossed_unix_millis(&self) -> u64 {
        self.0
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|crossing| crossing.crossed_unix_millis)
            .expect("the chain crossed while a group was being proven")
    }
}

fn now_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// A prover that takes measurable time to prove a group and to fold one, and no
/// time to do anything else.
///
/// Everything else delegates to [`NativeProver`], so the epoch still composes
/// exactly as it does in the other tests — the only thing added is a cost on
/// the two stages whose placement relative to `T` is what these tests are about.
struct SlowGroupProver {
    inner: NativeProver,
    crossing: CrossDuringGroup,
}

impl SlowGroupProver {
    fn new(config: ChainConfig, crossing: CrossDuringGroup) -> Self {
        Self {
            inner: NativeProver::new(config),
            crossing,
        }
    }
}

impl Prover for SlowGroupProver {
    fn name(&self) -> &'static str {
        "native (group proofs deliberately slow)"
    }

    fn program_vk(&self, stage: Stage) -> ProgramVk {
        self.inner.program_vk(stage)
    }

    fn prove_epoch_diff(&self, witness: &EpochDiffWitness) -> Result<(EpochDiffOutput, Proof)> {
        self.inner.prove_epoch_diff(witness)
    }

    fn prove_committee(&self, witness: &CommitteeWitness) -> Result<(CommitteeOutput, Proof)> {
        self.inner.prove_committee(witness)
    }

    fn prove_slot(&self, witness: &SlotProofWitness) -> Result<(SlotProofOutput, Proof)> {
        self.inner.prove_slot(witness)
    }

    fn prove_justification(
        &self,
        witness: &JustificationWitness,
    ) -> Result<(JustificationOutput, Proof)> {
        self.inner.prove_justification(witness)
    }

    fn prove_finalization(
        &self,
        witness: &FinalizationWitness,
    ) -> Result<(FinalizationOutput, Proof)> {
        self.inner.prove_finalization(witness)
    }

    fn prove_group(&self, witness: &SlotProofWitness) -> Result<(GroupProofOutput, Fp12, Proof)> {
        // Before the sleep, so the tick that collects this proof has already
        // ingested the crossing — which is what a daemon on gossip has too, its
        // loop still running while the prover works.
        self.crossing.take();
        std::thread::sleep(GROUP_PROVE);
        self.inner.prove_group(witness)
    }

    fn prove_aggregate(&self, witness: &AggregateWitness) -> Result<(AggregateOutput, Proof)> {
        std::thread::sleep(FOLD_PROVE);
        self.inner.prove_aggregate(witness)
    }

    fn prove_stream_final(
        &self,
        witness: &StreamFinalWitness,
    ) -> Result<(StreamFinalOutput, Proof)> {
        self.inner.prove_stream_final(witness)
    }
}

fn chain() -> SyntheticChain {
    SyntheticChain::new(TEST_CONFIG, VALIDATORS, FIRST_EPOCH, LAST_EPOCH)
}

/// A daemon that has justified epoch 10 the batch way and is sitting on 11,
/// which it will stream.
async fn streaming_daemon(dir: &Path, chain: &SyntheticChain) -> Orchestrator<MockBeaconApi> {
    streaming_daemon_with(dir, chain, CrossDuringGroup::default()).await
}

/// The same, with a prover that moves the head while it proves a group.
async fn streaming_daemon_with(
    dir: &Path,
    chain: &SyntheticChain,
    crossing: CrossDuringGroup,
) -> Orchestrator<MockBeaconApi> {
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
    let mut daemon = Orchestrator::open(
        mock,
        config,
        Box::new(SlowGroupProver::new(TEST_CONFIG, crossing)),
    )
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
/// folds nothing, and proves the backlog as one group with a one-slot tail.
///
/// This is the production shape when the prover is saturated: the epoch is
/// opened so late that the very first evaluation of the trigger already holds
/// enough stake to justify, so the pipeline fires on that tick and the `!fire`
/// branch — the only place a fold happens — never runs at all.
///
/// **The backlog used to go inline instead, and that inverted in `9f10d05`.**
/// While a child cost 35.629 s the final proof carried all three slots itself;
/// at the measured 1.520 s plus 0.83 s for a proof's first child, a group is
/// cheaper than the two extra slots it saves inlining. `folded_groups` is still
/// 0 — being behind leaves no tick to fold on, which is what this test is about
/// — and what moved is only where the backlog is proven.
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
        "the backlog is one group now that a child is cheaper than inlining it",
    );
    assert_eq!(
        latency["tail"],
        1,
        "the crossing slot goes inline; the {} before it are the group",
        SLOTS_TO_THRESHOLD - 1,
    );

    // One group, and still nothing folded: a fold needs a tick the daemon never
    // gets here, and the final proof verifies the group directly instead.
    let epoch_dir = epoch_dir(dir.path(), stream_epoch);
    assert!(
        epoch_dir.join("group_0.bin").exists(),
        "the backlog should be a group the final proof verifies as a child",
    );
    assert!(
        !epoch_dir.join("aggregate_0.bin").exists(),
        "nothing was folded, so there is no aggregate",
    );

    // The window between `T` and the final proof holds that group, and the
    // repricing is what put it there: this asserted the window was *empty* while
    // a child cost 35.629 s and inlining three slots beat proving one group.
    // Charging it is the point of the metric — `late_group_millis` is the term
    // that names work done after `T` — so the invariant is that it accounts for
    // the group rather than that no group exists.
    let late_group = latency["late_group_millis"]
        .as_u64()
        .expect("late_group_millis");
    assert!(
        late_group >= GROUP_PROVE.as_millis() as u64,
        "late_group_millis ({late_group} ms) is under one group proof ({} ms), \
         so the group the plan puts after `T` is not being charged to it",
        GROUP_PROVE.as_millis(),
    );

    // And it is not charged to the trigger either. This is the assertion that
    // was inverted once already: the daemon never held back here at all — it
    // fired on the first tick that evaluated the trigger — and an older stamp
    // reported the fire path's work as a wait.
    let wait = latency["wait_millis"].as_u64().expect("wait_millis");
    assert!(
        wait < GROUP_PROVE.as_millis() as u64,
        "wait_millis ({wait} ms) contains a group proof ({} ms); the fired \
         timestamp has drifted back into the fire path's work",
        GROUP_PROVE.as_millis(),
    );

    let t2_minus_t = latency["t2_minus_t_millis"].as_u64().expect("t2_minus_t");
    assert!(
        t2_minus_t >= wait,
        "T2 - T ({t2_minus_t} ms) covers the wait ({wait} ms) and the final proof",
    );
}

/// `T` is the chain's, and a daemon that noticed the crossing late must still
/// report the moment the chain crossed.
///
/// The same scenario as the test above — the epoch is opened after its threshold
/// has already gone by — because that is the only case where the two candidate
/// definitions of `T` differ, and it is also the production case: the daemon is
/// blind to the crossing for the length of every proof, so it notices late
/// exactly when it is busiest.
///
/// It was defined the other way until 2026-08-19, and the last assertion here is
/// the one that failed then: `T2 - T` was `proof - observed`, so an epoch the
/// daemon reached late reported only the part it had been awake for. On mainnet
/// that hid a median of 105 s and once 743 s, and it hid the most from the
/// epochs that were worst — a metric that flatters itself under load is worse
/// than one that is merely wrong, because the case it hides is the case worth
/// seeing.
#[tokio::test]
async fn test_t_is_the_crossing_slot_even_when_the_daemon_noticed_late() {
    let dir = tempfile::tempdir().unwrap();
    let chain = chain();
    let mut daemon = streaming_daemon(dir.path(), &chain).await;

    let boundary = (FIRST_EPOCH + 1) * SPE;
    daemon
        .api()
        .set_head(chain.header_at(boundary + SLOTS_TO_THRESHOLD));
    daemon.catch_up().await.unwrap();

    // Where the chain crossed, known without asking the daemon: one validator
    // attests per slot from the boundary on, and the third of them carries this
    // epoch over 2/3.
    let crossing = boundary + SLOTS_TO_THRESHOLD - 1;

    let latency = latency(dir.path());
    assert_eq!(
        latency["threshold_slot"], crossing,
        "T belongs to the slot that crossed the threshold",
    );
    assert_eq!(
        latency["threshold_unix_millis"].as_u64(),
        Some(chain.slot_unix_millis(crossing)),
        "T is that slot's boundary, genesis plus a slot count, and nothing else",
    );

    let threshold = latency["threshold_unix_millis"]
        .as_u64()
        .expect("threshold");
    let observed = latency["observed_unix_millis"].as_u64().expect("observed");
    let proof = latency["proof_unix_millis"].as_u64().expect("proof");
    let t2_minus_t = latency["t2_minus_t_millis"].as_u64().expect("t2_minus_t");
    let observation = latency["observation_millis"].as_u64().expect("observation");

    // The premise: this daemon really did notice late. Without it the test would
    // pass under either definition and pin nothing.
    assert!(
        observed > threshold,
        "the daemon was supposed to reach this epoch after its threshold; \
         observed {observed} is not after T {threshold}",
    );
    assert_eq!(
        observation,
        observed - threshold,
        "the observation delay is the whole of what the daemon did not see",
    );

    assert_eq!(
        t2_minus_t,
        proof - threshold,
        "T2 - T runs from the chain's crossing to the proof",
    );
    assert_eq!(
        t2_minus_t - observation,
        proof - observed,
        "and it exceeds what the old definition reported by exactly that delay",
    );
    assert!(
        proof - observed < t2_minus_t,
        "T2 - T ({t2_minus_t} ms) must not collapse to what the daemon was awake \
         for ({} ms); that is the stamp this test exists to prevent",
        proof - observed,
    );

    // The four terms are in order and do not overlap, so a reader can attribute
    // the number rather than only compare it.
    let wait = latency["wait_millis"].as_u64().expect("wait_millis");
    let late_group = latency["late_group_millis"]
        .as_u64()
        .expect("late_group_millis");
    assert!(
        observation + wait + late_group <= t2_minus_t,
        "T2 - T ({t2_minus_t} ms) must cover the delay ({observation} ms), the \
         wait ({wait} ms), the late group ({late_group} ms) and the final proof",
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

    // The same prover that put 400 ms into `late_group_millis` on the behind
    // path puts none into it here, because no group proof runs after `T`. That
    // difference is the entire value of folding: not that the group proof is
    // cheaper, but that it is off the critical path.
    let late_group = latency["late_group_millis"]
        .as_u64()
        .expect("late_group_millis");
    assert!(
        late_group < GROUP_PROVE.as_millis() as u64,
        "late_group_millis ({late_group} ms) contains a group proof ({} ms) — \
         every group was proven and folded before the threshold crossed",
        GROUP_PROVE.as_millis(),
    );

    let wait = latency["wait_millis"].as_u64().expect("wait_millis");
    assert!(
        wait < GROUP_PROVE.as_millis() as u64,
        "wait_millis ({wait} ms) must not contain a group proof ({} ms)",
        GROUP_PROVE.as_millis(),
    );
}

/// The third case, which is neither of the two above: the chain crosses while a
/// group is being proven, and the group lands on an epoch that is already
/// justifiable.
///
/// The daemon has to do something with that group, and until 2026-08-19 it did
/// the one thing that cannot pay — it folded it. The fold was started by
/// `collect`, an arm below the in-flight-proof early return and so above any
/// evaluation of the trigger, which meant a whole aggregate proof was queued
/// against an epoch the chain had already carried over two thirds, and the
/// daemon did not look again until that proof finished. Measured over 29
/// steady-state mainnet epochs on the 2026-08-19 run, **42% of the 2,500 s
/// between the chain crossing and the daemon noticing was proofs started after
/// the crossing**, and nine of the ten were exactly this fold.
///
/// Folding here cannot pay, whatever the numbers: with no aggregate the final
/// proof verifies the group directly, so the fold buys back nothing on the
/// critical path and adds its own length to it. So the group is held instead,
/// the trigger runs on the same tick that collected it, and the final proof
/// takes the group whole.
///
/// The pipeline is not starved by that. The group still ran, the final proof
/// still absorbs it, and the slots that closed since go inline — what stops is
/// only the *adding* of work to an epoch that no longer needs any.
#[tokio::test]
async fn test_a_group_that_lands_on_a_justifiable_epoch_is_not_folded_first() {
    let dir = tempfile::tempdir().unwrap();
    let chain = chain();
    let crossing = CrossDuringGroup::default();
    let mut daemon = streaming_daemon_with(dir.path(), &chain, crossing.clone()).await;

    let stream_epoch = FIRST_EPOCH + 1;
    let boundary = stream_epoch * SPE;
    let crossing_slot = boundary + SLOTS_TO_THRESHOLD - 1;

    // One slot of the epoch is on the chain, which is one attester and a quarter
    // of the stake: not enough, so the daemon closes it and starts a group.
    daemon.api().set_head(chain.header_at(boundary + 1));

    // And the rest of the epoch arrives while that group is being proven. This
    // is the production shape — a mainnet fold is 110 s and a slot is 12 — and
    // the only shape in which the daemon can be holding enough to justify and
    // not know it.
    crossing.arm(
        daemon.api().head_handle(),
        chain.header_at(boundary + SLOTS_TO_THRESHOLD),
    );

    // Driven until the epoch closes rather than in one call, because a tick that
    // collects a fold reports no progress and leaves nothing proving, so
    // `catch_up` returns on it. One call is enough once the fold is gone; the
    // loop is what lets the assertions below be the ones that fail.
    let mut ticks = Vec::new();
    for _ in 0..4 {
        ticks.extend(daemon.catch_up().await.unwrap());
        if ticks.iter().any(|tick| tick.justified.is_some()) {
            break;
        }
    }
    assert_eq!(
        ticks.iter().filter_map(|t| t.justified).collect::<Vec<_>>(),
        vec![stream_epoch],
    );

    let latency = latency(dir.path());
    assert_eq!(latency["epoch"], stream_epoch);
    assert_eq!(
        latency["threshold_slot"], crossing_slot,
        "the chain crossed on the slot that arrived while the group was proving",
    );

    // The assertion the fix exists for. Without it the daemon queued a fold on
    // this tick and did not evaluate the trigger again until it finished.
    assert_eq!(
        latency["folded_groups"], 0,
        "an epoch that is already justifiable must not have work added to it: \
         a fold here is a whole aggregate proof between the crossing and the \
         daemon seeing it, and takes nothing off the critical path",
    );
    let epoch_dir = epoch_dir(dir.path(), stream_epoch);
    assert!(
        !epoch_dir.join("aggregate_0.bin").exists(),
        "an aggregate was proven for an epoch that no longer needed one",
    );

    // Which is the same thing said in time: the daemon observed the crossing
    // without an aggregate proof in the way.
    let observed = latency["observed_unix_millis"].as_u64().expect("observed");
    let blind = observed - crossing.crossed_unix_millis();
    assert!(
        blind < FOLD_PROVE.as_millis() as u64,
        "the daemon took {blind} ms to see a crossing it was holding, which is \
         a fold ({} ms) it queued while it was not looking",
        FOLD_PROVE.as_millis(),
    );

    // And the pipeline was not starved to get it. The group ran, the final proof
    // absorbed it whole, and the two slots that closed after it went inline.
    assert!(
        epoch_dir.join("group_0.bin").exists(),
        "the group the epoch opened with was never proven",
    );
    assert_eq!(
        latency["late_groups"], 1,
        "the group that landed on the fire tick is the one the final proof \
         verifies; nothing else was proven for it",
    );
    assert_eq!(
        latency["tail"],
        SLOTS_TO_THRESHOLD - 1,
        "every slot the held group does not cover goes inline, up to the \
         crossing and no further",
    );
    let late_group = latency["late_group_millis"]
        .as_u64()
        .expect("late_group_millis");
    assert!(
        late_group < GROUP_PROVE.as_millis() as u64,
        "late_group_millis ({late_group} ms) contains a group proof ({} ms); the \
         fire path had a landed group to absorb and should have proven nothing",
        GROUP_PROVE.as_millis(),
    );
}

/// The bound that makes `wait_millis` mean something: the trigger can never
/// hold longer than the tail it is holding for could possibly repay.
///
/// This is the invariant the live run violated by two orders of magnitude.
/// Mainnet epoch 469483 reported a 141.6 s wait against a tail of 8,454 leaves —
/// 13.0 s of proving at [`ProverModel::per_named_s`], so even emptying the tail
/// entirely would have been a 10:1 loss. Nothing in the trigger could produce
/// that: `--max-trigger-wait-millis` caps the hold at 10 s. The 141.6 s was the
/// late group proof, charged to the wait by a timestamp taken in the wrong
/// place, and the two are separate fields now.
///
/// Both paths are checked, because the point is that neither of them can hide a
/// proof inside the wait. The behind path is the one that used to fail.
#[tokio::test]
async fn test_the_reported_wait_never_exceeds_what_the_tail_is_worth() {
    let per_named_millis = ProverModel::default().per_named_s() * 1000.0;

    for behind in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let chain = chain();
        let mut daemon = streaming_daemon(dir.path(), &chain).await;

        let stream_epoch = FIRST_EPOCH + 1;
        let boundary = stream_epoch * SPE;

        if behind {
            daemon
                .api()
                .set_head(chain.header_at(boundary + SLOTS_TO_THRESHOLD));
            daemon.catch_up().await.unwrap();
        } else {
            for slot in boundary..=boundary + SLOTS_TO_THRESHOLD {
                daemon.api().set_head(chain.header_at(slot));
                daemon.catch_up().await.unwrap();
            }
        }

        let latency = latency(dir.path());
        assert_eq!(latency["epoch"], stream_epoch);
        let wait = latency["wait_millis"].as_u64().expect("wait_millis") as f64;
        let tail_named = latency["tail_named"].as_u64().expect("tail_named") as f64;

        // What the whole tail is worth, plus one trigger interval: the daemon
        // cannot fire between two evaluations, so it may overshoot by one.
        let budget = tail_named * per_named_millis
            + OrchestratorConfig::new(TEST_CONFIG, "test")
                .trigger_interval
                .as_millis() as f64;
        assert!(
            wait <= budget,
            "behind={behind}: waited {wait} ms for a tail of {tail_named} leaves \
             worth {:.1} ms of proving. A wait can only ever buy back the tail it \
             is waiting for, so this is time lost on every outcome — and a wait \
             this far past the budget is a proof charged to the trigger, not a \
             trigger that held.",
            tail_named * per_named_millis,
        );
    }
}

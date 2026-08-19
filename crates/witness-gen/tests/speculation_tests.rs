//! Whether an epoch's opening proofs run beside the epoch before it, or on it.
//!
//! # What these measure
//!
//! An epoch cannot be justified until three proofs have run one after another:
//! the epoch diff that moves the accumulator onto it, the committee proof that
//! every later proof of it counts against, and the final proof that closes it.
//! On mainnet the first two are 223 s of a 375 s cycle against an epoch's 384,
//! which is why the daemon paced the chain instead of catching up and why
//! `folded_groups` was 0 on every epoch it ever proved.
//!
//! Neither of the first two has to be there. The committees of epoch E are
//! fixed by a RANDAO mix from the end of epoch E-2, and the diff into E needs
//! only the two boundaries around it — so both can be proved while epoch E-1 is
//! still running, and merely awaited when E opens.
//!
//! These tests pin that with a prover that takes a known time per stage and
//! records the window each proof occupied. A stage that overlaps another stage's
//! window ran beside it; one that overlaps nothing ran on the chain. That is a
//! direct measurement of the thing the change is for, rather than a proxy for
//! it.
//!
//! # The control is in the same run
//!
//! The first epoch of a run has nothing precomputed — there was no earlier epoch
//! to precompute it — so its committee proof is inline by construction. Every
//! epoch after it is proved ahead. Both appear in
//! [`test_an_epoch_opens_on_proofs_made_while_the_epoch_before_it_ran`], so the
//! difference between them is measured against the same prover, on the same
//! chain, in the same process.

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

/// How long the test prover takes over each of the three stages that matter.
///
/// The committee proof is the one being moved, so it is the long one. The final
/// proof is longer than the diff and the committee together, which is what lets
/// a speculation started as an epoch opens finish before the epoch closes —
/// the same relationship the mainnet numbers have once the change lands.
const DIFF_PROVE: Duration = Duration::from_millis(100);
const COMMITTEE_PROVE: Duration = Duration::from_millis(500);
const FINAL_PROVE: Duration = Duration::from_millis(900);

/// What one epoch used to cost: the three proofs, one after another.
///
/// The daemon's cycle was this sum plus its host work, which is the whole of
/// why 375 s of prover time paced a 384 s epoch.
const SERIAL_CYCLE: Duration = Duration::from_millis(1_500);

/// One proof, and the wall-clock window it occupied.
#[derive(Clone, Copy, Debug)]
struct Window {
    stage: Stage,
    epoch: u64,
    start: Instant,
    end: Instant,
}

impl Window {
    /// Whether these two proofs were ever in flight at the same time.
    fn overlaps(&self, other: &Window) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// Every proof the run made, in the order they finished.
#[derive(Clone, Default)]
struct ProofLog(Arc<Mutex<Vec<Window>>>);

impl ProofLog {
    fn record(&self, stage: Stage, epoch: u64, start: Instant) {
        self.0.lock().unwrap().push(Window {
            stage,
            epoch,
            start,
            end: Instant::now(),
        });
    }

    fn all(&self) -> Vec<Window> {
        self.0.lock().unwrap().clone()
    }

    /// The one proof of `stage` for `epoch`. Panics if there is not exactly
    /// one, because every assertion here is about a stage that runs once.
    fn one(&self, stage: Stage, epoch: u64) -> Window {
        let found: Vec<Window> = self
            .all()
            .into_iter()
            .filter(|w| w.stage == stage && w.epoch == epoch)
            .collect();
        assert_eq!(
            found.len(),
            1,
            "expected exactly one {} proof of epoch {epoch}, found {}",
            stage.as_str(),
            found.len(),
        );
        found[0]
    }

    /// Whether any other proof was in flight while this one was.
    fn ran_beside_anything(&self, window: &Window) -> Option<Window> {
        self.all().into_iter().find(|other| {
            !(other.stage == window.stage && other.epoch == window.epoch) && other.overlaps(window)
        })
    }
}

/// A prover that takes a known time over the three stages an epoch's cycle is
/// made of, and records when each one ran.
///
/// Everything else delegates to [`NativeProver`], so an epoch still composes
/// exactly as it does everywhere else in the suite.
struct TimedProver {
    inner: NativeProver,
    log: ProofLog,
}

impl TimedProver {
    fn new(config: ChainConfig, log: ProofLog) -> Self {
        Self {
            inner: NativeProver::new(config),
            log,
        }
    }
}

impl Prover for TimedProver {
    fn name(&self) -> &'static str {
        "native (opening proofs deliberately slow)"
    }

    fn program_vk(&self, stage: Stage) -> ProgramVk {
        self.inner.program_vk(stage)
    }

    fn prove_epoch_diff(&self, witness: &EpochDiffWitness) -> Result<(EpochDiffOutput, Proof)> {
        let started = Instant::now();
        std::thread::sleep(DIFF_PROVE);
        let out = self.inner.prove_epoch_diff(witness)?;
        self.log.record(Stage::EpochDiff, witness.epoch_2, started);
        Ok(out)
    }

    fn prove_committee(&self, witness: &CommitteeWitness) -> Result<(CommitteeOutput, Proof)> {
        let started = Instant::now();
        std::thread::sleep(COMMITTEE_PROVE);
        let out = self.inner.prove_committee(witness)?;
        self.log
            .record(Stage::Committee, witness.target_epoch, started);
        Ok(out)
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
        self.inner.prove_group(witness)
    }

    fn prove_aggregate(&self, witness: &AggregateWitness) -> Result<(AggregateOutput, Proof)> {
        self.inner.prove_aggregate(witness)
    }

    fn prove_stream_final(
        &self,
        witness: &StreamFinalWitness,
    ) -> Result<(StreamFinalOutput, Proof)> {
        let started = Instant::now();
        std::thread::sleep(FINAL_PROVE);
        let out = self.inner.prove_stream_final(witness)?;
        self.log
            .record(Stage::StreamFinal, witness.target_epoch, started);
        Ok(out)
    }
}

fn chain() -> SyntheticChain {
    SyntheticChain::new(TEST_CONFIG, VALIDATORS, FIRST_EPOCH, LAST_EPOCH)
}

/// A streaming daemon on `chain`, with the node's head at `head_slot`.
async fn daemon(
    dir: &std::path::Path,
    chain: &SyntheticChain,
    head_slot: u64,
    log: ProofLog,
) -> Orchestrator<MockBeaconApi> {
    let mock = chain.mock(head_slot);
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
    Orchestrator::open(mock, config, Box::new(TimedProver::new(TEST_CONFIG, log)))
        .await
        .expect("orchestrator opens")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Every epoch after the first opens on a diff and a committee proof that ran
/// while the epoch before it was still being proved.
///
/// The head sits several epochs ahead of the cursor, which is where a daemon
/// that is keeping up actually sits — an epoch cannot be justified before its
/// attestations exist — and is also what makes the next epoch's boundary
/// readable, which is what proving ahead needs.
#[tokio::test]
async fn test_an_epoch_opens_on_proofs_made_while_the_epoch_before_it_ran() {
    let dir = tempfile::tempdir().unwrap();
    let chain = chain();
    let log = ProofLog::default();
    let mut daemon = daemon(
        dir.path(),
        &chain,
        LAST_EPOCH * SPE + SLOTS_TO_THRESHOLD,
        log.clone(),
    )
    .await;

    let ticks = daemon.catch_up().await.unwrap();
    let justified: Vec<u64> = ticks.iter().filter_map(|t| t.justified).collect();
    assert_eq!(
        justified,
        vec![
            FIRST_EPOCH,
            FIRST_EPOCH + 1,
            FIRST_EPOCH + 2,
            FIRST_EPOCH + 3
        ],
        "every epoch the chain serves is still justified, which is what proving \
         ahead must not change",
    );

    // The control. The first epoch of a run has no earlier epoch to have proved
    // its committees, so it proves them itself, on the chain — and nothing else
    // is in flight while it does.
    let bootstrap = log.one(Stage::Committee, FIRST_EPOCH);
    assert!(
        log.ran_beside_anything(&bootstrap).is_none(),
        "the first epoch's committee proof has nothing to run beside, so it is \
         on the critical path: {:?}",
        log.ran_beside_anything(&bootstrap),
    );

    // The change. Each later epoch's committee proof was in flight while the
    // epoch before it was closing.
    for epoch in [FIRST_EPOCH + 2, FIRST_EPOCH + 3] {
        let committee = log.one(Stage::Committee, epoch);
        let previous_final = log.one(Stage::StreamFinal, epoch - 1);
        assert!(
            committee.overlaps(&previous_final),
            "epoch {epoch}'s committee proof must run beside epoch {}'s final \
             proof, not after it",
            epoch - 1,
        );
        // Its diff too, which has to finish first: the committee witness binds
        // the accumulator root the diff produces.
        let diff = log.one(Stage::EpochDiff, epoch);
        assert!(
            diff.end <= committee.start,
            "epoch {epoch}'s committee proof binds the root its diff produces, \
             so the diff must finish first",
        );
        assert!(
            diff.end <= previous_final.end,
            "epoch {epoch}'s diff must also be off the critical path",
        );
        // The strongest form of the claim: by the time the previous epoch
        // closed, this epoch's opening was already proved and waiting, so
        // opening it costs an await and nothing else.
        assert!(
            committee.end < previous_final.end,
            "epoch {epoch}'s opening proofs must be finished before epoch {} \
             closes, or opening it still waits on them",
            epoch - 1,
        );
    }

    // What that buys, measured. The cycle — one epoch's final proof to the
    // next one's — is now shorter than the three proofs it used to be the sum
    // of, which is the whole claim: the diff and the committee are no longer
    // on it.
    for epoch in [FIRST_EPOCH + 2, FIRST_EPOCH + 3] {
        let cycle = log
            .one(Stage::StreamFinal, epoch)
            .end
            .duration_since(log.one(Stage::StreamFinal, epoch - 1).end);
        assert!(
            cycle < SERIAL_CYCLE,
            "epoch {epoch} closed {cycle:?} after epoch {} did, which is no \
             better than proving its diff and committee on the chain \
             ({SERIAL_CYCLE:?}) — they have not left it",
            epoch - 1,
        );
    }
}

/// An epoch that fires on the tick it opens still starts the next epoch's
/// opening proofs, because the loop keeps running while its own proofs do.
///
/// This is mainnet epoch 469482 -> 469483, which cost 137 s of `T2 - T`.
///
/// The daemon opened 469482 at 02:11:30 and its threshold had already crossed,
/// so it fired on the tick it opened and the `!fire` branch — the only other
/// place [`Engine::speculate`] is called — never ran. `open_epoch`'s own call
/// had bailed: epoch 469483's first slot did not exist for another five
/// seconds. The loop then sat inside a blocking prover until 02:16:53, so the
/// retry that would have started 469483's opening proofs never happened and
/// nothing refreshed the head it would have been made against. 469483 proved
/// its own diff and committee — 153 s — before it could open, and opened with
/// 16.6 s of slack against a group proof of 105 s. Nothing could be folded, and
/// its whole backlog landed on the critical path: 299.7 s, against 162.3 s for
/// the epoch beside it that had 236 s of slack.
///
/// Both halves of that are pinned here. The head moves during the final proof,
/// which is the only thing a daemon proving on its loop cannot see, and the
/// assertion is that the next epoch's opening proofs ran beside that proof
/// rather than after it.
// Multi-threaded, because the point is that the chain moves on whether or not
// the daemon is in a position to look. A current-thread runtime would let a
// daemon blocking inside its prover hold the timer as well, which is a stronger
// claim than reality makes and not the one under test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_the_next_epoch_starts_while_this_one_proves_even_if_it_never_waited() {
    let dir = tempfile::tempdir().unwrap();
    let chain = chain();
    let log = ProofLog::default();
    let stream_epoch = FIRST_EPOCH + 1;
    let next_epoch = stream_epoch + 1;

    // The head stops on the streaming epoch's first slot, so the run justifies
    // the epoch before it and opens this one against a chain that holds none of
    // its attestations yet — and, crucially, none of the next epoch's boundary
    // either, so nothing can be proved ahead at the moment the epoch opens.
    let mut daemon = daemon(dir.path(), &chain, stream_epoch * SPE, log.clone()).await;
    let head = daemon.api().head_handle();
    daemon.catch_up().await.unwrap();
    assert_eq!(daemon.state().cursor_epoch, stream_epoch);
    assert!(
        log.all()
            .iter()
            .all(|w| !(w.stage == Stage::Committee && w.epoch == next_epoch)),
        "the next epoch cannot have been proved ahead yet: its boundary does \
         not exist on a chain that has not reached it",
    );

    // Now the whole epoch arrives at once, which is what being behind looks
    // like from the pipeline's side: the very first evaluation of the trigger
    // already holds enough stake, so it fires on the tick it sees it and never
    // takes the branch that folds.
    daemon
        .api()
        .set_head(chain.header_at(stream_epoch * SPE + SLOTS_TO_THRESHOLD));

    // And the next epoch begins while this one's final proof runs. On mainnet
    // this was five seconds after the epoch opened and five minutes before the
    // loop executed again.
    let arrived = chain.header_at(next_epoch * SPE + SLOTS_TO_THRESHOLD);
    tokio::spawn(async move {
        tokio::time::sleep(FINAL_PROVE / 4).await;
        *head.lock().unwrap() = Some(arrived);
    });

    daemon.catch_up().await.unwrap();
    assert_eq!(
        daemon.state().justified_through,
        Some(next_epoch),
        "both epochs still close, which is what proving off the loop must not \
         change",
    );

    let closing = log.one(Stage::StreamFinal, stream_epoch);
    let diff = log.one(Stage::EpochDiff, next_epoch);
    let committee = log.one(Stage::Committee, next_epoch);
    assert!(
        diff.overlaps(&closing),
        "epoch {next_epoch}'s diff must run beside epoch {stream_epoch}'s final \
         proof. It can only start once the loop has seen a head it did not have \
         when the epoch opened, so a loop that is inside the prover never sees \
         it and the diff lands on the next epoch's opening path instead",
    );
    assert!(
        committee.overlaps(&closing),
        "and so must its committee proof, which is the expensive half: \
         {COMMITTEE_PROVE:?} of the {SERIAL_CYCLE:?} an epoch has",
    );
    assert!(
        diff.end <= committee.start,
        "the committee witness binds the root the diff produces, so proving \
         them off the loop must not have reordered them",
    );
}

/// A daemon that cannot prove the next epoch ahead still proves it inline.
///
/// The head never leaves the epoch being streamed, so the boundary the next
/// epoch's diff needs does not exist yet and nothing can be started early. This
/// is the shape of every case the fallback has to survive — the first epoch of a
/// run, a restart, an epoch whose speculation was thrown away after a reorg —
/// and the epoch must still close, on the critical path, rather than fail.
#[tokio::test]
async fn test_an_epoch_that_could_not_be_proved_ahead_opens_on_the_critical_path() {
    let dir = tempfile::tempdir().unwrap();
    let chain = chain();
    let log = ProofLog::default();
    let stream_epoch = FIRST_EPOCH + 1;
    let mut daemon = daemon(dir.path(), &chain, (FIRST_EPOCH + 1) * SPE, log.clone()).await;

    // A slot at a time, and never past the epoch being streamed, so the next
    // epoch's boundary is never readable.
    let mut ticks = Vec::new();
    for slot in stream_epoch * SPE..=stream_epoch * SPE + SLOTS_TO_THRESHOLD {
        daemon.api().set_head(chain.header_at(slot));
        ticks.extend(daemon.catch_up().await.unwrap());
    }

    assert_eq!(
        ticks.iter().filter_map(|t| t.justified).collect::<Vec<_>>(),
        vec![FIRST_EPOCH, stream_epoch],
        "the epoch still closes with nothing proved ahead of it",
    );

    let committee = log.one(Stage::Committee, stream_epoch);
    assert!(
        log.ran_beside_anything(&committee).is_none(),
        "with no room to prove it ahead, the committee proof is on the chain — \
         which is correct, and only slower",
    );
}

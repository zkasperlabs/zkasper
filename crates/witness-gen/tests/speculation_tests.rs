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
//! These tests pin that with provers that take a known time per stage, prove one
//! thing at a time as a card does, and record the window each proof occupied. A
//! stage that overlaps another stage's window ran beside it; one that overlaps
//! nothing ran on the chain. That is a direct measurement of the thing the
//! change is for, rather than a proxy for it.
//!
//! # An epoch's closing path is a group and then a proof
//!
//! It used to be one proof. `9f10d05` repriced a recursion at the 1.520 s it
//! measures, which made a child cheap enough that the planner cuts a backlog
//! into groups instead of inlining it — see `18b1afe` for the same flip in
//! `streaming_test`. So an epoch that opens past its own threshold now proves a
//! group and *then* the proof that closes it, and the group is longer than the
//! whole of the next epoch's opening.
//!
//! Two things follow, and both are asserted below rather than assumed:
//!
//! - The opening proofs no longer overlap the *closing* proof. They overlap the
//!   group in front of it and are finished before the closing proof starts,
//!   which is better and not worse — so what these assert is that they ran
//!   beside the epoch, and finished before it closed.
//! - **One card can no longer hold both.** The opening proofs and the epoch's
//!   own two proofs are now four proofs on one GPU, and the opening ones win the
//!   race for it: measured here, a single card runs the next epoch's committee
//!   proof *between* this epoch's group and its closing proof, which puts it
//!   squarely on `T2 - T`. That is what
//!   [`test_one_card_puts_the_next_epoch_in_front_of_this_one`] pins, and it is
//!   a routing problem rather than a scheduling one: no ordering of one card
//!   fits four proofs into the time of two. The two tests that assert the
//!   opening is free therefore run on the two cards the deployment has, with
//!   `epoch_diff` and `committee` routed to the second.
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
use zkasper_witness_gen::split_prover::SplitProver;

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

/// The stages the opening of an epoch is made of, which are the ones that must
/// not be on its cycle.
const OPENING: [Stage; 2] = [Stage::EpochDiff, Stage::Committee];

/// The stages an epoch proves for itself, which are the ones that must be.
const OWN: [Stage; 3] = [Stage::Group, Stage::Aggregate, Stage::StreamFinal];

/// One proof: when the card was asked for it, and the window it spent on it.
///
/// The two differ by however long the call waited for the card, which is the
/// measurement these tests turn on — a proof that waited was behind another
/// proof, and the daemon put it there.
#[derive(Clone, Copy, Debug)]
struct Window {
    stage: Stage,
    epoch: u64,
    asked: Instant,
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

/// How long a call may take to pick a free card up before it counts as having
/// waited for it. Taking an uncontended mutex is microseconds; this is slack for
/// a loaded machine, and an order of magnitude below the shortest modelled
/// stage.
const NOT_WAITING: Duration = Duration::from_millis(10);

impl ProofLog {
    fn record(&self, stage: Stage, epoch: u64, asked: Instant, start: Instant) {
        self.0.lock().unwrap().push(Window {
            stage,
            epoch,
            asked,
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

    /// The proofs `epoch` made for itself, in the order they ran. Its opening
    /// proofs are not among them: those were made while the epoch before it ran.
    fn own(&self, epoch: u64) -> Vec<Window> {
        let mut found: Vec<Window> = self
            .all()
            .into_iter()
            .filter(|w| w.epoch == epoch && OWN.contains(&w.stage))
            .collect();
        found.sort_by_key(|w| w.start);
        assert!(!found.is_empty(), "epoch {epoch} proved nothing of its own");
        found
    }

    /// The window `epoch` spent proving itself: its first proof to its last.
    fn proving(&self, epoch: u64) -> Window {
        let own = self.own(epoch);
        Window {
            stage: Stage::Group,
            epoch,
            asked: own[0].asked,
            start: own[0].start,
            end: own[own.len() - 1].end,
        }
    }

    /// `epoch`'s own proofs that had to wait for a card, and what was on it.
    ///
    /// Its own proofs never wait for each other — the pipeline starts the next
    /// one only once the last has landed — so anything here waited for a proof
    /// of another epoch, which is the next epoch's opening sitting on this
    /// one's critical path. That is what the second card is bought to prevent,
    /// and no ordering of one card avoids it.
    fn queued(&self, epoch: u64) -> Vec<(Window, Option<Window>)> {
        self.own(epoch)
            .into_iter()
            .filter(|w| w.start.duration_since(w.asked) > NOT_WAITING)
            .map(|w| (w, self.held_the_card(&w)))
            .collect()
    }

    /// What held the card until `waited` got it: the proof that gave it up
    /// between the call being made and the call starting.
    fn held_the_card(&self, waited: &Window) -> Option<Window> {
        self.all()
            .into_iter()
            .filter(|other| waited.asked <= other.end && other.end <= waited.start)
            .max_by_key(|other| other.end)
    }

    /// What the epochs would have cost with nothing overlapping anything: every
    /// proof `epoch` needed, opening included, one after another.
    fn serial(&self, epoch: u64) -> Duration {
        self.all()
            .into_iter()
            .filter(|w| w.epoch == epoch && (OWN.contains(&w.stage) || OPENING.contains(&w.stage)))
            .map(|w| w.end.duration_since(w.start))
            .sum()
    }
}

/// One card: a known time over the three stages an epoch's cycle is made of,
/// one proof at a time, and a record of when each one ran.
///
/// The lock is the point. A prover is a process holding a GPU and Proofman
/// serialises proving on a mutex, so a second call queues — exactly as
/// [`crate::remote_prover::RemoteProver`] queues on its connection. Without it a
/// test measures a machine with as many cards as it has threads, and every
/// question about what a second card buys answers itself.
///
/// Everything else delegates to [`NativeProver`], so an epoch still composes
/// exactly as it does everywhere else in the suite. The group and the fold are
/// not slept on — the native circuits are the cost there, and it is larger than
/// any of the modelled ones — but they are timed and recorded, because an
/// epoch's own path is what the opening proofs have to stay out of.
struct TimedProver {
    inner: NativeProver,
    gpu: Mutex<()>,
    log: ProofLog,
}

impl TimedProver {
    fn new(config: ChainConfig, log: ProofLog) -> Self {
        Self {
            inner: NativeProver::new(config),
            gpu: Mutex::new(()),
            log,
        }
    }
}

/// A second handle onto a card, so two stages can be routed to the same one.
///
/// [`SplitProver`] takes a prover per route and so cannot say "these two stages,
/// that card" on its own; a deployment says it by pointing two routes at one
/// address, and this is that.
struct CardHandle(Arc<TimedProver>);

/// The deployment's shape: everything on one card, `routed` on a second.
fn two_cards(log: ProofLog, routed: &[Stage]) -> Box<dyn Prover> {
    let second = Arc::new(TimedProver::new(TEST_CONFIG, log.clone()));
    Box::new(
        SplitProver::new(
            Box::new(TimedProver::new(TEST_CONFIG, log)),
            routed
                .iter()
                .map(|stage| {
                    (
                        *stage,
                        Box::new(CardHandle(second.clone())) as Box<dyn Prover>,
                    )
                })
                .collect(),
        )
        .expect("a second card for the opening proofs"),
    )
}

impl Prover for TimedProver {
    fn name(&self) -> &'static str {
        "native (opening proofs deliberately slow)"
    }

    fn program_vk(&self, stage: Stage) -> ProgramVk {
        self.inner.program_vk(stage)
    }

    fn prove_epoch_diff(&self, witness: &EpochDiffWitness) -> Result<(EpochDiffOutput, Proof)> {
        let asked = Instant::now();
        let _gpu = self.gpu.lock().unwrap();
        let started = Instant::now();
        std::thread::sleep(DIFF_PROVE);
        let out = self.inner.prove_epoch_diff(witness)?;
        self.log
            .record(Stage::EpochDiff, witness.epoch_2, asked, started);
        Ok(out)
    }

    fn prove_committee(&self, witness: &CommitteeWitness) -> Result<(CommitteeOutput, Proof)> {
        let asked = Instant::now();
        let _gpu = self.gpu.lock().unwrap();
        let started = Instant::now();
        std::thread::sleep(COMMITTEE_PROVE);
        let out = self.inner.prove_committee(witness)?;
        self.log
            .record(Stage::Committee, witness.target_epoch, asked, started);
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
        let asked = Instant::now();
        let _gpu = self.gpu.lock().unwrap();
        let started = Instant::now();
        let out = self.inner.prove_group(witness)?;
        self.log
            .record(Stage::Group, witness.target_epoch, asked, started);
        Ok(out)
    }

    fn prove_aggregate(&self, witness: &AggregateWitness) -> Result<(AggregateOutput, Proof)> {
        let asked = Instant::now();
        let _gpu = self.gpu.lock().unwrap();
        let started = Instant::now();
        let out = self.inner.prove_aggregate(witness)?;
        self.log
            .record(Stage::Aggregate, witness.target_epoch, asked, started);
        Ok(out)
    }

    fn prove_stream_final(
        &self,
        witness: &StreamFinalWitness,
    ) -> Result<(StreamFinalOutput, Proof)> {
        let asked = Instant::now();
        let _gpu = self.gpu.lock().unwrap();
        let started = Instant::now();
        std::thread::sleep(FINAL_PROVE);
        let out = self.inner.prove_stream_final(witness)?;
        self.log
            .record(Stage::StreamFinal, witness.target_epoch, asked, started);
        Ok(out)
    }
}

impl Prover for CardHandle {
    fn name(&self) -> &'static str {
        self.0.name()
    }

    fn program_vk(&self, stage: Stage) -> ProgramVk {
        self.0.program_vk(stage)
    }

    fn prove_epoch_diff(&self, w: &EpochDiffWitness) -> Result<(EpochDiffOutput, Proof)> {
        self.0.prove_epoch_diff(w)
    }

    fn prove_committee(&self, w: &CommitteeWitness) -> Result<(CommitteeOutput, Proof)> {
        self.0.prove_committee(w)
    }

    fn prove_slot(&self, w: &SlotProofWitness) -> Result<(SlotProofOutput, Proof)> {
        self.0.prove_slot(w)
    }

    fn prove_justification(
        &self,
        w: &JustificationWitness,
    ) -> Result<(JustificationOutput, Proof)> {
        self.0.prove_justification(w)
    }

    fn prove_finalization(&self, w: &FinalizationWitness) -> Result<(FinalizationOutput, Proof)> {
        self.0.prove_finalization(w)
    }

    fn prove_group(&self, w: &SlotProofWitness) -> Result<(GroupProofOutput, Fp12, Proof)> {
        self.0.prove_group(w)
    }

    fn prove_aggregate(&self, w: &AggregateWitness) -> Result<(AggregateOutput, Proof)> {
        self.0.prove_aggregate(w)
    }

    fn prove_stream_final(&self, w: &StreamFinalWitness) -> Result<(StreamFinalOutput, Proof)> {
        self.0.prove_stream_final(w)
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
    let prover = Box::new(TimedProver::new(TEST_CONFIG, log));
    daemon_on(dir, chain, head_slot, prover).await
}

/// The same, on whatever cards are given.
async fn daemon_on(
    dir: &std::path::Path,
    chain: &SyntheticChain,
    head_slot: u64,
    prover: Box<dyn Prover>,
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
    Orchestrator::open(mock, config, prover)
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
///
/// On two cards, with the opening stages routed to the second. One card cannot
/// pass this and no scheduling makes it: an epoch that opens past its threshold
/// proves a group and a closing proof, the next epoch's opening is two more, and
/// four proofs do not fit on one GPU in the time of two. See
/// [`test_one_card_puts_the_next_epoch_in_front_of_this_one`] for what one card
/// does instead.
// Multi-threaded, because two cards proving at once is the property under test
// and each proof holds a blocking thread for its whole length.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_an_epoch_opens_on_proofs_made_while_the_epoch_before_it_ran() {
    let dir = tempfile::tempdir().unwrap();
    let chain = chain();
    let log = ProofLog::default();
    let mut daemon = daemon_on(
        dir.path(),
        &chain,
        LAST_EPOCH * SPE + SLOTS_TO_THRESHOLD,
        two_cards(log.clone(), &OPENING),
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

    // The change. Each later epoch's opening proofs were in flight while the
    // epoch before it was still proving.
    //
    // Beside that epoch, not beside its closing proof. Since `9f10d05` the
    // epoch proves a group first, and the group outlasts the whole opening —
    // so the opening finishes before the closing proof starts, which is the
    // same claim arriving earlier rather than a weaker one. What says it is
    // still early enough is `committee.end < closes`, below.
    for epoch in [FIRST_EPOCH + 2, FIRST_EPOCH + 3] {
        let committee = log.one(Stage::Committee, epoch);
        let diff = log.one(Stage::EpochDiff, epoch);
        let before = log.proving(epoch - 1);
        assert!(
            committee.overlaps(&before),
            "epoch {epoch}'s committee proof must run beside epoch {}, not \
             after it: {committee:?} against {before:?}",
            epoch - 1,
        );
        assert!(
            diff.overlaps(&before),
            "and so must its diff: {diff:?} against {before:?}",
        );
        // Which has to finish first: the committee witness binds the
        // accumulator root the diff produces.
        assert!(
            diff.end <= committee.start,
            "epoch {epoch}'s committee proof binds the root its diff produces, \
             so the diff must finish first",
        );
        // The strongest form of the claim: by the time the previous epoch
        // closed, this epoch's opening was already proved and waiting, so
        // opening it costs an await and nothing else.
        let closes = log.own(epoch - 1).last().expect("it closed").end;
        assert!(
            committee.end < closes,
            "epoch {epoch}'s opening proofs must be finished before epoch {} \
             closes, or opening it still waits on them",
            epoch - 1,
        );
        // And the other half of "beside", which one card cannot give: nothing
        // epoch-1 still had to prove ever waited for a card. A card that took
        // the committee proof in front of the closing proof would put
        // `COMMITTEE_PROVE` of the next epoch onto this one's `T2 - T`.
        assert!(
            log.queued(epoch - 1).is_empty(),
            "epoch {}'s own proofs waited for a card while epoch {epoch}'s \
             opening had it: {:?}",
            epoch - 1,
            log.queued(epoch - 1),
        );
    }

    // What that buys, measured. The cycle — one epoch's closing proof to the
    // next one's — is shorter than proving everything that epoch needed one
    // proof at a time, which is the whole claim: the diff and the committee are
    // no longer on it.
    //
    // Measured against what the run actually cost rather than a constant. The
    // epoch's own proofs are the native circuits and are not modelled, so a
    // number fixed in this file stops describing the epoch the moment the
    // planner cuts it differently — which is exactly what `9f10d05` did.
    for epoch in [FIRST_EPOCH + 2, FIRST_EPOCH + 3] {
        let cycle = log
            .own(epoch)
            .last()
            .expect("it closed")
            .end
            .duration_since(log.own(epoch - 1).last().expect("it closed").end);
        let serial = log.serial(epoch);
        assert!(
            cycle < serial,
            "epoch {epoch} closed {cycle:?} after epoch {} did, against \
             {serial:?} of proving one thing at a time — its diff and committee \
             have not left the cycle",
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
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
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
    let mut daemon = daemon_on(
        dir.path(),
        &chain,
        stream_epoch * SPE,
        two_cards(log.clone(), &OPENING),
    )
    .await;
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

    let closing = log.proving(stream_epoch);
    let diff = log.one(Stage::EpochDiff, next_epoch);
    let committee = log.one(Stage::Committee, next_epoch);
    assert!(
        diff.overlaps(&closing),
        "epoch {next_epoch}'s diff must run beside epoch {stream_epoch}'s own \
         proving. It can only start once the loop has seen a head it did not \
         have when the epoch opened, so a loop that is inside the prover never \
         sees it and the diff lands on the next epoch's opening path instead: \
         {diff:?} against {closing:?}",
    );
    assert!(
        committee.overlaps(&closing),
        "and so must its committee proof, which is the expensive half: \
         {COMMITTEE_PROVE:?} against an epoch that proves {closing:?}",
    );
    assert!(
        diff.end <= committee.start,
        "the committee witness binds the root the diff produces, so proving \
         them off the loop must not have reordered them",
    );
    // Beside, and not in front of. Epoch 11 proves a group and then the proof
    // that closes it, and a card that took the committee proof in between would
    // have put it on `T2 - T`.
    assert!(
        log.queued(stream_epoch).is_empty(),
        "epoch {stream_epoch}'s own proofs waited for a card while epoch \
         {next_epoch}'s opening had it: {:?}",
        log.queued(stream_epoch),
    );
    assert!(
        committee.end < log.own(stream_epoch).last().expect("it closed").end,
        "and it must be finished before epoch {stream_epoch} closes, or opening \
         epoch {next_epoch} still waits on it",
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

/// One card cannot hold both, and this is what it costs.
///
/// The counterpart to the two tests above, on the same chain and the same epoch
/// with the second card taken away. An epoch that opens past its own threshold
/// proves a group and then the proof that closes it; the next epoch's opening is
/// a diff and a committee proof. That is four proofs, and one GPU proves one at
/// a time, so two of them have to wait — and the ones that win the race for the
/// card are the opening proofs, because they are started as the epoch opens and
/// the closing proof is not queued until the group has landed.
///
/// So a single card runs the next epoch's committee proof *between* this epoch's
/// group and its closing proof. That is not a throughput cost: it is
/// [`COMMITTEE_PROVE`] added to `T2 - T`, the one number the project exists to
/// minimise, on every epoch.
///
/// It was not true before `9f10d05`. An epoch used to close on one proof, so
/// the opening had one proof to fit beside rather than two to fit between, and
/// the same single card was enough. Nothing about the daemon changed; the
/// planner cutting a backlog into groups did.
///
/// This asserts the cost rather than mourning it, so that a change which fixes
/// it fails here and has to say so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_one_card_puts_the_next_epoch_in_front_of_this_one() {
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

    daemon.catch_up().await.unwrap();
    assert_eq!(
        daemon.state().justified_through,
        Some(LAST_EPOCH),
        "one card still proves every epoch; what it cannot do is prove two at \
         once",
    );

    let epoch = FIRST_EPOCH + 2;
    let queued = log.queued(epoch);
    assert!(
        !queued.is_empty(),
        "one card should have made a proof of epoch {epoch} wait for an opening \
         proof of epoch {}; if it no longer does, the second card is no longer \
         needed and this test is the one to delete",
        epoch + 1,
    );
    // Both halves of the epoch waited, and for the two halves of the next
    // epoch's opening: the group behind the diff, and the closing proof behind
    // the committee proof. The second is the expensive one, because everything
    // after the group is `T2 - T`.
    let behind: Vec<(Stage, Stage, u64)> = queued
        .iter()
        .filter_map(|(waited, ahead)| ahead.map(|a| (waited.stage, a.stage, a.epoch)))
        .collect();
    assert!(
        behind.contains(&(Stage::StreamFinal, Stage::Committee, epoch + 1)),
        "the proof that closes epoch {epoch} must be seen waiting for epoch \
         {}'s committee proof, which is the whole cost of one card: {queued:?}",
        epoch + 1,
    );
    let (closing, _) = queued
        .iter()
        .find(|(waited, _)| waited.stage == Stage::StreamFinal)
        .expect("it waited");
    assert!(
        closing.start.duration_since(closing.asked) >= COMMITTEE_PROVE / 2,
        "and waited a good part of {COMMITTEE_PROVE:?} for it, straight onto \
         `T2 - T`: {:?}",
        closing.start.duration_since(closing.asked),
    );
}

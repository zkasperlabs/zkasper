//! Whether a second prover is a second proof in flight, or only a second queue.
//!
//! # What a card buys
//!
//! A prover is one process holding one GPU, and Proofman serialises proving on
//! a mutex, so one prover proves one thing at a time however many callers it
//! has. Routing a stage to a second card therefore changes *which* card is busy
//! by itself; what makes it change *how many* are busy is a pipeline that will
//! hold one proof in flight per prover rather than one for the whole pipeline.
//!
//! Measured on mainnet with two RTX 5090s over 2,740 s and eleven epochs,
//! 2026-08-19, with `committee` routed to the second card: the first card was
//! busy 14% of the time and the second 75%, and only 19% of the first card's
//! work was done while the second was working. The pipeline held one in-flight
//! proof for the whole of itself, so the second card mostly changed which card
//! was busy.
//!
//! # What is independent, and what is not
//!
//! Not everything may overlap. A group feeds the fold that follows it, folds
//! chain into one another, and the final proof binds a finished aggregate — so
//! the only pair of streaming proofs that are genuinely independent is a fold
//! and the group after it: the fold was handed its units when it started, and
//! the next group covers the ones after those. That pair is what these tests
//! measure, because it is the pair a second card can actually run at once.
//!
//! The cards here behave as a real one does — a second call queues on the card's
//! own lock, exactly as `RemoteProver` queues on its connection — and record
//! both the instant they were asked and the instant they began. A pipeline that
//! forgot the per-prover bound is then visible as two proofs asked for at once
//! rather than as a proof that merely took twice as long.

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
    // Twice as many slots as there are validators to attest at them, so the
    // epoch still has slots left when the threshold is crossed.
    slots_per_epoch: 8,
    validators_tree_depth: 2,
    acc_tree_depth: 2,
    beacon_state_validators_field_index: 11,
    fulu_fork_epoch: 0,
};
const SPE: u64 = TEST_CONFIG.slots_per_epoch;

const FIRST_EPOCH: u64 = 10;
const LAST_EPOCH: u64 = 12;
const VALIDATORS: usize = 4;

/// Cumulative balance crosses 2/3 of 128 ETH at the third attesting validator,
/// so the epoch closes two groups and two folds in.
const SLOTS_TO_THRESHOLD: u64 = 3;

/// How long the card that folds takes over one.
///
/// Long enough that the fold is still running several trigger intervals after
/// it started, which is what gives the other card a tick on which to start the
/// group beside it. On mainnet the same relationship holds for free: a fold is
/// tens of seconds and a tick is 200 ms.
const FOLD_PROVE: Duration = Duration::from_millis(1_200);

/// How long the chain takes to reach its next slot.
///
/// Short against [`FOLD_PROVE`], so that slots close while a fold is in flight.
/// That is the case a second card is for and the case a daemon fed one slot per
/// tick never reaches: a slot that closes only once the fold has landed is a
/// group there was never a free card to prove.
const HEAD_STEP: Duration = Duration::from_millis(400);

/// One proof: when the card was asked for it, and the window it was busy with
/// it. The two differ by however long the call queued on the card.
#[derive(Clone, Copy, Debug)]
struct Window {
    card: &'static str,
    stage: Stage,
    asked: Instant,
    start: Instant,
    end: Instant,
}

impl Window {
    /// Whether the two were being proved at the same time.
    fn overlaps(&self, other: &Window) -> bool {
        self.start < other.end && other.start < self.end
    }

    /// Whether the two were asked for at the same time, which is what the
    /// pipeline decides and the card only suffers.
    fn asked_together(&self, other: &Window) -> bool {
        self.asked < other.end && other.asked < self.end
    }

    /// Whether this is one of the streaming pipeline's own proofs, as opposed
    /// to an opening proof the next epoch's speculation runs beside them.
    fn streamed(&self) -> bool {
        matches!(
            self.stage,
            Stage::Group | Stage::Aggregate | Stage::StreamFinal
        )
    }
}

#[derive(Clone, Default)]
struct ProofLog(Arc<Mutex<Vec<Window>>>);

impl ProofLog {
    fn record(&self, window: Window) {
        self.0.lock().unwrap().push(window);
    }

    fn windows(&self) -> Vec<Window> {
        self.0.lock().unwrap().clone()
    }

    /// Every pair of streaming proofs the pipeline had in flight on one card at
    /// once. One prover proves one thing at a time, so this must stay empty
    /// whatever the routing is.
    fn double_booked(&self) -> Vec<(Window, Window)> {
        self.pairs(|one, other| {
            one.card == other.card
                && one.streamed()
                && other.streamed()
                && one.asked_together(other)
        })
    }

    fn pairs(&self, keep: impl Fn(&Window, &Window) -> bool) -> Vec<(Window, Window)> {
        let windows = self.windows();
        let mut found = Vec::new();
        for (i, one) in windows.iter().enumerate() {
            for other in &windows[i + 1..] {
                if keep(one, other) {
                    found.push((*one, *other));
                }
            }
        }
        found
    }
}

/// One card: one GPU, one proof at a time, and a second caller queues.
struct Card {
    name: &'static str,
    inner: NativeProver,
    gpu: Mutex<()>,
    log: ProofLog,
}

impl Card {
    fn new(name: &'static str, log: ProofLog) -> Self {
        Self {
            name,
            inner: NativeProver::new(TEST_CONFIG),
            gpu: Mutex::new(()),
            log,
        }
    }

    fn run<T>(&self, stage: Stage, prove: impl FnOnce(&NativeProver) -> Result<T>) -> Result<T> {
        let asked = Instant::now();
        let _held = self.gpu.lock().unwrap();
        let start = Instant::now();
        if stage == Stage::Aggregate {
            std::thread::sleep(FOLD_PROVE);
        }
        let proved = prove(&self.inner);
        self.log.record(Window {
            card: self.name,
            stage,
            asked,
            start,
            end: Instant::now(),
        });
        proved
    }
}

impl Prover for Card {
    fn name(&self) -> &'static str {
        "native (one card, timed)"
    }

    fn program_vk(&self, stage: Stage) -> ProgramVk {
        self.inner.program_vk(stage)
    }

    fn prove_epoch_diff(&self, w: &EpochDiffWitness) -> Result<(EpochDiffOutput, Proof)> {
        self.run(Stage::EpochDiff, |p| p.prove_epoch_diff(w))
    }

    fn prove_committee(&self, w: &CommitteeWitness) -> Result<(CommitteeOutput, Proof)> {
        self.run(Stage::Committee, |p| p.prove_committee(w))
    }

    fn prove_slot(&self, w: &SlotProofWitness) -> Result<(SlotProofOutput, Proof)> {
        self.run(Stage::SlotProof, |p| p.prove_slot(w))
    }

    fn prove_justification(
        &self,
        w: &JustificationWitness,
    ) -> Result<(JustificationOutput, Proof)> {
        self.run(Stage::Justification, |p| p.prove_justification(w))
    }

    fn prove_finalization(&self, w: &FinalizationWitness) -> Result<(FinalizationOutput, Proof)> {
        self.run(Stage::Finalization, |p| p.prove_finalization(w))
    }

    fn prove_group(&self, w: &SlotProofWitness) -> Result<(GroupProofOutput, Fp12, Proof)> {
        self.run(Stage::Group, |p| p.prove_group(w))
    }

    fn prove_aggregate(&self, w: &AggregateWitness) -> Result<(AggregateOutput, Proof)> {
        self.run(Stage::Aggregate, |p| p.prove_aggregate(w))
    }

    fn prove_stream_final(&self, w: &StreamFinalWitness) -> Result<(StreamFinalOutput, Proof)> {
        self.run(Stage::StreamFinal, |p| p.prove_stream_final(w))
    }
}

/// A streaming daemon on `chain`, proving on whatever `prover` is.
async fn daemon(
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

/// Stream one epoch against a chain that keeps moving, and hand back the epochs
/// the ticks justified.
async fn stream_one_epoch(
    daemon: &mut Orchestrator<MockBeaconApi>,
    chain: &SyntheticChain,
) -> Vec<u64> {
    // The epoch before this one has nothing to finalize, so it goes through the
    // batch path and leaves the justification this one streams against.
    let mut justified: Vec<u64> = daemon
        .catch_up()
        .await
        .unwrap()
        .iter()
        .filter_map(|tick| tick.justified)
        .collect();

    let stream_epoch = FIRST_EPOCH + 1;
    let boundary = stream_epoch * SPE;
    // The head moves on its own clock rather than a tick's, because the daemon
    // being busy is the whole point. A slot's attestations are carried by the
    // block after it, so a head one slot ahead is the earliest the daemon can
    // close the one behind it.
    let head = daemon.api().head_handle();
    let headers: Vec<_> = (boundary..=boundary + SLOTS_TO_THRESHOLD)
        .map(|slot| chain.header_at(slot))
        .collect();
    tokio::spawn(async move {
        for header in headers {
            *head.lock().unwrap() = Some(header);
            tokio::time::sleep(HEAD_STEP).await;
        }
    });

    for _ in 0..500 {
        justified.extend(
            daemon
                .catch_up()
                .await
                .unwrap()
                .iter()
                .filter_map(|tick| tick.justified),
        );
        if justified.contains(&stream_epoch) {
            return justified;
        }
        tokio::time::sleep(HEAD_STEP / 8).await;
    }
    panic!("the epoch never closed: {justified:?}");
}

fn chain() -> SyntheticChain {
    SyntheticChain::new(TEST_CONFIG, VALIDATORS, FIRST_EPOCH, LAST_EPOCH)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A fold on the card it is routed to does not stop the other card proving the
/// group that follows it.
///
/// The two are independent by construction — the fold was handed its units when
/// it started and the group covers the ones after them — so a pipeline that
/// held one proof for the whole of itself left the second card idle for the
/// length of every fold. Here the fold is the slow stage and it is the only one
/// routed away, which is the shape of the deployment: eight stages on one card
/// and one stage on another.
// Multi-threaded, because the claim is about two proofs being in flight at
// once and each of them holds a blocking thread for its whole length.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_stage_on_its_own_card_runs_beside_the_other_card() {
    let dir = tempfile::tempdir().unwrap();
    let chain = chain();
    let log = ProofLog::default();
    let split = SplitProver::new(
        Box::new(Card::new("one", log.clone())),
        vec![(
            Stage::Aggregate,
            Box::new(Card::new("two", log.clone())) as Box<dyn Prover>,
        )],
    )
    .expect("two cards, the fold on the second");
    assert_eq!(split.routed(), vec!["aggregate"]);

    let mut daemon = daemon(dir.path(), &chain, (FIRST_EPOCH + 1) * SPE, Box::new(split)).await;
    let justified = stream_one_epoch(&mut daemon, &chain).await;

    assert_eq!(
        justified,
        vec![FIRST_EPOCH, FIRST_EPOCH + 1],
        "both epochs still close, which is what proving on two cards must not \
         change",
    );
    assert!(
        log.double_booked().is_empty(),
        "one card was asked for two proofs at once: {:?}",
        log.double_booked(),
    );

    let beside = log.pairs(|one, other| {
        one.card != other.card
            && one.overlaps(other)
            && [one.stage, other.stage].contains(&Stage::Group)
            && [one.stage, other.stage].contains(&Stage::Aggregate)
    });
    assert!(
        !beside.is_empty(),
        "no group proof was ever in flight while a fold was, so the second card \
         changed which card was busy and not how many: {:?}",
        log.windows(),
    );
}

/// One card is still one proof at a time, whatever the pipeline may hold.
///
/// The control for the test above, on the same chain and the same epoch: with
/// nothing routed away there is one prover, so nothing may overlap and the
/// epoch must close exactly as it did before. This is the shape every existing
/// deployment and every other test in the suite runs in, and the per-prover
/// bound must not have loosened it into a per-pipeline one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_card_still_proves_one_thing_at_a_time() {
    let dir = tempfile::tempdir().unwrap();
    let chain = chain();
    let log = ProofLog::default();

    let mut daemon = daemon(
        dir.path(),
        &chain,
        (FIRST_EPOCH + 1) * SPE,
        Box::new(Card::new("one", log.clone())),
    )
    .await;
    let justified = stream_one_epoch(&mut daemon, &chain).await;

    assert_eq!(justified, vec![FIRST_EPOCH, FIRST_EPOCH + 1]);
    assert!(
        log.double_booked().is_empty(),
        "the one card was asked for two proofs at once: {:?}",
        log.double_booked(),
    );
    assert!(
        log.pairs(|one, other| one.card != other.card).is_empty(),
        "there was only one card",
    );
}

//! What one tick costs while the prover is still working.
//!
//! `catch_up` does not sleep between ticks while a proof is in flight: the wait
//! *is* the tick, inside `Proving::settle`, which returns at the trigger
//! interval or the instant the proof lands. So while a 68 s mainnet group proof
//! runs, the loop closes a `stream` span every 200 ms — around 900 of them for
//! one epoch — and the only thing that decides whether that is a healthy
//! pipeline or a spinning core is what one of those ticks costs.
//!
//! # Why the cost has to be pinned through the log
//!
//! It used to be impossible to tell, because the number the daemon printed was
//! not a cost. The span was held as an entered guard across the await, and an
//! entered guard is never exited when the future yields, so `settle`'s own sleep
//! was billed to `time.busy`:
//!
//! ```text
//! INFO stream{target_epoch=469508}: close time.busy=201ms time.idle=2.40µs
//! ```
//!
//! Five of those a second, 1,270 lines a minute, each claiming a full
//! core-second per second of work. It was read as a hot loop twice before the
//! arithmetic settled it: across one 2.5-hour mainnet run those lines claimed
//! 6,291 seconds of busy against the 2,177 seconds of CPU the entire process had
//! used — 289% of it, on one span, in a daemon averaging a quarter of a core.
//! The wait was always free. Only the accounting was not.
//!
//! That is why this measures what the fmt layer prints rather than timing the
//! loop from outside. A wall-clock test would have passed the whole time: the
//! daemon never was slow, and an assertion that cannot fail on the broken
//! version pins nothing. The defect was in the diagnostic, so the diagnostic is
//! what is under test.
//!
//! # One test, one binary
//!
//! `tracing` caches callsite interest globally, so a second test touching the
//! `stream` callsite from another thread can decide it before this one installs
//! its subscriber, and the layer then sees nothing at all. That is a race, not a
//! failure, which is worse — so this test gets a process to itself, and the
//! assertion on how many waiting ticks were seen is what would catch it if the
//! isolation ever stopped holding.

mod common;

use std::path::Path;
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

use tracing::span::{Attributes, Id};
use tracing::Subscriber;
use tracing_subscriber::layer::{Context as LayerContext, Layer, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;

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

/// Long enough that the loop has to wait out several trigger intervals for one
/// proof, which is the situation being measured, and nothing longer.
const SLOW_PROVE: Duration = Duration::from_millis(1200);

// ---------------------------------------------------------------------------
// A prover that keeps the loop waiting
// ---------------------------------------------------------------------------

/// [`NativeProver`], but the two streaming stages take real time.
///
/// Sleeping on the proving thread is what a remote prover does to this loop:
/// the blocking task is parked, `settle` times out against it again and again,
/// and every one of those timeouts is a tick this test measures.
struct SlowProver(NativeProver);

impl Prover for SlowProver {
    fn name(&self) -> &'static str {
        "native (deliberately slow)"
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
        std::thread::sleep(SLOW_PROVE);
        self.0.prove_group(witness)
    }

    fn prove_aggregate(&self, witness: &AggregateWitness) -> Result<(AggregateOutput, Proof)> {
        std::thread::sleep(SLOW_PROVE);
        self.0.prove_aggregate(witness)
    }

    fn prove_stream_final(
        &self,
        witness: &StreamFinalWitness,
    ) -> Result<(StreamFinalOutput, Proof)> {
        self.0.prove_stream_final(witness)
    }
}

// ---------------------------------------------------------------------------
// The busy/idle split, as the log prints it
// ---------------------------------------------------------------------------

/// Every `stream` span that closed, as one [`Tick`].
///
/// The busy/idle split is the same accounting `tracing_subscriber`'s fmt layer
/// does for its `time.busy` / `time.idle` fields, so what is asserted here is
/// the number an operator reads — not a second measurement that could agree
/// with the code while the log disagrees with both.
#[derive(Clone, Default)]
struct TickCost(Arc<Mutex<Vec<Tick>>>);

#[derive(Clone, Copy)]
struct Tick {
    busy: Duration,
    idle: Duration,
    /// Whether anything opened a span under this one.
    ///
    /// This is what separates the tick being measured from every other tick. A
    /// pass that collects a proof, builds a witness or starts the next stage
    /// does so inside a `witness` or `stage` span, and is entitled to cost what
    /// that work costs. A pass that found the prover still busy opens nothing —
    /// it drains gossip, asks for the next epoch's opening proofs and returns —
    /// so it is the one whose cost has to stay near zero, and telling them
    /// apart by their children works the same before and after the fix.
    worked: bool,
}

struct SpanTimings {
    busy: Duration,
    idle: Duration,
    last: Instant,
    worked: bool,
}

impl TickCost {
    fn ticks(&self) -> Vec<Tick> {
        self.0.lock().expect("tick costs").clone()
    }
}

impl<S> Layer<S> for TickCost
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: LayerContext<'_, S>) {
        if attrs.metadata().name() == "stream" {
            if let Some(span) = ctx.span(id) {
                span.extensions_mut().insert(SpanTimings {
                    busy: Duration::ZERO,
                    idle: Duration::ZERO,
                    last: Instant::now(),
                    worked: false,
                });
            }
            return;
        }
        // Anything else opening under a tick is that tick doing real work.
        let Some(scope) = ctx.span_scope(id) else {
            return;
        };
        for span in scope {
            if let Some(timings) = span.extensions_mut().get_mut::<SpanTimings>() {
                timings.worked = true;
                return;
            }
        }
    }

    fn on_enter(&self, id: &Id, ctx: LayerContext<'_, S>) {
        if let Some(span) = ctx.span(id) {
            if let Some(timings) = span.extensions_mut().get_mut::<SpanTimings>() {
                let now = Instant::now();
                timings.idle += now.saturating_duration_since(timings.last);
                timings.last = now;
            }
        }
    }

    fn on_exit(&self, id: &Id, ctx: LayerContext<'_, S>) {
        if let Some(span) = ctx.span(id) {
            if let Some(timings) = span.extensions_mut().get_mut::<SpanTimings>() {
                let now = Instant::now();
                timings.busy += now.saturating_duration_since(timings.last);
                timings.last = now;
            }
        }
    }

    fn on_close(&self, id: Id, ctx: LayerContext<'_, S>) {
        let Some(span) = ctx.span(&id) else {
            return;
        };
        let Some(timings) = span.extensions_mut().remove::<SpanTimings>() else {
            return;
        };
        let idle = timings.idle + Instant::now().saturating_duration_since(timings.last);
        self.0.lock().expect("tick costs").push(Tick {
            busy: timings.busy,
            idle,
            worked: timings.worked,
        });
    }
}

/// A daemon that has justified epoch 10 the batch way and is sitting on 11,
/// which it will stream against a prover that makes it wait.
async fn slow_daemon(dir: &Path, chain: &SyntheticChain) -> Orchestrator<MockBeaconApi> {
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
        Box::new(SlowProver(NativeProver::new(TEST_CONFIG))),
    )
    .await
    .expect("orchestrator opens");
    daemon.catch_up().await.expect("the first epoch is proven");
    daemon
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

/// A tick that finds the prover still working costs a fraction of the interval
/// it waits out, and reports itself that way.
///
/// The budget is a tenth of the trigger interval, which is far looser than what
/// the loop actually does — a waiting tick measured 14 µs here, and about a
/// millisecond on mainnet where there is gossip to drain and a head to refresh.
/// Loose on purpose: this is a ceiling on a poll that runs five times a second
/// forever, not a benchmark. Anything approaching it means either the tick has
/// started doing real work on a pass that found nothing to do, or the span is
/// being held across the await again — which bills the wait as work and makes a
/// sleeping daemon read as a spinning one.
#[tokio::test]
async fn test_a_tick_that_waits_on_a_proof_costs_almost_nothing() {
    let cost = TickCost::default();
    let _tracing =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(cost.clone()));

    let dir = tempfile::tempdir().expect("tempdir");
    let chain = SyntheticChain::new(TEST_CONFIG, VALIDATORS, FIRST_EPOCH, LAST_EPOCH);
    let mut daemon = slow_daemon(dir.path(), &chain).await;

    let boundary = (FIRST_EPOCH + 1) * SPE;
    for slot in boundary..=boundary + SLOTS_TO_THRESHOLD {
        daemon.api().set_head(chain.header_at(slot));
        daemon.catch_up().await.expect("the epoch streams");
    }

    let interval = OrchestratorConfig::new(TEST_CONFIG, "test").trigger_interval;
    // A tick that opened nothing and still lasted a whole trigger interval is
    // one where `settle` timed out on a proof that had not landed. Selecting on
    // the total rather than on the idle half is what makes this fail the old way
    // round, where that very wait was reported as busy and idle was microseconds.
    let waited: Vec<Tick> = cost
        .ticks()
        .into_iter()
        .filter(|tick| !tick.worked && tick.busy + tick.idle >= interval.mul_f64(0.75))
        .collect();

    assert!(
        waited.len() >= 3,
        "expected the loop to wait out several trigger intervals while the prover \
         slept, saw {} such ticks in {} closed spans. Without them this test \
         proves nothing — check that the subscriber is still installed before \
         anything touches the `stream` callsite",
        waited.len(),
        cost.ticks().len(),
    );

    let budget = interval / 10;
    let worst = waited
        .iter()
        .map(|tick| tick.busy)
        .max()
        .expect("a waiting tick");
    assert!(
        worst <= budget,
        "a tick that only waited out the trigger interval reported {worst:?} of \
         time.busy, over a budget of {budget:?}. At five ticks a second there is \
         no headroom for real work on a pass that found the prover still busy — \
         and if the loop is in fact asleep, then the span is being held across \
         the await and the log is calling a sleeping daemon a spinning one.",
    );
}

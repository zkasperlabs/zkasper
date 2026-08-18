//! Prometheus metrics, served by the daemon itself.
//!
//! Two halves, and neither of them is a stopwatch.
//!
//! *Durations come from `tracing`.* Every stage runs inside a span named
//! `stage` carrying a `stage` field, and [`StageMetrics`] is a
//! `tracing_subscriber` layer that turns each span's close into
//! `zkasper_stage_duration_seconds` and `zkasper_stage_busy_seconds`. It keeps
//! the same busy/idle split the `fmt` layer already logs, so `busy` is the work
//! and the difference is what the stage spent waiting on the node or the
//! prover. Nothing here measures time that a span does not already measure.
//!
//! *Everything else is read from the source that owns it.* The gossip source
//! and the publisher already hold monotonic atomics, so they are mirrored with
//! `absolute()` rather than counted a second time; the accumulator gauges come
//! off the in-memory store. No file is parsed to produce a metric.
//!
//! Names follow the Prometheus conventions rather than the manifest's: base
//! units (seconds, bytes, gwei), `_total` on every counter, histograms where the
//! distribution is the point. The manifest keeps its millisecond fields — the
//! API and the dashboard are a separate contract.

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use metrics::{
    counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram, Unit,
};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id};
use tracing::Subscriber;
use tracing_subscriber::layer::Context as LayerContext;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

use crate::artifacts::{EpochLatency, StageTiming};
use crate::gossip::Counters as GossipCounters;
use crate::prover::Stage;
use crate::publish::{PublishCounters, ZISK_VERSION};
use crate::store::StoreState;

/// Name of the span every stage runs inside, and the field carrying which stage
/// it is. `#[instrument]` needs both as literals, so the orchestrator spells
/// them out; the layer measures spans that match and ignores every other one,
/// which is what keeps the label set to the nine stages.
const STAGE_SPAN: &str = "stage";
const STAGE_FIELD: &str = "stage";

/// How often the process collector re-reads `/proc/self`.
const PROCESS_INTERVAL: Duration = Duration::from_secs(10);

/// `T2 - T`, the number the whole streaming pipeline exists to make small.
/// Measured between 1.2 s and 7 s so far, with the low end packed: the buckets
/// are dense there and run well past the observed tail, because an epoch that
/// took 20 s is the one worth seeing.
const LATENCY_BUCKETS: &[f64] = &[
    0.5, 0.75, 1.0, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 10.0, 15.0, 20.0, 30.0,
];

/// How long the trigger held past the threshold. Capped by
/// `--max-trigger-wait-millis`, which defaults to 10 s.
const WAIT_BUCKETS: &[f64] = &[
    0.1, 0.25, 0.5, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 12.0,
];

/// Absentees the final proof opened inline. A count, not a duration, but the
/// distribution is what says whether the trigger rule is paying for itself.
const TAIL_BUCKETS: &[f64] = &[
    0.0, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0, 1024.0, 4096.0,
];

/// Stages span three orders of magnitude: a fold is 50 ms and the committee
/// proof is about 130 s, so one bucket set has to cover both.
const STAGE_BUCKETS: &[f64] = &[
    0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 192.0, 256.0, 512.0,
];

/// Which histograms get buckets.
const BUCKETS: &[(&str, &[f64])] = &[
    ("zkasper_t2_minus_t_seconds", LATENCY_BUCKETS),
    ("zkasper_trigger_wait_seconds", WAIT_BUCKETS),
    ("zkasper_tail_named", TAIL_BUCKETS),
    ("zkasper_stage_duration_seconds", STAGE_BUCKETS),
    ("zkasper_stage_busy_seconds", STAGE_BUCKETS),
    ("zkasper_prove_duration_seconds", STAGE_BUCKETS),
    ("zkasper_wrap_duration_seconds", STAGE_BUCKETS),
];

/// Serve `/metrics` on `addr` for the life of the process.
///
/// Must be called from inside the Tokio runtime: the exporter's listener and
/// the process collector are both tasks on it.
pub fn install(addr: SocketAddr) -> Result<()> {
    configured()?
        .with_http_listener(addr)
        .install()
        .context("install the Prometheus exporter")?;
    describe();

    // Rust gives no process metrics for free, and the standard ones —
    // `process_resident_memory_bytes` and the rest — are how a leak is told
    // apart from a slow chain. This is the crate that reads them.
    let collector = metrics_process::Collector::default();
    collector.describe();
    tokio::spawn(async move {
        loop {
            collector.collect();
            tokio::time::sleep(PROCESS_INTERVAL).await;
        }
    });
    Ok(())
}

/// The same recorder with no listener, handing back the handle that renders it.
///
/// What it renders is what `/metrics` serves, which is what makes it worth
/// asserting against: the tests check the exposition rather than the fields the
/// daemon happened to set.
pub fn install_recorder() -> Result<metrics_exporter_prometheus::PrometheusHandle> {
    let handle = configured()?
        .install_recorder()
        .context("install the Prometheus recorder")?;
    describe();
    Ok(handle)
}

/// The exporter, with every histogram's buckets set. Anything left as a summary
/// could not be aggregated across daemons.
fn configured() -> Result<PrometheusBuilder> {
    let mut builder = PrometheusBuilder::new();
    for (metric, buckets) in BUCKETS {
        builder = builder
            .set_buckets_for_metric(Matcher::Full((*metric).to_string()), buckets)
            .with_context(|| format!("set buckets for {metric}"))?;
    }
    Ok(builder)
}

/// The deploy this process is, as labels on a gauge of 1.
///
/// The standard way to correlate a change in any other series with a restart:
/// this project moves constants often enough that "did the numbers change or did
/// the binary" is a question worth being able to answer.
pub fn build_info(chain: &str, prover: &str, pipeline: &str) {
    gauge!(
        "zkasper_build_info",
        "version" => env!("CARGO_PKG_VERSION"),
        "commit" => option_env!("ZKASPER_COMMIT").unwrap_or("unknown"),
        "zisk_version" => ZISK_VERSION,
        "chain" => chain.to_string(),
        "prover" => prover.to_string(),
        "pipeline" => pipeline.to_string(),
    )
    .set(1.0);
}

/// Where the accumulator, the chain and the node are, as of now.
///
/// Called wherever the manifest is written, which is the end of every tick, so
/// `zkasper_manifest_updated_timestamp_seconds` is a heartbeat with the
/// resolution of the poll interval. A daemon that is wedged stops moving it, and
/// that is the first thing to alert on.
pub fn observe_state(state: &StoreState, head_slot: u64, node_finalized: Option<u64>) {
    gauge!("zkasper_manifest_updated_timestamp_seconds").set(unix_seconds());
    gauge!("zkasper_accumulator_epoch").set(state.cursor_epoch as f64);
    gauge!("zkasper_bootstrap_epoch").set(state.bootstrap_epoch as f64);
    gauge!("zkasper_head_slot").set(head_slot as f64);
    gauge!("zkasper_validators").set(state.num_validators as f64);
    gauge!("zkasper_total_active_balance_gwei").set(state.total_active_balance as f64);
    if let Some(epoch) = state.justified_through {
        gauge!("zkasper_justified_epoch").set(epoch as f64);
    }
    if let Some(checkpoint) = &state.finalized {
        gauge!("zkasper_finalized_epoch").set(checkpoint.epoch as f64);
    }
    if let Some(epoch) = node_finalized {
        gauge!("zkasper_node_finalized_epoch").set(epoch as f64);
    }
}

/// What the event stream has delivered and lost.
///
/// `dropped` is the nastiest failure this daemon has: the node threw
/// attestations away because its own SSE channel overflowed, the epoch is
/// quietly short of weight, and it looks exactly like a slow chain. It never
/// recovers on its own — the fix is `--http-sse-capacity-multiplier` on the
/// node — so any increase at all is worth waking someone for.
pub fn observe_gossip(counters: GossipCounters) {
    counter!("zkasper_gossip_attestations_total").absolute(counters.attestations);
    counter!("zkasper_gossip_reconnects_total").absolute(counters.reconnects);
    counter!("zkasper_gossip_dropped_total").absolute(counters.dropped);
}

/// How the mirror at the public API is keeping up.
pub fn observe_publish(counters: PublishCounters) {
    counter!("zkasper_publish_posted_total").absolute(counters.posted);
    counter!("zkasper_publish_spooled_total").absolute(counters.spooled);
    counter!("zkasper_publish_dropped_total").absolute(counters.dropped);
    gauge!("zkasper_publish_pending").set(counters.pending as f64);
}

/// What the prover charged for a stage, and how big the proof was.
///
/// The stage's own duration is not here: the span already measures it. These are
/// the prover's own accounting, which is the only source for them when the
/// prover is on another machine.
pub fn observe_stage(timing: &StageTiming) {
    let Some(stage) = stage_label(&timing.stage) else {
        return;
    };
    if let Some(millis) = timing.prove_millis {
        histogram!("zkasper_prove_duration_seconds", "stage" => stage).record(seconds(millis));
    }
    if let Some(millis) = timing.wrap_millis {
        histogram!("zkasper_wrap_duration_seconds", "stage" => stage).record(seconds(millis));
    }
    // Recorded even when it is zero, which is every witness-only run: a counter
    // that only appears once it is non-zero cannot be rated from a fresh start.
    counter!("zkasper_proof_bytes_total", "stage" => stage).increment(timing.proof_bytes);
}

/// One epoch's measured latency, the moment it is known.
pub fn observe_latency(latency: &EpochLatency) {
    histogram!("zkasper_t2_minus_t_seconds").record(seconds(latency.t2_minus_t_millis));
    histogram!("zkasper_trigger_wait_seconds").record(seconds(latency.wait_millis));
    histogram!("zkasper_tail_named").record(latency.tail_named as f64);
    counter!("zkasper_groups_folded_total").increment(latency.folded_groups as u64);
    counter!("zkasper_groups_late_total").increment(latency.late_groups as u64);
}

/// An epoch was justified, by either pipeline.
pub fn epoch_justified() {
    counter!("zkasper_epochs_justified_total").increment(1);
}

/// An epoch was finalized.
pub fn epoch_finalized() {
    counter!("zkasper_epochs_finalized_total").increment(1);
}

/// An epoch was given up on. `reason` is a closed set, so it is safe as a label.
pub fn epoch_abandoned(reason: &'static str) {
    counter!("zkasper_epochs_abandoned_total", "reason" => reason).increment(1);
}

fn describe() {
    describe_gauge!(
        "zkasper_build_info",
        "Always 1. The version, commit and Zisk release this process was built from."
    );
    describe_gauge!(
        "zkasper_manifest_updated_timestamp_seconds",
        Unit::Seconds,
        "When the daemon last completed a tick and rewrote its manifest."
    );
    describe_gauge!(
        "zkasper_accumulator_epoch",
        "Epoch the accumulator represents."
    );
    describe_gauge!(
        "zkasper_bootstrap_epoch",
        "Epoch the accumulator was bootstrapped at."
    );
    describe_gauge!(
        "zkasper_head_slot",
        "Head slot as last reported by the beacon node."
    );
    describe_gauge!("zkasper_validators", "Validators in the accumulator.");
    describe_gauge!(
        "zkasper_total_active_balance_gwei",
        "Total active balance the accumulator commits to."
    );
    describe_gauge!(
        "zkasper_justified_epoch",
        "Last epoch this daemon justified."
    );
    describe_gauge!(
        "zkasper_finalized_epoch",
        "Last epoch this daemon finalized."
    );
    describe_gauge!(
        "zkasper_node_finalized_epoch",
        "Last epoch the beacon node considers finalized."
    );
    describe_gauge!(
        "zkasper_publish_pending",
        "Batches waiting to reach the API."
    );

    describe_counter!(
        "zkasper_gossip_attestations_total",
        "Attestations delivered by the event stream."
    );
    describe_counter!(
        "zkasper_gossip_reconnects_total",
        "Times the event stream had to be reconnected. Each one is a hole blocks had to repair."
    );
    describe_counter!(
        "zkasper_gossip_dropped_total",
        "Times the node reported dropping events because its SSE channel overflowed. \
         Raise --http-sse-capacity-multiplier on the node."
    );
    describe_counter!(
        "zkasper_publish_posted_total",
        "Batches accepted by the API."
    );
    describe_counter!(
        "zkasper_publish_spooled_total",
        "Batches written to the disk spool."
    );
    describe_counter!(
        "zkasper_publish_dropped_total",
        "Batches lost because the outage outlasted the spool."
    );
    describe_counter!("zkasper_epochs_justified_total", "Epochs justified.");
    describe_counter!("zkasper_epochs_finalized_total", "Epochs finalized.");
    describe_counter!(
        "zkasper_epochs_abandoned_total",
        "Epochs given up on, by reason."
    );
    describe_counter!(
        "zkasper_groups_folded_total",
        "Group proofs folded into the running aggregate before the threshold."
    );
    describe_counter!(
        "zkasper_groups_late_total",
        "Group proofs the final proof had to verify itself, because they arrived too late to fold."
    );
    describe_counter!(
        "zkasper_proof_bytes_total",
        Unit::Bytes,
        "Proof bytes produced, by stage."
    );

    describe_histogram!(
        "zkasper_t2_minus_t_seconds",
        Unit::Seconds,
        "From holding the attestation that crossed the threshold to holding a proof of it."
    );
    describe_histogram!(
        "zkasper_trigger_wait_seconds",
        Unit::Seconds,
        "The part of T2 - T that was the trigger holding back rather than the prover working."
    );
    describe_histogram!(
        "zkasper_tail_named",
        "Absentees the final proof had to open inline."
    );
    describe_histogram!(
        "zkasper_stage_duration_seconds",
        Unit::Seconds,
        "Wall-clock time a stage span was open, by stage."
    );
    describe_histogram!(
        "zkasper_stage_busy_seconds",
        Unit::Seconds,
        "Time a stage span was entered, by stage. The rest of its duration was spent awaiting."
    );
    describe_histogram!(
        "zkasper_prove_duration_seconds",
        Unit::Seconds,
        "What the prover charged for the proof, by stage."
    );
    describe_histogram!(
        "zkasper_wrap_duration_seconds",
        Unit::Seconds,
        "What the prover charged for compressing the proof, by stage."
    );
}

/// Turns a stage name back into the one `'static` string for it.
///
/// Rejecting anything unrecognised is the cardinality guard: a label can only
/// ever be one of the nine stages.
fn stage_label(name: &str) -> Option<&'static str> {
    Stage::from_str(name).ok().map(Stage::as_str)
}

fn seconds(millis: u64) -> f64 {
    millis as f64 / 1000.0
}

fn unix_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or_default()
}

/// Turns the close of every `stage` span into a duration histogram.
///
/// The busy/idle split is the one `tracing_subscriber`'s `fmt` layer computes
/// for its `time.busy` / `time.idle` log fields, kept here so the numbers in the
/// log and the numbers in Prometheus are the same measurement.
pub struct StageMetrics;

/// One span's accounting, held in its extensions until it closes.
struct Timings {
    stage: &'static str,
    busy: Duration,
    idle: Duration,
    last: Instant,
}

/// Pulls the `stage` field out of a span's attributes.
#[derive(Default)]
struct StageVisitor(Option<&'static str>);

impl Visit for StageVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == STAGE_FIELD {
            self.0 = stage_label(value);
        }
    }

    fn record_debug(&mut self, _field: &Field, _value: &dyn std::fmt::Debug) {}
}

impl<S> Layer<S> for StageMetrics
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: LayerContext<'_, S>) {
        if attrs.metadata().name() != STAGE_SPAN {
            return;
        }
        let mut visitor = StageVisitor::default();
        attrs.record(&mut visitor);
        let Some(stage) = visitor.0 else {
            return;
        };
        let Some(span) = ctx.span(id) else {
            return;
        };
        span.extensions_mut().insert(Timings {
            stage,
            busy: Duration::ZERO,
            idle: Duration::ZERO,
            last: Instant::now(),
        });
    }

    fn on_enter(&self, id: &Id, ctx: LayerContext<'_, S>) {
        let Some(span) = ctx.span(id) else {
            return;
        };
        let mut extensions = span.extensions_mut();
        if let Some(timings) = extensions.get_mut::<Timings>() {
            let now = Instant::now();
            timings.idle += now.saturating_duration_since(timings.last);
            timings.last = now;
        }
    }

    fn on_exit(&self, id: &Id, ctx: LayerContext<'_, S>) {
        let Some(span) = ctx.span(id) else {
            return;
        };
        let mut extensions = span.extensions_mut();
        if let Some(timings) = extensions.get_mut::<Timings>() {
            let now = Instant::now();
            timings.busy += now.saturating_duration_since(timings.last);
            timings.last = now;
        }
    }

    fn on_close(&self, id: Id, ctx: LayerContext<'_, S>) {
        let Some(span) = ctx.span(&id) else {
            return;
        };
        let Some(timings) = span.extensions_mut().remove::<Timings>() else {
            return;
        };
        let idle = timings.idle + Instant::now().saturating_duration_since(timings.last);
        histogram!("zkasper_stage_duration_seconds", "stage" => timings.stage)
            .record((timings.busy + idle).as_secs_f64());
        histogram!("zkasper_stage_busy_seconds", "stage" => timings.stage)
            .record(timings.busy.as_secs_f64());
    }
}

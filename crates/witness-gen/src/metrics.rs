//! Prometheus metrics, served by the daemon itself.
//!
//! Three halves, and none of them is a stopwatch.
//!
//! *Durations come from `tracing`.* Three kinds of span are measured, and
//! [`StageMetrics`] turns each one's close into a histogram: `stage` is a whole
//! pipeline stage, `witness` is the part of it that built the witness, and
//! `verify` is a proof being checked. The layer keeps the busy/idle split the
//! `fmt` layer already logs, so `busy` is work and the difference is waiting on
//! the node or the prover. Nothing here measures time a span does not.
//!
//! *Every duration is a histogram, and each family has its own ladder.* The
//! pipeline spans four orders of magnitude — a 2 ms fold, a 192 ms wrap, a 132 s
//! committee proof — and one bucket set cannot resolve all of that. A gauge
//! would be worse than either: it answers "what was the last one", which is the
//! question a shell script already answers.
//!
//! *Everything else is read from the source that owns it.* The gossip source and
//! the publisher hold monotonic atomics, mirrored with `absolute()` rather than
//! counted twice; the accumulator gauges come off the in-memory store. No file
//! is parsed to produce a metric.
//!
//! Names follow the Prometheus conventions rather than the manifest's: base
//! units — seconds, bytes, dollars — `_total` on every counter, and histograms
//! wherever the distribution is the point. The manifest keeps its millisecond
//! fields; the API and the dashboard are a separate contract.

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

use crate::artifacts::{EpochCost, EpochLatency, StageTiming};
use crate::gossip::Counters as GossipCounters;
use crate::prover::Stage;
use crate::publish::{PublishCounters, ZISK_VERSION};
use crate::store::StoreState;

/// The three span names the layer measures, and the field naming which stage
/// each one belongs to. `#[instrument]` needs them as literals, so callers
/// spell them out; a span matching none of these is ignored, which is what
/// keeps the label set to the nine stages.
const STAGE_SPAN: &str = "stage";
const WITNESS_SPAN: &str = "witness";
const VERIFY_SPAN: &str = "verify";
const STAGE_FIELD: &str = "stage";

/// How often the liveness gauge is written, and how often the process collector
/// re-reads `/proc/self`.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
const PROCESS_INTERVAL: Duration = Duration::from_secs(10);

/// Milliseconds in an hour, for turning prover time into money.
const MILLIS_PER_HOUR: f64 = 3_600_000.0;

/// Anything the pipeline does, from a 2 ms fold to a 132 s committee proof.
///
/// One ladder for every family that measures pipeline work, roughly doubling
/// each step so the relative error is bounded everywhere, with extra density
/// between 100 s and 150 s because that is where the committee proof — 92% of
/// what an epoch costs — actually lands.
const WORK_BUCKETS: &[f64] = &[
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0,
    100.0, 125.0, 150.0, 200.0, 300.0, 600.0,
];

/// Compressing a proof once it exists. Measured at 0.192 s on a warm prover,
/// and nearly all of a cold one is startup — so a wrap that leaves this ladder
/// says the prover was restarted, which is the thing worth seeing.
const WRAP_BUCKETS: &[f64] = &[
    0.01, 0.025, 0.05, 0.1, 0.15, 0.2, 0.3, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];

/// Verifying a proof: pure Rust, no GPU and no proving key, which is the whole
/// reason a light client can do it. Nobody has measured it, so the ladder is
/// deliberately wide and starts where a hash comparison would.
const VERIFY_BUCKETS: &[f64] = &[
    0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
    5.0, 10.0, 30.0,
];

/// Proof sizes. A wrapped proof measured 249 KB once, from one stage on one
/// card — one sample, not a distribution — so the ladder runs from a kilobyte
/// to four megabytes and lets the real shape appear.
const PROOF_BYTES_BUCKETS: &[f64] = &[
    1024.0, 4096.0, 16384.0, 65536.0, 131072.0, 196608.0, 262144.0, 393216.0, 524288.0, 1048576.0,
    2097152.0, 4194304.0,
];

/// How far a proof's start slipped from where the schedule put it. Negative
/// edges are the point: a proof that ran early is information, and a ladder
/// starting at zero would fold every early start into one bucket and call it
/// on time.
const DELAY_BUCKETS: &[f64] = &[
    -30.0, -12.0, -6.0, -3.0, -1.0, -0.25, 0.0, 0.25, 0.5, 1.0, 2.0, 4.0, 6.0, 12.0, 24.0, 48.0,
    96.0, 300.0,
];

/// Dollars. An epoch measured $0.0203 at $0.51/hr, so the ladder is centred
/// there and runs two decades either side.
const COST_BUCKETS: &[f64] = &[
    0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.02, 0.03, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0,
];

/// `T2 - T`, the number the whole streaming pipeline exists to make small.
/// Measured between 1.2 s and 7 s following live, with the low end packed.
///
/// The ladder runs to five minutes because a catch-up epoch is a different
/// animal — 185 s measured on the first epoch after a bootstrap — and a sample
/// that lands in `+Inf` cannot be quantified at all. Catch-ups are separated by
/// the `follow` label rather than by being thrown away; see [`observe_latency`].
const LATENCY_BUCKETS: &[f64] = &[
    0.5, 0.75, 1.0, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 10.0, 15.0, 20.0,
    30.0, 45.0, 60.0, 120.0, 300.0,
];

/// How long the trigger held past the threshold. Capped by
/// `--max-trigger-wait-millis`, which defaults to 10 s.
const WAIT_BUCKETS: &[f64] = &[
    0.1, 0.25, 0.5, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 12.0,
];

/// Absentees the final proof opened inline. A count, not a duration, but the
/// distribution is what says whether the trigger rule is paying for itself.
const TAIL_BUCKETS: &[f64] = &[
    0.0, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0, 1024.0, 4096.0, 16384.0,
];

/// Which histogram gets which ladder.
const BUCKETS: &[(&str, &[f64])] = &[
    ("zkasper_proof_duration_seconds", WORK_BUCKETS),
    ("zkasper_proof_busy_seconds", WORK_BUCKETS),
    ("zkasper_proof_start_delay_seconds", DELAY_BUCKETS),
    ("zkasper_witness_duration_seconds", WORK_BUCKETS),
    ("zkasper_witness_busy_seconds", WORK_BUCKETS),
    ("zkasper_prove_duration_seconds", WORK_BUCKETS),
    ("zkasper_epoch_prover_seconds", WORK_BUCKETS),
    ("zkasper_wrap_duration_seconds", WRAP_BUCKETS),
    ("zkasper_verify_duration_seconds", VERIFY_BUCKETS),
    ("zkasper_proof_size_bytes", PROOF_BYTES_BUCKETS),
    ("zkasper_proof_cost_usd", COST_BUCKETS),
    ("zkasper_epoch_cost_usd", COST_BUCKETS),
    ("zkasper_t2_minus_t_seconds", LATENCY_BUCKETS),
    ("zkasper_trigger_wait_seconds", WAIT_BUCKETS),
    ("zkasper_tail_named", TAIL_BUCKETS),
];

/// Serve `/metrics` on `addr` for the life of the process.
///
/// Must be called from inside the Tokio runtime: the listener, the heartbeat
/// and the process collector are all tasks on it.
pub fn install(addr: SocketAddr) -> Result<()> {
    configured()?
        .with_http_listener(addr)
        .install()
        .context("install the Prometheus exporter")?;
    describe();

    // Liveness, kept apart from progress. A stage can legitimately hold the
    // pipeline for over two minutes — the committee proof does — so the
    // manifest's timestamp cannot answer "is this process alive". This can: it
    // is written by a task of its own and stops only when the runtime does.
    tokio::spawn(async move {
        loop {
            gauge!("zkasper_heartbeat_timestamp_seconds").set(unix_seconds());
            tokio::time::sleep(HEARTBEAT_INTERVAL).await;
        }
    });

    // Rust gives no process metrics for free, and the standard ones —
    // `process_resident_memory_bytes`, `process_start_time_seconds` — are how a
    // leak is told from a slow chain and how uptime is read at all.
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

/// What an hour of the proving hardware costs, as the operator gave it.
///
/// Published as its own gauge, not only folded into the cost histograms, so a
/// reader can price the prover seconds at their own rate instead of taking this
/// deployment's.
pub fn prover_rate(usd_per_hour: Option<f64>) {
    if let Some(rate) = usd_per_hour {
        gauge!("zkasper_prover_usd_per_hour").set(rate);
    }
}

/// What the output directory is holding, after the retention bound has been
/// applied. Read once an epoch, when the pruning runs, because walking it is
/// the only way to know and doing that every tick would be the expensive part
/// of a tick.
pub fn observe_output(epochs: usize, bytes: u64) {
    gauge!("zkasper_retained_epochs").set(epochs as f64);
    gauge!("zkasper_output_bytes").set(bytes as f64);
}

/// How far a proof's start slipped from where the schedule expected it, and how
/// long it then took.
///
/// This pair replaces the old count of groups that missed the fold. That number
/// said something had gone wrong without saying how badly or where; a delay
/// distribution per stage says whether the daemon is chronically behind the
/// attestations, or was late once, and by how much.
pub fn observe_proof_start(stage: Stage, delay_s: f64) {
    histogram!("zkasper_proof_start_delay_seconds", "stage" => stage.as_str()).record(delay_s);
}

/// Where the accumulator, the chain and the node are, as of now.
///
/// Called wherever the manifest is written, which is the end of every tick.
/// Unlike the heartbeat this stops moving whenever the pipeline does; the two
/// answer different questions and both are alerted on.
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

/// What one stage cost: the prover's time, the proof it produced, and what that
/// time was worth.
///
/// The stage's own duration is not here — the span already measures it. These
/// are the prover's own accounting, which is the only source for them when the
/// prover is on another machine.
pub fn observe_stage(timing: &StageTiming, usd_per_hour: Option<f64>) {
    let Some(stage) = stage_label(&timing.stage) else {
        return;
    };
    if let Some(millis) = timing.prove_millis {
        histogram!("zkasper_prove_duration_seconds", "stage" => stage).record(seconds(millis));
    }
    if let Some(millis) = timing.wrap_millis {
        histogram!("zkasper_wrap_duration_seconds", "stage" => stage).record(seconds(millis));
    }
    // Recorded even when it is zero, which is every witness-only run: a series
    // that only appears once it is non-zero cannot be read from a fresh start.
    histogram!("zkasper_proof_size_bytes", "stage" => stage).record(timing.proof_bytes as f64);

    // 92% of an epoch's bill is one stage, so an unlabelled total would hide
    // the only interesting thing about it.
    let prover_millis = timing.prove_millis.unwrap_or(0) + timing.wrap_millis.unwrap_or(0);
    if let Some(usd) = usd(prover_millis, usd_per_hour) {
        histogram!("zkasper_proof_cost_usd", "stage" => stage).record(usd);
    }
}

/// What a whole epoch cost, once every stage of it has landed.
///
/// This is the number the project quotes — "$0.0203 a proof" — so it is
/// recorded as the distribution it is rather than the one sample it was.
pub fn observe_epoch_cost(cost: &EpochCost, usd_per_hour: Option<f64>) {
    // Recorded even at zero, which is every witness-only run. A zero here is
    // honest — no prover charged anything because there was no prover — and
    // `zkasper_build_info` carries the label that says which kind of run it was.
    histogram!("zkasper_epoch_prover_seconds").record(seconds(cost.prover_millis()));
    if let Some(usd) = usd(cost.prover_millis(), usd_per_hour) {
        histogram!("zkasper_epoch_cost_usd").record(usd);
    }
}

/// One epoch's measured latency, the moment it is known.
///
/// Split by `follow`, and that label is the whole point. An epoch the daemon
/// opened mid-flight — the first one after a bootstrap or a restart — folds
/// nothing before the trigger, so its final proof carries the entire epoch
/// inline and takes minutes rather than seconds. Mixed into one histogram those
/// samples move every quantile and there is no way to get them back out.
///
/// The rule is the manifest's own: a latency is a live follow only when at
/// least one group was folded before the threshold. Separated rather than
/// dropped, because a catch-up that is getting slower is still worth seeing.
pub fn observe_latency(latency: &EpochLatency) {
    let follow = if latency.folded_groups > 0 {
        "live"
    } else {
        "catchup"
    };
    histogram!("zkasper_t2_minus_t_seconds", "follow" => follow)
        .record(seconds(latency.t2_minus_t_millis));
    histogram!("zkasper_trigger_wait_seconds", "follow" => follow)
        .record(seconds(latency.wait_millis));
    histogram!("zkasper_tail_named", "follow" => follow).record(latency.tail_named as f64);
    counter!("zkasper_groups_folded_total").increment(latency.folded_groups as u64);
}

/// A proof was checked. The duration comes from the `verify` span; this is the
/// verdict, which a histogram cannot carry.
pub fn verified(stage: Stage, accepted: bool) {
    counter!(
        "zkasper_verify_total",
        "stage" => stage.as_str(),
        "result" => if accepted { "accepted" } else { "rejected" },
    )
    .increment(1);
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

/// Prover milliseconds priced at an hourly rate, when there is one.
fn usd(prover_millis: u64, usd_per_hour: Option<f64>) -> Option<f64> {
    usd_per_hour.map(|rate| prover_millis as f64 / MILLIS_PER_HOUR * rate)
}

fn describe() {
    describe_gauge!(
        "zkasper_build_info",
        "Always 1. The version, commit and Zisk release this process was built from."
    );
    describe_gauge!(
        "zkasper_heartbeat_timestamp_seconds",
        Unit::Seconds,
        "Written once a second by a task of its own. Stops only when the process does."
    );
    describe_gauge!(
        "zkasper_manifest_updated_timestamp_seconds",
        Unit::Seconds,
        "When the daemon last completed a tick and rewrote its manifest. Stops when the \
         pipeline does, which a long stage can legitimately do for over two minutes."
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
    describe_gauge!(
        "zkasper_retained_epochs",
        "Epoch directories the output directory is holding."
    );
    describe_gauge!(
        "zkasper_output_bytes",
        Unit::Bytes,
        "Bytes of witnesses and proofs on disk, after pruning."
    );
    describe_gauge!(
        "zkasper_prover_usd_per_hour",
        "What an hour of the proving hardware costs, as the operator gave it."
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
        "zkasper_verify_total",
        "Proofs checked on the host, by stage and verdict."
    );

    describe_histogram!(
        "zkasper_t2_minus_t_seconds",
        Unit::Seconds,
        "From holding the attestation that crossed the threshold to holding a proof of it. \
         `follow=\"live\"` is the number this project quotes; `follow=\"catchup\"` is an epoch \
         opened mid-flight, which folds nothing and proves the whole epoch inline."
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
        "zkasper_proof_duration_seconds",
        Unit::Seconds,
        "Wall-clock time to make one proof, witness generation included, by stage."
    );
    describe_histogram!(
        "zkasper_proof_busy_seconds",
        Unit::Seconds,
        "The part of that which was not spent awaiting the node or the prover, by stage."
    );
    describe_histogram!(
        "zkasper_proof_start_delay_seconds",
        Unit::Seconds,
        "Actual start minus the start the schedule expected, by stage. Negative is early."
    );
    describe_histogram!(
        "zkasper_witness_duration_seconds",
        Unit::Seconds,
        "Wall-clock time spent building a stage's witness, by stage."
    );
    describe_histogram!(
        "zkasper_witness_busy_seconds",
        Unit::Seconds,
        "Time building a witness that was not spent awaiting the beacon node, by stage."
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
    describe_histogram!(
        "zkasper_verify_duration_seconds",
        Unit::Seconds,
        "Checking a proof on the host: pure Rust, no GPU and no proving key. What a light \
         client would pay."
    );
    describe_histogram!(
        "zkasper_proof_size_bytes",
        Unit::Bytes,
        "Size of the proof a stage produced. Zero on a witness-only run."
    );
    describe_histogram!(
        "zkasper_proof_cost_usd",
        "Prover time for one stage, priced at zkasper_prover_usd_per_hour."
    );
    describe_histogram!(
        "zkasper_epoch_cost_usd",
        "Prover time for a whole epoch, priced at zkasper_prover_usd_per_hour."
    );
    describe_histogram!(
        "zkasper_epoch_prover_seconds",
        Unit::Seconds,
        "Prover time a whole epoch bought, proving and wrapping together."
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

/// Turns the close of every measured span into a duration histogram.
///
/// The busy/idle split is the one `tracing_subscriber`'s `fmt` layer computes
/// for its `time.busy` / `time.idle` log fields, kept here so the numbers in the
/// log and the numbers in Prometheus are the same measurement.
pub struct StageMetrics;

/// Which pair of histograms a span's close is recorded into. `busy` is `None`
/// where the work is synchronous and the split would say nothing.
struct Family {
    duration: &'static str,
    busy: Option<&'static str>,
}

/// The span names this layer measures, and nothing else.
fn family_for(span_name: &str) -> Option<Family> {
    match span_name {
        STAGE_SPAN => Some(Family {
            duration: "zkasper_proof_duration_seconds",
            busy: Some("zkasper_proof_busy_seconds"),
        }),
        WITNESS_SPAN => Some(Family {
            duration: "zkasper_witness_duration_seconds",
            busy: Some("zkasper_witness_busy_seconds"),
        }),
        VERIFY_SPAN => Some(Family {
            duration: "zkasper_verify_duration_seconds",
            busy: None,
        }),
        _ => None,
    }
}

/// One span's accounting, held in its extensions until it closes.
struct Timings {
    family: Family,
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
        let Some(family) = family_for(attrs.metadata().name()) else {
            return;
        };
        let mut visitor = StageVisitor::default();
        attrs.record(&mut visitor);
        let Some(stage) = visitor.0 else {
            return;
        };
        let Some(span) = ctx.span(id) else {
            return;
        };
        span.extensions_mut().insert(Timings {
            family,
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
        histogram!(timings.family.duration, "stage" => timings.stage)
            .record((timings.busy + idle).as_secs_f64());
        if let Some(busy) = timings.family.busy {
            histogram!(busy, "stage" => timings.stage).record(timings.busy.as_secs_f64());
        }
    }
}

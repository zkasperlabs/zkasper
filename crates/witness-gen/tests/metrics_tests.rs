//! What `/metrics` actually says, after a real epoch has gone through.
//!
//! The assertions read the rendered exposition rather than the values the
//! daemon set, because the exposition is the contract: a renamed metric, a unit
//! that went back to milliseconds or a histogram that silently became a summary
//! all break a dashboard and none of them break a compile.
//!
//! One test, because a Prometheus recorder is global and can only be installed
//! once in a process.

mod common;

use std::time::Duration;

use common::{MockBeaconApi, SyntheticChain};

use zkasper_common::ChainConfig;
use zkasper_witness_gen::metrics::StageMetrics;
use zkasper_witness_gen::orchestrator::{Orchestrator, OrchestratorConfig, Pipeline};
use zkasper_witness_gen::prover::NativeProver;

use tracing_subscriber::layer::SubscriberExt;

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
const SLOTS_TO_THRESHOLD: u64 = 3;
/// Any rate at all, so the derived cost families exist. The value is the
/// deployment's business; that it is published and multiplied is this test's.
const RATE_USD_PER_HOUR: f64 = 0.51;

/// Every series the alerts and the dashboard name. A metric that is only ever
/// described but never recorded does not appear in the exposition, so this is
/// also the check that each one is wired to something.
const EXPECTED: &[&str] = &[
    "zkasper_build_info",
    "zkasper_manifest_updated_timestamp_seconds",
    "zkasper_accumulator_epoch",
    "zkasper_head_slot",
    "zkasper_validators",
    "zkasper_total_active_balance_gwei",
    "zkasper_justified_epoch",
    "zkasper_finalized_epoch",
    "zkasper_epochs_justified_total",
    "zkasper_epochs_finalized_total",
    "zkasper_groups_folded_total",
    "zkasper_proof_size_bytes",
    "zkasper_proof_cost_usd",
    "zkasper_epoch_cost_usd",
    "zkasper_epoch_prover_seconds",
    "zkasper_prover_usd_per_hour",
    "zkasper_t2_minus_t_seconds",
    "zkasper_trigger_wait_seconds",
    "zkasper_tail_named",
    "zkasper_proof_duration_seconds",
    "zkasper_proof_busy_seconds",
    "zkasper_proof_start_delay_seconds",
    "zkasper_witness_duration_seconds",
    "zkasper_witness_busy_seconds",
    "zkasper_retained_epochs",
    "zkasper_output_bytes",
];

/// Stages that must have been measured by their span. `bootstrap` and
/// `epoch_diff` come from the batch path, the rest from streaming one epoch.
const EXPECTED_STAGES: &[&str] = &[
    "bootstrap",
    "epoch_diff",
    "committee",
    "justification",
    "group",
    "aggregate",
    "stream_final",
];

#[tokio::test]
async fn metrics_expose_a_streamed_epoch() {
    let handle = zkasper_witness_gen::metrics::install_recorder().expect("recorder installs");
    // The stage spans are the only source of the duration histograms, so the
    // layer has to be under the test for them to exist at all.
    let _tracing =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(StageMetrics));
    zkasper_witness_gen::metrics::build_info("test", "native", "streaming");
    zkasper_witness_gen::metrics::prover_rate(Some(RATE_USD_PER_HOUR));

    let dir = tempfile::tempdir().unwrap();
    let chain = SyntheticChain::new(TEST_CONFIG, VALIDATORS, FIRST_EPOCH, LAST_EPOCH);
    let mut daemon = open(dir.path(), chain.mock((FIRST_EPOCH + 1) * SPE)).await;

    // Epoch 10 the batch way, epoch 11 streamed, which is what produces a
    // latency to put in the histogram.
    daemon.catch_up().await.unwrap();
    let boundary = (FIRST_EPOCH + 1) * SPE;
    for slot in boundary..=boundary + SLOTS_TO_THRESHOLD {
        daemon.api().set_head(chain.header_at(slot));
        daemon.catch_up().await.unwrap();
    }
    assert_eq!(daemon.state().justified_through, Some(FIRST_EPOCH + 1));

    let rendered = handle.render();

    for metric in EXPECTED {
        assert!(
            rendered.contains(&format!("\n# TYPE {metric} ")),
            "{metric} is not in the exposition:\n{rendered}",
        );
    }

    // The rate is published as its own gauge, so a reader can price the prover
    // seconds at their rate instead of taking this deployment's.
    assert!(
        rendered.contains(&format!("zkasper_prover_usd_per_hour {RATE_USD_PER_HOUR}")),
        "the hourly rate is not exposed:\n{rendered}",
    );

    // Base units and `_total` on counters, or a standard dashboard reads the
    // wrong scale. The manifest keeps its millisecond fields; these must not.
    assert!(
        !rendered.contains("zkasper_t2_minus_t_millis"),
        "a millisecond metric leaked into the exposition",
    );
    assert!(
        rendered.contains("# TYPE zkasper_epochs_justified_total counter"),
        "counters have to be counters:\n{rendered}",
    );

    // A distribution, not the last value. `_bucket` only appears when the
    // exporter was given buckets; without them it would render a summary and
    // nothing could be aggregated across daemons.
    assert!(
        rendered.contains("zkasper_t2_minus_t_seconds_bucket{le="),
        "T2 - T is not a bucketed histogram:\n{rendered}",
    );
    assert!(
        rendered.contains("zkasper_tail_named_bucket{le="),
        "tail_named is not a bucketed histogram:\n{rendered}",
    );

    for stage in EXPECTED_STAGES {
        assert!(
            rendered.contains(&format!(
                "zkasper_proof_duration_seconds_count{{stage=\"{stage}\"}}"
            )),
            "no span measured the {stage} stage:\n{rendered}",
        );
    }

    // The witness spans are a separate family, so a stage whose witness build
    // is slow can be told from one whose prover is.
    for stage in [
        "bootstrap",
        "epoch_diff",
        "group",
        "aggregate",
        "stream_final",
    ] {
        assert!(
            rendered.contains(&format!(
                "zkasper_witness_duration_seconds_count{{stage=\"{stage}\"}}"
            )),
            "no span measured the {stage} witness:\n{rendered}",
        );
    }

    // What replaced the count of late groups: how far each proof's start
    // slipped from the schedule, per stage, with negative buckets so an early
    // start is not rounded to on time.
    assert!(
        rendered.contains("zkasper_proof_start_delay_seconds_bucket{stage=\"group\",le=\"-30\"}"),
        "the start delay has no negative buckets:\n{rendered}",
    );
    assert!(
        !rendered.contains("zkasper_groups_late_total"),
        "late_groups was replaced, not kept alongside",
    );

    // The epoch advanced, which is the other thing worth alerting on.
    assert!(
        rendered.contains(&format!("zkasper_accumulator_epoch {}", FIRST_EPOCH + 1)),
        "the accumulator gauge did not follow the store:\n{rendered}",
    );
    assert!(
        rendered.contains("zkasper_epochs_justified_total 2"),
        "both epochs should have been counted:\n{rendered}",
    );
}

async fn open(dir: &std::path::Path, mock: MockBeaconApi) -> Orchestrator<MockBeaconApi> {
    Orchestrator::open(
        mock,
        OrchestratorConfig {
            db_path: dir.join("zkasperd.db"),
            output_dir: dir.join("out"),
            poll_interval: Duration::ZERO,
            pipeline: Pipeline::Streaming,
            prover_usd_per_hour: Some(RATE_USD_PER_HOUR),
            ..OrchestratorConfig::new(TEST_CONFIG, "test")
        },
        Box::new(NativeProver::new(TEST_CONFIG)),
    )
    .await
    .expect("orchestrator opens")
}

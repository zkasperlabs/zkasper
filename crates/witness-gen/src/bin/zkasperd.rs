//! zkasperd — the continuous witness generator.
//!
//! Bootstraps an accumulator from a recent finalized state, then follows the
//! chain: one epoch diff per epoch, slot proofs as attestations arrive, a
//! justification the moment 2/3 is crossed, and a finalization when two
//! consecutive epochs justify.
//!
//! Built without `--features zisk-prover` it produces witnesses and no proofs;
//! with it, and `--prover zisk`, it produces real ones from a prover that is
//! initialised once and kept warm for the life of the process. See
//! `crate::prover` and `crate::zisk_prover`.
//!
//! `--prover remote` puts that warm prover on another machine, which is the
//! shape the deployment actually has: the GPU box runs a prover and nothing
//! else. It needs no CUDA here, so a witness-only build can drive a real GPU.
//! See `crate::remote_prover`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use tracing::info;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use zkasper_common::ChainConfig;
use zkasper_witness_gen::beacon_api::BeaconApiClient;
use zkasper_witness_gen::orchestrator::{Orchestrator, OrchestratorConfig, Pipeline};
use zkasper_witness_gen::prover::{NativeProver, Prover};
use zkasper_witness_gen::publish::{DaemonInfo, PublishConfig, Publisher};
use zkasper_witness_gen::remote_prover::{RemoteProver, RemoteProverConfig};
use zkasper_witness_gen::streaming::StreamPolicy;

#[derive(Clone, Copy, ValueEnum)]
enum Chain {
    Mainnet,
    Gnosis,
}

/// Which pipeline to prove epochs with.
#[derive(Clone, Copy, ValueEnum)]
enum Mode {
    Batch,
    Streaming,
}

/// What produces the proofs.
#[derive(Clone, Copy, ValueEnum)]
enum Backend {
    /// Run the circuits, produce no proofs. Every witness is still checked by
    /// the logic that would prove it.
    Native,
    /// Real Zisk proofs, from one prover held open for the whole run.
    Zisk,
    /// Real Zisk proofs, from a prover server on another machine.
    Remote,
}

impl Chain {
    fn config(self) -> ChainConfig {
        match self {
            Chain::Mainnet => ChainConfig::MAINNET,
            Chain::Gnosis => ChainConfig::GNOSIS,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Chain::Mainnet => "mainnet",
            Chain::Gnosis => "gnosis",
        }
    }
}

#[derive(Parser)]
#[command(name = "zkasperd")]
#[command(about = "Continuous witness generation for zkasper finality proofs")]
struct Cli {
    /// Beacon node API URL
    #[arg(long, env = "BEACON_API_URL")]
    beacon_url: String,

    /// Persistent accumulator state
    #[arg(long, default_value = "zkasperd.db")]
    db_path: PathBuf,

    /// Directory for witness files and status.json
    #[arg(long, default_value = "zkasper-out")]
    output_dir: PathBuf,

    /// Target chain
    #[arg(long, default_value = "mainnet")]
    chain: Chain,

    /// Slot to bootstrap from. Defaults to the node's finalized checkpoint.
    /// Ignored when the state file already exists.
    #[arg(long)]
    bootstrap_slot: Option<u64>,

    /// Attestation signing domain (hex). Derived from the node's fork and
    /// genesis when not given.
    #[arg(long)]
    signing_domain: Option<String>,

    /// Seconds to wait after a poll that found nothing new
    #[arg(long, default_value_t = 4)]
    poll_seconds: u64,

    /// How often a streaming epoch re-reads gossip and re-evaluates the trigger.
    /// The daemon cannot fire between two evaluations, so this is the resolution
    /// of "the instant enough attestations arrived".
    #[arg(long, default_value_t = 200)]
    trigger_interval_millis: u64,

    /// Fraction of the total active balance the streaming trigger waits for,
    /// as a numerator over --threshold-denominator. The circuit enforces 2/3 and
    /// rejects anything under it, so a higher setting only ever costs latency —
    /// weight arrives a committee at a time, about 3.1% of the stake, so a
    /// margin that pushes the crossing into the next slot costs a whole slot.
    #[arg(long, default_value_t = 2)]
    threshold_numerator: u64,

    #[arg(long, default_value_t = 3)]
    threshold_denominator: u64,

    /// Longest the trigger may hold past the threshold while in-flight
    /// attestations are still making the final proof shorter.
    ///
    /// A backstop against a source that trickles for ever, not the rule. It has
    /// to sit above the whole useful range or it truncates the rule instead:
    /// arrivals fall below the break-even rate 8–9 s into a slot and the burst
    /// drains at a p90 of 9.8 s, both measured from the start of the slot, while
    /// this is measured from the threshold crossing — which lands anywhere in
    /// the slot. Below one slot, because past that the slot being waited for is
    /// no longer the one filling.
    #[arg(long, default_value_t = 10_000)]
    max_trigger_wait_millis: u64,

    /// Read attestations from blocks rather than from the node's event stream.
    /// A slot later by construction; only for a node that will not serve
    /// `/eth/v1/events`.
    #[arg(long)]
    no_gossip: bool,

    /// How many epochs past a checkpoint to keep looking for its attestations
    #[arg(long, default_value_t = 2)]
    attestation_lookahead_epochs: u64,

    /// Catch up to the node's head and exit, instead of following the chain
    #[arg(long)]
    once: bool,

    /// Public API to mirror every stage to, as it happens. Without it the
    /// daemon publishes nothing but the manifest on disk.
    #[arg(long, env = "ZKASPER_API_URL")]
    api_url: Option<String>,

    /// Bearer token for `--api-url`. Prefer the environment: an argument is
    /// visible to every process on the box.
    #[arg(long, env = "ZKASPER_API_TOKEN", hide_env_values = true)]
    api_token: Option<String>,

    /// Where batches wait out an API that is not answering. Defaults to
    /// `spool` under the output directory.
    #[arg(long)]
    api_spool: Option<PathBuf>,

    /// Identifies this daemon to the API, which deduplicates per daemon.
    #[arg(long, default_value = "zkasperd")]
    api_daemon_id: String,

    /// How long events accumulate before a batch is posted.
    #[arg(long, default_value_t = 1000)]
    api_batch_millis: u64,

    /// Floor on the interval between published progress updates. Each one is a
    /// row in the API's database, and the free tier is a row budget.
    #[arg(long, default_value_t = 6000)]
    api_progress_millis: u64,

    /// Floor on the interval between published status snapshots.
    #[arg(long, default_value_t = 10000)]
    api_status_millis: u64,

    /// Pipeline to prove epochs with
    #[arg(long, default_value = "batch")]
    mode: Mode,

    /// What produces the proofs
    #[arg(long, default_value = "native")]
    prover: Backend,

    /// Directory holding the guest ELFs, for `--prover zisk`
    #[arg(long, default_value = zkasper_witness_gen::prover::DEFAULT_ELF_DIR)]
    #[cfg(feature = "zisk-prover")]
    elf_dir: PathBuf,

    /// Prove on the GPU. Without it the run measures the CPU.
    #[arg(long)]
    #[cfg(feature = "zisk-prover")]
    gpu: bool,

    /// Proving key directory. Defaults to Zisk's own, `~/.zisk/provingKey`.
    #[arg(long)]
    #[cfg(feature = "zisk-prover")]
    proving_key: Option<PathBuf>,

    /// `host:port` of the prover server, for `--prover remote`
    #[arg(long, default_value = "127.0.0.1:9099")]
    prover_addr: String,

    /// Token the prover server expects, for `--prover remote`
    #[arg(long, env = "ZKASPER_PROVER_TOKEN")]
    prover_token: Option<String>,

    /// Where witnesses wait out a prover outage. Defaults to
    /// `<output-dir>/prover-spool`.
    #[arg(long)]
    prover_spool: Option<PathBuf>,

    /// Address to serve Prometheus metrics on, at `/metrics`.
    ///
    /// Localhost by default: this is a scrape target for an agent on the same
    /// box, not a public surface, and it says where the accumulator is before
    /// the daemon has published anything.
    #[arg(long, default_value = "127.0.0.1:9464")]
    metrics_addr: SocketAddr,

    /// Serve no metrics at all.
    #[arg(long)]
    no_metrics: bool,
}

impl Cli {
    /// Build the prover this run was asked for.
    ///
    /// One prover, for the life of the process: see `crate::prover` on why that
    /// is the only shape worth measuring.
    fn build_prover(&self, chain: ChainConfig, pipeline: Pipeline) -> Result<Box<dyn Prover>> {
        match self.prover {
            Backend::Native => Ok(Box::new(NativeProver::new(chain))),
            #[cfg(feature = "zisk-prover")]
            Backend::Zisk => {
                use zkasper_witness_gen::zisk_prover::{ZiskProver, ZiskProverConfig};
                Ok(Box::new(ZiskProver::new(ZiskProverConfig {
                    elf_dir: self.elf_dir.clone(),
                    gpu: self.gpu,
                    proving_key: self.proving_key.clone(),
                    ..ZiskProverConfig::new(chain, pipeline.stages())
                })?))
            }
            #[cfg(not(feature = "zisk-prover"))]
            Backend::Zisk => anyhow::bail!(
                "this binary was built without the `zisk-prover` feature; \
                 rebuild with `cargo build --release --features zisk-prover`",
            ),
            Backend::Remote => Ok(Box::new(RemoteProver::connect(RemoteProverConfig {
                spool_dir: Some(
                    self.prover_spool
                        .clone()
                        .unwrap_or_else(|| self.output_dir.join("prover-spool")),
                ),
                ..RemoteProverConfig::new(
                    chain,
                    &self.prover_addr,
                    self.prover_token.clone().context(
                        "--prover remote needs --prover-token (or ZKASPER_PROVER_TOKEN)",
                    )?,
                    pipeline.stages(),
                )
            })?)),
        }
    }
}

impl Cli {
    /// Build the publisher, if this run was given somewhere to publish to.
    ///
    /// A URL without a token is a misconfiguration rather than a request to
    /// publish anonymously, so it fails here instead of being rejected an epoch
    /// at a time by the API.
    fn build_publisher(&self, config: &OrchestratorConfig) -> Result<Option<Arc<Publisher>>> {
        let Some(url) = &self.api_url else {
            return Ok(None);
        };
        let token = self
            .api_token
            .clone()
            .context("--api-url needs --api-token (or ZKASPER_API_TOKEN)")?;
        Publisher::spawn(
            PublishConfig {
                daemon_id: self.api_daemon_id.clone(),
                batch_interval: Duration::from_millis(self.api_batch_millis),
                progress_interval: Duration::from_millis(self.api_progress_millis),
                status_interval: Duration::from_millis(self.api_status_millis),
                ..PublishConfig::new(
                    url,
                    token,
                    self.api_spool
                        .clone()
                        .unwrap_or_else(|| config.output_dir.join("spool")),
                )
            },
            DaemonInfo {
                id: self.api_daemon_id.clone(),
                chain: config.chain_name.clone(),
                prover: self.prover_name().to_string(),
                pipeline: match config.pipeline {
                    Pipeline::Batch => "batch",
                    Pipeline::Streaming => "streaming",
                }
                .to_string(),
            },
        )
        .map(Some)
    }

    fn prover_name(&self) -> &'static str {
        match self.prover {
            Backend::Native => "native",
            Backend::Zisk => "zisk",
            Backend::Remote => "remote",
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // The stage spans are the benchmark instrument: `fmt` logs each one's
    // busy/idle when it closes, and the metrics layer records the same
    // measurement as a histogram. One instrumentation, two consumers.
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(
            tracing_subscriber::fmt::layer()
                .with_span_events(FmtSpan::CLOSE)
                .with_target(false),
        )
        .with(zkasper_witness_gen::metrics::StageMetrics)
        .init();

    let pipeline = match cli.mode {
        Mode::Batch => Pipeline::Batch,
        Mode::Streaming => Pipeline::Streaming,
    };
    if !cli.no_metrics {
        zkasper_witness_gen::metrics::install(cli.metrics_addr)?;
        zkasper_witness_gen::metrics::build_info(
            cli.chain.name(),
            cli.prover_name(),
            match pipeline {
                Pipeline::Batch => "batch",
                Pipeline::Streaming => "streaming",
            },
        );
        info!(addr = %cli.metrics_addr, "serving Prometheus metrics");
    }
    let config = OrchestratorConfig {
        db_path: cli.db_path.clone(),
        output_dir: cli.output_dir.clone(),
        bootstrap_slot: cli.bootstrap_slot,
        signing_domain: cli
            .signing_domain
            .as_deref()
            .map(parse_hex_bytes32)
            .transpose()?,
        poll_interval: Duration::from_secs(cli.poll_seconds),
        trigger_interval: Duration::from_millis(cli.trigger_interval_millis),
        attestation_lookahead_epochs: cli.attestation_lookahead_epochs,
        pipeline,
        stream_policy: StreamPolicy {
            threshold_numerator: cli.threshold_numerator,
            threshold_denominator: cli.threshold_denominator,
            max_wait_s: cli.max_trigger_wait_millis as f64 / 1000.0,
            ..StreamPolicy::default()
        },
        // Only the streaming pipeline has a trigger to be early for; the batch
        // path walks blocks either way.
        gossip_url: (pipeline == Pipeline::Streaming && !cli.no_gossip)
            .then(|| cli.beacon_url.clone()),
        ..OrchestratorConfig::new(cli.chain.config(), cli.chain.name())
    };

    // Built before the first beacon call, so a missing ELF or proving key fails
    // now rather than after a bootstrap has already been paid for.
    let prover = cli.build_prover(cli.chain.config(), pipeline)?;

    info!(
        chain = %config.chain_name,
        db = %config.db_path.display(),
        out = %config.output_dir.display(),
        prover = prover.name(),
        "zkasperd starting",
    );

    let publisher = cli.build_publisher(&config)?;

    let mut orchestrator = Orchestrator::open_with_publisher(
        BeaconApiClient::new(&cli.beacon_url),
        config,
        prover,
        publisher.clone(),
    )
    .await?;

    let result = if cli.once {
        orchestrator.catch_up().await.map(|ticks| {
            info!(
                ticks = ticks.len(),
                epoch = orchestrator.state().cursor_epoch,
                "caught up",
            );
        })
    } else {
        tokio::select! {
            result = orchestrator.run() => result,
            () = stopped() => {
                info!("stopping");
                Ok(())
            }
        }
    };

    // The last epoch of a run is the one most worth publishing, and it is the
    // one a dropped runtime would take with it.
    if let Some(publisher) = &publisher {
        publisher.flush().await;
    }
    result
}

/// Resolves when the process is asked to stop.
async fn stopped() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install the SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

fn parse_hex_bytes32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s.strip_prefix("0x").unwrap_or(s)).context("invalid hex")?;
    anyhow::ensure!(bytes.len() == 32, "expected 32 bytes, got {}", bytes.len());
    Ok(bytes.try_into().unwrap())
}

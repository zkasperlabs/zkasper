//! Take an init point from a beacon state.
//!
//! `zkasperd` no longer proves its own starting accumulator — see
//! [`zkasper_witness_gen::init_point`] for why the trust delta is narrow. It
//! starts from a tuple an operator supplies instead, and this is what produces
//! one:
//!
//! ```text
//! zkasper-init-point --beacon-url http://localhost:5052 --out init-point.json
//! ```
//!
//! With no `--slot` it takes the node's finalized checkpoint, which is where a
//! run should start: everything the pipeline needs after that is within the
//! node's state window.
//!
//! The output is a small JSON file. Anyone with a beacon node can run this
//! against the same slot and compare it byte for byte with the one a deployment
//! publishes, which is what replaces the deleted bootstrap proof.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use tracing_subscriber::EnvFilter;

use zkasper_common::ChainConfig;
use zkasper_witness_gen::beacon_api::{BeaconApiClient, ChainStatusApi};
use zkasper_witness_gen::{init_point, network};

#[derive(Clone, Copy, ValueEnum)]
enum Chain {
    Mainnet,
    Gnosis,
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
#[command(
    name = "zkasper-init-point",
    about = "Take a zkasperd init point from a beacon state"
)]
struct Cli {
    #[arg(long, env = "BEACON_API_URL")]
    beacon_url: String,

    /// Chain parameters. What the init point records as its chain comes from
    /// the node's genesis validators root, not from this — the same rule
    /// `zkasperd` follows, so the two labels cannot disagree.
    #[arg(long, default_value = "mainnet")]
    chain: Chain,

    /// Epoch boundary slot to take the accumulator from. Defaults to the node's
    /// finalized checkpoint, which is the oldest state it still serves and the
    /// newest one a run can start behind.
    #[arg(long)]
    slot: Option<u64>,

    /// Where to write the init point. `-` writes to stdout.
    #[arg(long, default_value = "init-point.json")]
    out: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let cli = Cli::parse();
    let config = cli.chain.config();
    let api = BeaconApiClient::new(&cli.beacon_url);
    let (chain_name, _) = network::resolve(&api, cli.chain.name()).await?;

    let slot = match cli.slot {
        Some(slot) => slot,
        None => {
            api.get_finality_checkpoints("head")
                .await
                .context("fetch finality checkpoints to pick a slot")?
                .finalized
                .epoch
                * config.slots_per_epoch
        }
    };

    let init = init_point::generate(&api, &config, chain_name, slot).await?;
    if cli.out == PathBuf::from("-") {
        println!("{}", serde_json::to_string_pretty(&init)?);
    } else {
        init.write(&cli.out)?;
        eprintln!("wrote {}", cli.out.display());
    }
    Ok(())
}

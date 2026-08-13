use zkasper_witness_gen::{
    beacon_api, db, epoch_state, witness_bootstrap, witness_epoch_diff, witness_slot_proof,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use zkasper_common::ChainConfig;

use beacon_api::BeaconApiClient;
use db::Db;
use epoch_state::EpochState;

#[derive(Clone, ValueEnum)]
enum Chain {
    Mainnet,
    Gnosis,
}

#[derive(Parser)]
#[command(name = "zkasper-witness-gen")]
#[command(about = "Witness generator for zkasper finality proofs")]
struct Cli {
    /// Beacon node API URL
    #[arg(long, env = "BEACON_API_URL")]
    beacon_url: String,

    /// Path for persistent state (Poseidon tree, cursor)
    #[arg(long, default_value = "zkasper.db")]
    db_path: String,

    /// Output directory for witness files
    #[arg(long, default_value = ".")]
    output_dir: String,

    /// Target chain
    #[arg(long, default_value = "mainnet")]
    chain: Chain,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build initial Poseidon tree from the full validator set
    Bootstrap {
        /// Slot to bootstrap from (must be an epoch boundary)
        slot: u64,
    },
    /// Generate epoch diff witness between two epoch-boundary slots
    EpochDiff {
        /// Last slot of the previous epoch
        slot1: u64,
        /// Last slot of the current epoch
        slot2: u64,
    },
    /// Generate per-slot proof witnesses for a target checkpoint
    SlotProofs {
        /// The epoch of the checkpoint to prove
        epoch: u64,
        /// Target block root (hex, 0x-prefixed)
        #[arg(long)]
        target_root: String,
        /// Signing domain (hex, 0x-prefixed)
        #[arg(long)]
        signing_domain: String,
    },
    /// Continuous mode: watch for new finalized checkpoints and generate proofs
    Run,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let api = BeaconApiClient::new(&cli.beacon_url);
    let db = Db::new(&cli.db_path);
    let config = match cli.chain {
        Chain::Mainnet => ChainConfig::MAINNET,
        Chain::Gnosis => ChainConfig::GNOSIS,
    };

    match cli.command {
        Command::Bootstrap { slot } => {
            eprintln!("bootstrapping from slot {slot}...");

            let (witness, tree, _epoch_state, total_active_balance, num_validators) =
                witness_bootstrap::build(&api, &config, slot).await?;

            let epoch = witness.epoch;

            // Save tree state to DB
            db.save(&tree, epoch, total_active_balance, num_validators)?;
            eprintln!("saved tree state: epoch={epoch}, validators={num_validators}, total_active_balance={total_active_balance}");

            // Serialize witness
            let output_path = format!("{}/bootstrap_input.bin", cli.output_dir);
            let bytes = bincode::serialize(&witness).context("serialize bootstrap witness")?;
            std::fs::write(&output_path, bytes).context("write bootstrap witness")?;
            eprintln!(
                "wrote {output_path} ({} bytes)",
                std::fs::metadata(&output_path)?.len()
            );
        }

        Command::EpochDiff { slot1, slot2 } => {
            eprintln!("epoch diff: slot {slot1} -> {slot2}...");

            let (mut tree, cursor_epoch, total_active_balance, _num_validators) =
                db.load()?.context("no saved state — run bootstrap first")?;

            eprintln!("loaded tree state: cursor_epoch={cursor_epoch}, total_active_balance={total_active_balance}");

            // TODO: persist EpochState to DB for incremental epoch diffs.
            // For now, use empty EpochState (forces slow recomputation path).
            let old_state = EpochState::empty(slot1, _num_validators);

            let (witness, _new_epoch_state, new_total_active_balance, new_num_validators) =
                witness_epoch_diff::build(
                    &api,
                    &config,
                    &mut tree,
                    &old_state,
                    slot2,
                    total_active_balance,
                )
                .await?;

            let new_epoch = witness.epoch_2;

            // Save updated tree
            db.save(
                &tree,
                new_epoch,
                new_total_active_balance,
                new_num_validators,
            )?;
            eprintln!("saved tree state: epoch={new_epoch}, validators={new_num_validators}, total_active_balance={new_total_active_balance}");

            // Serialize witness
            let output_path = format!("{}/epoch_diff_input.bin", cli.output_dir);
            let bytes = bincode::serialize(&witness).context("serialize epoch diff witness")?;
            std::fs::write(&output_path, bytes).context("write epoch diff witness")?;
            eprintln!(
                "wrote {output_path} ({} bytes)",
                std::fs::metadata(&output_path)?.len()
            );
        }

        Command::SlotProofs {
            epoch,
            target_root,
            signing_domain,
        } => {
            eprintln!("slot proofs for epoch {epoch}...");

            let (tree, _cursor_epoch, total_active_balance, _num_validators) = db
                .load()?
                .context("no saved state — run bootstrap + epoch-diff first")?;

            let target_root = parse_hex_bytes32(&target_root)?;
            let signing_domain = parse_hex_bytes32(&signing_domain)?;

            let slot_witnesses = witness_slot_proof::build_per_slot(
                &api,
                &config,
                &tree,
                epoch,
                target_root,
                total_active_balance,
                signing_domain,
            )
            .await?;

            eprintln!("built {} slot proof witnesses", slot_witnesses.len());

            // Serialize each slot witness
            for sw in &slot_witnesses {
                let output_path = format!("{}/slot_proof_input_{}.bin", cli.output_dir, sw.slot);
                let bytes =
                    bincode::serialize(&sw.witness).context("serialize slot proof witness")?;
                std::fs::write(&output_path, &bytes).context("write slot proof witness")?;
                eprintln!(
                    "  slot {}: {} bytes, {} counted validators",
                    sw.slot,
                    bytes.len(),
                    sw.counted_indices.len(),
                );
            }

            // Also serialize the justification witness (aggregates slot outputs)
            // The slot proof outputs would come from running the provers,
            // but for now we can pre-build the justification metadata.
            let output_path = format!("{}/slot_proofs_metadata.bin", cli.output_dir);
            let metadata: Vec<(u64, Vec<u64>)> = slot_witnesses
                .iter()
                .map(|sw| (sw.slot, sw.counted_indices.clone()))
                .collect();
            let bytes = bincode::serialize(&metadata).context("serialize metadata")?;
            std::fs::write(&output_path, &bytes).context("write metadata")?;
            eprintln!("wrote {output_path} ({} bytes)", bytes.len(),);
        }

        Command::Run => {
            eprintln!("continuous mode not yet implemented");
            todo!("run")
        }
    }

    Ok(())
}

fn parse_hex_bytes32(s: &str) -> Result<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).context("invalid hex")?;
    anyhow::ensure!(bytes.len() == 32, "expected 32 bytes, got {}", bytes.len());
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    Ok(result)
}

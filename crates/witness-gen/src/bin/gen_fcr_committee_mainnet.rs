//! Prove the mainnet committee assignment, and check it against the node's.
//!
//! Usage: gen-fcr-committee-mainnet --beacon-url URL --epoch E
//!
//! The circuit computes the assignment from the RANDAO seed; the node computes
//! it from its own state. If the two committee roots agree, the transcription
//! and the slot mapping are the ones mainnet actually runs — which is the only
//! evidence that turns `Assignment::unproven` into `Assignment::proven`.

use anyhow::Result;
use clap::Parser;
use zkasper_common::ChainConfig;
use zkasper_fcr_types::FcrCommitteeWitness;
use zkasper_witness_gen::acc_tree::AccTree;
use zkasper_witness_gen::beacon_api::{BeaconApi, BeaconApiClient};
use zkasper_witness_gen::{committee, init_point, state_diff};

#[derive(Parser)]
struct Args {
    #[arg(long, env = "BEACON_API_URL")]
    beacon_url: String,
    #[arg(long)]
    epoch: u64,
    #[arg(long)]
    randao: String,
}

/// `get_seed(state, epoch, DOMAIN_BEACON_ATTESTER)`.
fn get_seed(epoch: u64, mix: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(zkasper_common::constants::DOMAIN_BEACON_ATTESTER);
    h.update(epoch.to_le_bytes());
    h.update(mix);
    h.finalize().into()
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config = ChainConfig::MAINNET;
    let api = BeaconApiClient::new(&args.beacon_url);
    let slot = args.epoch * config.slots_per_epoch;

    let mix: [u8; 32] = hex_to_32(&args.randao)?;
    let seed = get_seed(args.epoch, &mix);
    eprintln!("epoch {} seed 0x{}", args.epoch, hex(&seed));

    eprintln!("fetching the registry at slot {slot}...");
    let validators = init_point::fetch_registry(&api, slot).await?;
    let data: Vec<_> = validators
        .iter()
        .map(state_diff::validator_response_to_data)
        .collect();
    let tree = AccTree::build(&data, args.epoch, config.acc_tree_depth);
    let total_active_balance: u64 = data
        .iter()
        .map(|v| v.active_effective_balance(args.epoch))
        .sum();
    eprintln!(
        "  {} in the registry, {} gwei active",
        validators.len(),
        total_active_balance
    );

    eprintln!("opening the active set...");
    let active: Vec<_> = validators
        .iter()
        .enumerate()
        .filter(|(i, _)| data[*i].active_effective_balance(args.epoch) > 0)
        .filter_map(|(i, v)| committee::opened(i as u64, v, args.epoch).ok())
        .collect();
    eprintln!("  {} active", active.len());

    let indices: Vec<u64> = active.iter().map(|v| v.validator_index).collect();
    let witness = FcrCommitteeWitness {
        accumulator_commitment: zkasper_common::acc::commitment(
            &tree.root(),
            total_active_balance,
        ),
        acc_root: tree.root(),
        total_active_balance,
        seed,
        epoch: args.epoch,
        acc_multi_proof: tree.build_multi_proof(&indices),
        active,
    };

    eprintln!("proving the assignment (90 rounds per validator)...");
    let started = std::time::Instant::now();
    let out = zkasper_fcr_committee_guest::verify_fcr_committee(
        &witness,
        config.slots_per_epoch,
    );
    eprintln!("  {:?}", started.elapsed());

    // The node's own assignment, for comparison.
    let theirs = committee::build(
        &api.get_committees(&slot.to_string(), args.epoch).await?,
        &validators,
        &tree,
        &config,
        args.epoch,
        args.epoch,
        total_active_balance,
    )?;

    println!();
    println!("circuit committee root  0x{}", hex_digest(&out.committee_root));
    println!("node    committee root  0x{}", hex_digest(&theirs.root()));
    println!(
        "agree                   {}",
        if out.committee_root == theirs.root() { "YES" } else { "NO" }
    );
    Ok(())
}

fn hex(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn hex_digest(d: &zkasper_common::acc::Digest) -> String {
    d.iter().map(|w| format!("{w:016x}")).collect()
}
fn hex_to_32(s: &str) -> Result<[u8; 32]> {
    let raw = s.trim_start_matches("0x");
    let bytes = (0..32)
        .map(|i| u8::from_str_radix(&raw[2 * i..2 * i + 2], 16))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(bytes.try_into().unwrap())
}

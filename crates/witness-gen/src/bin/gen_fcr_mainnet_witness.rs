//! Build an FCR batch witness from a live beacon node, and judge it.
//!
//! Usage: gen-fcr-mainnet-witness --beacon-url URL [--slot S] [--count N] [--out F]
//!
//! Head votes are read from the blocks that included them, which is a lower
//! bound on what a prover collecting from gossip at t=8s would hold — so a
//! support figure from here is conservative against the real one.

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use zkasper_common::types::*;
use zkasper_common::ChainConfig;
use zkasper_fcr_types::{BlockHeaderWitness, FcrBatchWitness, FcrSlotWitness};
use zkasper_witness_gen::acc_tree::AccTree;
use zkasper_witness_gen::attestation_collector::SlotStream;
use zkasper_witness_gen::beacon_api::{BeaconApi, BeaconApiClient, ChainStatusApi};
use zkasper_witness_gen::{committee, init_point};

#[derive(Parser)]
struct Args {
    #[arg(long, env = "BEACON_API_URL")]
    beacon_url: String,
    /// First slot of the batch. Defaults to a slot two epochs behind the head,
    /// so the blocks that carry its attestations exist and are canonical.
    #[arg(long)]
    slot: Option<u64>,
    #[arg(long, default_value = "3")]
    count: u64,
    #[arg(long, default_value = "/mnt/ssd/fcr-mainnet-witness.bin")]
    out: String,
    /// RANDAO mix at `epoch - 2`, which is what `get_seed` reads. Supplying it
    /// proves the committee assignment rather than trusting the node's.
    #[arg(long)]
    randao: Option<String>,
    /// Evaluate every slot in the range on its own, as a one-slot window, and
    /// report which of them clear the threshold alone. The registry, the
    /// accumulator and the committee tree are built once and reused across all
    /// of them -- they are a property of the epoch, not of the slot.
    #[arg(long)]
    scan: bool,
}

/// The canonical head at `slot`, walking back through missed slots.
///
/// A slot with no block has no header to fetch -- the API 404s -- and the head a
/// later slot inherits is the last block *before* it, which can be several slots
/// back. Asking for `slot - 1` and trusting it is wrong exactly when a block was
/// missed, which is the case the whole empty-slot discount exists for.
async fn head_at(api: &BeaconApiClient, mut slot: u64) -> Result<(u64, [u8; 32])> {
    for _ in 0..64 {
        if let Ok(h) = api.get_header(&slot.to_string()).await {
            return Ok((slot, h.root()));
        }
        slot = slot.checked_sub(1).context("walked past genesis")?;
    }
    anyhow::bail!("no block within 64 slots")
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config = ChainConfig::MAINNET;
    let spe = config.slots_per_epoch;
    let api = BeaconApiClient::new(&args.beacon_url);

    let head: u64 = api.get_header("head").await?.fields().slot;
    let first_slot = args.slot.unwrap_or(head - 2 * spe - (head % spe));
    let epoch = first_slot / spe;
    let last_slot = first_slot + args.count - 1;
    anyhow::ensure!(
        last_slot / spe == epoch,
        "a batch cannot cross an epoch boundary: {first_slot}..{last_slot}",
    );
    eprintln!("head {head}; batch {first_slot}..{last_slot} in epoch {epoch}");

    // The checkpoints this epoch's attestations name.
    let target_slot = epoch * spe;
    let target_root = api.get_header(&target_slot.to_string()).await?.root();
    let source_root = api
        .get_header(&((epoch - 1) * spe).to_string())
        .await?
        .root();

    // The signing domain these attestations were made under.
    let fork_version: [u8; 4] = api.get_fork_version(&target_slot.to_string()).await?;
    let genesis_validators_root: [u8; 32] = api.get_genesis_validators_root().await?;

    // The validator set, and the accumulator over it.
    eprintln!("fetching the registry at slot {target_slot}...");
    let validators = init_point::fetch_registry(&api, target_slot).await?;
    eprintln!("  {} validators", validators.len());
    let data: Vec<ValidatorData> = validators
        .iter()
        .map(zkasper_witness_gen::state_diff::validator_response_to_data)
        .collect();
    let tree = AccTree::build(&data, epoch, config.acc_tree_depth);
    let total_active_balance: u64 = data.iter().map(|v| v.active_effective_balance(epoch)).sum();
    let acc_root = tree.root();
    let accumulator_commitment = zkasper_common::acc::commitment(&acc_root, total_active_balance);

    // The committee tree, from the node's own assignment.
    eprintln!("building the committee tree...");
    let committees = Arc::new(committee::build(
        &api.get_committees(&target_slot.to_string(), epoch).await?,
        &validators,
        &tree,
        &config,
        epoch,
        epoch,
        total_active_balance,
    )?);

    // Head votes, from the blocks that carried them.
    let mut stream = SlotStream::new(&config, committees.clone(), epoch, target_root, source_root);
    for slot in first_slot..=(last_slot + 2) {
        match api.get_block_attestations(&slot.to_string()).await {
            Ok(atts) => stream.ingest(&atts)?,
            Err(_) => eprintln!("  no block at {slot}"),
        }
    }

    let mut parent_head_root = api.get_header(&(first_slot - 1).to_string()).await?.root();
    let parent_head_slot = first_slot - 1;

    if args.scan {
        println!();
        println!(
            "{:>10}  {:>10}  {:>20}  {:>20}  {:>9}  {}",
            "slot", "absentees", "support (gwei)", "threshold (gwei)", "support/C", "k=1"
        );
        let committee_weight = total_active_balance / spe;
        for slot in first_slot..=last_slot {
            let Some(complement) = stream.close(slot) else {
                println!("{slot:>10}  (no attestations)");
                continue;
            };
            let header = api.get_header(&slot.to_string()).await.ok().map(|h| {
                let f = h.fields();
                BlockHeaderWitness {
                    slot: f.slot,
                    proposer_index: f.proposer_index,
                    parent_root: f.parent_root,
                    state_root: f.state_root,
                    body_root: f.body_root,
                }
            });
            let absentees = complement.witness.absentees.len();
            let mut named: Vec<u64> = complement
                .witness
                .absentees
                .iter()
                .map(|v| v.validator_index)
                .chain(
                    complement
                        .witness
                        .secondary
                        .iter()
                        .flat_map(|a| a.attesting_validators.iter().map(|v| v.validator_index)),
                )
                .collect();
            named.sort_unstable();
            let one = FcrBatchWitness {
                accumulator_commitment,
                acc_root,
                total_active_balance,
                committee_root: committees.root(),
                acc_multi_proof: tree.build_multi_proof(&named),
                committee_multi_proof: committees.multi_proof(&[slot % spe]),
                signing_domain: zkasper_common::bls::compute_domain(
                    &zkasper_common::constants::DOMAIN_BEACON_ATTESTER,
                    &fork_version,
                    &genesis_validators_root,
                ),
                parent_head_root: head_at(&api, slot - 1).await?.1,
                parent_head_slot: head_at(&api, slot - 1).await?.0,
                byzantine_threshold: 25,
                proposer_score_boost: 40,
                current_slot: slot + 1,
                slots: vec![FcrSlotWitness {
                    complement: complement.witness,
                    head_header: header,
                }],
            };
            let out = zkasper_fcr_proof_guest::verify_fcr_batch(&one);
            println!(
                "{:>10}  {:>10}  {:>20}  {:>20}  {:>8.2}%  {}",
                slot,
                absentees,
                out.support,
                out.threshold,
                100.0 * out.support as f64 / committee_weight as f64,
                if out.confirmed { "CONFIRMED" } else { "no" },
            );
        }
        return Ok(());
    }

    let mut entries = Vec::new();
    for slot in first_slot..=last_slot {
        let complement = stream
            .close(slot)
            .with_context(|| format!("no complement for slot {slot}"))?;
        let header = match api.get_header(&slot.to_string()).await {
            Ok(h) => {
                let f = h.fields();
                Some(BlockHeaderWitness {
                    slot: f.slot,
                    proposer_index: f.proposer_index,
                    parent_root: f.parent_root,
                    state_root: f.state_root,
                    body_root: f.body_root,
                })
            }
            Err(_) => None,
        };
        if let Some(h) = &header {
            parent_head_root = zkasper_common::ssz::block_header_root(
                h.slot,
                h.proposer_index,
                &h.parent_root,
                &h.state_root,
                &h.body_root,
            );
        }
        let voted = complement.witness.primary[0].data_beacon_block_root;
        eprintln!(
            "  slot {slot}: {} absentees, {} minority aggregates, primary head {}",
            complement.witness.absentees.len(),
            complement.witness.secondary.len(),
            if voted == parent_head_root {
                "canonical"
            } else {
                "NOT canonical"
            },
        );
        entries.push(FcrSlotWitness {
            complement: complement.witness,
            head_header: header,
        });
    }

    let mut named: Vec<u64> = entries
        .iter()
        .flat_map(|e| {
            e.complement
                .absentees
                .iter()
                .map(|v| v.validator_index)
                .chain(
                    e.complement
                        .secondary
                        .iter()
                        .flat_map(|a| a.attesting_validators.iter().map(|v| v.validator_index)),
                )
        })
        .collect();
    named.sort_unstable();

    let witness = FcrBatchWitness {
        accumulator_commitment,
        acc_root,
        total_active_balance,
        committee_root: committees.root(),
        acc_multi_proof: tree.build_multi_proof(&named),
        committee_multi_proof: committees.multi_proof(
            &(first_slot..=last_slot)
                .map(|s| s % spe)
                .collect::<Vec<_>>(),
        ),
        signing_domain: zkasper_common::bls::compute_domain(
            &zkasper_common::constants::DOMAIN_BEACON_ATTESTER,
            &fork_version,
            &genesis_validators_root,
        ),
        parent_head_root: api.get_header(&(first_slot - 1).to_string()).await?.root(),
        parent_head_slot,
        byzantine_threshold: 25,
        proposer_score_boost: 40,
        current_slot: last_slot + 1,
        slots: entries,
    };

    let bytes = bincode::serialize(&witness)?;
    std::fs::write(&args.out, &bytes)?;
    println!("wrote {}: {} bytes", args.out, bytes.len());

    // Prove the assignment, if the seed was supplied. Without it the verifier
    // refuses, which is the point: a confirmation against a partition nobody
    // proved is not a weaker confirmation, it is not one.
    let assignment = match &args.randao {
        Some(r) => {
            let mix = hex_to_32(r)?;
            let seed = get_seed(epoch, &mix);
            let active: Vec<_> = validators
                .iter()
                .enumerate()
                .filter(|(i, _)| data[*i].active_effective_balance(epoch) > 0)
                .filter_map(|(i, v)| committee::opened(i as u64, v, epoch).ok())
                .collect();
            let indices: Vec<u64> = active.iter().map(|v| v.validator_index).collect();
            eprintln!("proving the assignment over {} active...", active.len());
            let proof = zkasper_fcr_committee_guest::verify_fcr_committee(
                &zkasper_fcr_types::FcrCommitteeWitness {
                    accumulator_commitment,
                    acc_root,
                    total_active_balance,
                    seed,
                    epoch,
                    acc_multi_proof: tree.build_multi_proof(&indices),
                    active,
                },
                spe,
            );
            anyhow::ensure!(
                proof.committee_root == committees.root(),
                "the proven assignment is not the one the batch was proved against",
            );
            zkasper_fcr_verifier::Assignment::from_committee_proof(&proof)
        }
        None => zkasper_fcr_verifier::Assignment::unproven(committees.root()),
    };

    // Run the circuit, then judge it with the specification's own arithmetic.
    let out = zkasper_fcr_proof_guest::verify_fcr_batch(&witness);
    let window = zkasper_fcr_verifier::accumulate(std::slice::from_ref(&out))
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let params = zkasper_fcr_verifier::Params::default();
    let threshold =
        zkasper_fcr_verifier::safety_threshold(&window, parent_head_slot, last_slot + 1, &params)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;

    println!();
    println!(
        "head           slot {} root 0x{}",
        out.head_slot,
        hex(&out.head_root)
    );
    println!("support        {:>20} gwei", out.support);
    println!(
        "threshold      {:>20} gwei  (spec, via fast_confirmation)",
        threshold
    );
    println!(
        "margin         {:>20} gwei",
        out.support as i128 - threshold as i128
    );
    println!(
        "verdict        {}",
        match zkasper_fcr_verifier::is_confirmed(
            &window,
            &assignment,
            parent_head_slot,
            last_slot + 1,
            &params,
        ) {
            Ok(true) => "CONFIRMED".to_string(),
            Ok(false) => "not confirmed: support below the threshold".to_string(),
            Err(e) => format!("refused: {e:?}"),
        }
    );
    Ok(())
}

fn hex(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
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

fn hex_to_32(s: &str) -> Result<[u8; 32]> {
    let raw = s.trim_start_matches("0x");
    let bytes = (0..32)
        .map(|i| u8::from_str_radix(&raw[2 * i..2 * i + 2], 16))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(bytes.try_into().unwrap())
}

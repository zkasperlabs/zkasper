//! Witness for the FCR rule proof: one slot of `on_fast_confirmation` over
//! the node's fork-choice store, every validator's latest vote, and the
//! registries the rule reads. The rule's state before that slot is replayed
//! natively, by the same guest code, from the spec's initialization at the
//! finalized checkpoint.
//!
//! Votes are the node's latest messages rebuilt from attestations included in
//! blocks (`process_attestation`: newest attestation slot wins, first wins a
//! tie); attestations seen only on gossip are not visible to a witness.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use clap::Parser;
use zkasper_fcr_rule_guest::{
    encode, run, BlockNode, Cp, EpochSeed, Header, LazyAssignments, RegistryHeader, RuleState,
    Witness, NO_VOTE, SLOTS_PER_EPOCH,
};
use zkasper_witness_gen::beacon_api::{
    AttestationResponse, BeaconApi, BeaconApiClient, ForkChoiceNodeResponse, ValidatorResponse,
};
use zkasper_witness_gen::init_point;

#[derive(Parser)]
struct Args {
    #[arg(long, env = "BEACON_API_URL")]
    beacon_url: String,
    /// The slot to prove; default: the head slot.
    #[arg(long)]
    slot: Option<u64>,
    #[arg(long, default_value = "/mnt/ssd/fcr-rule-witness.bin")]
    out: String,
    #[arg(long, default_value = "25")]
    byzantine_threshold: u64,
    #[arg(long, default_value = "40")]
    proposer_score_boost: u64,
}

struct Registry {
    epoch: u64,
    balances: Vec<u64>,
    slashed: Vec<bool>,
    total_active_balance: u64,
}

fn registry_at(validators: &[ValidatorResponse], epoch: u64, n: usize) -> Registry {
    let mut balances = vec![0u64; n];
    let mut slashed = vec![false; n];
    let mut total = 0u64;
    for v in validators {
        let i = v.index as usize;
        slashed[i] = v.slashed;
        if v.activation_epoch <= epoch && epoch < v.exit_epoch {
            balances[i] = v.effective_balance;
            total += v.effective_balance;
        }
    }
    Registry {
        epoch,
        balances,
        slashed,
        total_active_balance: total,
    }
}

struct CommitteeTable(BTreeMap<(u64, u64), Vec<u64>>);

impl CommitteeTable {
    fn committee(&self, slot: u64, index: u64) -> Option<&[u64]> {
        self.0.get(&(slot, index)).map(Vec::as_slice)
    }
}

fn get_bit(bitfield: &[u8], idx: usize) -> bool {
    bitfield
        .get(idx / 8)
        .is_some_and(|b| (b >> (idx % 8)) & 1 == 1)
}

/// `attestation_collector::resolve_attesting_validators`, over the raw table.
fn attesters(att: &AttestationResponse, ct: &CommitteeTable) -> Vec<u64> {
    if let Some(single) = att.single_attester {
        return ct
            .committee(att.data_slot, single.committee_index)
            .filter(|c| c.contains(&single.attester_index))
            .map(|_| vec![single.attester_index])
            .unwrap_or_default();
    }
    let mut out = Vec::new();
    if att.committee_bits.is_empty() {
        if let Some(c) = ct.committee(att.data_slot, att.data_index) {
            for (bit, &v) in c.iter().enumerate() {
                if get_bit(&att.aggregation_bits, bit) {
                    out.push(v);
                }
            }
        }
        return out;
    }
    let mut offset = 0;
    for ci in 0..att.committee_bits.len() * 8 {
        if !get_bit(&att.committee_bits, ci) {
            continue;
        }
        let Some(c) = ct.committee(att.data_slot, ci as u64) else {
            continue;
        };
        for (j, &v) in c.iter().enumerate() {
            if get_bit(&att.aggregation_bits, offset + j) {
                out.push(v);
            }
        }
        offset += c.len();
    }
    out
}

/// The store's finalized and unrealized-justified checkpoints as of slot `t`:
/// the greatest over the blocks imported by then, with the unrealized
/// finalized checkpoints of earlier epochs pulled up at the epoch tick.
fn checkpoints_at(nodes: &[ForkChoiceNodeResponse], t: u64) -> (Cp, Cp) {
    let epoch_start = t / SLOTS_PER_EPOCH * SLOTS_PER_EPOCH;
    let mut fin = Cp::default();
    let mut uj = Cp::default();
    for n in nodes.iter().filter(|n| n.slot <= t) {
        if n.finalized_epoch > fin.epoch {
            fin = Cp {
                epoch: n.finalized_epoch,
                root: n.finalized_root,
            };
        }
        if n.slot < epoch_start {
            if let (Some(e), Some(r)) = (n.unrealized_finalized_epoch, n.unrealized_finalized_root) {
                if e > fin.epoch {
                    fin = Cp { epoch: e, root: r };
                }
            }
        }
        let (je, jr) = match (n.unrealized_justified_epoch, n.unrealized_justified_root) {
            (Some(e), Some(r)) => (e, r),
            _ => (n.justified_epoch, n.justified_root),
        };
        if je > uj.epoch {
            uj = Cp { epoch: je, root: jr };
        }
    }
    (fin, uj)
}

fn seed(epoch: u64, mix: &[u8; 32]) -> [u8; 32] {
    let mut b = Vec::with_capacity(44);
    b.extend_from_slice(&zkasper_common::constants::DOMAIN_BEACON_ATTESTER);
    b.extend_from_slice(&epoch.to_le_bytes());
    b.extend_from_slice(mix);
    zkasper_fcr_rule_guest::sha256(&b)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let api = BeaconApiClient::new(&args.beacon_url);
    let spe = SLOTS_PER_EPOCH;

    let head_slot = api.get_header("head").await?.fields().slot;
    let target = args.slot.unwrap_or(head_slot);
    let target_epoch = target / spe;

    // The store: proto-array nodes known by `target`, parents before children.
    let mut nodes: Vec<ForkChoiceNodeResponse> = api
        .get_fork_choice_nodes()
        .await?
        .into_iter()
        .filter(|n| n.slot <= target)
        .collect();
    nodes.sort_by_key(|n| n.slot);
    let idx: BTreeMap<[u8; 32], u32> = nodes
        .iter()
        .enumerate()
        .map(|(i, n)| (n.block_root, i as u32))
        .collect();
    let blocks: Vec<BlockNode> = nodes
        .iter()
        .map(|n| BlockNode {
            root: n.block_root,
            slot: n.slot,
            parent: n.parent_root.and_then(|p| idx.get(&p).copied()),
            justified_checkpoint: Cp {
                epoch: n.justified_epoch,
                root: n.justified_root,
            },
            unrealized_justified_checkpoint: n
                .unrealized_justified_epoch
                .zip(n.unrealized_justified_root)
                .map(|(epoch, root)| Cp { epoch, root }),
            optimistic_or_invalid: n.execution_status.starts_with("Optimistic")
                || n.execution_status.starts_with("Invalid"),
        })
        .collect();

    // The head at `target` and its canonical chain.
    let head = nodes
        .iter()
        .filter(|n| n.slot <= target)
        .max_by_key(|n| n.slot)
        .context("no node at or before the target")?;
    let head_root = head.block_root;
    let mut canonical: Vec<u32> = Vec::new();
    let mut cur = Some(idx[&head_root]);
    while let Some(i) = cur {
        canonical.push(i);
        cur = blocks[i as usize].parent;
    }
    canonical.reverse();
    let head_at = |t: u64| -> [u8; 32] {
        canonical
            .iter()
            .rev()
            .map(|&i| &blocks[i as usize])
            .find(|b| b.slot <= t)
            .map(|b| b.root)
            .expect("canonical block at or before t")
    };

    let (finalized, _) = checkpoints_at(&nodes, target);
    let t0 = finalized.epoch * spe;
    eprintln!(
        "target slot {target} (epoch {target_epoch}), head {} at {}, finalized epoch {} -> replay from {t0}",
        hex(&head_root)[..10].to_string(),
        head.slot,
        finalized.epoch
    );

    // Registries, one per epoch the replay can reference.
    let mut registries: Vec<Registry> = Vec::new();
    let mut n_validators = 0usize;
    for epoch in finalized.epoch..=target_epoch {
        let slot = epoch * spe;
        eprintln!("fetching the registry at slot {slot} (epoch {epoch})...");
        let validators = init_point::fetch_registry(&api, slot).await?;
        n_validators = n_validators.max(validators.iter().map(|v| v.index as usize + 1).max().unwrap_or(0));
        registries.push(registry_at(&validators, epoch, n_validators));
    }
    for r in &mut registries {
        r.balances.resize(n_validators, 0);
        r.slashed.resize(n_validators, false);
    }
    let reg_idx = |epoch: u64| -> u32 {
        registries
            .iter()
            .position(|r| r.epoch == epoch)
            .unwrap_or_else(|| panic!("no registry for epoch {epoch}")) as u32
    };
    eprintln!("  {} validators, {} registries", n_validators, registries.len());

    // Committees, for resolving attestations; one epoch before the replay
    // window too, since a block carries the previous slot's attestations.
    let mut table = BTreeMap::new();
    for epoch in (finalized.epoch - 1)..=target_epoch {
        eprintln!("fetching committees of epoch {epoch}...");
        for c in api.get_committees(&target.to_string(), epoch).await? {
            table.insert((c.slot, c.index), c.validators);
        }
    }
    let committees = CommitteeTable(table);

    // Attestations, per block slot: the tree's blocks by root (forks included,
    // the node imported them), older canonical blocks by slot.
    let att_from = t0.saturating_sub(spe);
    let mut by_slot: BTreeMap<u64, Vec<(u64, [u8; 32], Vec<u64>)>> = BTreeMap::new();
    let tree_min_slot = nodes.first().map(|n| n.slot).unwrap_or(t0);
    let mut fetched = 0usize;
    for slot in att_from..tree_min_slot {
        if let Ok(atts) = api.get_block_attestations(&slot.to_string()).await {
            let entry = by_slot.entry(slot).or_default();
            for a in &atts {
                entry.push((a.data_slot, a.data_beacon_block_root, attesters(a, &committees)));
            }
            fetched += 1;
        }
    }
    for n in &nodes {
        let atts = api
            .get_block_attestations(&format!("0x{}", hex(&n.block_root)))
            .await
            .with_context(|| format!("attestations of {}", hex(&n.block_root)))?;
        let entry = by_slot.entry(n.slot).or_default();
        for a in &atts {
            entry.push((a.data_slot, a.data_beacon_block_root, attesters(a, &committees)));
        }
        fetched += 1;
    }
    eprintln!("  attestations from {fetched} blocks");

    // Seeds for the assignment tables.
    let mut epoch_seeds = Vec::new();
    for epoch in finalized.epoch..=target_epoch {
        let mix = api.get_randao(&target.to_string(), epoch - 2).await?;
        epoch_seeds.push(EpochSeed {
            epoch,
            seed: seed(epoch, &mix),
            registry: reg_idx(epoch),
        });
    }

    // Vote roots index blocks first, then roots the store no longer holds.
    let mut extra_roots: Vec<[u8; 32]> = Vec::new();
    let mut extra_idx: BTreeMap<[u8; 32], u32> = BTreeMap::new();
    let mut vote_roots = vec![NO_VOTE; n_validators];
    let mut vote_slots = vec![0u32; n_validators];

    let base = &registries[0];
    let slashed_bits: Vec<u8> = (0..n_validators.div_ceil(8))
        .map(|byte| {
            (0..8)
                .filter(|bit| base.slashed.get(byte * 8 + bit).copied().unwrap_or(false))
                .fold(0u8, |acc, bit| acc | 1 << bit)
        })
        .collect();
    let registry_headers: Vec<RegistryHeader> = registries
        .iter()
        .map(|r| RegistryHeader {
            epoch: r.epoch,
            total_active_balance: r.total_active_balance,
            balance_changes: (0..n_validators)
                .filter(|&i| r.balances[i] != base.balances[i])
                .map(|i| (i as u32, r.balances[i]))
                .collect(),
            slashed_toggles: (0..n_validators)
                .filter(|&i| r.slashed[i] != base.slashed[i])
                .map(|i| i as u32)
                .collect(),
        })
        .collect();

    let mut state = RuleState {
        confirmed_root: finalized.root,
        previous_epoch_observed_justified: finalized,
        previous_epoch_observed_justified_registry: reg_idx(finalized.epoch),
        current_epoch_observed_justified: finalized,
        current_epoch_observed_justified_registry: reg_idx(finalized.epoch),
        previous_epoch_greatest_unrealized_checkpoint: finalized,
        previous_slot_head: finalized.root,
        current_slot_head: finalized.root,
        head_balance_registry: reg_idx(finalized.epoch),
        last_update_slot: None,
    };

    let header_for = |t: u64, state: &RuleState, extra_roots: &[[u8; 32]]| -> Header {
        let (fin, uj) = checkpoints_at(&nodes, t);
        let head_registry_epoch = registries[state.head_balance_registry as usize].epoch;
        let head_balance_update = (t / spe != head_registry_epoch).then(|| reg_idx(t / spe));
        let checkpoint_balance_update = (t % spe == 0
            && state.previous_epoch_greatest_unrealized_checkpoint
                != state.current_epoch_observed_justified)
            .then(|| reg_idx(state.previous_epoch_greatest_unrealized_checkpoint.epoch));
        Header {
            slot: t,
            head_root: head_at(t),
            finalized_checkpoint: fin,
            unrealized_justified_checkpoint: uj,
            byzantine_threshold: args.byzantine_threshold,
            proposer_score_boost: args.proposer_score_boost,
            state: state.clone(),
            blocks: blocks.clone(),
            extra_roots: extra_roots.to_vec(),
            registries: registry_headers.clone(),
            n_validators: n_validators as u32,
            equivocating_indices: Vec::new(),
            head_balance_update,
            checkpoint_balance_update,
            epoch_seeds: epoch_seeds.clone(),
        }
    };

    // Ingest a slot's blocks: `process_attestation` semantics.
    let mut ingest = |slot: u64, vote_roots: &mut Vec<u32>, vote_slots: &mut Vec<u32>, extra_roots: &mut Vec<[u8; 32]>, extra_idx: &mut BTreeMap<[u8; 32], u32>| {
        let Some(atts) = by_slot.get(&slot) else { return };
        for (data_slot, root, validators) in atts {
            let ri = match idx.get(root) {
                Some(&i) => i,
                None => *extra_idx.entry(*root).or_insert_with(|| {
                    extra_roots.push(*root);
                    (blocks.len() + extra_roots.len() - 1) as u32
                }),
            };
            for &v in validators {
                let v = v as usize;
                let fresh = vote_roots[v] == NO_VOTE && vote_slots[v] == 0;
                if *data_slot as u32 > vote_slots[v] || fresh {
                    vote_roots[v] = ri;
                    vote_slots[v] = *data_slot as u32;
                }
            }
        }
    };
    for slot in att_from..t0 {
        ingest(slot, &mut vote_roots, &mut vote_slots, &mut extra_roots, &mut extra_idx);
    }

    // Replay to the slot before the target.
    for t in t0..target {
        ingest(t, &mut vote_roots, &mut vote_slots, &mut extra_roots, &mut extra_idx);
        let header = header_for(t, &state, &extra_roots);
        let w = Witness {
            header,
            vote_roots: &vote_roots,
            vote_slots: &vote_slots,
            balances: &base.balances,
            slashed: &slashed_bits,
        };
        let out = run(&w);
        if out.outcome.advanced || out.outcome.restarted_from_justified || out.outcome.reverted_to_finalized {
            eprintln!(
                "  replay slot {t}: confirmed {} -> {} {:?}",
                &hex(&out.confirmed_root_before)[..10],
                &hex(&out.confirmed_root_after)[..10],
                out.outcome
            );
        }
        state = out.post_state;
    }

    // The proven slot.
    ingest(target, &mut vote_roots, &mut vote_slots, &mut extra_roots, &mut extra_idx);
    let header = header_for(target, &state, &extra_roots);
    let voted = vote_roots.iter().filter(|&&r| r != NO_VOTE).count();
    let bytes = encode(&header, &vote_roots, &vote_slots, &base.balances, &slashed_bits);
    std::fs::write(&args.out, &bytes)?;
    let words: Vec<u64> = bytes
        .chunks(8)
        .map(|c| {
            let mut w = [0u8; 8];
            w[..c.len()].copy_from_slice(c);
            u64::from_le_bytes(w)
        })
        .collect();
    let w = Witness::decode(&words).map_err(|e| anyhow::anyhow!(e))?;

    // The assignment tables the guest would derive must match the node's committees.
    let assignments = LazyAssignments::new(&w);
    let tbl = assignments.table(target_epoch).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let mut checked = 0usize;
    for ((slot, _), validators) in committees.0.iter().filter(|((s, _), _)| s / spe == target_epoch) {
        for &v in validators {
            anyhow::ensure!(tbl[v as usize] as u64 == *slot, "assignment mismatch: validator {v} slot {slot} vs {}", tbl[v as usize]);
            checked += 1;
        }
    }
    eprintln!("assignment table matches the node's committees for epoch {target_epoch} ({checked} validators)");

    let out = run(&w);
    let public = out.public_bytes();
    std::fs::write(format!("{}.expect", args.out), hex(&public))?;
    let (support, threshold) = out.outcome.unconfirmed_support.unwrap_or((0, 0));
    println!(
        "{{\"slot\":{},\"head_root\":\"0x{}\",\"confirmed_before\":\"0x{}\",\"confirmed_after\":\"0x{}\",\"advanced\":{},\"restarted\":{},\"reverted\":{},\"unconfirmed_support\":{},\"unconfirmed_threshold\":{},\"validators\":{},\"voted\":{},\"blocks\":{},\"extra_roots\":{},\"registries\":{},\"witness_bytes\":{},\"replayed_slots\":{}}}",
        target,
        hex(&head_root),
        hex(&out.confirmed_root_before),
        hex(&out.confirmed_root_after),
        out.outcome.advanced,
        out.outcome.restarted_from_justified,
        out.outcome.reverted_to_finalized,
        support,
        threshold,
        n_validators,
        voted,
        blocks.len(),
        extra_roots.len(),
        registries.len(),
        bytes.len(),
        target - t0
    );
    Ok(())
}

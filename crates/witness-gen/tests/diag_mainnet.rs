//! TEMPORARY diagnostic harness (not part of the suite). Reports real-mainnet
//! facts and isolates the BLS batch failure seen in `test_ssz_file_finality`.

use std::collections::HashMap;

use anyhow::{Context, Result};

use zkasper_common::ChainConfig;
use zkasper_witness_gen::beacon_api::{
    self, AttestationResponse, BeaconApi, CommitteeResponse, HeaderResponse, ValidatorResponse,
};
use zkasper_witness_gen::ssz_state;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test_data");

struct StateData {
    raw_ssz: Vec<u8>,
    validators: Vec<ValidatorResponse>,
    header: HeaderResponse,
}

struct Api {
    states: HashMap<String, StateData>,
    atts: HashMap<String, Vec<AttestationResponse>>,
    committees: HashMap<u64, Vec<CommitteeResponse>>,
}

#[async_trait::async_trait]
impl BeaconApi for Api {
    async fn get_validators(&self, id: &str) -> Result<Vec<ValidatorResponse>> {
        Ok(self.states[id].validators.clone())
    }
    async fn get_block_attestations(&self, id: &str) -> Result<Vec<AttestationResponse>> {
        self.atts.get(id).cloned().context("no atts")
    }
    async fn get_committees(&self, _s: &str, epoch: u64) -> Result<Vec<CommitteeResponse>> {
        self.committees
            .get(&epoch)
            .cloned()
            .context("no committees")
    }
    async fn get_header(&self, id: &str) -> Result<HeaderResponse> {
        Ok(self.states[id].header.clone())
    }
    async fn get_state_ssz(&self, id: &str) -> Result<Option<Vec<u8>>> {
        Ok(Some(self.states[id].raw_ssz.clone()))
    }
}

fn load_state(api: &mut Api, filename: &str, config: &ChainConfig) -> u64 {
    let path = format!("{DIR}/{filename}");
    let raw_ssz = std::fs::read(&path).unwrap();
    let (state_root, _) = ssz_state::compute_state_root(&raw_ssz, config).unwrap();
    let validators = ssz_state::extract_validators(&raw_ssz, config).unwrap();
    let mut header = ssz_state::extract_header(&raw_ssz, config).unwrap();
    header.state_root = state_root;
    let slot = header.slot;
    api.states.insert(
        slot.to_string(),
        StateData {
            raw_ssz,
            validators,
            header,
        },
    );
    slot
}

fn load_finality(api: &mut Api, filename: &str) -> (u64, [u8; 32]) {
    use flate2::read::GzDecoder;
    use std::io::Read;
    let f = std::fs::File::open(format!("{DIR}/{filename}")).unwrap();
    let mut s = String::new();
    GzDecoder::new(f).read_to_string(&mut s).unwrap();
    let data: serde_json::Value = serde_json::from_str(&s).unwrap();
    let target_epoch = data["target_epoch"].as_u64().unwrap();
    let mut target_root = [0u8; 32];
    target_root.copy_from_slice(
        &hex::decode(
            data["target_root"]
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap(),
        )
        .unwrap(),
    );
    let committees = data["committees"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| beacon_api::parse_committee_entry(e).unwrap())
        .collect();
    api.committees.insert(target_epoch, committees);
    for (slot, arr) in data["attestations_by_slot"].as_object().unwrap() {
        api.atts.insert(
            slot.clone(),
            arr.as_array()
                .unwrap()
                .iter()
                .map(|e| beacon_api::parse_attestation_entry(e).unwrap())
                .collect(),
        );
    }
    (target_epoch, target_root)
}

// ---------------------------------------------------------------------------
// 1. Real active validator count
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn diag_active_validator_count() {
    const CONFIG: ChainConfig = ChainConfig::MAINNET;
    let mut api = Api {
        states: HashMap::new(),
        atts: HashMap::new(),
        committees: HashMap::new(),
    };

    for f in ["state_13776608.ssz", "state_13776928.ssz"] {
        let slot = load_state(&mut api, f, &CONFIG);
        let epoch = slot / CONFIG.slots_per_epoch;
        let vs = &api.states[&slot.to_string()].validators;

        let mut active = 0u64;
        let mut active_balance = 0u128;
        let mut exited = 0u64;
        let mut pending = 0u64;
        let mut hist: HashMap<u64, u64> = HashMap::new();
        let mut max_eb = 0u64;
        let mut compounding = 0u64; // effective_balance > 32 ETH => 0x02 creds
        for v in vs {
            let d = zkasper_witness_gen::state_diff::validator_response_to_data(v);
            if d.is_active(epoch) {
                active += 1;
                active_balance += d.effective_balance as u128;
                *hist.entry(d.effective_balance / 1_000_000_000).or_default() += 1;
                max_eb = max_eb.max(d.effective_balance);
                if d.effective_balance > 32_000_000_000 {
                    compounding += 1;
                }
            } else if d.activation_epoch > epoch {
                pending += 1;
            } else {
                exited += 1;
            }
        }
        let mut buckets: Vec<_> = hist.into_iter().collect();
        buckets.sort_by_key(|&(_, c)| std::cmp::Reverse(c));
        eprintln!("=== {f} slot={slot} epoch={epoch}");
        eprintln!("  registry_len       {}", vs.len());
        eprintln!("  ACTIVE             {active}");
        eprintln!("  pending_activation {pending}");
        eprintln!("  exited/slashed     {exited}");
        eprintln!(
            "  total_active_bal   {active_balance} gwei ({} ETH)",
            active_balance / 1_000_000_000
        );
        eprintln!(
            "  avg eff bal        {} ETH",
            active_balance / active as u128 / 1_000_000_000
        );
        eprintln!("  max eff bal        {} ETH", max_eb / 1_000_000_000);
        eprintln!("  eff_bal > 32 ETH   {compounding}");
        eprintln!(
            "  top eff-bal buckets (ETH -> count): {:?}",
            &buckets[..buckets.len().min(8)]
        );
    }
}

// ---------------------------------------------------------------------------
// 2. BLS failure isolation + slot-proof op counts
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn diag_finality_bls() {
    use zkasper_common::bls::{
        compute_signing_root, fast_aggregate_verify, verify_attestation_batch, SignedMessage,
    };
    use zkasper_common::op_counter;

    const CONFIG: ChainConfig = ChainConfig::MAINNET;
    let mut api = Api {
        states: HashMap::new(),
        atts: HashMap::new(),
        committees: HashMap::new(),
    };
    let slot = load_state(&mut api, "state_13776928.ssz", &CONFIG);
    let (target_epoch, target_root) = load_finality(&mut api, "finality_epoch_430529.json.gz");

    let (_w, tree, _es, total_active_balance, _n) =
        zkasper_witness_gen::witness_bootstrap::build(&api, &CONFIG, slot)
            .await
            .unwrap();

    let raw = &api.states[&slot.to_string()].raw_ssz;
    let signing_domain = zkasper_common::bls::compute_domain(
        &zkasper_common::bls::DOMAIN_BEACON_ATTESTER,
        &ssz_state::extract_fork_version(raw),
        &ssz_state::extract_genesis_validators_root(raw),
    );

    let slots = zkasper_witness_gen::witness_slot_proof::build_per_slot(
        &api,
        &CONFIG,
        &tree,
        target_epoch,
        target_root,
        total_active_balance,
        signing_domain,
    )
    .await
    .unwrap();

    eprintln!("\n=== per-slot BLS diagnosis ===");
    let mut total_dupe_slots = 0;
    let mut total_att = 0;
    let mut indiv_fail = 0;
    let mut batch_fail_dupe = 0;
    let mut batch_ok = 0;
    let mut attesting_balance_total: u64 = 0;

    for s in &slots {
        let mut roots = Vec::new();
        let mut msgs_pk = Vec::new();
        for a in &s.witness.attestations {
            let dr = zkasper_common::ssz::attestation_data_root(
                a.data_slot,
                a.data_index,
                &a.data_beacon_block_root,
                a.data_source_epoch,
                &a.data_source_root,
                a.data_target_epoch,
                &a.data_target_root,
            );
            roots.push(compute_signing_root(&dr, &signing_domain));
            msgs_pk.push(
                a.attesting_validators
                    .iter()
                    .map(|v| v.pubkey)
                    .collect::<Vec<_>>(),
            );
        }
        total_att += s.witness.attestations.len();

        // Individual FastAggregateVerify per attestation
        let mut per_att_ok = Vec::new();
        for (i, a) in s.witness.attestations.iter().enumerate() {
            let ok = fast_aggregate_verify(&msgs_pk[i], &roots[i], &a.signature.0);
            if !ok {
                indiv_fail += 1;
            }
            per_att_ok.push(ok);
        }

        // Duplicate signing roots?
        let mut dupe = false;
        for i in 0..roots.len() {
            for j in i + 1..roots.len() {
                if roots[i] == roots[j] {
                    dupe = true;
                }
            }
        }
        if dupe {
            total_dupe_slots += 1;
        }

        let msgs: Vec<SignedMessage> = s
            .witness
            .attestations
            .iter()
            .enumerate()
            .map(|(i, a)| SignedMessage {
                pubkeys: &msgs_pk[i],
                signing_root: &roots[i],
                signature: &a.signature.0,
            })
            .collect();
        let batch = verify_attestation_batch(&msgs);
        if batch {
            batch_ok += 1;
        } else if dupe {
            batch_fail_dupe += 1;
        }

        let all_indiv_ok = per_att_ok.iter().all(|&b| b);
        eprintln!(
            "slot {} atts={} indiv_all_ok={} dup_signing_root={} batch_ok={}",
            s.slot,
            s.witness.attestations.len(),
            all_indiv_ok,
            dupe,
            batch,
        );
    }

    eprintln!(
        "\nslots={} atts={} indiv_failures={} slots_with_dup_signing_roots={} batch_ok={} batch_fail_due_to_dup={}",
        slots.len(), total_att, indiv_fail, total_dupe_slots, batch_ok, batch_fail_dupe,
    );

    // How many slots have acc_multi_proof built over a wider index set than the
    // circuit reconstructs (all attesters vs count_balance=true only)?
    let mut mismatch_slots = 0;
    for s in &slots {
        let mut all: Vec<u64> = Vec::new();
        for a in &s.witness.attestations {
            for v in &a.attesting_validators {
                all.push(v.validator_index);
            }
        }
        all.sort_unstable();
        all.dedup();
        if all.len() != s.counted_indices.len() {
            mismatch_slots += 1;
        }
    }
    eprintln!(
        "\nslots where acc multi-proof index set != circuit leaf set: {mismatch_slots}/{}",
        slots.len()
    );

    // Op counts on a slot with distinct signing roots AND all==counted.
    let clean = slots.iter().find(|s| {
        let mut roots = Vec::new();
        let mut all: Vec<u64> = Vec::new();
        for a in &s.witness.attestations {
            let dr = zkasper_common::ssz::attestation_data_root(
                a.data_slot,
                a.data_index,
                &a.data_beacon_block_root,
                a.data_source_epoch,
                &a.data_source_root,
                a.data_target_epoch,
                &a.data_target_root,
            );
            roots.push(compute_signing_root(&dr, &signing_domain));
            for v in &a.attesting_validators {
                all.push(v.validator_index);
            }
        }
        all.sort_unstable();
        all.dedup();
        let n = roots.len();
        roots.sort();
        roots.dedup();
        roots.len() == n && n > 1 && all.len() == s.counted_indices.len()
    });

    if let Some(s) = clean {
        let n_att = s.witness.attestations.len();
        let n_val: usize = s
            .witness
            .attestations
            .iter()
            .map(|a| a.attesting_validators.len())
            .sum();
        let n_counted = s.counted_indices.len();
        eprintln!(
            "\n=== slot-proof op count: slot {} ({n_att} attestations, {n_val} attester slots, {n_counted} counted, {} auxiliaries) ===",
            s.slot,
            s.witness.acc_multi_proof.auxiliaries.len(),
        );

        op_counter::reset();
        let before = op_counter::snapshot();
        let out = zkasper_slot_proof_guest::verify_slot_proof(&s.witness);
        let total = op_counter::snapshot().delta(&before);
        eprintln!("TOTAL {total}");
        eprintln!("  bls_fraction {:.4}", total.bls_fraction());
        eprintln!("  attesting_balance {}", out.attesting_balance);

        op_counter::reset();
        let s0 = op_counter::snapshot();
        let mut leaves = Vec::new();
        for a in &s.witness.attestations {
            for v in &a.attesting_validators {
                if v.count_balance {
                    leaves.push((
                        zkasper_common::acc::leaf(&v.pubkey, v.active_effective_balance),
                        v.validator_index,
                    ));
                }
            }
        }
        let ph_leaf = op_counter::snapshot().delta(&s0);
        eprintln!("  acc_leaf   {ph_leaf}");

        leaves.sort_unstable_by_key(|&(_, i)| i);
        op_counter::reset();
        let s0 = op_counter::snapshot();
        let _ = zkasper_common::merkle::batch_root(
            zkasper_common::acc::compress,
            &leaves,
            &s.witness.acc_multi_proof.auxiliaries,
            CONFIG.acc_tree_depth,
        );
        let ph_merkle = op_counter::snapshot().delta(&s0);
        eprintln!("  acc_merkle {ph_merkle}");

        let mut roots = Vec::new();
        let mut pks = Vec::new();
        for a in &s.witness.attestations {
            let dr = zkasper_common::ssz::attestation_data_root(
                a.data_slot,
                a.data_index,
                &a.data_beacon_block_root,
                a.data_source_epoch,
                &a.data_source_root,
                a.data_target_epoch,
                &a.data_target_root,
            );
            roots.push(compute_signing_root(&dr, &signing_domain));
            pks.push(
                a.attesting_validators
                    .iter()
                    .map(|v| v.pubkey)
                    .collect::<Vec<_>>(),
            );
        }
        let msgs: Vec<SignedMessage> = s
            .witness
            .attestations
            .iter()
            .enumerate()
            .map(|(i, a)| SignedMessage {
                pubkeys: &pks[i],
                signing_root: &roots[i],
                signature: &a.signature.0,
            })
            .collect();
        op_counter::reset();
        let s0 = op_counter::snapshot();
        let ok = verify_attestation_batch(&msgs);
        let ph_bls = op_counter::snapshot().delta(&s0);
        eprintln!("  bls_batch  {ph_bls} (ok={ok})");

        op_counter::reset();
        let s0 = op_counter::snapshot();
        let mut hashes = 0u64;
        for a in &s.witness.attestations {
            let _ = zkasper_common::ssz::attestation_data_root(
                a.data_slot,
                a.data_index,
                &a.data_beacon_block_root,
                a.data_source_epoch,
                &a.data_source_root,
                a.data_target_epoch,
                &a.data_target_root,
            );
            hashes += 1;
        }
        let ph_data = op_counter::snapshot().delta(&s0);
        eprintln!("  att_data_root ({hashes} atts) {ph_data}");
    } else {
        eprintln!("\nno clean slot found");
    }

    // Aggregate participation across all slots, ignoring the BLS check.
    for s in &slots {
        for a in &s.witness.attestations {
            for v in &a.attesting_validators {
                if v.count_balance {
                    attesting_balance_total += v.active_effective_balance;
                }
            }
        }
    }
    eprintln!(
        "\ntotal_active_balance {total_active_balance}  attesting_balance {attesting_balance_total}  participation {:.2}%",
        attesting_balance_total as f64 / total_active_balance as f64 * 100.0,
    );
}

#[tokio::test]
#[ignore]
async fn diag_gnosis_active() {
    let config = ChainConfig::GNOSIS;
    let mut api = Api {
        states: HashMap::new(),
        atts: HashMap::new(),
        committees: HashMap::new(),
    };
    let slot = load_state(&mut api, "state_26696480.ssz", &config);
    let epoch = slot / config.slots_per_epoch;
    let vs = &api.states[&slot.to_string()].validators;
    let mut active = 0u64;
    let mut bal = 0u128;
    let mut maxeb = 0u64;
    for v in vs {
        let d = zkasper_witness_gen::state_diff::validator_response_to_data(v);
        if d.is_active(epoch) {
            active += 1;
            bal += d.effective_balance as u128;
            maxeb = maxeb.max(d.effective_balance);
        }
    }
    eprintln!("GNOSIS slot={slot} epoch={epoch} registry={} ACTIVE={active} total_active_bal={bal} max_eb={maxeb}", vs.len());
}

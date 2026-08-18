//! TEMPORARY diagnostic harness (not part of the suite). Reports real-mainnet
//! facts and checks, against real aggregates, that the key a slot proof never
//! enumerates is the key that signed.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use anyhow::{Context, Result};

use zkasper_common::acc::G1Point;
use zkasper_common::bls::{
    compute_signing_root, fast_aggregate_verify, verify_attestation_batch, PointSum, SignedMessage,
};
use zkasper_common::types::{AttestationWitness, SlotComplementWitness};
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
// 2. Complement verification + slot-proof op counts
// ---------------------------------------------------------------------------

/// `hash_tree_root(AttestationData)` for one aggregate.
fn data_root(a: &AttestationWitness) -> [u8; 32] {
    zkasper_common::ssz::attestation_data_root(
        a.data_slot,
        a.data_index,
        &a.data_beacon_block_root,
        a.data_source_epoch,
        &a.data_source_root,
        a.data_target_epoch,
        &a.data_target_root,
    )
}

/// Validator indices a complement names — absentees plus the signers of any
/// minority head vote. Exactly what its accumulator opening covers.
fn named(complement: &SlotComplementWitness) -> BTreeSet<u64> {
    let mut named: BTreeSet<u64> = complement
        .absentees
        .iter()
        .map(|v| v.validator_index)
        .collect();
    for a in &complement.secondary {
        named.extend(a.attesting_validators.iter().map(|v| v.validator_index));
    }
    named
}

/// The primary aggregate's public key, derived the way the circuit derives it:
/// the committee minus everyone the complement names.
fn derived_key(complement: &SlotComplementWitness) -> G1Point {
    let mut key = PointSum::from_point(complement.committee.pubkey);
    for a in &complement.secondary {
        for v in &a.attesting_validators {
            key.sub(&v.pubkey).expect("shared x-coordinate");
        }
    }
    for v in &complement.absentees {
        key.sub(&v.pubkey).expect("shared x-coordinate");
    }
    key.get().expect("committee aggregate is the identity")
}

#[tokio::test]
#[ignore]
async fn diag_finality_bls() {
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

    let committees = Arc::new(
        zkasper_witness_gen::committee::build(
            &api.committees[&target_epoch],
            &api.states[&slot.to_string()].validators,
            &tree,
            &CONFIG,
            target_epoch,
            target_epoch,
            total_active_balance,
        )
        .unwrap(),
    );

    let slots = zkasper_witness_gen::witness_slot_proof::build_per_slot(
        &api,
        &CONFIG,
        &tree,
        committees,
        target_epoch,
        target_root,
        total_active_balance,
        signing_domain,
    )
    .await
    .unwrap();

    eprintln!("\n=== per-slot complement diagnosis ===");
    let mut total_primary = 0;
    let mut total_secondary = 0;
    let mut minority_slots = 0;
    let mut derived_fail = 0;
    let mut secondary_fail = 0;

    for s in &slots {
        let complement = &s.witness.slots[0];

        // The claim the whole scheme rests on: the key nobody enumerated is the
        // key that signed. Everything else in this loop is context for it.
        let signatures: Vec<[u8; 96]> = complement.primary.iter().map(|a| a.signature.0).collect();
        let derived_ok = verify_attestation_batch(&[SignedMessage {
            pubkeys: &[derived_key(complement)],
            signing_root: &compute_signing_root(
                &data_root(&complement.primary[0]),
                &signing_domain,
            ),
            signatures: &signatures,
        }]);
        if !derived_ok {
            derived_fail += 1;
        }

        // Minority head votes, whose signers are named rather than derived.
        let mut secondary_ok = true;
        for a in &complement.secondary {
            let pubkeys: Vec<G1Point> = a.attesting_validators.iter().map(|v| v.pubkey).collect();
            if !fast_aggregate_verify(
                &pubkeys,
                &compute_signing_root(&data_root(a), &signing_domain),
                &a.signature.0,
            ) {
                secondary_ok = false;
                secondary_fail += 1;
            }
        }

        total_primary += complement.primary.len();
        total_secondary += complement.secondary.len();
        if !complement.secondary.is_empty() {
            minority_slots += 1;
        }

        eprintln!(
            "slot {} primary={} secondary={} absentees={} named={} derived_ok={derived_ok} secondary_ok={secondary_ok}",
            s.slot,
            complement.primary.len(),
            complement.secondary.len(),
            complement.absentees.len(),
            named(complement).len(),
        );
    }

    eprintln!(
        "\nslots={} primary_aggregates={total_primary} secondary_aggregates={total_secondary} \
         slots_with_minority_head_vote={minority_slots} derived_key_failures={derived_fail} \
         secondary_failures={secondary_fail}",
        slots.len(),
    );

    // Op counts on the slot that names the most validators: everything a slot
    // proof does beyond one multi-pairing scales with that number, so the worst
    // case is the one the cost model is about.
    let worst = slots
        .iter()
        .max_by_key(|s| named(&s.witness.slots[0]).len())
        .expect("no slots collected");
    let complement = &worst.witness.slots[0];
    eprintln!(
        "\n=== slot-proof op count: slot {} ({} primary, {} secondary, {} absentees, {} named, {} auxiliaries) ===",
        worst.slot,
        complement.primary.len(),
        complement.secondary.len(),
        complement.absentees.len(),
        named(complement).len(),
        worst.witness.acc_multi_proof.auxiliaries.len(),
    );

    op_counter::reset();
    let before = op_counter::snapshot();
    let out = zkasper_slot_proof_guest::verify_slot_proof(&worst.witness);
    let total = op_counter::snapshot().delta(&before);
    eprintln!("TOTAL {total}");
    eprintln!("  bls_fraction {:.4}", total.bls_fraction());
    eprintln!("  attesting_balance {}", out.attesting_balance);

    op_counter::reset();
    let s0 = op_counter::snapshot();
    let mut leaves = Vec::new();
    for a in &complement.secondary {
        for v in &a.attesting_validators {
            leaves.push((
                zkasper_common::acc::leaf(&v.pubkey, v.active_effective_balance),
                v.validator_index,
            ));
        }
    }
    for v in &complement.absentees {
        leaves.push((
            zkasper_common::acc::leaf(&v.pubkey, v.active_effective_balance),
            v.validator_index,
        ));
    }
    let ph_leaf = op_counter::snapshot().delta(&s0);
    eprintln!("  acc_leaf   {ph_leaf}");

    leaves.sort_unstable_by_key(|&(_, i)| i);
    op_counter::reset();
    let s0 = op_counter::snapshot();
    let _ = zkasper_common::merkle::batch_root(
        zkasper_common::acc::compress,
        &leaves,
        &worst.witness.acc_multi_proof.auxiliaries,
        CONFIG.acc_tree_depth,
    );
    let ph_merkle = op_counter::snapshot().delta(&s0);
    eprintln!("  acc_merkle {ph_merkle}");

    // The curve subtractions that replaced one Merkle opening per attester.
    op_counter::reset();
    let s0 = op_counter::snapshot();
    let primary_key = derived_key(complement);
    let ph_complement = op_counter::snapshot().delta(&s0);
    eprintln!("  complement {ph_complement}");

    let mut pubkeys: Vec<Vec<G1Point>> = vec![vec![primary_key]];
    let mut roots = vec![compute_signing_root(
        &data_root(&complement.primary[0]),
        &signing_domain,
    )];
    let mut signatures: Vec<Vec<[u8; 96]>> =
        vec![complement.primary.iter().map(|a| a.signature.0).collect()];
    for a in &complement.secondary {
        pubkeys.push(a.attesting_validators.iter().map(|v| v.pubkey).collect());
        roots.push(compute_signing_root(&data_root(a), &signing_domain));
        signatures.push(vec![a.signature.0]);
    }
    let msgs: Vec<SignedMessage> = (0..roots.len())
        .map(|i| SignedMessage {
            pubkeys: &pubkeys[i],
            signing_root: &roots[i],
            signatures: &signatures[i],
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
    for a in complement.primary.iter().chain(&complement.secondary) {
        let _ = data_root(a);
        hashes += 1;
    }
    let ph_data = op_counter::snapshot().delta(&s0);
    eprintln!("  att_data_root ({hashes} atts) {ph_data}");

    // Aggregate participation across all slots, ignoring the BLS check.
    let attesting_balance: u64 = slots.iter().map(|s| s.marginal_balance).sum();
    eprintln!(
        "\ntotal_active_balance {total_active_balance}  attesting_balance {attesting_balance}  participation {:.2}%",
        attesting_balance as f64 / total_active_balance as f64 * 100.0,
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

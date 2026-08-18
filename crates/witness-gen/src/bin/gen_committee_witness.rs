//! Parameterised committee witnesses, for the committee-proof bench harness.
//!
//! The committee proof is ~94% of the fleet's work and one mainnet run is 961k
//! validators, so nothing about it can be evaluated at full scale in less than
//! an hour. This writes the same witness `zkasper_witness_gen::committee::build`
//! produces for a real epoch, at a size and an accumulator depth a person picks,
//! so `scripts/committee_bench.py` can measure a strategy in seconds and
//! extrapolate.
//!
//! Usage: gen-committee-witness <out> <active> [registry] [acc-depth] [slots]
//!
//! `registry` is a multiple of `active`, and the surplus validators are exited
//! and spread evenly through the index space rather than parked at the end:
//! mainnet opens the ~961k active out of a 2.2M registry, and it is a gap
//! *inside* the opened range that costs the multi-proof an auxiliary. With
//! `registry == active` the opening is one contiguous run and the tree is fully
//! occupied, which is the regime a 4-ary tree can be compared in.

use rayon::prelude::*;

use zkasper_common::constants::FAR_FUTURE_EPOCH;
use zkasper_common::types::{BlsPubkey, ValidatorData};
use zkasper_common::ChainConfig;

use zkasper_witness_gen::acc_tree::AccTree;
use zkasper_witness_gen::beacon_api::{CommitteeResponse, ValidatorResponse};

const EPOCH: u64 = 100;
const BALANCE: u64 = 32_000_000_000;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: gen-committee-witness <out> <active> [registry] [acc-depth] [slots]");
        std::process::exit(1);
    }
    let out = &args[1];
    let active: usize = args[2].parse().expect("active must be an integer");
    let registry: usize = args.get(3).map_or(active, |a| a.parse().expect("registry"));
    let acc_depth: u32 = args.get(4).map_or(22, |a| a.parse().expect("acc-depth"));
    let slots: u64 = args.get(5).map_or(32, |a| a.parse().expect("slots"));

    assert!(
        registry >= active,
        "registry must hold every active validator"
    );
    assert_eq!(
        registry % active,
        0,
        "registry must be a whole multiple of active, so the gaps are even",
    );
    assert!(
        (registry as u64) <= 1 << acc_depth,
        "a depth-{acc_depth} accumulator holds {} leaves",
        1u64 << acc_depth,
    );

    let stride = registry / active;

    // Real keys, because the accumulator leaf commits to the decompressed point
    // and the curve-add precompile is undefined on anything that is not one.
    let validators: Vec<ValidatorData> = (0..registry)
        .into_par_iter()
        .map(|i| {
            let mut ikm = [0u8; 32];
            ikm[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            ikm[8] = 0xAB;
            ValidatorData {
                pubkey: BlsPubkey(
                    blst::min_pk::SecretKey::key_gen(&ikm, &[])
                        .expect("key_gen")
                        .sk_to_pk()
                        .compress(),
                ),
                effective_balance: BALANCE,
                activation_epoch: 0,
                // Every `stride`-th validator is active; the rest have exited,
                // so they sit in the accumulator with a zero balance, are in no
                // committee, and are the gaps the multi-proof pays for.
                exit_epoch: if i % stride == 0 { FAR_FUTURE_EPOCH } else { 1 },
            }
        })
        .collect();

    let responses: Vec<ValidatorResponse> = validators
        .iter()
        .enumerate()
        .map(|(i, v)| ValidatorResponse {
            index: i as u64,
            pubkey: v.pubkey.0,
            effective_balance: v.effective_balance,
            activation_epoch: v.activation_epoch,
            exit_epoch: v.exit_epoch,
            withdrawal_credentials: [0u8; 32],
            slashed: false,
            activation_eligibility_epoch: 0,
            withdrawable_epoch: FAR_FUTURE_EPOCH,
        })
        .collect();

    // Round-robin over slots rather than contiguous blocks, so the buckets
    // interleave the way a real shuffle's do. The proof still reads members in
    // index order, so this changes nothing it measures except realism.
    let committees: Vec<CommitteeResponse> = (0..slots)
        .map(|s| CommitteeResponse {
            slot: EPOCH * slots + s,
            index: 0,
            validators: (0..registry as u64)
                .filter(|i| i % stride as u64 == 0 && (i / stride as u64) % slots == s)
                .collect(),
        })
        .collect();

    let config = ChainConfig {
        slots_per_epoch: slots,
        acc_tree_depth: acc_depth,
        ..ChainConfig::MAINNET
    };
    let tree = AccTree::build(&validators, EPOCH, acc_depth);
    let committees = zkasper_witness_gen::committee::build(
        &committees,
        &responses,
        &tree,
        &config,
        EPOCH,
        EPOCH,
        active as u64 * BALANCE,
    )
    .expect("build committees");

    let bytes = zkasper_common::committee::to_bytes(&zkasper_common::committee::encode(
        &committees.witness,
    ));
    std::fs::write(out, &bytes).expect("write witness");
    println!(
        "{out}: {} members, {} auxiliaries, depth {acc_depth}, {} bytes",
        committees.witness.members.len(),
        committees.witness.acc_multi_proof.auxiliaries.len(),
        bytes.len(),
    );
}

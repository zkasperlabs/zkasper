//! Write an FCR batch witness for the prover, at production accumulator depth.
//!
//! Usage: gen-fcr-witness <out.bin> [slots]
//!
//! The validator set is synthetic and small — the point is a witness the guest
//! ELF accepts, so the depth is mainnet's rather than a test fixture's. A real
//! mainnet witness needs the collector; this is what proves the circuit runs
//! under the prover at all.

use zkasper_common::types::*;
use zkasper_common::ChainConfig;
use zkasper_fcr_types::{BlockHeaderWitness, FcrBatchWitness, FcrSlotWitness};
use zkasper_witness_gen::fixture::Epoch;

const PER_SLOT: usize = 4;
const EPOCH: u64 = 10;
const PARENT_HEAD: [u8; 32] = [0x11; 32];

fn main() {
    let mut args = std::env::args().skip(1);
    let out = args
        .next()
        .expect("usage: gen-fcr-witness <out.bin> [slots]");
    let slots: u64 = args.next().map_or(3, |s| s.parse().expect("slots"));

    let epoch = Epoch::new(ChainConfig::MAINNET, EPOCH, slots.max(4), PER_SLOT);

    let mut parent = PARENT_HEAD;
    let mut entries = Vec::new();
    for slot_in_epoch in 0..slots {
        let header = BlockHeaderWitness {
            slot: epoch.slot(slot_in_epoch),
            proposer_index: slot_in_epoch,
            parent_root: parent,
            state_root: [slot_in_epoch as u8 + 1; 32],
            body_root: [slot_in_epoch as u8 + 0x80; 32],
        };
        parent = zkasper_common::ssz::block_header_root(
            header.slot,
            header.proposer_index,
            &header.parent_root,
            &header.state_root,
            &header.body_root,
        );
        let members = &epoch.committees.members[slot_in_epoch as usize];
        let complement = SlotComplementWitness {
            slot_in_epoch,
            committee: epoch.committees.aggregate(slot_in_epoch).unwrap().clone(),
            primary: vec![AttestationWitness {
                data_slot: epoch.slot(slot_in_epoch),
                data_index: 0,
                data_beacon_block_root: parent,
                data_source_epoch: EPOCH - 1,
                data_source_root: epoch.source_root,
                data_target_epoch: EPOCH,
                data_target_root: epoch.target_root,
                signature: BlsSignature(
                    epoch.sign(members, &epoch.signing_root(slot_in_epoch, parent)),
                ),
                attesting_validators: Vec::new(),
            }],
            secondary: Vec::new(),
            absentees: Vec::new(),
        };
        entries.push(FcrSlotWitness {
            complement,
            head_header: Some(header),
        });
    }

    let witness = FcrBatchWitness {
        accumulator_commitment: epoch.accumulator_commitment,
        acc_root: epoch.acc_root,
        total_active_balance: epoch.total_active_balance,
        committee_root: epoch.committees.root(),
        acc_multi_proof: epoch.tree.build_multi_proof(&[]),
        committee_multi_proof: epoch
            .committees
            .multi_proof(&(0..slots).collect::<Vec<_>>()),
        signing_domain: epoch.signing_domain,
        parent_head_root: PARENT_HEAD,
        parent_head_slot: epoch.slot(0) - 1,
        byzantine_threshold: 25,
        proposer_score_boost: 40,
        current_slot: epoch.slot(0) + slots,
        slots: entries,
    };

    let bytes = bincode::serialize(&witness).expect("serialize");
    std::fs::write(&out, &bytes).expect("write");
    println!("wrote {out}: {} bytes, {slots} slots", bytes.len());
}

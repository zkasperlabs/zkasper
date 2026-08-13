#![cfg_attr(target_os = "zkvm", no_main)]

use zkasper_common::types::SlotProofWitness;
use zkasper_slot_proof_guest::verify_slot_proof;

#[cfg(target_os = "zkvm")]
ziskos::entrypoint!(main);

fn main() {
    let witness: SlotProofWitness =
        bincode::deserialize(&zkasper_guest_io::read_witness()).expect("deserialize witness");

    zkasper_guest_io::commit(verify_slot_proof(&witness).public_bytes());
}

#[path = "../../guest_io.rs"]
mod zkasper_guest_io;

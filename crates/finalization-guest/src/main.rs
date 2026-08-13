#![cfg_attr(target_os = "zkvm", no_main)]

use zkasper_common::types::FinalizationWitness;
use zkasper_finalization_guest::verify_finalization;

#[cfg(target_os = "zkvm")]
ziskos::entrypoint!(main);

fn main() {
    let witness: FinalizationWitness =
        bincode::deserialize(&zkasper_guest_io::read_witness()).expect("deserialize witness");

    zkasper_guest_io::commit(verify_finalization(&witness).public_bytes());
}

#[path = "../../guest_io.rs"]
mod zkasper_guest_io;

#![cfg_attr(target_os = "zkvm", no_main)]

use zkasper_common::types::JustificationWitness;
use zkasper_justification_guest::verify_justification;

#[cfg(target_os = "zkvm")]
ziskos::entrypoint!(main);

fn main() {
    let witness: JustificationWitness =
        bincode::deserialize(&zkasper_guest_io::read_witness()).expect("deserialize witness");

    zkasper_guest_io::commit(verify_justification(&witness).public_bytes());
}

#[path = "../../guest_io.rs"]
mod zkasper_guest_io;

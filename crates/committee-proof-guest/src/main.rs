#![cfg_attr(target_os = "zkvm", no_main)]

use zkasper_common::types::CommitteeWitness;

#[cfg(target_os = "zkvm")]
ziskos::entrypoint!(main);

fn main() {
    let witness: CommitteeWitness =
        bincode::deserialize(&zkasper_guest_io::read_witness()).expect("deserialize witness");

    let output =
        zkasper_common::committee::verify(&witness, zkasper_common::constants::ACC_TREE_DEPTH);
    zkasper_guest_io::commit(output.public_bytes());
}

#[path = "../../guest_io.rs"]
mod zkasper_guest_io;

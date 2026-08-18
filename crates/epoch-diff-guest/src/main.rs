#![cfg_attr(target_os = "zkvm", no_main)]

use zkasper_common::types::EpochDiffWitness;
use zkasper_epoch_diff_guest::verify_epoch_diff;

#[cfg(target_os = "zkvm")]
ziskos::entrypoint!(main);

fn main() {
    let witness: EpochDiffWitness =
        bincode::deserialize(&zkasper_guest_io::read_witness()).expect("deserialize witness");

    zkasper_guest_io::commit(verify_epoch_diff(&witness).public_bytes());
}

#[path = "../../guest_io.rs"]
mod zkasper_guest_io;

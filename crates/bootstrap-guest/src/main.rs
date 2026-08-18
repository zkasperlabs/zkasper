#![cfg_attr(target_os = "zkvm", no_main)]

use zkasper_bootstrap_guest::{public_bytes, verify_bootstrap};
use zkasper_common::types::BootstrapWitness;

#[cfg(target_os = "zkvm")]
ziskos::entrypoint!(main);

fn main() {
    let witness: BootstrapWitness =
        bincode::deserialize(&zkasper_guest_io::read_witness()).expect("deserialize witness");

    let (commitment, acc_root, total_active_balance) = verify_bootstrap(&witness);

    zkasper_guest_io::commit(public_bytes(
        &witness,
        &commitment,
        &acc_root,
        total_active_balance,
    ));
}

#[path = "../../guest_io.rs"]
mod zkasper_guest_io;

#![cfg_attr(target_os = "zkvm", no_main)]

use zkasper_bootstrap_guest::verify_bootstrap;
use zkasper_common::recursion::PublicWriter;
use zkasper_common::types::BootstrapWitness;

#[cfg(target_os = "zkvm")]
ziskos::entrypoint!(main);

fn main() {
    let witness: BootstrapWitness =
        bincode::deserialize(&zkasper_guest_io::read_witness()).expect("deserialize witness");

    let (commitment, acc_root, total_active_balance) = verify_bootstrap(&witness);

    zkasper_guest_io::commit(
        PublicWriter::new()
            .digest(&commitment)
            .digest(&acc_root)
            .u64(total_active_balance)
            .bytes32(&witness.state_root)
            .u64(witness.epoch)
            .finish(),
    );
}

#[path = "../../guest_io.rs"]
mod zkasper_guest_io;

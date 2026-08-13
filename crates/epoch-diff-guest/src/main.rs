#![cfg_attr(target_os = "zkvm", no_main)]

use zkasper_common::recursion::PublicWriter;
use zkasper_common::types::EpochDiffWitness;
use zkasper_epoch_diff_guest::verify_epoch_diff;

#[cfg(target_os = "zkvm")]
ziskos::entrypoint!(main);

fn main() {
    let witness: EpochDiffWitness =
        bincode::deserialize(&zkasper_guest_io::read_witness()).expect("deserialize witness");

    let (commitment, acc_root, total_active_balance) = verify_epoch_diff(&witness);

    zkasper_guest_io::commit(
        PublicWriter::new()
            .digest(&commitment)
            .digest(&acc_root)
            .u64(total_active_balance)
            .bytes32(&witness.state_root_2)
            .u64(witness.epoch_2)
            .finish(),
    );
}

#[path = "../../guest_io.rs"]
mod zkasper_guest_io;

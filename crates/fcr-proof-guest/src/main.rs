//! FCR batch proof: head-vote support over a run of consecutive slots.
//! See [`zkasper_fcr_proof_guest::verify_fcr_batch`].

#![cfg_attr(target_os = "zkvm", no_main)]

use zkasper_fcr_types::FcrBatchWitness;
use zkasper_fcr_proof_guest::verify_fcr_batch;

#[cfg(target_os = "zkvm")]
ziskos::entrypoint!(main);

fn main() {
    let witness: FcrBatchWitness =
        bincode::deserialize(zkasper_guest_io::read_witness()).expect("deserialize witness");

    zkasper_guest_io::commit(verify_fcr_batch(&witness).public_bytes());
}

#[path = "../../guest_io.rs"]
mod zkasper_guest_io;

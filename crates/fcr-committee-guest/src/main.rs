//! FCR committee proof: the epoch's assignment, proven.
//! See [`zkasper_fcr_committee_guest::verify_fcr_committee`].

#![cfg_attr(target_os = "zkvm", no_main)]

use zkasper_fcr_committee_guest::verify_fcr_committee;
use zkasper_fcr_types::FcrCommitteeWitness;

#[cfg(target_os = "zkvm")]
ziskos::entrypoint!(main);

fn main() {
    let witness: FcrCommitteeWitness =
        bincode::deserialize(zkasper_guest_io::read_witness()).expect("deserialize witness");

    zkasper_guest_io::commit(
        verify_fcr_committee(&witness, zkasper_common::constants::SLOTS_PER_EPOCH).public_bytes(),
    );
}

#[path = "../../guest_io.rs"]
mod zkasper_guest_io;

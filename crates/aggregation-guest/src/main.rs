#![cfg_attr(target_os = "zkvm", no_main)]

use zkasper_aggregation_guest::verify_aggregate;
use zkasper_common::types::AggregateWitness;

#[cfg(target_os = "zkvm")]
ziskos::entrypoint!(main);

fn main() {
    let witness: AggregateWitness =
        bincode::deserialize(zkasper_guest_io::read_witness()).expect("deserialize witness");

    zkasper_guest_io::commit(verify_aggregate(&witness).public_bytes());
}

#[path = "../../guest_io.rs"]
mod zkasper_guest_io;

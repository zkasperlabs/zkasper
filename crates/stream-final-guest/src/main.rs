#![cfg_attr(target_os = "zkvm", no_main)]

use zkasper_common::types::StreamFinalWitness;
use zkasper_stream_final_guest::verify_stream_final;

#[cfg(target_os = "zkvm")]
ziskos::entrypoint!(main);

fn main() {
    let witness: StreamFinalWitness =
        bincode::deserialize(&zkasper_guest_io::read_witness()).expect("deserialize witness");

    zkasper_guest_io::commit(verify_stream_final(&witness).public_bytes());
}

#[path = "../../guest_io.rs"]
mod zkasper_guest_io;

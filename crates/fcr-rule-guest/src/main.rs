//! FCR rule proof: one `on_fast_confirmation` transition, the function
//! Lighthouse calls, over the node's store and every validator's vote.
//! See [`zkasper_fcr_rule_guest::run`].

#![cfg_attr(target_os = "zkvm", no_main)]

use zkasper_fcr_rule_guest::{run, Witness};

#[cfg(target_os = "zkvm")]
ziskos::entrypoint!(main);

fn main() {
    let words = zkasper_guest_io::read_words();
    let witness = Witness::decode(words).expect("decode witness");
    zkasper_guest_io::commit(run(&witness).public_bytes());
}

#[path = "../../guest_io.rs"]
mod zkasper_guest_io;

#![cfg_attr(target_os = "zkvm", no_main)]

#[cfg(target_os = "zkvm")]
ziskos::entrypoint!(main);

fn main() {
    let output = zkasper_common::committee::verify(
        zkasper_guest_io::read_words(),
        zkasper_common::constants::ACC_TREE_DEPTH,
    );
    zkasper_guest_io::commit(output.public_bytes());
}

#[path = "../../guest_io.rs"]
mod zkasper_guest_io;

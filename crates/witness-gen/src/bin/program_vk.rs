//! Print the verification key of a guest ELF.
//!
//! This is the one thing `scripts/bake_child_vks.sh` cannot do for itself: a
//! key falls out of a program's ROM Merkle setup, so deriving it costs minutes
//! and gigabytes of `~/.zisk/cache` per ELF and needs the proving key installed.
//! Every ELF named on the command line is set up on one client, because
//! building that client is the 19.52 s a bake pays once rather than per guest.
//!
//! ```text
//! cargo build --release -p zkasper-witness-gen --features zisk-prover \
//!   --bin zkasper-program-vk
//! target/release/zkasper-program-vk target/elf/.../zkasper-slot-proof-guest
//! ```
//!
//! Deliberately not [`zkasper_witness_gen::zisk_prover::ZiskProver`]: that
//! refuses to start when an ELF is not the one the guests were baked against,
//! which is exactly the state a bake runs in.

#[cfg(not(feature = "zisk-prover"))]
fn main() {
    eprintln!("build this with --features zisk-prover");
    std::process::exit(2);
}

#[cfg(feature = "zisk-prover")]
fn main() -> anyhow::Result<()> {
    use anyhow::{anyhow, Context};
    use zisk_sdk::{GuestProgram, ProverClient};

    let elfs: Vec<String> = std::env::args().skip(1).collect();
    if elfs.is_empty() {
        eprintln!("usage: zkasper-program-vk <guest.elf> ...");
        std::process::exit(2);
    }

    let client = ProverClient::embedded()
        .build()
        .map_err(|e| anyhow!("initialise the Zisk prover: {e}"))?;

    for elf in elfs {
        let program = GuestProgram::from_uri(&elf).with_context(|| format!("load {elf}"))?;
        client
            .setup(&program)
            .run_sync()
            .map_err(|e| anyhow!("ROM setup for {elf}: {e}"))?;
        // The default hash mode, Poseidon1, is the family
        // `zisklib::verify_zisk_proof` recurses under; a key from any other
        // would be rejected by every parent proof.
        let vk = program
            .vk()
            .map_err(|e| anyhow!("verification key for {elf}: {e}"))?;
        let words: Vec<String> = vk.vk.iter().map(u64::to_string).collect();
        println!("{elf} {}", words.join(","));
    }
    Ok(())
}

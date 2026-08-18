//! Real Zisk proofs, through the trait the daemon proves with.
//!
//! Ignored by default: these need the 47 GB Zisk proving key and a ROM setup per
//! guest, and a proof is minutes on a GPU or tens of minutes on a CPU. Run them
//! where that is available:
//!
//! ```text
//! ./scripts/build_guests.sh slot-proof-guest group-proof-guest
//! cargo test --release --features zisk-prover --test zisk_proof_tests -- --ignored --nocapture
//! ```
//!
//! What they are for is the two claims the pipeline rests on and that no native
//! run can check: that a proof this prover returns is one
//! [`zkasper_common::recursion::verify_child`] accepts, and that it is only
//! accepted under its own program's key — without which a parent proof would
//! take a proof of any stage for a proof of the stage it wanted.

#![cfg(feature = "zisk-prover")]

mod common;

use std::time::Instant;

use common::stream_fixture;

use zkasper_common::constants::ACC_TREE_DEPTH;
use zkasper_common::recursion::verify_child;
use zkasper_common::ChainConfig;
use zkasper_witness_gen::attestation_collector::SlotComplement;
use zkasper_witness_gen::prover::{Prover, Stage};
use zkasper_witness_gen::streaming;
use zkasper_witness_gen::zisk_prover::{ZiskProver, ZiskProverConfig, DEFAULT_ELF_DIR};

/// A test binary runs from its package directory, not the workspace root, so the
/// ELF directory has to be resolved rather than taken as it stands.
fn elf_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(DEFAULT_ELF_DIR)
}

/// One prover, two programs, two proofs.
///
/// The witness is the same in both: a group proof and a slot proof take the
/// identical [`zkasper_common::types::SlotProofWitness`] and differ only in
/// whether they finish the pairing. That makes it the cleanest possible test of
/// the thing this design depends on — that one initialised prover can serve
/// several guests, so a fleet is sized by concurrency and not by how many
/// programs the pipeline has.
///
/// It prints what each phase cost. The initialisation is the number the
/// streaming design exists to pay once.
#[test]
#[ignore = "needs a Zisk proving key and minutes of proving"]
fn one_warm_prover_serves_two_programs() {
    let fixture = stream_fixture(ACC_TREE_DEPTH);
    let units: Vec<&SlotComplement> = fixture.units[..2].iter().collect();
    let witness = streaming::group_witness(
        &fixture.context,
        &fixture.epoch.tree,
        &fixture.epoch.committees,
        &units,
    );

    let started = Instant::now();
    let prover = ZiskProver::new(ZiskProverConfig {
        elf_dir: elf_dir(),
        // So the same test measures the GPU on a box that has one, without a
        // code change: `ZKASPER_GPU=1 cargo test ...`.
        gpu: std::env::var_os("ZKASPER_GPU").is_some(),
        ..ZiskProverConfig::new(ChainConfig::MAINNET, &[Stage::Group, Stage::SlotProof])
    })
    .expect("build a prover; is the proving key installed and are the guests built?");
    println!("init + setup: {:?}", started.elapsed());

    let group_vk = prover.program_vk(Stage::Group);
    let slot_vk = prover.program_vk(Stage::SlotProof);
    assert_ne!(
        group_vk, slot_vk,
        "two guests must not share a verification key, or one could stand in for the other",
    );

    let started = Instant::now();
    let (group, _miller, group_proof) = prover.prove_group(&witness).expect("group proof");
    println!(
        "group proof: {:?}, {:?}",
        started.elapsed(),
        prover.last_cost()
    );

    // Second program on the same prover. Whatever this costs beyond the proof
    // itself is what switching guests costs.
    let started = Instant::now();
    let (slot, slot_proof) = prover.prove_slot(&witness).expect("slot proof");
    println!(
        "slot proof: {:?}, {:?}",
        started.elapsed(),
        prover.last_cost()
    );

    assert_eq!(group.attesting_balance, slot.attesting_balance);

    // Each proof is accepted under its own program's key and its own outputs...
    assert!(verify_child(&group_proof, &group_vk, &group.public_bytes()));
    assert!(verify_child(&slot_proof, &slot_vk, &slot.public_bytes()));

    // ...and under nothing else. A parent that binds the key it expects cannot
    // be handed a proof of the other guest, or of different outputs.
    assert!(!verify_child(&group_proof, &slot_vk, &group.public_bytes()));
    assert!(!verify_child(&slot_proof, &group_vk, &slot.public_bytes()));
    assert!(!verify_child(&group_proof, &group_vk, &slot.public_bytes()));
}

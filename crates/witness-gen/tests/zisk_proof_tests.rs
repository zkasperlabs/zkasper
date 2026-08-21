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
//!
//! The second of those is checked twice: once on the key directly, and once in
//! the child position of a real parent circuit, which is where it has to hold.

#![cfg(feature = "zisk-prover")]

mod common;

use std::time::Instant;

use common::stream_fixture;

use zkasper_common::constants::ACC_TREE_DEPTH;
use zkasper_common::recursion::verify_child;
use zkasper_common::types::SlotProofWitness;
use zkasper_common::ChainConfig;
use zkasper_witness_gen::attestation_collector::SlotComplement;
use zkasper_witness_gen::child_vks;
use zkasper_witness_gen::prover::{Prover, Stage, DEFAULT_ELF_DIR};
use zkasper_witness_gen::streaming;
use zkasper_witness_gen::zisk_prover::{ZiskProver, ZiskProverConfig};

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

    // The key a parent binds is a constant it was compiled with, so the ELF the
    // prover loaded has to be the program the guests were baked against. This
    // is the same comparison `ZiskProver::new` makes; asserting it here says
    // which guest is out of date rather than which stage failed to set up.
    assert_eq!(
        slot_vk,
        child_vks::SLOT,
        "the slot-proof ELF is not the one the justification guest was baked against; \
         run scripts/bake_child_vks.sh",
    );
    assert_eq!(group_vk, child_vks::GROUP);
}

/// A real proof of the wrong program, in the child position of a real parent.
///
/// The test above is about the predicate; this is about the circuit that
/// applies it. `justification-guest` verifies its slot children against a key it
/// was compiled with, so a group proof — an honest proof of a real program, with
/// a real prover behind it — cannot stand in for a slot proof however the
/// witness is arranged. There is no longer a field to arrange: the key the fold
/// binds is not in the witness at all.
///
/// ```text
/// ./scripts/bake_child_vks.sh
/// ZKASPER_GPU=1 cargo test --release --features zisk-prover \
///   --test zisk_proof_tests -- --ignored --nocapture a_child_proof
/// ```
#[test]
#[ignore = "needs a Zisk proving key and minutes of proving"]
fn a_child_proof_from_another_program_is_refused() {
    let chain = ChainConfig::MAINNET;
    let epoch = zkasper_witness_gen::fixture::Epoch::new(chain.clone(), 100, 1, 2);
    let prover = ZiskProver::new(ZiskProverConfig {
        elf_dir: elf_dir(),
        gpu: std::env::var_os("ZKASPER_GPU").is_some(),
        ..ZiskProverConfig::new(
            chain.clone(),
            &[Stage::Committee, Stage::SlotProof, Stage::Group],
        )
    })
    .expect("build a prover");

    let complement = epoch.complement(0, &[]);
    let witness = SlotProofWitness {
        accumulator_commitment: epoch.accumulator_commitment,
        committee_root: epoch.committees.root(),
        source_epoch: epoch.epoch - 1,
        source_root: epoch.source_root,
        target_epoch: epoch.epoch,
        target_root: epoch.target_root,
        signing_domain: epoch.signing_domain,
        acc_root: epoch.acc_root,
        total_active_balance: epoch.total_active_balance,
        acc_multi_proof: epoch.tree.build_multi_proof(&complement.named_indices),
        committee_multi_proof: epoch.committees.multi_proof(&[0]),
        slots: vec![complement.witness],
    };

    let (committee_output, committee_proof) = prover
        .prove_committee(&epoch.committees.witness)
        .expect("committee proof");
    let (slot, slot_proof) = prover.prove_slot(&witness).expect("slot proof");
    let (_group, _miller, group_proof) = prover.prove_group(&witness).expect("group proof");

    let context = zkasper_witness_gen::witness_justification::Context {
        accumulator_commitment: epoch.accumulator_commitment,
        acc_root: epoch.acc_root,
        target_epoch: epoch.epoch,
        target_root: epoch.target_root,
        source_root: epoch.source_root,
        total_active_balance: epoch.total_active_balance,
        justification_program_vk: prover.program_vk(Stage::Justification),
    };
    let link = |proof: Vec<u64>| {
        zkasper_witness_gen::witness_justification::build(
            &context,
            Some(committee_output.clone()),
            committee_proof.clone(),
            None,
            Vec::new(),
            vec![slot.clone()],
            vec![proof],
        )
    };

    // The real slot proof folds.
    zkasper_justification_guest::verify_justification(&link(slot_proof));

    // The group proof does not, and the fold has no way to be told otherwise.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let refused = std::panic::catch_unwind(|| {
        zkasper_justification_guest::verify_justification(&link(group_proof));
    })
    .is_err();
    std::panic::set_hook(previous);
    assert!(
        refused,
        "a proof of the group program was folded as a slot proof",
    );
}

/// Per-stage cost, warm, with repeats.
///
/// `BENCHMARKS.md` quotes the stage floor at 3.640 s, the group proof at
/// 4.188 s, the slot proof at 4.506 s and the wrap at 48 ms, from `cargo-zisk`
/// invocations. This measures the same three stages from one warm in-process
/// prover, which is what the daemon actually pays, and prints every repeat so
/// the spread is visible rather than averaged away.
///
/// The stage floor is the committee proof over 64 members, which is what the
/// published figure is: 32 slots of 2.
#[test]
#[ignore = "needs a Zisk proving key and minutes of proving"]
fn warm_stage_times() {
    let repeats: usize = std::env::var("ZKASPER_REPEATS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);

    let chain = ChainConfig::MAINNET;
    let fixture = stream_fixture(ACC_TREE_DEPTH);
    let units: Vec<&SlotComplement> = fixture.units[..2].iter().collect();
    let group = streaming::group_witness(
        &fixture.context,
        &fixture.epoch.tree,
        &fixture.epoch.committees,
        &units,
    );
    let slots = chain.slots_per_epoch;
    let floor = zkasper_witness_gen::fixture::Epoch::new(chain.clone(), 100, slots, 2);

    let started = Instant::now();
    let prover = ZiskProver::new(ZiskProverConfig {
        elf_dir: elf_dir(),
        gpu: std::env::var_os("ZKASPER_GPU").is_some(),
        ..ZiskProverConfig::new(chain, &[Stage::Committee, Stage::Group, Stage::SlotProof])
    })
    .expect("build a prover");
    println!("COLD init + setup: {:?}", started.elapsed());

    // Nothing after the first proof pays initialisation. `gap_millis` is what
    // the call cost outside the prover's own accounting — the native circuit
    // run and the serialization — and it is the number a warm prover keeps
    // small.
    for run in 0..repeats {
        for stage in [Stage::Committee, Stage::Group, Stage::SlotProof] {
            let started = Instant::now();
            match stage {
                Stage::Committee => {
                    prover
                        .prove_committee(&floor.committees.witness)
                        .expect("committee proof");
                }
                Stage::Group => {
                    prover.prove_group(&group).expect("group proof");
                }
                _ => {
                    prover.prove_slot(&group).expect("slot proof");
                }
            }
            let cost = prover.last_cost().expect("a cost");
            let elapsed = started.elapsed().as_millis() as u64;
            println!(
                "WARM run={run} stage={} prove_millis={} wrap_millis={} \
                 call_millis={elapsed} gap_millis={}",
                stage.as_str(),
                cost.prove_millis,
                cost.wrap_millis,
                elapsed.saturating_sub(cost.prove_millis + cost.wrap_millis),
            );
        }
    }
}

/// What a recursive child verification costs, as a curve in child count.
///
/// [`zkasper_witness_gen::streaming::ProverModel::recursion_verify_s`] was a
/// zero for as long as nothing could measure it: the fixtures carry stub child
/// proofs, a guest rejects an empty proof, and the two stages that recurse could
/// therefore only be proved with the recursion removed. This sweep is the
/// measurement, and it uses the real circuit — one justification link per point,
/// over `k` real slot proofs and one real committee proof, so `k + 1` children.
///
/// **Read the shape, not one point.** A large fixed cost with a cheap per-child
/// term and a genuinely linear cost want different pipelines, and only a sweep
/// tells them apart.
///
/// ```text
/// ./scripts/build_guests.sh committee-proof-guest slot-proof-guest justification-guest
/// ZKASPER_GPU=1 cargo test --release --features zisk-prover \
///   --test zisk_proof_tests -- --ignored --nocapture recursion_cost_curve
/// ```
#[test]
#[ignore = "needs a Zisk proving key and an hour of proving"]
fn recursion_cost_curve() {
    let children: Vec<usize> = std::env::var("ZKASPER_CHILDREN")
        .unwrap_or_else(|_| "1,2,3,4,6,8,11,16,22".into())
        .split(',')
        .map(|v| v.trim().parse().expect("a child count"))
        .collect();
    let slots = *children.iter().max().expect("at least one point") as u64;

    let chain = ChainConfig::MAINNET;
    let prover = ZiskProver::new(ZiskProverConfig {
        elf_dir: elf_dir(),
        gpu: std::env::var_os("ZKASPER_GPU").is_some(),
        ..ZiskProverConfig::new(
            chain.clone(),
            &[Stage::Committee, Stage::SlotProof, Stage::Justification],
        )
    })
    .expect("build a prover");

    // One synthetic epoch, `slots` committees of two. The committee proof and
    // every slot proof below are real proofs of it, because a recursion has
    // nothing to verify otherwise.
    let epoch = zkasper_witness_gen::fixture::Epoch::new(chain, 100, slots, 2);
    let (committee_output, committee_proof) = prover
        .prove_committee(&epoch.committees.witness)
        .expect("committee proof");
    println!(
        "committee proof over {} members: {:?}",
        epoch.committees.witness.members.len(),
        prover.last_cost(),
    );

    let mut slot_outputs = Vec::new();
    let mut slot_proofs = Vec::new();
    for slot in 0..slots {
        let complement = epoch.complement(slot, &[]);
        let (output, proof) = prover
            .prove_slot(&SlotProofWitness {
                accumulator_commitment: epoch.accumulator_commitment,
                committee_root: epoch.committees.root(),
                source_epoch: epoch.epoch - 1,
                source_root: epoch.source_root,
                target_epoch: epoch.epoch,
                target_root: epoch.target_root,
                signing_domain: epoch.signing_domain,
                acc_root: epoch.acc_root,
                total_active_balance: epoch.total_active_balance,
                acc_multi_proof: epoch.tree.build_multi_proof(&complement.named_indices),
                committee_multi_proof: epoch.committees.multi_proof(&[slot]),
                slots: vec![complement.witness],
            })
            .expect("slot proof");
        println!("SLOT slot={slot} {:?}", prover.last_cost());
        slot_outputs.push(output);
        slot_proofs.push(proof);
    }

    let context = zkasper_witness_gen::witness_justification::Context {
        accumulator_commitment: epoch.accumulator_commitment,
        acc_root: epoch.acc_root,
        target_epoch: epoch.epoch,
        target_root: epoch.target_root,
        source_root: epoch.source_root,
        total_active_balance: epoch.total_active_balance,
        justification_program_vk: prover.program_vk(Stage::Justification),
    };

    // The link that opens an epoch, at every width in the sweep: `k` slot
    // proofs and the committee proof.
    let mut points: Vec<(f64, f64)> = Vec::new();
    for &k in &children {
        prover
            .prove_justification(&zkasper_witness_gen::witness_justification::build(
                &context,
                Some(committee_output.clone()),
                committee_proof.clone(),
                None,
                Vec::new(),
                slot_outputs[..k].to_vec(),
                slot_proofs[..k].to_vec(),
            ))
            .expect("opening link");
        let cost = prover.last_cost().expect("a cost");
        println!(
            "OPENING children={} slots={k} prove_millis={} wrap_millis={}",
            k + 1,
            cost.prove_millis,
            cost.wrap_millis,
        );
        points.push(((k + 1) as f64, cost.prove_millis as f64 / 1000.0));
    }

    // The link the daemon runs after the epoch opens: one predecessor and
    // `width` slot proofs. Same child count, different children, which is what
    // says the curve is about recursion rather than about slots.
    let (opening, opening_proof) = prover
        .prove_justification(&zkasper_witness_gen::witness_justification::build(
            &context,
            Some(committee_output),
            committee_proof,
            None,
            Vec::new(),
            slot_outputs[..1].to_vec(),
            slot_proofs[..1].to_vec(),
        ))
        .expect("the link to extend");

    for width in [1usize, 2, 4] {
        if 1 + width > slot_outputs.len() {
            continue;
        }
        prover
            .prove_justification(&zkasper_witness_gen::witness_justification::build(
                &context,
                None,
                Vec::new(),
                Some(opening.clone()),
                opening_proof.clone(),
                slot_outputs[1..1 + width].to_vec(),
                slot_proofs[1..1 + width].to_vec(),
            ))
            .expect("extending link");
        println!(
            "EXTENDING children={} prove_millis={}",
            width + 1,
            prover.last_cost().expect("a cost").prove_millis,
        );
    }

    // Least squares over the sweep, so the report is a line and not a guess.
    let n = points.len() as f64;
    let sx: f64 = points.iter().map(|p| p.0).sum();
    let sy: f64 = points.iter().map(|p| p.1).sum();
    let sxx: f64 = points.iter().map(|p| p.0 * p.0).sum();
    let sxy: f64 = points.iter().map(|p| p.0 * p.1).sum();
    let slope = (n * sxy - sx * sy) / (n * sxx - sx * sx);
    println!(
        "OLS {:.3} s + {slope:.3} s per child",
        (sy - slope * sx) / n
    );
}

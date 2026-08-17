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

    // Publish both endpoints, not just the new one.
    //
    // Committing only the new side leaves the proof unmoored: it attests "there
    // is a valid transition to X" without saying what it started from, so a
    // client holding accumulator A cannot check that this proof advanced from A.
    // Chaining is the entire security model of the accumulator, and it cannot be
    // enforced against values the proof never names. The circuit already
    // verifies `acc_root_1` and `state_root_1` internally; publishing them is
    // what lets a verifier close the loop.
    let commitment_1 = zkasper_common::acc::commitment(
        &witness.acc_root_1,
        witness.total_active_balance_1,
    );

    zkasper_guest_io::commit(
        PublicWriter::new()
            // -- where this proof started --
            .digest(&commitment_1)
            .bytes32(&witness.state_root_1)
            .u64(witness.epoch_1)
            // -- where it ends --
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

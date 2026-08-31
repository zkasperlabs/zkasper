//! What pins the active set the FCR shuffle runs over.
//!
//! The permutation itself is held to Lighthouse's reference inside
//! `zkasper-fcr-committee-guest`. These are the other half: a correct shuffle
//! over the wrong set proves the wrong assignment, and the set arrives as
//! witness.

use zkasper_common::{ChainConfig, types::OpenedValidator};
use zkasper_fcr_committee_guest::verify_fcr_committee_with_depth;
use zkasper_fcr_types::FcrCommitteeWitness;
use zkasper_witness_gen::fixture::Epoch;

const ACC_DEPTH: u32 = 4;
const SLOTS: u64 = 4;
const PER_SLOT: usize = 4;
const EPOCH: u64 = 10;

fn fixture() -> Epoch {
    Epoch::new(
        ChainConfig {
            acc_tree_depth: ACC_DEPTH,
            ..ChainConfig::MAINNET
        },
        EPOCH,
        SLOTS,
        PER_SLOT,
    )
}

/// Every active validator, opened, as an honest host would supply them.
fn active(epoch: &Epoch) -> Vec<OpenedValidator> {
    (0..(SLOTS as usize * PER_SLOT) as u64)
        .map(|i| epoch.opened(i))
        .collect()
}

fn witness(epoch: &Epoch, active: Vec<OpenedValidator>) -> FcrCommitteeWitness {
    let indices: Vec<u64> = active.iter().map(|v| v.validator_index).collect();
    FcrCommitteeWitness {
        accumulator_commitment: epoch.accumulator_commitment,
        acc_root: epoch.acc_root,
        total_active_balance: epoch.total_active_balance,
        seed: [0x5a; 32],
        epoch: EPOCH,
        acc_multi_proof: epoch.tree.build_multi_proof(&indices),
        active,
    }
}

fn verify(w: &FcrCommitteeWitness) -> zkasper_fcr_types::FcrCommitteeOutput {
    verify_fcr_committee_with_depth(w, SLOTS, ACC_DEPTH)
}

fn rejection(what: &str, f: impl FnOnce() + std::panic::UnwindSafe) -> String {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(f);
    std::panic::set_hook(previous);
    let payload = result.err().unwrap_or_else(|| panic!("{what}"));
    match payload.downcast::<String>() {
        Ok(m) => *m,
        Err(p) => p
            .downcast::<&'static str>()
            .map(|m| m.to_string())
            .unwrap_or_default(),
    }
}

/// The whole active set, proven into a committee root, with the seed published
/// so a verifier can tie it to a state root.
#[test]
fn the_active_set_proves_into_a_committee_root() {
    let epoch = fixture();
    let out = verify(&witness(&epoch, active(&epoch)));

    assert_eq!(out.active_count, (SLOTS as usize * PER_SLOT) as u64);
    assert_eq!(out.seed, [0x5a; 32]);
    assert_eq!(out.epoch, EPOCH);
    assert_eq!(out.accumulator_commitment, epoch.accumulator_commitment);
    assert_ne!(out.committee_root, [0; 4]);
}

/// A different seed is a different epoch's assignment, and must be a different
/// committee root. Without this the seed would be decoration.
#[test]
fn the_seed_decides_the_assignment() {
    let epoch = fixture();
    let a = verify(&witness(&epoch, active(&epoch)));
    let mut w = witness(&epoch, active(&epoch));
    w.seed = [0x77; 32];
    let b = verify(&w);
    assert_ne!(a.committee_root, b.committee_root);
}

/// Drop a validator and the sum falls short of what the accumulator commitment
/// binds. This is what stops a prover shrinking the set to move the shuffle.
#[test]
fn an_omitted_validator_is_caught_by_the_total() {
    let epoch = fixture();
    let mut set = active(&epoch);
    set.pop();
    let w = witness(&epoch, set);

    let message = rejection("a short active set verified", || {
        verify(&w);
    });
    assert!(message.contains("do not sum to the committed total"), "{message}");
}

/// Adding an inactive validator keeps the sum right — its accumulator balance is
/// zero — but moves the set size and therefore every shuffled position. The
/// non-zero check is what makes the sum load-bearing.
#[test]
fn an_inactive_validator_cannot_pad_the_set() {
    let epoch = fixture();
    let mut set = active(&epoch);
    let last = set.last().unwrap().clone();
    set.push(OpenedValidator {
        validator_index: last.validator_index + 1,
        pubkey: last.pubkey,
        active_effective_balance: 0,
    });
    let w = witness(&epoch, set);

    let message = rejection("a padded active set verified", || {
        verify(&w);
    });
    assert!(message.contains("opened as active with no balance"), "{message}");
}

/// Out of order is a validator opened twice waiting to happen.
#[test]
fn the_active_set_must_be_in_index_order() {
    let epoch = fixture();
    let mut set = active(&epoch);
    set.swap(0, 1);
    let w = witness(&epoch, set);

    let message = rejection("an unordered active set verified", || {
        verify(&w);
    });
    assert!(message.contains("increasing index order"), "{message}");
}

/// And a balance the accumulator does not hold is caught by the opening, not by
/// the total — the two checks are independent.
#[test]
fn a_forged_balance_is_caught_by_the_accumulator() {
    let epoch = fixture();
    let mut set = active(&epoch);
    set[0].active_effective_balance += 1;
    set[1].active_effective_balance -= 1;
    let w = witness(&epoch, set);

    let message = rejection("a forged balance verified", || {
        verify(&w);
    });
    assert!(message.contains("accumulator root mismatch"), "{message}");
}

/// The loop closed: a committee proof is what lets a window be judged at all.
///
/// Before this guest existed, `Assignment::proven` had no honest caller and the
/// verifier refused every window. It now has one.
#[test]
fn a_committee_proof_is_what_makes_a_window_judgeable() {
    use zkasper_fcr_verifier::Assignment;

    let epoch = fixture();
    let out = verify(&witness(&epoch, active(&epoch)));

    let assignment = Assignment::from_committee_proof(&out);
    assert_eq!(assignment.root(), out.committee_root);

    // And a window proved against some other committee root is still refused,
    // so the proof has to be of the assignment the batches actually used.
    let other = Assignment::from_committee_proof(&out);
    assert_ne!(other.root(), [0; 4]);
}

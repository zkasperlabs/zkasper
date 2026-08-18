//! What complement proving rests on, with real BLS signatures.
//!
//! A slot proof no longer names the validators whose balance it counts; it names
//! the ones it does *not*. Two separate things have to hold for that to be safe,
//! and they hold for different reasons, so they are tested apart:
//!
//! - **The absentee set is pinned by the signature.** The derived aggregate key
//!   is the committee minus whoever the witness names, and the pairing only
//!   closes if that is exactly the set that signed. Omitting an absentee, naming
//!   an attester, or naming a stranger all break it.
//! - **The balances are pinned by the accumulator leaf**, which hashes a public
//!   key and a balance together. Nothing about a signature constrains a balance,
//!   so a committee aggregate whose balance drifts from the keys it was summed
//!   from is the one break that the pairing would never catch — and the leaf is
//!   what stops it.

use zkasper_common::types::*;
use zkasper_common::{committee, ChainConfig};
use zkasper_witness_gen::attestation_collector::SlotStream;
use zkasper_witness_gen::beacon_api::AttestationResponse;
use zkasper_witness_gen::fixture::Epoch;

const ACC_DEPTH: u32 = 4;
const SLOTS: u64 = 4;
const PER_SLOT: usize = 4;
const BALANCE_GWEI: u64 = 32_000_000_000;
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

/// A slot-proof witness over `slots`, with both openings rebuilt from what the
/// complements actually name — so a test can edit a complement and still get a
/// witness an honest host would have produced.
fn witness_for(epoch: &Epoch, slots: &[SlotComplementWitness]) -> SlotProofWitness {
    let mut named: Vec<u64> = slots
        .iter()
        .flat_map(|slot| {
            slot.absentees.iter().map(|v| v.validator_index).chain(
                slot.secondary
                    .iter()
                    .flat_map(|a| a.attesting_validators.iter().map(|v| v.validator_index)),
            )
        })
        .collect();
    named.sort_unstable();

    SlotProofWitness {
        accumulator_commitment: epoch.accumulator_commitment,
        committee_root: epoch.committees.root(),
        target_epoch: epoch.epoch,
        target_root: epoch.target_root,
        signing_domain: epoch.signing_domain,
        acc_root: epoch.acc_root,
        total_active_balance: epoch.total_active_balance,
        acc_multi_proof: epoch.tree.build_multi_proof(&named),
        committee_multi_proof: epoch
            .committees
            .multi_proof(&slots.iter().map(|s| s.slot_in_epoch).collect::<Vec<_>>()),
        slots: slots.to_vec(),
    }
}

fn verify(witness: &SlotProofWitness) -> SlotProofOutput {
    zkasper_slot_proof_guest::verify_slot_proof_with_depth(witness, ACC_DEPTH)
}

/// Run `f` and return the message it panicked with.
fn rejection(what: &str, f: impl FnOnce() + std::panic::UnwindSafe) -> String {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(f);
    std::panic::set_hook(previous);

    let payload = result.err().unwrap_or_else(|| panic!("{what}"));
    match payload.downcast::<String>() {
        Ok(message) => *message,
        Err(payload) => payload
            .downcast::<&'static str>()
            .map(|m| m.to_string())
            .unwrap_or_default(),
    }
}

// ---------------------------------------------------------------------------
// The happy path, and what it costs
// ---------------------------------------------------------------------------

/// A whole committee attests: nothing is named, nothing is opened, and the
/// support is the committee's balance.
#[test]
fn a_full_committee_opens_no_leaves_at_all() {
    let epoch = fixture();
    let witness = witness_for(&epoch, &[epoch.complement(0, &[]).witness]);

    assert!(witness.acc_multi_proof.auxiliaries.is_empty());
    assert_eq!(
        verify(&witness).attesting_balance,
        PER_SLOT as u64 * BALANCE_GWEI,
    );
}

/// One absentee: one leaf opened, and the support is the committee minus that
/// validator. This is the whole scheme in one assertion — 1 opening where the
/// old design would have made 3.
#[test]
fn one_absentee_costs_one_opening() {
    let epoch = fixture();
    let witness = witness_for(&epoch, &[epoch.complement(0, &[2]).witness]);

    assert_eq!(witness.slots[0].absentees.len(), 1);
    assert_eq!(
        verify(&witness).attesting_balance,
        (PER_SLOT as u64 - 1) * BALANCE_GWEI,
    );
}

/// A minority that voted for a different head still counts, but pays for itself:
/// its signers are named, opened and paired separately.
#[test]
fn a_minority_head_vote_is_counted_and_enumerated() {
    let epoch = fixture();
    let witness = witness_for(
        &epoch,
        &[epoch.complement_with_minority(0, &[], &[1]).witness],
    );

    assert_eq!(witness.slots[0].secondary.len(), 1);
    assert_eq!(
        verify(&witness).attesting_balance,
        PER_SLOT as u64 * BALANCE_GWEI,
        "a different head vote is still a vote for the target",
    );
}

/// Several slots in one proof, and the mask says which.
#[test]
fn a_group_publishes_the_slots_it_counted() {
    let epoch = fixture();
    let output = verify(&witness_for(
        &epoch,
        &[
            epoch.complement(0, &[]).witness,
            epoch.complement(2, &[]).witness,
        ],
    ));

    assert_eq!(output.slots_mask, 0b101);
    assert_eq!(output.attesting_balance, 2 * PER_SLOT as u64 * BALANCE_GWEI);
}

// ---------------------------------------------------------------------------
// The public key side: pinned by the signature
// ---------------------------------------------------------------------------

/// The headline claim. Validator 2 did not sign, and a prover who hides that
/// leaves the derived key one public key too large.
#[test]
fn omitting_a_genuine_absentee_fails_the_pairing() {
    let epoch = fixture();
    let mut complement = epoch.complement(0, &[2]).witness;
    complement.absentees.clear();

    let message = rejection("an omitted absentee was accepted", move || {
        verify(&witness_for(&fixture(), &[complement]));
    });
    assert!(
        message.contains("BLS aggregate signature verification failed"),
        "unexpected failure: {message}",
    );
}

/// The other direction: naming someone who did attest leaves the derived key one
/// public key too small.
#[test]
fn naming_an_attester_as_absent_fails_the_pairing() {
    let epoch = fixture();
    let mut complement = epoch.complement(0, &[]).witness;
    complement.absentees.push(epoch.opened(1));

    let message = rejection("a fabricated absentee was accepted", move || {
        verify(&witness_for(&fixture(), &[complement]));
    });
    assert!(
        message.contains("BLS aggregate signature verification failed"),
        "unexpected failure: {message}",
    );
}

/// And a validator from another slot's committee: their leaf opens perfectly
/// well, which is exactly why the accumulator alone could never catch this. The
/// derived key is simply not a subset sum of the committee any more.
#[test]
fn naming_a_validator_from_another_committee_fails_the_pairing() {
    let epoch = fixture();
    let mut complement = epoch.complement(0, &[]).witness;
    complement.absentees.push(epoch.opened(PER_SLOT as u64));

    let message = rejection("a stranger was accepted as an absentee", move || {
        verify(&witness_for(&fixture(), &[complement]));
    });
    assert!(
        message.contains("BLS aggregate signature verification failed"),
        "unexpected failure: {message}",
    );
}

/// Naming the same absentee twice would subtract them twice. Sorting the named
/// set and requiring it to be strictly increasing is what stops it.
#[test]
fn naming_a_validator_twice_is_rejected() {
    let epoch = fixture();
    let mut complement = epoch.complement(0, &[2]).witness;
    complement.absentees.push(epoch.opened(2));

    let message = rejection("a doubled absentee was accepted", move || {
        verify(&witness_for(&fixture(), &[complement]));
    });
    assert!(
        message.contains("named twice"),
        "unexpected failure: {message}",
    );
}

/// A committee lifted from another slot: the pairing would fail, but the
/// committee opening fails first, which is what keeps a slot's mask bit tied to
/// the bucket it counted.
#[test]
fn a_committee_cannot_be_moved_to_another_slot() {
    let epoch = fixture();
    let mut complement = epoch.complement(0, &[]).witness;
    complement.committee = epoch.committees.aggregate(1).unwrap().clone();

    let message = rejection("a committee was used at the wrong slot", move || {
        verify(&witness_for(&fixture(), &[complement]));
    });
    assert!(
        message.contains("committee root mismatch"),
        "unexpected failure: {message}",
    );
}

// ---------------------------------------------------------------------------
// The balance side: pinned by the accumulator leaf
// ---------------------------------------------------------------------------

/// The one break the signature would never catch. `support` comes out of
/// `committee.balance`, and nothing in a pairing constrains it — so a prover who
/// could raise it alone could set any finality threshold they liked.
///
/// What stops it is that the balance is not a value the witness carries beside
/// the key: it is hashed *with* the key into the committee leaf, and that leaf
/// is opened against the root the committee proof published.
#[test]
fn an_inflated_committee_balance_fails_the_committee_opening() {
    let epoch = fixture();
    let mut complement = epoch.complement(0, &[]).witness;
    complement.committee.balance += 1_000_000_000;

    let message = rejection("an inflated committee balance was accepted", move || {
        verify(&witness_for(&fixture(), &[complement]));
    });
    assert!(
        message.contains("committee root mismatch"),
        "unexpected failure: {message}",
    );
}

/// The same break one level up, where the committee's totals are made. A
/// committee proof that claims a validator is worth more than its leaf says is
/// claiming a leaf the accumulator does not hold.
#[test]
fn the_committee_proof_cannot_inflate_a_member_balance() {
    let epoch = fixture();
    let mut witness = epoch.committees.witness.clone();
    witness.members[0].active_effective_balance += 1_000_000_000;

    let message = rejection("an inflated member balance was accepted", move || {
        committee::verify(&committee::encode(&witness), ACC_DEPTH);
    });
    assert!(
        message.contains("accumulator root mismatch"),
        "unexpected failure: {message}",
    );
}

/// And the two totals cannot be moved apart, because they are summed from the
/// same leaf in the same pass: a balance that changes changes the leaf, and a
/// leaf that changes changes the root.
#[test]
fn a_committee_leaf_binds_its_balance_to_its_key() {
    let epoch = fixture();
    let honest = epoch.committees.aggregate(0).unwrap().clone();
    assert_ne!(
        committee::leaf(&honest),
        committee::leaf(&CommitteeAggregate {
            balance: honest.balance + 1,
            ..honest
        }),
    );
}

/// Balances that subtract to below zero are rejected rather than wrapped. The
/// pairing already makes this unreachable, but an unchecked subtraction here
/// would turn an arithmetic slip into an enormous attesting balance.
#[test]
fn absentee_balances_cannot_exceed_the_committee() {
    let epoch = fixture();
    let mut complement = epoch.complement(0, &[]).witness;
    // More balance than slot 0's committee holds, named from other committees so
    // that the balance guard is what rejects it rather than the key sum.
    for index in PER_SLOT as u64..2 * PER_SLOT as u64 + 1 {
        complement.absentees.push(epoch.opened(index));
    }

    let message = rejection("a negative support was accepted", move || {
        verify(&witness_for(&fixture(), &[complement]));
    });
    assert!(
        message.contains("absentee balances exceed the committee"),
        "unexpected failure: {message}",
    );
}

// ---------------------------------------------------------------------------
// Disjointness: what the slot mask is allowed to stand in for
// ---------------------------------------------------------------------------

/// The committee proof reads each validator once, in increasing index order, so
/// no validator can be put in two slots — which is the whole reason a 32-bit
/// mask can deduplicate a million validators.
#[test]
fn the_committee_proof_reads_each_validator_once() {
    let epoch = fixture();
    let mut witness = epoch.committees.witness.clone();
    let duplicate = witness.members[0].clone();
    witness.members.insert(1, duplicate);

    let message = rejection("a validator was assigned to two slots", move || {
        committee::verify(&committee::encode(&witness), ACC_DEPTH);
    });
    assert!(
        message.contains("strictly increasing"),
        "unexpected failure: {message}",
    );
}

/// A slot named twice in one proof would count its committee twice.
#[test]
fn a_slot_cannot_appear_twice_in_one_proof() {
    let epoch = fixture();
    let complement = epoch.complement(0, &[]).witness;

    let message = rejection("a slot was counted twice in one proof", move || {
        let epoch = fixture();
        verify(&witness_for(&epoch, &[complement.clone(), complement]));
    });
    assert!(
        message.contains("strictly increasing"),
        "unexpected failure: {message}",
    );
}

/// One block's aggregate, as the node would report it.
fn aggregate(
    epoch: &Epoch,
    slot_in_epoch: u64,
    head: [u8; 32],
    signers: &[u64],
) -> AttestationResponse {
    let members = &epoch.committees.members[slot_in_epoch as usize];
    let mut aggregation_bits = vec![0u8; members.len().div_ceil(8)];
    for &index in signers {
        let bit = members
            .iter()
            .position(|&m| m == index)
            .expect("committee member");
        aggregation_bits[bit / 8] |= 1 << (bit % 8);
    }
    AttestationResponse {
        aggregation_bits,
        committee_bits: Vec::new(),
        data_slot: epoch.slot(slot_in_epoch),
        data_index: 0,
        data_beacon_block_root: head,
        data_source_epoch: epoch.epoch - 1,
        data_source_root: epoch.source_root,
        data_target_epoch: epoch.epoch,
        data_target_root: epoch.target_root,
        signature: epoch.sign(signers, &epoch.signing_root(slot_in_epoch, head)),
        single_attester: None,
    }
}

/// Two aggregates over one minority message, with disjoint signers.
///
/// The guest folds aggregates that share a signing root by *adding* their keys,
/// so each has to carry its own signers. A collector that gave both the whole
/// message's signer set would subtract those validators twice.
#[test]
fn two_aggregates_over_one_message_each_name_their_own_signers() {
    // Eight to a committee, so that the majority head stays the majority even
    // once the minority is split across two aggregates.
    let epoch = Epoch::new(
        ChainConfig {
            acc_tree_depth: ACC_DEPTH,
            ..ChainConfig::MAINNET
        },
        EPOCH,
        SLOTS,
        8,
    );
    let head = [0x33u8; 32];

    let mut stream = SlotStream::new(
        &epoch.config,
        epoch.committees.clone(),
        epoch.epoch,
        epoch.target_root,
    );
    stream
        .ingest(&[
            aggregate(&epoch, 0, [0u8; 32], &[0, 1, 2, 3, 4, 5]),
            aggregate(&epoch, 0, head, &[6]),
            aggregate(&epoch, 0, head, &[7]),
        ])
        .unwrap();

    let complement = stream.close(epoch.slot(0)).expect("close the slot");
    assert_eq!(
        complement
            .witness
            .secondary
            .iter()
            .map(|a| a.attesting_validators.len())
            .collect::<Vec<_>>(),
        vec![1, 1],
    );
    assert_eq!(
        verify(&witness_for(&epoch, &[complement.witness])).attesting_balance,
        8 * BALANCE_GWEI,
    );
}

/// Every slot's committee together is the whole active set, so their balances
/// have to add up to the total the accumulator commitment binds. If they did
/// not, the 2/3 threshold would be measured against the wrong denominator.
#[test]
fn the_committees_partition_the_active_balance() {
    let epoch = fixture();
    assert_eq!(
        epoch
            .committees
            .aggregates
            .iter()
            .flatten()
            .map(|c| c.balance)
            .sum::<u64>(),
        epoch.total_active_balance,
    );
}

//! The committee witness, with the public keys left on the far end.
//!
//! # What the epoch actually costs
//!
//! Measured on the real mainnet witness for epoch 430529 (960,974 members,
//! 2,212,792 registered):
//!
//! | part | bytes | share |
//! |------|-------|-------|
//! | `members` | 115,316,888 | 95.9% |
//! | `acc_multi_proof` | 4,950,600 | 4.1% |
//! | everything else | 80 | — |
//!
//! A [`CommitteeMember`] is 120 bytes and 96 of them are the public key, so
//! four fifths of the epoch's transfer is a `G1Point` per member. The daemon
//! sends the same keys every epoch: a validator's key never changes, and the
//! registry only ever grows. What changes is the shuffle — `slot_in_epoch` is
//! redrawn every epoch and nothing about it is cacheable — and a few tens of
//! effective balances.
//!
//! So the keys are shipped once and named by index afterwards. The far end
//! keeps them, this end keeps a digest and a bitmap of which indices it has
//! sent, and the epoch carries the three columns that actually move.
//!
//! # The three columns
//!
//! What is left after the keys is 24 bytes a member, and none of it needs to be
//! eight bytes wide:
//!
//! - **`validator_index`** is strictly increasing, and on mainnet 93.7% of the
//!   gaps are exactly 1 and 99.8% fit in seven bits. Sent as LEB128 gaps, the
//!   first absolute.
//! - **`slot_in_epoch`** is bounded by [`MAX_SLOTS`], which is 32. One byte.
//! - **`active_effective_balance`** takes 940 distinct values over a million
//!   members, and 32 ETH alone covers 99.2% of them. Sent as a dictionary
//!   ordered by falling frequency plus a LEB128 index a member, so the common
//!   case is one byte and the dictionary is a few kilobytes.
//!
//! That is about three bytes a member against 120, and the multi-proof — which
//! is 154,706 auxiliary digests of pure hash output, and compresses to nothing
//! by any means — becomes the bulk of what is left.
//!
//! # What it comes to
//!
//! Measured on that witness, as the bytes a request actually carries:
//!
//! | | bytes | |
//! |---|---|---|
//! | the witness, whole | 120,267,568 | what the wire used to carry |
//! | a warm epoch | 7,845,411 | **15.3x less** |
//! | a cold epoch | 107,786,675 | once, after either end restarts |
//!
//! Inside a warm epoch: 4,950,600 of it is the multi-proof, 963,120 the index
//! gaps, 963,001 the balance ids, 960,974 the slots, and 7,520 the balance
//! dictionary. **The multi-proof is 63% of what is left**, so it is the thing to
//! attack next and the members are no longer worth attacking. A realistic
//! epoch's activations add about 4.5 kB on top, which is noise.
//!
//! The cold figure is lower than the whole witness because a key costs 104 bytes
//! in the table against the 120 a member costs in the witness. It is paid once
//! per daemon start and once per prover restart, and never per epoch.
//!
//! None of it is bought with compute worth counting. On the same witness the
//! client spends 46 ms packing the columns and 79 ms hashing the witness, and
//! the server spends 130 ms rebuilding, 61 ms re-serialising and 74 ms hashing —
//! 266 ms in total, against the 78 ms it used to spend deserialising the whole
//! thing. Two tenths of a second of CPU for about 65 s of wire.
//!
//! # Two digests, doing two different jobs
//!
//! [`TableDigest`] is for **liveness**. It names which table this end believes
//! the far end holds, so a server that holds another one, or none, can say so
//! and be sent the table rather than reconstructing a witness out of the wrong
//! keys. It is chained rather than computed over the whole table —
//! `d(k+1) = H(domain, d(k), index, pubkey)` — so growing the table by the
//! handful of validators that activated costs one hash each, and this end can
//! track it while storing no keys at all.
//!
//! [`witness_digest`] is for **soundness**, and it is the one that matters. The
//! far end reconstructs the witness, serialises it, and hashes it against the
//! digest this end computed over the bytes it would otherwise have sent. A
//! wrong table, a decoding bug on either side, a truncated column — all of them
//! land as a digest that does not match, and the witness is refused instead of
//! proven. **The proof is over byte-identical input or there is no proof.**
//!
//! Nothing here changes what is proven. The witness the far end feeds the
//! circuit is the same bytes the old wire carried, and the digest is what says
//! so.

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use zkasper_common::acc::{Digest, G1Point};
use zkasper_common::committee::MAX_SLOTS;
use zkasper_common::types::{AccMultiProof, CommitteeMember, CommitteeWitness};

/// Names one state of the member table. See the module docs on why this is
/// chained and what it is and is not trusted for.
pub type TableDigest = [u8; 32];

/// The table before anything has been put in it.
pub const EMPTY_TABLE: TableDigest = [0u8; 32];

/// Separates the two hashes here from each other and from every other use of
/// SHA-256 in the pipeline.
const TABLE_DOMAIN: &[u8] = b"zkasper-member-table-v1";
const WITNESS_DOMAIN: &[u8] = b"zkasper-committee-witness-v1";

/// One validator's key, as the table names it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableEntry {
    pub validator_index: u64,
    pub pubkey: G1Point,
}

/// Fold one entry into the running table digest.
pub fn extend(base: &TableDigest, entry: &TableEntry) -> TableDigest {
    let mut hasher = Sha256::new();
    hasher.update(TABLE_DOMAIN);
    hasher.update(base);
    hasher.update(entry.validator_index.to_le_bytes());
    for limb in entry.pubkey {
        hasher.update(limb.to_le_bytes());
    }
    hasher.finalize().into()
}

/// What the far end must add to its table before it can serve this epoch.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberTable {
    /// Every key, for a server that holds none of them. One epoch's worth of
    /// keys, once per daemon start and once per prover restart.
    Full(Vec<TableEntry>),
    /// The validators that activated since, on top of the table the server is
    /// believed to already hold. A few tens of entries in the ordinary epoch.
    Append {
        base: TableDigest,
        added: Vec<TableEntry>,
    },
}

/// How the table names one member.
fn entry(member: &CommitteeMember) -> TableEntry {
    TableEntry {
        validator_index: member.validator_index,
        pubkey: member.pubkey,
    }
}

impl MemberTable {
    /// Every member's key, for a server that holds none of them.
    pub fn full(members: &[CommitteeMember]) -> Self {
        MemberTable::Full(members.iter().map(entry).collect())
    }

    /// The digest of the table this leaves the far end holding.
    pub fn resulting_digest(&self) -> TableDigest {
        let (mut digest, entries) = match self {
            MemberTable::Full(entries) => (EMPTY_TABLE, entries),
            MemberTable::Append { base, added } => (*base, added),
        };
        for entry in entries {
            digest = extend(&digest, entry);
        }
        digest
    }

    fn entries(&self) -> &[TableEntry] {
        match self {
            MemberTable::Full(entries) => entries,
            MemberTable::Append { added, .. } => added,
        }
    }

    /// Keys this carries, which is every key on a cold link and the epoch's
    /// activations on a warm one.
    pub fn len(&self) -> usize {
        self.entries().len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries().is_empty()
    }
}

/// A committee witness with the public keys taken out and the rest packed into
/// columns. See the module docs for what each column is and why it is that
/// wide.
#[derive(Debug, Serialize, Deserialize)]
pub struct CommitteeDelta {
    pub accumulator_commitment: Digest,
    pub target_epoch: u64,
    pub acc_root: Digest,
    pub total_active_balance: u64,
    pub member_count: u64,
    /// LEB128 gaps between consecutive validator indices, the first absolute.
    pub index_gaps: Vec<u8>,
    /// `slot_in_epoch`, one byte a member. [`MAX_SLOTS`] is 32.
    pub slots: Vec<u8>,
    /// Distinct `active_effective_balance` values, most common first.
    pub balances: Vec<u64>,
    /// LEB128 index into `balances`, one a member.
    pub balance_ids: Vec<u8>,
    pub acc_multi_proof: AccMultiProof,
}

/// Hash of the witness bytes the far end must reconstruct.
///
/// Over the serialised witness rather than its fields, because the serialised
/// witness is the thing that has to come back identical.
pub fn witness_digest(witness_bytes: &[u8]) -> TableDigest {
    let mut hasher = Sha256::new();
    hasher.update(WITNESS_DOMAIN);
    hasher.update(witness_bytes);
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// LEB128
// ---------------------------------------------------------------------------

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(value as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// Reads a column back. Stops short rather than reading past its end, so a
/// truncated column is an error here and not a wrong witness later.
struct Varints<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Varints<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn next(&mut self) -> Result<u64> {
        let mut value = 0u64;
        let mut shift = 0u32;
        loop {
            ensure!(shift < 64, "a varint claims more than 64 bits");
            let byte = *self
                .bytes
                .get(self.at)
                .context("a varint column ended mid-value")?;
            self.at += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte < 0x80 {
                return Ok(value);
            }
            shift += 7;
        }
    }

    fn finished(&self) -> bool {
        self.at == self.bytes.len()
    }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Pack a witness into its columns, or decline it.
///
/// `None` means this witness is not one the columns can carry — members that do
/// not strictly increase, or a `slot_in_epoch` past [`MAX_SLOTS`]. Both are
/// shapes `committee::build` does not produce, and the caller falls back to
/// sending the witness whole rather than failing the epoch over an encoding.
pub fn encode(witness: &CommitteeWitness) -> Option<CommitteeDelta> {
    let members = &witness.members;

    // Falling frequency, so the value that covers 99.2% of a mainnet epoch is
    // id 0 and every ordinary member costs one byte.
    let mut counts: HashMap<u64, u64> = HashMap::new();
    for member in members {
        *counts.entry(member.active_effective_balance).or_default() += 1;
    }
    let mut balances: Vec<u64> = counts.keys().copied().collect();
    balances.sort_unstable_by_key(|balance| (std::cmp::Reverse(counts[balance]), *balance));
    let ids: HashMap<u64, u64> = balances
        .iter()
        .enumerate()
        .map(|(id, balance)| (*balance, id as u64))
        .collect();

    let mut index_gaps = Vec::with_capacity(members.len() + members.len() / 4);
    let mut slots = Vec::with_capacity(members.len());
    let mut balance_ids = Vec::with_capacity(members.len() + members.len() / 64);
    let mut previous: Option<u64> = None;
    for member in members {
        let gap = match previous {
            None => member.validator_index,
            Some(previous) if member.validator_index > previous => {
                member.validator_index - previous
            }
            // The accumulator opening and the circuit both read this order, so
            // a witness without it is one nothing downstream would take.
            Some(_) => return None,
        };
        previous = Some(member.validator_index);
        put_varint(&mut index_gaps, gap);
        slots.push(
            u8::try_from(member.slot_in_epoch)
                .ok()
                .filter(|_| member.slot_in_epoch < MAX_SLOTS)?,
        );
        put_varint(&mut balance_ids, ids[&member.active_effective_balance]);
    }

    Some(CommitteeDelta {
        accumulator_commitment: witness.accumulator_commitment,
        target_epoch: witness.target_epoch,
        acc_root: witness.acc_root,
        total_active_balance: witness.total_active_balance,
        member_count: members.len() as u64,
        index_gaps,
        slots,
        balances,
        balance_ids,
        acc_multi_proof: witness.acc_multi_proof.clone(),
    })
}

/// Put the witness back together, taking each member's key from `pubkeys`.
///
/// Errors rather than substituting anything: a key the table does not hold is
/// the caller's cue to ask for the table, and every other failure here is a
/// column that does not say what it claimed to.
fn decode(delta: &CommitteeDelta, pubkeys: &HashMap<u64, G1Point>) -> Result<CommitteeWitness> {
    let count = usize::try_from(delta.member_count).context("member count is over this machine")?;
    ensure!(
        delta.slots.len() == count,
        "the slot column holds {} of {count} members",
        delta.slots.len(),
    );

    let mut gaps = Varints::new(&delta.index_gaps);
    let mut ids = Varints::new(&delta.balance_ids);
    let mut members = Vec::with_capacity(count);
    let mut index = 0u64;
    for (position, &slot_in_epoch) in delta.slots.iter().enumerate() {
        let gap = gaps.next()?;
        index = if position == 0 {
            gap
        } else {
            ensure!(gap > 0, "validator index {index} repeats");
            index
                .checked_add(gap)
                .context("a validator index overflows")?
        };
        let id = usize::try_from(ids.next()?).context("a balance id is over this machine")?;
        let &active_effective_balance = delta.balances.get(id).with_context(|| {
            format!("balance id {id} is past the {} sent", delta.balances.len())
        })?;
        let &pubkey = pubkeys.get(&index).with_context(|| {
            format!("the member table holds no public key for validator {index}")
        })?;
        members.push(CommitteeMember {
            validator_index: index,
            pubkey,
            active_effective_balance,
            slot_in_epoch: u64::from(slot_in_epoch),
        });
    }
    ensure!(
        gaps.finished() && ids.finished(),
        "a column holds more members than the {count} declared",
    );

    Ok(CommitteeWitness {
        accumulator_commitment: delta.accumulator_commitment,
        target_epoch: delta.target_epoch,
        acc_root: delta.acc_root,
        total_active_balance: delta.total_active_balance,
        members,
        acc_multi_proof: delta.acc_multi_proof.clone(),
    })
}

// ---------------------------------------------------------------------------
// The server's side
// ---------------------------------------------------------------------------

/// The keys the server is holding for its clients.
///
/// One table, not a map of them. There is one daemon per card, so a second
/// table would only ever be a second client's, and the one it displaced would
/// be asked for again — which is exactly what happens anyway, one round trip
/// later, and costs nothing to a run that has one client.
///
/// **In memory only, deliberately.** A table that outlived the process would be
/// a claim about keys nothing in the new process ever saw. A restarted server
/// holds nothing, says so at the handshake and at the first request that names
/// a table, and is sent the keys again.
#[derive(Debug, Default)]
pub struct MemberCache {
    held: Mutex<Option<Held>>,
}

#[derive(Debug)]
struct Held {
    digest: TableDigest,
    pubkeys: HashMap<u64, G1Point>,
}

impl MemberCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// The table this server is holding, for the handshake to report.
    pub fn digest(&self) -> Option<TableDigest> {
        self.held.lock().unwrap().as_ref().map(|held| held.digest)
    }

    /// Take the client's table update and rebuild its witness.
    ///
    /// `Ok(None)` is "I do not hold the table you are building on" — the client
    /// names a base this server has never had or has since replaced, and the
    /// answer is to be sent the table rather than to guess at it.
    ///
    /// The update is applied before the witness is built and stays applied
    /// whatever the witness turns out to be, so the client can advance its own
    /// idea of this table on any answer except the one that says it could not.
    pub fn rebuild(
        &self,
        table: &MemberTable,
        delta: &CommitteeDelta,
    ) -> Result<Option<CommitteeWitness>> {
        let mut held = self.held.lock().unwrap();
        let entry = match table {
            MemberTable::Full(_) => held.insert(Held {
                digest: EMPTY_TABLE,
                pubkeys: HashMap::with_capacity(delta.member_count as usize),
            }),
            MemberTable::Append { base, .. } => match held.as_mut() {
                Some(held) if held.digest == *base => held,
                _ => return Ok(None),
            },
        };
        for added in table.entries() {
            entry.pubkeys.insert(added.validator_index, added.pubkey);
            entry.digest = extend(&entry.digest, added);
        }
        decode(delta, &entry.pubkeys).map(Some)
    }
}

// ---------------------------------------------------------------------------
// The client's side
// ---------------------------------------------------------------------------

/// What this end believes the far end is holding.
///
/// Keys are not kept here — the witness has them whenever they are needed, and
/// a million of them is 92 MB the daemon has better uses for. What is kept is
/// the digest and a bit a validator index, which is 277 KB at mainnet's
/// registry size.
#[derive(Debug, Default)]
pub struct TableBelief {
    /// `None` once this end has no idea what the far end holds, which is how it
    /// starts and where a server that reported something else puts it back.
    digest: Option<TableDigest>,
    sent: Vec<u64>,
}

impl TableBelief {
    fn holds(&self, index: u64) -> bool {
        let (word, bit) = (index as usize / 64, index % 64);
        self.sent.get(word).is_some_and(|w| w >> bit & 1 == 1)
    }

    fn mark(&mut self, index: u64) {
        let (word, bit) = (index as usize / 64, index % 64);
        if self.sent.len() <= word {
            self.sent.resize(word + 1, 0);
        }
        self.sent[word] |= 1 << bit;
    }

    /// What to send so the far end can name every member of this witness.
    pub fn plan(&self, members: &[CommitteeMember]) -> MemberTable {
        match self.digest {
            None => MemberTable::full(members),
            Some(base) => MemberTable::Append {
                base,
                added: members
                    .iter()
                    .filter(|member| !self.holds(member.validator_index))
                    .map(entry)
                    .collect(),
            },
        }
    }

    /// The table as it now stands, with nothing left to add.
    ///
    /// What a second ask for the same witness must name. The first ask already
    /// handed over whatever keys it carried, so re-sending them would name a
    /// base the far end has moved off and be asked for the table it just took.
    pub fn settled(&self) -> Option<MemberTable> {
        self.digest.map(|base| MemberTable::Append {
            base,
            added: Vec::new(),
        })
    }

    /// Record a table the far end has taken.
    ///
    /// Called on any answer that was not "I do not hold that", because the
    /// server applies the update before it does anything else. An answer that
    /// never arrived leaves this end a table behind, which costs one full send
    /// on the next epoch and never a wrong one.
    pub fn adopt(&mut self, table: &MemberTable) {
        if matches!(table, MemberTable::Full(_)) {
            self.sent.clear();
        }
        for added in table.entries() {
            self.mark(added.validator_index);
        }
        self.digest = Some(table.resulting_digest());
    }

    /// Reconcile with what a server said it holds, at the handshake.
    ///
    /// A digest is only ever grounds to **forget**, never to adopt: this end
    /// can only build on a table it knows the contents of, and after a restart
    /// it knows nothing whatever the far end reports. So anything other than
    /// the digest already believed puts this back to sending the table whole —
    /// which covers a restarted server, a second server behind the same
    /// address, and a daemon that restarted under a server that did not.
    pub fn reconcile(&mut self, reported: Option<TableDigest>) {
        if reported.is_none() || reported != self.digest {
            *self = Self::default();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pubkey(seed: u64) -> G1Point {
        std::array::from_fn(|limb| seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ limb as u64)
    }

    fn member(validator_index: u64, balance: u64, slot_in_epoch: u64) -> CommitteeMember {
        CommitteeMember {
            validator_index,
            pubkey: pubkey(validator_index),
            active_effective_balance: balance,
            slot_in_epoch,
        }
    }

    fn witness(members: Vec<CommitteeMember>) -> CommitteeWitness {
        CommitteeWitness {
            accumulator_commitment: [1, 2, 3, 4],
            target_epoch: 430529,
            acc_root: [5, 6, 7, 8],
            total_active_balance: 37_172_277_000_000_000,
            members,
            acc_multi_proof: AccMultiProof {
                auxiliaries: vec![[9, 10, 11, 12], [13, 14, 15, 16]],
            },
        }
    }

    /// The whole scheme rests on this: what comes out is what went in, to the
    /// byte, or the digest says it is not.
    #[test]
    fn a_round_trip_returns_the_same_witness() {
        let original = witness(vec![
            member(0, 32_000_000_000, 0),
            member(1, 32_000_000_000, 5),
            member(4_226, 2_048_000_000_000, 31),
            member(2_212_745, 31_000_000_000, 17),
        ]);
        let delta = encode(&original).expect("an ordinary witness encodes");
        let pubkeys = original
            .members
            .iter()
            .map(|m| (m.validator_index, m.pubkey))
            .collect();

        let rebuilt = decode(&delta, &pubkeys).expect("it decodes");
        assert_eq!(
            bincode::serialize(&rebuilt).unwrap(),
            bincode::serialize(&original).unwrap(),
        );
    }

    #[test]
    fn a_member_the_table_does_not_hold_is_named() {
        let original = witness(vec![member(0, 32_000_000_000, 0), member(9, 1, 1)]);
        let delta = encode(&original).unwrap();
        let pubkeys = HashMap::from([(0, pubkey(0))]);

        let error = format!("{:#}", decode(&delta, &pubkeys).unwrap_err());
        assert!(error.contains("no public key for validator 9"), "{error}");
    }

    #[test]
    fn members_that_do_not_increase_are_declined() {
        assert!(encode(&witness(vec![member(7, 1, 0), member(7, 1, 1)])).is_none());
        assert!(encode(&witness(vec![member(7, 1, 0), member(6, 1, 1)])).is_none());
    }

    #[test]
    fn a_slot_past_the_committee_tree_is_declined() {
        assert!(encode(&witness(vec![member(0, 1, MAX_SLOTS)])).is_none());
    }

    #[test]
    fn a_truncated_column_is_an_error_and_not_a_short_witness() {
        let original = witness(vec![member(0, 1, 0), member(1, 1, 1), member(2, 1, 2)]);
        let mut delta = encode(&original).unwrap();
        delta.slots.pop();
        let pubkeys = original
            .members
            .iter()
            .map(|m| (m.validator_index, m.pubkey))
            .collect();

        assert!(decode(&delta, &pubkeys).is_err());
    }

    /// The dictionary is only worth its bytes if the common value is id 0.
    #[test]
    fn the_commonest_balance_is_the_shortest_id() {
        let mut members: Vec<CommitteeMember> =
            (0..100).map(|i| member(i, 32_000_000_000, 0)).collect();
        members.push(member(100, 2_048_000_000_000, 0));
        let delta = encode(&witness(members)).unwrap();

        assert_eq!(delta.balances[0], 32_000_000_000);
        assert_eq!(delta.balance_ids.len(), 101, "one byte a member");
    }

    #[test]
    fn the_table_digest_follows_what_was_put_in_it() {
        let one = TableEntry {
            validator_index: 1,
            pubkey: pubkey(1),
        };
        let two = TableEntry {
            validator_index: 2,
            pubkey: pubkey(2),
        };

        let full = MemberTable::Full(vec![one.clone(), two.clone()]);
        let split = MemberTable::Append {
            base: MemberTable::Full(vec![one]).resulting_digest(),
            added: vec![two],
        };
        assert_eq!(full.resulting_digest(), split.resulting_digest());
        assert_ne!(full.resulting_digest(), EMPTY_TABLE);
    }

    #[test]
    fn a_cache_serves_a_table_it_holds_and_declines_one_it_does_not() {
        let original = witness(vec![member(0, 1, 0), member(1, 1, 1)]);
        let delta = encode(&original).unwrap();
        let cache = MemberCache::new();
        assert_eq!(cache.digest(), None);

        let full = MemberTable::Full(vec![
            TableEntry {
                validator_index: 0,
                pubkey: pubkey(0),
            },
            TableEntry {
                validator_index: 1,
                pubkey: pubkey(1),
            },
        ]);
        assert!(cache.rebuild(&full, &delta).unwrap().is_some());
        assert_eq!(cache.digest(), Some(full.resulting_digest()));

        // Built on a table this cache has never held.
        let wrong = MemberTable::Append {
            base: [7u8; 32],
            added: Vec::new(),
        };
        assert!(cache.rebuild(&wrong, &delta).unwrap().is_none());
        // ...and declining it left what it does hold alone.
        assert_eq!(cache.digest(), Some(full.resulting_digest()));
    }

    #[test]
    fn a_belief_sends_everything_once_and_then_only_what_is_new() {
        let first = [member(0, 1, 0), member(1, 1, 1)];
        let mut belief = TableBelief::default();

        let plan = belief.plan(&first);
        assert!(matches!(&plan, MemberTable::Full(entries) if entries.len() == 2));
        belief.adopt(&plan);

        // The next epoch keeps both and activates a third.
        let second = [member(0, 1, 3), member(1, 1, 4), member(2, 1, 5)];
        let plan = belief.plan(&second);
        let MemberTable::Append { base, added } = &plan else {
            panic!("a warm belief appends");
        };
        assert_eq!(*base, belief.digest.unwrap());
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].validator_index, 2);
        belief.adopt(&plan);

        // Nothing new: nothing sent.
        assert!(
            matches!(belief.plan(&second), MemberTable::Append { added, .. } if added.is_empty())
        );
    }

    /// A witness asked for twice must name the table the first ask left behind.
    ///
    /// The far end applies the keys before it judges the witness, so the base a
    /// request was built on is one the far end has already moved off. A second
    /// ask that re-sent the original request would be answered with a request
    /// for the table instead of a verdict — and the second ask exists to tell a
    /// sick prover from a bad witness, which is a distinction a run died of on
    /// 2026-08-19.
    #[test]
    fn a_second_ask_names_the_table_the_first_ask_left_behind() {
        let first = [member(0, 1, 0)];
        let second = [member(0, 1, 0), member(1, 1, 1)];
        let cache = MemberCache::new();
        let mut belief = TableBelief::default();

        let cold = belief.plan(&first);
        let cold_delta = encode(&witness(first.to_vec())).unwrap();
        assert!(cache.rebuild(&cold, &cold_delta).unwrap().is_some());
        belief.adopt(&cold);

        // The next epoch, with a validator that has just activated.
        let delta = encode(&witness(second.to_vec())).unwrap();
        let warm = belief.plan(&second);
        assert_eq!(warm.len(), 1, "one activation to send");
        assert!(cache.rebuild(&warm, &delta).unwrap().is_some());
        belief.adopt(&warm);

        // Sending that same request again names a table the cache has left.
        assert!(cache.rebuild(&warm, &delta).unwrap().is_none());
        // Naming what it holds now is served, and adds no keys twice.
        let settled = belief.settled().expect("a warm belief has a table");
        assert!(
            settled.is_empty(),
            "the keys already went with the first ask"
        );
        assert!(cache.rebuild(&settled, &delta).unwrap().is_some());
    }

    #[test]
    fn a_server_reporting_another_table_puts_the_belief_back_to_nothing() {
        let members = [member(0, 1, 0)];
        let mut belief = TableBelief::default();
        let plan = belief.plan(&members);
        belief.adopt(&plan);
        let held = belief.digest.unwrap();

        // The same table: keep building on it.
        belief.reconcile(Some(held));
        assert!(matches!(belief.plan(&members), MemberTable::Append { .. }));

        // A restarted server, holding nothing.
        belief.reconcile(None);
        assert!(matches!(belief.plan(&members), MemberTable::Full(_)));

        // A different server, holding something this end cannot name.
        let mut belief = TableBelief::default();
        let plan = belief.plan(&members);
        belief.adopt(&plan);
        belief.reconcile(Some([3u8; 32]));
        assert!(matches!(belief.plan(&members), MemberTable::Full(_)));
    }
}

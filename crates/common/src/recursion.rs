//! Recursive proof verification.
//!
//! `verify_zisk_proof` checks a VADCOP final proof from inside a guest, which is
//! what lets slot proofs be produced independently and folded together later.
//!
//! Verifying the proof is only half the job. A valid proof of *some* slot says
//! nothing about *which* slot, so an aggregator that only called
//! `verify_zisk_proof` would accept a proof of a different slot, a different
//! epoch, or a different program entirely. This module also exposes the child's
//! program verification key and committed public bytes so the aggregator can
//! bind both.
//!
//! Which key it binds them to is the other half again. [`verify_child`] checks
//! the proof against whatever key it is handed, so a key read out of the witness
//! binds the child to a program the prover chose. [`verify_baked_child`] takes
//! one the guest was compiled with instead, and that is what every recursive
//! edge in this pipeline uses except the two a program cannot bake — its own.
//!
//! There is a third key, and it is the one that decides whether any of the above
//! is a check at all. `zisklib::verify_zisk_proof` splits the last four words off
//! the buffer and passes them to the STARK verifier as `rootC` — the commitment
//! to the *constant polynomials*, which for a circom-compiled circuit are the
//! gates and the wiring. `proofman`'s generated `vadcop_final` verifier is byte
//! for byte the same code as its `recursive2` verifier; the two differ only in
//! that root. So the circuit being verified is named by those four words and by
//! nothing else, and a prover who supplies their own supplies their own circuit,
//! whose 69 public values — the program key at index 1 included — are then
//! whatever they wrote. [`VADCOP_FINAL_VK`] pins them.
//!
//! Serialized proof layout, in u64 words:
//! `[minimal][n_publics][is_vadcop_final][program_vk(4)][publics(64)][proof..][vadcop_vk(4)]`
//!
//! The child is an uncompressed `vadcop_final` proof, and that is a performance
//! decision as much as a format one. A compressed proof has Merkle arity 2, so
//! `proofman`'s `arity * 4 == WIDTH` fixes the verifier's hash width at 8, and
//! `syscall_poseidon1` only accepts width 16 — every Merkle and FRI hash inside
//! the guest falls back to software Poseidon. Measured on a slot proof, that is
//! 242.8 M RISC-V steps a child against 10.9 M, and 306 precompiled permutations
//! against 3,877. The uncompressed proof is 369,224 bytes rather than 254,624,
//! and it is the `is_vadcop_final_proof` flag at index 0 of its public vector
//! that pushes the program key one word later than a compressed proof's.

use alloc::vec::Vec;

/// Length of the program verification key, in u64 words.
pub const PROGRAM_VK_LEN: usize = 4;

/// Number of public values a Zisk proof carries.
pub const ZISK_PUBLICS: usize = 64;

/// Public values are committed as u32 slots, so this many bytes fit.
pub const MAX_PUBLIC_BYTES: usize = ZISK_PUBLICS * 4;

/// Length of the VADCOP final verification key, in u64 words.
pub const VADCOP_VK_LEN: usize = 4;

const VK_OFFSET: usize = 3;
const PUBLICS_OFFSET: usize = VK_OFFSET + PROGRAM_VK_LEN;
/// Header, publics, and the key the verifier splits off the end. A buffer
/// shorter than this makes the two overlap, and the tail read below would
/// return public values rather than a key.
const MIN_PROOF_WORDS: usize = PUBLICS_OFFSET + ZISK_PUBLICS + VADCOP_VK_LEN;

/// Whether a proof is laid out the way the offsets above read it.
///
/// A compressed proof carries no `is_vadcop_final` flag, so every field after
/// the header sits one word earlier and the same offsets would read a key out
/// of the child's own public values. Rejecting it here is what keeps the
/// binding a parse of the format rather than of one word past it.
fn is_uncompressed(proof: &[u64]) -> bool {
    proof.len() >= MIN_PROOF_WORDS && proof[0] == 0
}

/// Identifies which guest program produced a proof.
pub type ProgramVk = [u64; PROGRAM_VK_LEN];

/// A child key a guest was built without. No program has it, so a guest holding
/// one cannot verify anything; `scripts/bake_child_vks.sh` is what fills it in.
pub const UNSET_VK: ProgramVk = [0; PROGRAM_VK_LEN];

/// The proving system every proof in this pipeline is proved under.
///
/// `rootC` of the `vadcop_final` circuit, read from
/// `provingKey/zisk/vadcop_final/vadcop_final.verkey.bin` of the Zisk
/// **v1.1.0-alpha** proving key — the release `Cargo.toml` pins `ziskos` and
/// `zisk-sdk` to. It is a constant of that release and of nothing in this
/// repository, so unlike the child program keys it depends on no guest ELF,
/// there is no dependency graph to walk, and one shared constant is enough.
///
/// **Rederive it on a Zisk bump, before anything else.** A stale value refuses
/// every proof, which is the safe direction and an obvious one; the value for
/// v1.0.0-alpha is `[16418290590932191654, 2682920145730279116,
/// 9421690135668477588, 7053485478104629196]` and is not this. Compressed
/// proofs are a different circuit with a different root again, and the layout
/// check rejects them before this is consulted.
pub const VADCOP_FINAL_VK: ProgramVk = [
    11800534191493876478,
    6047701255643179780,
    11700752144183100736,
    12226993988674551281,
];

/// The VADCOP final verification key a proof asks to be checked under.
///
/// This is a request, not a property: it is the tail of a buffer the prover
/// wrote, and `zisklib::verify_zisk_proof` obeys it. See the module docs.
pub fn child_vadcop_vk(proof: &[u64]) -> Option<ProgramVk> {
    if !is_uncompressed(proof) {
        return None;
    }
    let tail = &proof[proof.len() - VADCOP_VK_LEN..];
    Some([tail[0], tail[1], tail[2], tail[3]])
}

/// The program verification key a proof commits to.
pub fn child_program_vk(proof: &[u64]) -> Option<ProgramVk> {
    if !is_uncompressed(proof) {
        return None;
    }
    Some([
        proof[VK_OFFSET],
        proof[VK_OFFSET + 1],
        proof[VK_OFFSET + 2],
        proof[VK_OFFSET + 3],
    ])
}

/// The byte stream the child committed with `ziskos::io::commit_slice`.
pub fn child_public_bytes(proof: &[u64]) -> Option<[u8; MAX_PUBLIC_BYTES]> {
    if !is_uncompressed(proof) {
        return None;
    }
    let mut out = [0u8; MAX_PUBLIC_BYTES];
    for i in 0..ZISK_PUBLICS {
        let word = proof[PUBLICS_OFFSET + i];
        if word > u32::MAX as u64 {
            return None;
        }
        out[4 * i..4 * i + 4].copy_from_slice(&(word as u32).to_le_bytes());
    }
    Some(out)
}

/// A stored proof, split back into the parts Zisk's own `Proof` is made of.
///
/// The pipeline keeps proofs as the flat word vector `ProveOutput::get_proof_u64`
/// hands out — `[minimal | n_publics | stark_publics | proof | zisk_vk]` — and
/// that is all any zkasper consumer needs. Zisk's `wrap_proof`, the only door to
/// an on-chain proof, wants a `zisk_common::Proof` instead, and the SDK has no
/// inverse: `Proof::load` reads its own bincode and nothing rebuilds a
/// `ProofBody::Vadcop` from words. Everything it needs is here except the hash
/// family, which is a constant of the Zisk release rather than of the proof.
pub struct StoredProof<'a> {
    /// Whether the proof was compressed. The PLONK wrap refuses a compressed
    /// one, so this is the first thing a wrapper must look at.
    pub minimal: bool,
    /// `[is_vadcop_final_proof?] | program_vk(4) | inputs(64)`, as the STARK
    /// transcript committed it.
    pub stark_publics: &'a [u64],
    /// The proof itself.
    pub proof: &'a [u64],
    /// The VADCOP final key the proof asks to be checked under.
    pub zisk_vk: ProgramVk,
}

impl StoredProof<'_> {
    /// The flag-free `[program_vk | inputs]` Zisk calls `publics_full`.
    pub fn publics_full(&self) -> &[u64] {
        if self.minimal {
            self.stark_publics
        } else {
            &self.stark_publics[1..]
        }
    }
}

/// Split a stored proof into its parts, or `None` if the words are not one.
pub fn split(words: &[u64]) -> Option<StoredProof<'_>> {
    let (&minimal, rest) = words.split_first()?;
    let (&n_publics, rest) = rest.split_first()?;
    let minimal = match minimal {
        0 => false,
        1 => true,
        _ => return None,
    };
    let n_publics = usize::try_from(n_publics).ok()?;
    // A minimal proof carries no `is_vadcop_final_proof` flag, so its public
    // vector is one word shorter. Anything else is not this format.
    if n_publics != PROGRAM_VK_LEN + ZISK_PUBLICS + usize::from(!minimal) {
        return None;
    }
    let (stark_publics, rest) = rest.split_at_checked(n_publics)?;
    let (proof, tail) = rest.split_at_checked(rest.len().checked_sub(VADCOP_VK_LEN)?)?;
    if proof.is_empty() {
        return None;
    }
    Some(StoredProof {
        minimal,
        stark_publics,
        proof,
        zisk_vk: [tail[0], tail[1], tail[2], tail[3]],
    })
}

/// Verify a child proof and bind it to the program and outputs the caller expects.
///
/// An empty proof is accepted on native targets so circuit logic can be
/// exercised in tests without a prover; inside a guest it is rejected.
pub fn verify_child(proof: &[u64], expected_vk: &ProgramVk, expected_publics: &[u8]) -> bool {
    if proof.is_empty() {
        return cfg!(not(target_os = "zkvm"));
    }
    assert!(
        expected_publics.len() <= MAX_PUBLIC_BYTES,
        "public outputs exceed the {MAX_PUBLIC_BYTES}-byte proof capacity",
    );

    // First, because every check under it is a statement about the circuit these
    // four words name. Get this wrong and the program key below is a public
    // value of a circuit the prover wrote, and agrees with whatever they wanted
    // it to agree with.
    if child_vadcop_vk(proof) != Some(VADCOP_FINAL_VK) {
        return false;
    }

    let Some(vk) = child_program_vk(proof) else {
        return false;
    };
    if vk != *expected_vk {
        return false;
    }

    let Some(publics) = child_public_bytes(proof) else {
        return false;
    };
    if &publics[..expected_publics.len()] != expected_publics {
        return false;
    }
    // Anything past the committed outputs must be zero, otherwise a prover
    // could smuggle unconstrained data into the public values.
    if publics[expected_publics.len()..].iter().any(|&b| b != 0) {
        return false;
    }

    #[cfg(feature = "count-ops")]
    crate::op_counter::inc_recursive_verify();

    ziskos::zisklib::verify_zisk_proof(proof)
}

/// [`verify_child`] against a key the parent was compiled with rather than one
/// it was handed.
///
/// This is the whole difference between binding a child and binding nothing: a
/// witness field names any program the prover likes, a constant names the
/// program this guest was built against. An unbaked guest says so rather than
/// failing as an ordinary key mismatch, because the two want different fixes.
pub fn verify_baked_child(proof: &[u64], baked: &ProgramVk, expected_publics: &[u8]) -> bool {
    if proof.is_empty() {
        return cfg!(not(target_os = "zkvm"));
    }
    assert_ne!(
        *baked, UNSET_VK,
        "this guest was built before its children had keys; run scripts/bake_child_vks.sh",
    );
    verify_child(proof, baked, expected_publics)
}

/// Fixed-width little-endian encoding of a proof's public outputs.
///
/// Both the guest that commits the outputs and the aggregator that checks them
/// go through this, so the two can never disagree on layout.
#[derive(Default)]
pub struct PublicWriter {
    bytes: Vec<u8>,
}

impl PublicWriter {
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.bytes.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn bytes32(&mut self, v: &[u8; 32]) -> &mut Self {
        self.bytes.extend_from_slice(v);
        self
    }

    pub fn digest(&mut self, v: &crate::acc::Digest) -> &mut Self {
        for w in v {
            self.bytes.extend_from_slice(&w.to_le_bytes());
        }
        self
    }

    pub fn program_vk(&mut self, v: &ProgramVk) -> &mut Self {
        for w in v {
            self.bytes.extend_from_slice(&w.to_le_bytes());
        }
        self
    }

    pub fn finish(&self) -> Vec<u8> {
        assert!(
            self.bytes.len() <= MAX_PUBLIC_BYTES,
            "public outputs exceed the {MAX_PUBLIC_BYTES}-byte proof capacity",
        );
        self.bytes.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 1.0.0-alpha `vadcop_final` root, and the 1.1.0-alpha
    /// `vadcop_final_compressed` one. Both are real circuits with real proofs
    /// behind them, which is the point: they are what a prover would reach for
    /// first, and they are not what this pipeline proves under.
    const FOREIGN_VKS: [ProgramVk; 3] = [
        [
            16418290590932191654,
            2682920145730279116,
            9421690135668477588,
            7053485478104629196,
        ],
        [
            7077556885608687133,
            1422085596864190689,
            2297137918351717267,
            14362995833492506538,
        ],
        UNSET_VK,
    ];

    /// A buffer shaped like a child proof: uncompressed, the flag set, the
    /// program key and public words where the offsets read them, and the VADCOP
    /// key on the end. Nothing between is a proof, so the STARK verifier refuses
    /// it — every assertion below is about a refusal that happens before that.
    fn shaped(program_vk: &ProgramVk, publics: &[u8], vadcop_vk: &ProgramVk) -> Vec<u64> {
        let mut words = alloc::vec![0u64; MIN_PROOF_WORDS];
        words[1] = 69;
        words[2] = 1;
        words[VK_OFFSET..PUBLICS_OFFSET].copy_from_slice(program_vk);
        for (i, chunk) in publics.chunks(4).enumerate() {
            let mut word = [0u8; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            words[PUBLICS_OFFSET + i] = u32::from_le_bytes(word) as u64;
        }
        let end = words.len() - VADCOP_VK_LEN;
        words[end..].copy_from_slice(vadcop_vk);
        words
    }

    /// The whole of this module's claim, in one assertion.
    ///
    /// A child that names any VADCOP key but ours is refused, and it is refused
    /// while everything else about it is right: the program key is the one the
    /// parent expects and the public bytes are the ones it asked for. Only the
    /// circuit differs, and the circuit is the thing that decides whether those
    /// two agreements mean anything.
    #[test]
    fn a_child_under_a_foreign_vadcop_key_is_refused() {
        let program_vk: ProgramVk = [1, 2, 3, 4];
        let publics = [7u8, 8, 9];
        for foreign in FOREIGN_VKS {
            let proof = shaped(&program_vk, &publics, &foreign);
            assert_eq!(child_program_vk(&proof), Some(program_vk));
            assert_eq!(child_vadcop_vk(&proof), Some(foreign));
            assert!(!verify_child(&proof, &program_vk, &publics));
        }
    }

    /// The tail is read from the end of the buffer, so a buffer short enough for
    /// the end to be inside the public values must not parse at all. Otherwise a
    /// prover picks four public words, which they also write, and the pin above
    /// checks a number against itself.
    #[test]
    fn the_vadcop_key_never_overlaps_the_public_values() {
        let proof = shaped(&[1, 2, 3, 4], &[], &VADCOP_FINAL_VK);
        assert_eq!(child_vadcop_vk(&proof), Some(VADCOP_FINAL_VK));
        assert_eq!(child_vadcop_vk(&proof[..proof.len() - 1]), None);
        assert_eq!(child_program_vk(&proof[..proof.len() - 1]), None);
    }

    fn stored_words(minimal: bool) -> Vec<u64> {
        let n_publics = PROGRAM_VK_LEN + ZISK_PUBLICS + usize::from(!minimal);
        let mut words = vec![minimal as u64, n_publics as u64];
        if !minimal {
            words.push(1);
        }
        words.extend([7, 8, 9, 10]);
        words.extend((0..ZISK_PUBLICS).map(|i| i as u64));
        words.extend([100, 101, 102]);
        words.extend(VADCOP_FINAL_VK);
        words
    }

    #[test]
    fn a_stored_proof_splits_into_what_zisk_wants_back() {
        let words = stored_words(false);
        let split = split(&words).expect("an uncompressed stored proof");
        assert!(!split.minimal);
        assert_eq!(split.zisk_vk, VADCOP_FINAL_VK);
        assert_eq!(split.proof, &[100, 101, 102]);
        assert_eq!(split.publics_full()[..PROGRAM_VK_LEN], [7, 8, 9, 10]);
        assert_eq!(split.publics_full().len(), PROGRAM_VK_LEN + ZISK_PUBLICS);
    }

    #[test]
    fn a_compressed_proof_says_so() {
        let words = stored_words(true);
        let split = split(&words).expect("a minimal stored proof");
        assert!(split.minimal, "the PLONK wrap refuses this one");
        assert_eq!(split.publics_full().len(), PROGRAM_VK_LEN + ZISK_PUBLICS);
    }

    #[test]
    fn a_truncated_or_mislabelled_proof_is_not_split() {
        let words = stored_words(false);
        assert!(split(&[]).is_none());
        // Shorter than the header, the publics and the key together. Losing
        // whole words off the tail is *not* detectable here — the format
        // carries no length, so the key just slides — which is why the key
        // itself is checked against [`VADCOP_FINAL_VK`] rather than trusted.
        assert!(split(&words[..2 + 69 + 2]).is_none());
        assert!(split(&[2, 69]).is_none(), "the minimal flag is a bool");

        let mut wrong = words.clone();
        wrong[1] = 68;
        assert!(
            split(&wrong).is_none(),
            "68 publics is a compressed proof count"
        );

        let mut empty = words[..2 + 69].to_vec();
        empty.extend(VADCOP_FINAL_VK);
        assert!(
            split(&empty).is_none(),
            "a header and a key with nothing between"
        );
    }

    /// Against a real proof, which is the only thing that can say the pinned
    /// constant is the one honest proofs actually carry. A wrong constant is the
    /// safe failure — it refuses everything — but it refuses everything at the
    /// far end of a proving run, so pin it here where it costs nothing.
    ///
    /// ```text
    /// ZKASPER_CHILD_PROOF=/path/to/child.words.bin cargo test -p zkasper-common
    /// ```
    #[test]
    fn a_real_child_carries_the_pinned_vadcop_key() {
        let Ok(path) = std::env::var("ZKASPER_CHILD_PROOF") else {
            return;
        };
        let bytes = std::fs::read(&path).expect("read the child proof");
        assert_eq!(bytes.len() % 8, 0, "{path} is not a u64 word stream");
        let proof: Vec<u64> = bytes
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
            .collect();
        assert_eq!(child_vadcop_vk(&proof), Some(VADCOP_FINAL_VK));

        let program_vk = child_program_vk(&proof).expect("an uncompressed child proof");
        let publics = child_public_bytes(&proof).expect("an uncompressed child proof");
        assert!(verify_child(&proof, &program_vk, &publics));

        // The same proof, asking to be checked under someone else's circuit.
        for foreign in FOREIGN_VKS {
            let mut forged = proof.clone();
            let end = forged.len() - VADCOP_VK_LEN;
            forged[end..].copy_from_slice(&foreign);
            assert!(!verify_child(&forged, &program_vk, &publics));
        }
    }
}

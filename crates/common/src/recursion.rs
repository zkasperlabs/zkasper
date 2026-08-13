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
//! Serialized proof layout, in u64 words:
//! `[minimal][n_publics][program_vk(4)][publics(64)][proof..][vadcop_vk(4)]`

use alloc::vec::Vec;

/// Length of the program verification key, in u64 words.
pub const PROGRAM_VK_LEN: usize = 4;

/// Number of public values a Zisk proof carries.
pub const ZISK_PUBLICS: usize = 64;

/// Public values are committed as u32 slots, so this many bytes fit.
pub const MAX_PUBLIC_BYTES: usize = ZISK_PUBLICS * 4;

const VK_OFFSET: usize = 2;
const PUBLICS_OFFSET: usize = VK_OFFSET + PROGRAM_VK_LEN;
const MIN_PROOF_WORDS: usize = PUBLICS_OFFSET + ZISK_PUBLICS;

/// Identifies which guest program produced a proof.
pub type ProgramVk = [u64; PROGRAM_VK_LEN];

/// The program verification key a proof commits to.
pub fn child_program_vk(proof: &[u64]) -> Option<ProgramVk> {
    if proof.len() < MIN_PROOF_WORDS {
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
    if proof.len() < MIN_PROOF_WORDS {
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

    pub fn finish(&self) -> Vec<u8> {
        assert!(
            self.bytes.len() <= MAX_PUBLIC_BYTES,
            "public outputs exceed the {MAX_PUBLIC_BYTES}-byte proof capacity",
        );
        self.bytes.clone()
    }
}

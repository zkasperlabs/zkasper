//! Guest input and output, shared by every guest binary via `#[path]`.
//!
//! Public outputs go through `ziskos::io::commit_slice`, which packs the byte
//! stream into the 64 u32 public slots that end up in the proof. The
//! aggregation guests read those same bytes back out of a child proof, so both
//! sides go through [`zkasper_common::recursion::PublicWriter`].

// Every guest takes the half of this it needs: bincode witnesses come in as
// bytes, the committee proof's comes in as words.
#![allow(dead_code)]

/// Read the serialized witness.
///
/// Borrowed rather than copied: Zisk maps the input into the guest's address
/// space, and a witness is up to nine figures of bytes, so the `to_vec` this
/// used to do was itself a material share of what the committee proof cost.
///
/// Natively the witness comes from the path in `argv[1]`, defaulting to
/// `input.bin`, so a circuit can be exercised without a prover.
pub fn read_witness() -> &'static [u8] {
    #[cfg(target_os = "zkvm")]
    {
        ziskos::io::read_slice()
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        std::boxed::Box::leak(read_file().into_boxed_slice())
    }
}

/// The same input as words, for a witness the guest reads in place.
///
/// Zisk's input region starts at an 8-byte aligned address and every record it
/// holds is padded to a multiple of 8, so a `u64` view of it is free — which is
/// the whole point, since a witness that is already in the guest's native
/// layout should not be parsed at all. The alignment is asserted rather than
/// assumed.
pub fn read_words() -> &'static [u64] {
    #[cfg(target_os = "zkvm")]
    {
        let (prefix, words, _) = unsafe { ziskos::io::read_slice().align_to::<u64>() };
        assert!(prefix.is_empty(), "Zisk handed in an unaligned input");
        words
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        std::boxed::Box::leak(
            read_file()
                .chunks(8)
                .map(|chunk| {
                    let mut word = [0u8; 8];
                    word[..chunk.len()].copy_from_slice(chunk);
                    u64::from_le_bytes(word)
                })
                .collect::<alloc_vec::Vec<u64>>()
                .into_boxed_slice(),
        )
    }
}

#[cfg(not(target_os = "zkvm"))]
fn read_file() -> alloc_vec::Vec<u8> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "input.bin".into());
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

/// Commit the proof's public outputs.
pub fn commit(bytes: alloc_vec::Vec<u8>) {
    assert!(
        bytes.len() <= zkasper_common::recursion::MAX_PUBLIC_BYTES,
        "public outputs exceed proof capacity",
    );
    #[cfg(target_os = "zkvm")]
    ziskos::io::commit_slice(&bytes);
    #[cfg(not(target_os = "zkvm"))]
    println!("public outputs ({} bytes): {}", bytes.len(), hex(&bytes));
}

#[cfg(not(target_os = "zkvm"))]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

mod alloc_vec {
    pub use std::vec::Vec;
}

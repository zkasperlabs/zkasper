//! Guest input and output, shared by every guest binary via `#[path]`.
//!
//! Public outputs go through `ziskos::io::commit_slice`, which packs the byte
//! stream into the 64 u32 public slots that end up in the proof. The
//! aggregation guests read those same bytes back out of a child proof, so both
//! sides go through [`zkasper_common::recursion::PublicWriter`].

/// Read the serialized witness.
///
/// Natively the witness comes from the path in `argv[1]`, defaulting to
/// `input.bin`, so a circuit can be exercised without a prover.
pub fn read_witness() -> alloc_vec::Vec<u8> {
    #[cfg(target_os = "zkvm")]
    {
        ziskos::io::read_slice().to_vec()
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        let path = std::env::args()
            .nth(1)
            .unwrap_or_else(|| "input.bin".into());
        std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
    }
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

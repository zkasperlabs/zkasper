//! What one recursive child verification costs, and nothing else.
//!
//! The guest reads `[n][len_0][proof_0 words]..[len_{n-1}][proof_{n-1} words]`
//! and calls `verify_zisk_proof` on each. No witness parsing, no field
//! arithmetic, no public-output binding: the difference between `n` and `n + 1`
//! children is one recursion and nothing but one recursion, which is what
//! separates the stage floor from the per-child slope.
#![cfg_attr(target_os = "zkvm", no_main)]

#[cfg(target_os = "zkvm")]
ziskos::entrypoint!(main);

fn main() {
    let words = read_words();
    let n = words[0] as usize;
    let mut at = 1usize;
    let mut verified = 0u64;
    for _ in 0..n {
        let len = words[at] as usize;
        let proof = &words[at + 1..at + 1 + len];
        at += 1 + len;
        if verify(proof) {
            verified += 1;
        }
    }
    // A child that fails returns early and costs less than one that passes, so a
    // failed verification would silently measure the wrong thing.
    assert!(verified == n as u64, "a child proof did not verify");
    commit(verified);
}

fn verify(proof: &[u64]) -> bool {
    #[cfg(target_os = "zkvm")]
    {
        ziskos::zisklib::verify_zisk_proof(proof)
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        let _ = proof;
        true
    }
}

fn commit(verified: u64) {
    #[cfg(target_os = "zkvm")]
    ziskos::io::commit_slice(&verified.to_le_bytes());
    #[cfg(not(target_os = "zkvm"))]
    println!("verified {verified}");
}

fn read_words() -> &'static [u64] {
    #[cfg(target_os = "zkvm")]
    {
        let (prefix, words, _) = unsafe { ziskos::io::read_slice().align_to::<u64>() };
        assert!(prefix.is_empty(), "Zisk handed in an unaligned input");
        words
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        let path = std::env::args().nth(1).unwrap_or_else(|| "input.bin".into());
        let bytes = std::fs::read(&path).expect("read the input");
        Box::leak(
            bytes
                .chunks_exact(8)
                .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
                .collect::<Vec<u64>>()
                .into_boxed_slice(),
        )
    }
}

//! Checking a proof on the host, and timing it.
//!
//! This is the number a light-client integrator asks for first, and nobody had
//! measured it. [`zkasper_common::recursion::verify_child`] runs the Zisk STARK
//! verifier in pure Rust — no GPU, no proving key, no 26 GB of setup — and that
//! property is the entire reason verifying a zkasper proof inside Helios is
//! possible at all. The tests assert it returns `true`; none of them says what
//! it costs.
//!
//! The timing cannot live in `zkasper-common`: that crate is compiled into every
//! guest, where `tracing` has no business and every byte of it is proving work.
//! So the instrumentation is here, on the host side, and this is the function a
//! host-side verifier should call instead of the raw one.
//!
//! It is off the latency path by construction. The daemon verifies an epoch's
//! proof *after* `T2` has been stamped, so what this measures can never inflate
//! the latency the project quotes.

use tracing::{info_span, warn};

use zkasper_common::recursion::{verify_child, ProgramVk};

use crate::prover::Stage;

/// Verify one proof against the program and public outputs it must commit to,
/// recording how long that took.
///
/// Returns `None` when there is nothing to check — a witness-only run produces
/// empty proofs, and calling this on one would record a verification that did
/// no work and flatter the histogram.
pub fn timed(stage: Stage, proof: &[u64], vk: &ProgramVk, publics: &[u8]) -> Option<bool> {
    if proof.is_empty() {
        return None;
    }
    let accepted = {
        // Synchronous from here to the end of the scope, so entering the span
        // rather than instrumenting a future is the honest shape.
        let _span = info_span!("verify", stage = stage.as_str(), words = proof.len()).entered();
        verify_child(proof, vk, publics)
    };
    crate::metrics::verified(stage, accepted);
    if !accepted {
        warn!(
            stage = stage.as_str(),
            words = proof.len(),
            "a proof this daemon produced does not verify",
        );
    }
    Some(accepted)
}

//! The child keys the guests were compiled against, seen from the host.
//!
//! A guest binds its children to constants rather than to witness fields, which
//! is what makes a recursive verification name a *program*. Nothing here is
//! authoritative — the constants live in the guest crates, and
//! `scripts/bake_child_vks.sh` writes them — but the host is where a mismatch
//! can be caught early and said out loud.
//!
//! [`check`] is that catch. A prover derives every key from the ELF it loaded;
//! if that key is not the one the guests were baked against, the two halves of
//! the pipeline disagree about which program is which, and every recursive
//! verification downstream would fail one proof at a time, minutes apart. It
//! fails at startup instead.

use anyhow::{bail, Result};

use zkasper_common::recursion::{ProgramVk, UNSET_VK};

use crate::prover::Stage;

pub const SLOT: ProgramVk = zkasper_justification_guest::child_vks::SLOT_PROGRAM_VK;
pub const COMMITTEE: ProgramVk = zkasper_aggregation_guest::child_vks::COMMITTEE_PROGRAM_VK;
pub const EPOCH_DIFF: ProgramVk = zkasper_aggregation_guest::child_vks::EPOCH_DIFF_PROGRAM_VK;
pub const GROUP: ProgramVk = zkasper_aggregation_guest::child_vks::GROUP_PROGRAM_VK;
pub const AGGREGATE: ProgramVk = zkasper_stream_final_guest::child_vks::AGGREGATE_PROGRAM_VK;
pub const JUSTIFICATION: ProgramVk =
    zkasper_stream_final_guest::child_vks::JUSTIFICATION_PROGRAM_VK;

/// The key a parent guest bakes for `stage`, when some parent bakes one.
///
/// `None` for the two stages nothing verifies: a finalization and a stream
/// final proof are consumed by a verifier, not by another circuit.
pub fn baked(stage: Stage) -> Option<ProgramVk> {
    Some(match stage {
        Stage::SlotProof => SLOT,
        Stage::Committee => COMMITTEE,
        Stage::EpochDiff => EPOCH_DIFF,
        Stage::Group => GROUP,
        Stage::Aggregate => AGGREGATE,
        Stage::Justification => JUSTIFICATION,
        Stage::Finalization | Stage::StreamFinal => return None,
    })
}

/// Refuse an ELF that is not the program the guests were built to verify.
///
/// A prover with no ELF at all reports [`UNSET_VK`] and so does an unbaked
/// guest, which is why both being unset passes: native mode proves nothing, and
/// there is nothing to disagree about. A real ELF never has that key, so an
/// unbaked guest facing a real prover fails here as the mismatch it is.
pub fn check(stage: Stage, derived: &ProgramVk) -> Result<()> {
    let Some(baked) = baked(stage) else {
        return Ok(());
    };
    if baked == *derived {
        return Ok(());
    }
    if baked == UNSET_VK {
        bail!(
            "the guests were built before the {} program had a key, so no parent proof could \
             verify one; run scripts/bake_child_vks.sh and rebuild the guests",
            stage.as_str(),
        );
    }
    bail!(
        "the {} program has key {derived:?}, but the guests were built to verify {baked:?}; \
         rebuild the guests with scripts/bake_child_vks.sh",
        stage.as_str(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two guests bake the same program's key, and the bake writes both. A pair
    /// that drifted would pin one chain to a program the other rejects.
    #[test]
    fn the_duplicated_keys_agree() {
        assert_eq!(
            zkasper_finalization_guest::child_vks::JUSTIFICATION_PROGRAM_VK,
            zkasper_stream_final_guest::child_vks::JUSTIFICATION_PROGRAM_VK,
        );
        assert_eq!(
            zkasper_finalization_guest::child_vks::EPOCH_DIFF_PROGRAM_VK,
            zkasper_aggregation_guest::child_vks::EPOCH_DIFF_PROGRAM_VK,
        );
    }

    #[test]
    fn a_stage_nothing_verifies_has_nothing_to_check() {
        assert!(baked(Stage::StreamFinal).is_none());
        assert!(check(Stage::StreamFinal, &[7; 4]).is_ok());
    }

    /// The check that stops a prover holding somebody else's ELF. Whatever the
    /// guests were baked against, a key that is not it has to be refused —
    /// otherwise every recursion downstream binds a program nobody chose.
    #[test]
    fn an_elf_the_guests_were_not_built_against_is_refused() {
        let wrong = [0xdead_beef_u64; 4];
        assert_ne!(baked(Stage::SlotProof), Some(wrong));
        let error = format!(
            "{:#}",
            check(Stage::SlotProof, &wrong).expect_err("a foreign slot-proof ELF"),
        );
        assert!(error.contains("bake_child_vks.sh"), "{error}");
    }
}

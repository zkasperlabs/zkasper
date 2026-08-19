//! Finalization proofs that reached a chain.
//!
//! The daemon proves; something else submits. That something — today the
//! `zkasper-cli` in the `zkasper-solana` repository — appends one JSON object
//! per accepted transaction to a file, and this module reads it. Keeping the
//! two apart means the submitter can be replaced, or run on another machine,
//! without the daemon growing a wallet.
//!
//! The shape is the `posting` object of `docs/finality/api-v1.md`. Fields the
//! submitter
//! did not report are absent rather than zero, on the same terms as every other
//! number this daemon publishes.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tracing::warn;

/// How many postings the status manifest carries. The website renders a list,
/// not a history; the whole history is in the event stream.
const KEEP: usize = 16;

/// One finalization proof, verified on another chain.
///
/// `fee_lamports` is the transaction fee. `rent_lamports` is what the submitter
/// left behind as the rent-exempt balance of the accounts the program created,
/// which is the larger number and is not refundable. `lamports_spent` is both.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Posting {
    /// Which chain, as `solana-mainnet-beta`, `solana-devnet` or `solana-localnet`.
    pub chain: String,
    pub program: String,
    /// Ethereum epoch the posted proof finalized.
    pub epoch: u64,
    pub finalized_root: String,
    pub signature: String,
    /// Slot of the chain it was posted to, not of Ethereum.
    pub slot: u64,
    pub compute_units: u64,
    pub fee_lamports: u64,
    pub rent_lamports: u64,
    pub lamports_spent: u64,
    /// `confirmed` or `failed`, as the submitter observed it.
    pub status: String,
    pub explorer: String,
    pub unix_millis: u64,
}

/// The postings file, read as it grows.
///
/// A submitter that runs anywhere writes lines; the daemon reads whole lines and
/// forgets the rest until next time. A partially written line is not an error,
/// it is a line that has not finished arriving.
pub struct PostingLog {
    path: PathBuf,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    recent: Vec<Posting>,
    seen: HashSet<String>,
}

impl PostingLog {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Re-reads the file and returns the postings that were not there before.
    ///
    /// Takes `&self` because the status manifest is built from an immutable
    /// borrow. Re-reading whole rather than tailing keeps it correct across a
    /// truncation, and the file holds a handful of lines an epoch.
    pub fn refresh(&self) -> Vec<Posting> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
            Err(e) => {
                warn!(path = %self.path.display(), error = %e, "cannot read the postings file");
                return Vec::new();
            }
        };

        let mut inner = self.inner.lock().expect("postings lock");
        let mut fresh = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let posting: Posting = match serde_json::from_str(line) {
                Ok(posting) => posting,
                Err(e) => {
                    warn!(error = %e, "skipping a posting that does not parse");
                    continue;
                }
            };
            if !inner.seen.insert(posting.signature.clone()) {
                continue;
            }
            inner.recent.push(posting.clone());
            fresh.push(posting);
        }
        let excess = inner.recent.len().saturating_sub(KEEP);
        inner.recent.drain(..excess);
        fresh
    }

    /// The most recent postings, oldest first.
    pub fn recent(&self) -> Vec<Posting> {
        self.inner.lock().expect("postings lock").recent.clone()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(signature: &str, epoch: u64) -> String {
        serde_json::to_string(&Posting {
            chain: "solana-devnet".into(),
            program: "Cuarryex9DFpVm6HNdCFvpS3EEeArSuTXDMNTk9hpKja".into(),
            epoch,
            finalized_root: "0x00".into(),
            signature: signature.into(),
            slot: 7,
            compute_units: 99_150,
            fee_lamports: 5_000,
            rent_lamports: 2_867_520,
            lamports_spent: 2_872_520,
            status: "confirmed".into(),
            explorer: "https://explorer.solana.com/tx/x?cluster=devnet".into(),
            unix_millis: 1,
        })
        .unwrap()
    }

    #[test]
    fn reports_each_posting_once() {
        let dir = std::env::temp_dir().join("zkasper-postings-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("postings.jsonl");
        std::fs::write(&path, format!("{}\n", line("aaa", 1))).unwrap();

        let log = PostingLog::new(&path);
        assert_eq!(log.refresh().len(), 1);
        assert!(log.refresh().is_empty());

        std::fs::write(&path, format!("{}\n{}\n", line("aaa", 1), line("bbb", 2))).unwrap();
        let fresh = log.refresh();
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].epoch, 2);
        assert_eq!(log.recent().len(), 2);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_missing_file_is_not_an_error() {
        assert!(PostingLog::new("/nonexistent/postings.jsonl")
            .refresh()
            .is_empty());
    }

    /// The line the `zkasper-solana` CLI writes must parse here unchanged.
    #[test]
    fn parses_what_the_submitter_writes() {
        let written = r#"{"chain":"solana-devnet","cluster":"devnet","compute_units":99150,"epoch":300001,"explorer":"https://explorer.solana.com/tx/4Jr?cluster=devnet","fee_lamports":5000,"finalized_root":"0x60fd","finalized_state_root":"0xee5e","lamports_spent":2872520,"program":"Cuarryex9DFpVm6HNdCFvpS3EEeArSuTXDMNTk9hpKja","rent_lamports":2867520,"signature":"4Jr","slot":11,"status":"confirmed","unix_millis":1787080977646}"#;
        let posting: Posting = serde_json::from_str(written).unwrap();
        assert_eq!(posting.epoch, 300_001);
        assert_eq!(posting.compute_units, 99_150);
        assert_eq!(posting.rent_lamports, 2_867_520);
    }
}

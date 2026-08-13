//! Persistent storage for the accumulator tree state and epoch cursor.
//!
//! Uses simple file-based persistence with bincode serialization.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use zkasper_common::acc::Digest;

use crate::acc_tree::AccTree;

#[derive(Serialize, Deserialize)]
struct DbState {
    tree_levels: Vec<Vec<Digest>>,
    tree_depth: u32,
    dense_depth: u32,
    cursor_epoch: u64,
    total_active_balance: u64,
    num_validators: u64,
}

pub struct Db {
    path: PathBuf,
}

impl Db {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Save the accumulator tree and tracking metadata to disk.
    pub fn save(
        &self,
        tree: &AccTree,
        cursor_epoch: u64,
        total_active_balance: u64,
        num_validators: u64,
    ) -> Result<()> {
        let state = DbState {
            tree_levels: tree.levels.clone(),
            tree_depth: tree.depth,
            dense_depth: tree.dense_depth,
            cursor_epoch,
            total_active_balance,
            num_validators,
        };
        let bytes = bincode::serialize(&state).context("serialize db state")?;
        std::fs::write(&self.path, bytes).context("write db file")?;
        Ok(())
    }

    /// Load the saved state from disk.
    ///
    /// Returns `None` if the file does not exist.
    /// Returns `(tree, cursor_epoch, total_active_balance, num_validators)`.
    pub fn load(&self) -> Result<Option<(AccTree, u64, u64, u64)>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&self.path).context("read db file")?;
        let state: DbState = bincode::deserialize(&bytes).context("deserialize db state")?;
        let tree = AccTree::from_raw(state.tree_levels, state.tree_depth, state.dense_depth);
        Ok(Some((
            tree,
            state.cursor_epoch,
            state.total_active_balance,
            state.num_validators,
        )))
    }
}

//! Which network a beacon node is actually on.
//!
//! `--chain` selects parameters: slots per epoch, tree depths, the fork
//! schedule. It cannot select a network. A synthetic node running mainnet
//! parameters over twelve validators answers every question mainnet answers,
//! and a run that took its label from the flag published that node's twelve
//! validators as mainnet.
//!
//! The genesis validators root is the network's identity. It is the hash tree
//! root of the genesis validator registry, it is fixed for the life of the
//! chain, and every signing domain on that chain is derived from it — so a node
//! that reports one and a validator set that signs against it are the same
//! network by construction. The daemon already fetches it for the attestation
//! domain. The label comes from there.
//!
//! A root this table does not hold is [`UNRECOGNISED`]. Publishing that is the
//! point: a network nobody here can name is not evidence of mainnet.

use anyhow::{ensure, Context, Result};
use tracing::warn;

use crate::beacon_api::ChainStatusApi;

/// The networks this daemon will name, by the genesis validators root a node
/// on each one reports at `/eth/v1/beacon/genesis`.
///
/// Hex rather than bytes so an operator can compare a line of this table
/// against a block explorer without decoding anything.
pub const KNOWN: [(&str, &str); 2] = [
    (
        "mainnet",
        "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
    ),
    (
        "gnosis",
        "f5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47",
    ),
];

/// What a run publishes as its chain when no known network claims its node.
pub const UNRECOGNISED: &str = "unrecognised";

/// The network `root` identifies, or `None` when no known network claims it.
///
/// `None` is not a failure. It is the honest answer for a devnet, a testnet
/// this table has never heard of, or a synthetic node, and the caller must
/// publish [`UNRECOGNISED`] rather than fall back to what it was told.
pub fn name_for(root: &[u8; 32]) -> Option<&'static str> {
    let root = hex::encode(root);
    KNOWN
        .iter()
        .find(|(_, known)| *known == root)
        .map(|(name, _)| *name)
}

/// The label a run reporting `root` may publish.
pub fn label_for(root: &[u8; 32]) -> &'static str {
    name_for(root).unwrap_or(UNRECOGNISED)
}

/// Ask the node what network it is on, and return the label to publish beside
/// the root it was resolved from.
///
/// `parameters` is the network `--chain` selected constants for. A node whose
/// root names a *different* known network is an error rather than a relabelling:
/// the run would be proving one chain's attestations against another's slots
/// per epoch. A root no network claims is not an error — that is a devnet, and
/// it publishes as [`UNRECOGNISED`].
pub async fn resolve(api: &impl ChainStatusApi, parameters: &str) -> Result<(String, [u8; 32])> {
    let root = api
        .get_genesis_validators_root()
        .await
        .context("fetch the genesis validators root, which is what names a network")?;
    match name_for(&root) {
        Some(named) => {
            ensure!(
                named == parameters,
                "--chain {parameters} but the node's genesis validators root 0x{} is {named}",
                hex::encode(root),
            );
        }
        None => warn!(
            genesis_validators_root = %format!("0x{}", hex::encode(root)),
            chain_parameters = parameters,
            "no known network has this genesis validators root; publishing as {UNRECOGNISED}",
        ),
    }
    Ok((label_for(&root).to_string(), root))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    #[test]
    fn names_the_networks_it_knows() {
        for (name, known) in KNOWN {
            assert_eq!(name_for(&root(known)), Some(name));
        }
    }

    #[test]
    fn refuses_to_name_a_root_it_does_not_know() {
        // A synthetic node running mainnet parameters: every constant matches
        // mainnet, the genesis it grew from does not.
        assert_eq!(name_for(&[0x11; 32]), None);
        assert_eq!(label_for(&[0x11; 32]), UNRECOGNISED);
    }

    #[test]
    fn one_root_names_one_network() {
        for (i, (_, a)) in KNOWN.iter().enumerate() {
            for (_, b) in &KNOWN[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }
}

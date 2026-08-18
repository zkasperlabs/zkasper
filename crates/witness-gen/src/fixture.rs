//! Synthetic epochs, for tests and for the witness-file generator.
//!
//! Complement proving needs more of a fixture than the old scheme did: a slot's
//! attesters are only meaningful against a committee, and the committee has to
//! be summed out of the same accumulator the attesters are opened from. Building
//! that in one place is what keeps the tests and the `.bin` files
//! `gen-test-witness` writes from drifting apart.
//!
//! Everything here uses real BLS keys and real signatures. The accumulator leaf
//! commits to a decompressed public key, so a synthetic byte pattern is not a
//! key at all, and the whole point of the scheme is that the signature is what
//! pins the absentee set — a fixture that faked it would test nothing.

use std::sync::Arc;

use zkasper_common::acc::{self, Digest};
use zkasper_common::bls::{compute_domain, compute_signing_root, DOMAIN_BEACON_ATTESTER};
use zkasper_common::constants::FAR_FUTURE_EPOCH;
use zkasper_common::ssz::attestation_data_root;
use zkasper_common::types::{
    AttestationWitness, BlsPubkey, BlsSignature, SlotComplementWitness, ValidatorData,
};
use zkasper_common::ChainConfig;

use crate::acc_tree::AccTree;
use crate::attestation_collector::SlotComplement;
use crate::beacon_api::{CommitteeResponse, ValidatorResponse};
use crate::committee::EpochCommittees;

/// One synthetic epoch: validators, accumulator, committees and keys.
pub struct Epoch {
    pub config: ChainConfig,
    pub epoch: u64,
    pub target_root: [u8; 32],
    pub source_root: [u8; 32],
    pub signing_domain: [u8; 32],
    pub keys: Vec<blst::min_pk::SecretKey>,
    pub validators: Vec<ValidatorData>,
    pub responses: Vec<ValidatorResponse>,
    pub tree: AccTree,
    pub committees: Arc<EpochCommittees>,
    pub acc_root: Digest,
    pub total_active_balance: u64,
    pub accumulator_commitment: Digest,
}

impl Epoch {
    /// `per_slot` validators in each of the first `slots` committees of `epoch`.
    ///
    /// Validators are handed out in index order, so committee `s` holds indices
    /// `s * per_slot .. (s + 1) * per_slot` — a partition, which is all the
    /// committee proof needs it to be.
    pub fn new(config: ChainConfig, epoch: u64, slots: u64, per_slot: usize) -> Self {
        let balance = 32_000_000_000u64;
        let keys: Vec<blst::min_pk::SecretKey> = (0..slots as usize * per_slot)
            .map(|i| {
                let mut ikm = [0u8; 32];
                ikm[0] = i as u8;
                ikm[1] = (i >> 8) as u8;
                ikm[2] = 0xAB;
                blst::min_pk::SecretKey::key_gen(&ikm, &[]).expect("key_gen")
            })
            .collect();

        let validators: Vec<ValidatorData> = keys
            .iter()
            .map(|sk| ValidatorData {
                pubkey: BlsPubkey(sk.sk_to_pk().compress()),
                effective_balance: balance,
                activation_epoch: 0,
                exit_epoch: FAR_FUTURE_EPOCH,
            })
            .collect();

        let responses: Vec<ValidatorResponse> = validators
            .iter()
            .enumerate()
            .map(|(i, v)| ValidatorResponse {
                index: i as u64,
                pubkey: v.pubkey.0,
                effective_balance: v.effective_balance,
                activation_epoch: v.activation_epoch,
                exit_epoch: v.exit_epoch,
                withdrawal_credentials: {
                    let mut wc = [0u8; 32];
                    wc[0] = 0x01;
                    wc
                },
                slashed: false,
                activation_eligibility_epoch: 0,
                withdrawable_epoch: FAR_FUTURE_EPOCH,
            })
            .collect();

        let committee_responses: Vec<CommitteeResponse> = (0..slots)
            .map(|s| CommitteeResponse {
                slot: epoch * config.slots_per_epoch + s,
                index: 0,
                validators: (0..per_slot as u64)
                    .map(|i| s * per_slot as u64 + i)
                    .collect(),
            })
            .collect();

        let total_active_balance = validators.len() as u64 * balance;
        let tree = AccTree::build(&validators, epoch, config.acc_tree_depth);
        let acc_root = tree.root();
        let committees = crate::committee::build(
            &committee_responses,
            &responses,
            &tree,
            &config,
            epoch,
            epoch,
            total_active_balance,
        )
        .expect("build committees");

        Self {
            epoch,
            target_root: [0x07; 32],
            source_root: [0x01; 32],
            signing_domain: compute_domain(&DOMAIN_BEACON_ATTESTER, &[0x04, 0, 0, 0], &[0xAA; 32]),
            keys,
            validators,
            responses,
            tree,
            committees: Arc::new(committees),
            acc_root,
            total_active_balance,
            accumulator_commitment: acc::commitment(&acc_root, total_active_balance),
            config,
        }
    }

    /// Global slot of `slot_in_epoch`.
    pub fn slot(&self, slot_in_epoch: u64) -> u64 {
        self.epoch * self.config.slots_per_epoch + slot_in_epoch
    }

    /// The signing root of the `AttestationData` a slot's committee votes on.
    ///
    /// `beacon_block_root` is what separates the primary message from a minority
    /// head vote; everything else about the data is fixed by the checkpoint.
    pub fn signing_root(&self, slot_in_epoch: u64, beacon_block_root: [u8; 32]) -> [u8; 32] {
        compute_signing_root(
            &attestation_data_root(
                self.slot(slot_in_epoch),
                0,
                &beacon_block_root,
                self.epoch.saturating_sub(1),
                &self.source_root,
                self.epoch,
                &self.target_root,
            ),
            &self.signing_domain,
        )
    }

    /// Aggregate signature of `signers` over one message.
    pub fn sign(&self, signers: &[u64], signing_root: &[u8; 32]) -> [u8; 96] {
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
        let signatures: Vec<blst::min_pk::Signature> = signers
            .iter()
            .map(|&i| self.keys[i as usize].sign(signing_root, dst, &[]))
            .collect();
        let refs: Vec<&blst::min_pk::Signature> = signatures.iter().collect();
        blst::min_pk::AggregateSignature::aggregate(&refs, true)
            .expect("aggregate")
            .to_signature()
            .to_bytes()
    }

    /// One slot's complement: everyone in the committee attests except `absent`.
    ///
    /// `absent` holds global validator indices.
    pub fn complement(&self, slot_in_epoch: u64, absent: &[u64]) -> SlotComplement {
        self.complement_with_minority(slot_in_epoch, absent, &[])
    }

    /// A complement where `minority` signs a different head than everyone else.
    pub fn complement_with_minority(
        &self,
        slot_in_epoch: u64,
        absent: &[u64],
        minority: &[u64],
    ) -> SlotComplement {
        let members = &self.committees.members[slot_in_epoch as usize];
        let primary_signers: Vec<u64> = members
            .iter()
            .copied()
            .filter(|i| !absent.contains(i) && !minority.contains(i))
            .collect();

        let mut named: Vec<u64> = absent.to_vec();
        named.extend_from_slice(minority);
        named.sort_unstable();

        let mut secondary = Vec::new();
        if !minority.is_empty() {
            let head = [0x33u8; 32];
            secondary.push(AttestationWitness {
                signature: BlsSignature(
                    self.sign(minority, &self.signing_root(slot_in_epoch, head)),
                ),
                attesting_validators: minority.iter().map(|&i| self.opened(i)).collect(),
                ..self.data(slot_in_epoch, head)
            });
        }

        let absentees: Vec<_> = {
            let mut sorted = absent.to_vec();
            sorted.sort_unstable();
            sorted.iter().map(|&i| self.opened(i)).collect()
        };
        let marginal_balance = self.committees.aggregate(slot_in_epoch).unwrap().balance
            - absentees
                .iter()
                .map(|v| v.active_effective_balance)
                .sum::<u64>();

        SlotComplement {
            slot: self.slot(slot_in_epoch),
            marginal_balance,
            named_indices: named,
            witness: SlotComplementWitness {
                slot_in_epoch,
                committee: self.committees.aggregate(slot_in_epoch).unwrap().clone(),
                primary: vec![AttestationWitness {
                    signature: BlsSignature(self.sign(
                        &primary_signers,
                        &self.signing_root(slot_in_epoch, [0u8; 32]),
                    )),
                    ..self.data(slot_in_epoch, [0u8; 32])
                }],
                secondary,
                absentees,
            },
        }
    }

    /// The leaf preimage the accumulator holds for one validator.
    pub fn opened(&self, index: u64) -> zkasper_common::types::OpenedValidator {
        crate::committee::opened(index, &self.responses[index as usize], self.epoch)
            .expect("open validator")
    }

    /// An `AttestationWitness` with the checkpoint fields filled in and no
    /// signature or signers — the caller supplies those.
    fn data(&self, slot_in_epoch: u64, beacon_block_root: [u8; 32]) -> AttestationWitness {
        AttestationWitness {
            data_slot: self.slot(slot_in_epoch),
            data_index: 0,
            data_beacon_block_root: beacon_block_root,
            data_source_epoch: self.epoch.saturating_sub(1),
            data_source_root: self.source_root,
            data_target_epoch: self.epoch,
            data_target_root: self.target_root,
            signature: BlsSignature([0; 96]),
            attesting_validators: Vec::new(),
        }
    }
}

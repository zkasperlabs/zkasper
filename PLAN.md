# zkasper — implementation plan

ZK proof of Ethereum beacon chain finality for trustless bridges, targeting Zisk zkVM.

## workspace layout

```
zkasper/
├── Cargo.toml                          # workspace root
├── PLAN.md
├── crates/
│   ├── common/                         # shared types, SSZ, Poseidon, Merkle, BLS
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── types.rs                # witness structs, validator data, checkpoint
│   │       ├── ssz.rs                  # SHA-256 Merkle ops, validator chunking
│   │       ├── poseidon.rs             # Poseidon hash over BN254 Fr + Merkle ops
│   │       ├── bls.rs                  # BLS12-381 sig verification, hash-to-G2
│   │       └── merkle.rs              # generic Merkle verify/update (hash-agnostic)
│   │
│   ├── witness-gen/                    # host-side: beacon API, diffing, Poseidon tree
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs                 # CLI (bootstrap / epoch-diff / finality / run)
│   │       ├── beacon_api.rs           # standard Beacon REST API client
│   │       ├── state_diff.rs           # diff two validator registries, build SSZ proofs
│   │       ├── poseidon_tree.rs        # full Poseidon tree in memory, incremental updates
│   │       ├── attestation_collector.rs # collect attestations for a target checkpoint
│   │       ├── witness_epoch_diff.rs   # assemble EpochDiffWitness
│   │       ├── witness_finality.rs     # assemble FinalityWitness
│   │       ├── witness_bootstrap.rs    # assemble BootstrapWitness
│   │       └── db.rs                   # bincode file persistence for Poseidon tree + cursor
│   │
│   ├── epoch-diff-guest/               # Zisk guest binary: Proof 1
│   │   ├── Cargo.toml
│   │   └── src/main.rs
│   │
│   ├── finality-guest/                 # Zisk guest binary: Proof 2
│   │   ├── Cargo.toml
│   │   └── src/main.rs
│   │
│   ├── bootstrap-guest/                # Zisk guest binary: one-time tree build
│   │   ├── Cargo.toml
│   │   └── src/main.rs
│   │
│   └── onchain-verifier/               # Solidity verifier stub
│       └── src/ZkasperVerifier.sol
```

## dependencies

workspace `Cargo.toml`:
```toml
[workspace]
members = ["crates/*"]
resolver = "2"

[workspace.dependencies]
serde = { version = "1", default-features = false, features = ["derive"] }
bincode = "1.3"
sha2 = "0.10"
ark-ff = "0.5"
ark-bn254 = "0.5"
ark-bls12-381 = "0.5"
ark-ec = "0.5"
ark-serialize = "0.5"
light-poseidon = "0.4"
ziskos = { git = "https://github.com/0xPolygonHermez/zisk.git", tag = "v0.15.0" }
```

guest crates need `[patch.crates-io]` for Zisk-patched crypto:
```toml
[patch.crates-io]
sha2 = { git = "https://github.com/0xPolygonHermez/zisk-patch-hashes.git" }
ark-ff = { git = "https://github.com/0xPolygonHermez/zisk-patch-ark-algebra.git" }
ark-bn254 = { git = "https://github.com/0xPolygonHermez/zisk-patch-ark-algebra.git" }
ark-bls12-381 = { git = "https://github.com/0xPolygonHermez/zisk-patch-ark-algebra.git" }
ark-ec = { git = "https://github.com/0xPolygonHermez/zisk-patch-ark-algebra.git" }
ark-serialize = { git = "https://github.com/0xPolygonHermez/zisk-patch-ark-algebra.git" }
```

`witness-gen` additionally depends on: `tokio`, `reqwest`, `clap`, `anyhow`, `serde_json`, `hex`, `async-trait`, `bincode`.

## crate: `common`

### `types.rs` — core data structures

```rust
pub struct BlsPubkey(pub [u8; 48]);
pub struct BlsSignature(pub [u8; 96]);

/// only the fields we need from a Validator
pub struct ValidatorData {
    pub pubkey: BlsPubkey,
    pub effective_balance: u64,   // Gwei
    pub activation_epoch: u64,
    pub exit_epoch: u64,
}

pub struct Checkpoint {
    pub epoch: u64,
    pub root: [u8; 32],
}

/// one changed validator between two epochs
pub struct ValidatorMutation {
    pub validator_index: u64,
    pub old_data: ValidatorData,
    pub new_data: ValidatorData,
    // 8 field-level SSZ hash tree leaves for the Validator container
    pub old_field_leaves: [[u8; 32]; 8],
    pub new_field_leaves: [[u8; 32]; 8],
    // raw pubkey split into 2x32-byte chunks (to verify field_leaves[0])
    pub old_pubkey_chunks: [[u8; 32]; 2],
    pub new_pubkey_chunks: [[u8; 32]; 2],
    // SHA-256 siblings in validators data tree (depth 40)
    pub old_ssz_siblings: Vec<[u8; 32]>,
    pub new_ssz_siblings: Vec<[u8; 32]>,
    // Poseidon siblings (depth 40)
    pub poseidon_siblings: Vec<[u8; 32]>,
}

pub struct EpochDiffWitness {
    pub state_root_1: [u8; 32],
    pub state_root_2: [u8; 32],
    pub poseidon_root_1: [u8; 32],
    pub total_active_balance_1: u64,
    pub epoch_2: u64,
    pub state_to_validators_siblings_1: Vec<[u8; 32]>,
    pub state_to_validators_siblings_2: Vec<[u8; 32]>,
    pub validators_list_length_1: u64,
    pub validators_list_length_2: u64,
    pub mutations: Vec<ValidatorMutation>,
}

pub struct AttestingValidator {
    pub validator_index: u64,
    pub pubkey: BlsPubkey,
    pub active_effective_balance: u64,
    pub poseidon_siblings: Vec<[u8; 32]>,
}

pub struct AttestationWitness {
    // Raw AttestationData fields (circuit recomputes hash_tree_root and verifies target)
    pub data_slot: u64,
    pub data_index: u64,
    pub data_beacon_block_root: [u8; 32],
    pub data_source_epoch: u64,
    pub data_source_root: [u8; 32],
    pub data_target_epoch: u64,
    pub data_target_root: [u8; 32],
    pub signature: BlsSignature,
    pub attesting_validators: Vec<AttestingValidator>,
}

pub struct FinalityWitness {
    // public inputs (circuit outputs)
    pub accumulator_commitment: [u8; 32],   // poseidon(poseidon_root, total_active_balance)
    pub finalized_block_root: [u8; 32],
    // private witness
    pub poseidon_root: [u8; 32],
    pub total_active_balance: u64,
    pub signing_domain: [u8; 32],
    pub attestations: Vec<AttestationWitness>,
}

pub struct BootstrapWitness {
    pub state_root: [u8; 32],
    pub epoch: u64,
    pub validators: Vec<ValidatorData>,
    pub state_to_validators_siblings: Vec<[u8; 32]>,
    pub validators_list_length: u64,
    pub validator_field_chunks: Vec<[[u8; 32]; 8]>,
    pub validator_pubkey_chunks: Vec<[[u8; 32]; 2]>,
}
```

### `ssz.rs` — SHA-256 Merkle operations

- `sha256_pair(left, right) -> [u8; 32]` — uses `sha2` crate (routes through `syscall_sha256_f` on Zisk)
- `validator_hash_tree_root(field_leaves: &[[u8; 32]; 8]) -> [u8; 32]` — merkleize 8 leaves (depth 3, 7 hashes)
- `list_hash_tree_root(data_root, length) -> [u8; 32]` — `sha256(data_root || le_bytes_pad32(length))`
- `verify_ssz_field_leaves(data: &ValidatorData, field_leaves: &[[u8; 32]; 8], pubkey_chunks: &[[u8; 32]; 2])` — check that the field leaves encode the claimed values

SSZ Validator container field layout (8 fields, each hashed to one leaf):
```
leaf[0] = sha256(pubkey[0..32] || pubkey[32..48]++zeros)
leaf[1] = withdrawal_credentials (32 bytes, opaque)
leaf[2] = le_pad32(effective_balance)
leaf[3] = le_pad32(slashed)
leaf[4] = le_pad32(activation_eligibility_epoch)
leaf[5] = le_pad32(activation_epoch)
leaf[6] = le_pad32(exit_epoch)
leaf[7] = le_pad32(withdrawable_epoch)
```

We verify leaves 0, 2, 5, 6 match the claimed `ValidatorData`. Leaves 1, 3, 4, 7 are opaque (provided by witness, hashed but not interpreted).

### `poseidon.rs` — Poseidon over BN254 Fr

- `poseidon_leaf(pubkey: &[u8; 48], active_eff_balance: u64) -> [u8; 32]`
  - `Poseidon(Fr(pubkey[0..32]), Fr(pubkey[32..48]++zeros), Fr(balance))`
  - uses `light-poseidon` with `new_circom(3)` (t=4, 3 inputs)
- `poseidon_pair(left, right) -> [u8; 32]` — for internal Merkle nodes, `new_circom(2)` (t=3)
- `compute_poseidon_merkle_root(leaf, index, siblings) -> [u8; 32]`
- `verify_poseidon_merkle_proof(leaf, index, siblings, root) -> bool`

On Zisk: `ark-ff` field ops route through `syscall_arith256_mod`, making each Poseidon hash ~300-500 modular arithmetic syscalls. No dedicated Poseidon precompile exists yet — this is the main perf bottleneck to discuss with Jordi.

### `bls.rs` — BLS12-381 signature verification

- `aggregate_pubkeys(pubkeys: &[[u8; 48]]) -> G1Projective` — G1 point additions
- `hash_to_g2(message: &[u8]) -> G2Projective` — IETF hash-to-curve (`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`)
- `verify_aggregate_signature(agg_pk, signing_root, signature) -> bool` — pairing check

On Zisk: curve ops via `syscall_bls12_381_{curve_add,curve_dbl,complex_*}`. Pairing built from Miller loop + final exponentiation using these primitives via patched `ark-bls12-381`.

### `merkle.rs` — generic Merkle helpers

Hash-function-agnostic `compute_root` and `verify_proof` parameterized by a closure `Fn(&[u8;32], &[u8;32]) -> [u8;32]`. Used by both SSZ and Poseidon code.

## crate: `epoch-diff-guest` (Proof 1)

Guest program logic (`#![no_main]`, `ziskos::entrypoint!(main)`):

1. Deserialize `EpochDiffWitness` from `read_input_slice()` via bincode
2. For each mutation:
   a. Verify `old_field_leaves` encode `old_data` (check pubkey_chunks hash to leaf[0], check scalar fields in leaves 2/5/6)
   b. Same for `new_field_leaves` / `new_data`
   c. Compute `old_validator_root = merkleize(old_field_leaves)`, verify Merkle path to SSZ data tree root via `old_ssz_siblings`
   d. Same for new -> get SSZ data tree root 2
   e. Verify old Poseidon leaf against `poseidon_root` (accumulative — each mutation updates the running root)
   f. Compute new Poseidon leaf, derive new `poseidon_root`
   g. Accumulate balance delta
3. All mutations must agree on the same SSZ data tree roots (verified implicitly since they each compute a full Merkle root)
4. Verify SSZ data tree roots link to `state_root_1` / `state_root_2` via `state_to_validators_siblings` + list length mix-in
5. Output: `poseidon_root_2` (8 x u32) + `total_active_balance_2` (2 x u32)

**Cost**: ~200 mutations x (7 SHA256 per validator root + 40 SHA256 Merkle path) x 2 trees + 200 x 40 Poseidon = ~19K SHA256 + ~8K Poseidon. Cheap.

**V2 optimization**: diff walk — instead of independent Merkle proofs per mutation, walk both trees top-down opening only diverging branches. Reduces to ~4K SHA256. Deferred.

**Note on sequential Poseidon updates**: Mutations must be processed in order. The Poseidon siblings for mutation N are valid only BEFORE mutations 0..N-1 are applied. The witness generator extracts siblings then applies the update.

## crate: `finality-guest` (Proof 2)

Guest program logic:

1. Deserialize `FinalityWitness`
2. For each attestation:
   a. For each `AttestingValidator`: compute `poseidon_leaf(pubkey, active_eff_balance)`, verify against `poseidon_root` via siblings. Accumulate balance. Collect pubkey.
   b. Aggregate pubkeys via G1 addition
   c. Compute `signing_root = sha256(attestation_data_root || signing_domain)`
   d. `hash_to_g2(signing_root)` -> message point
   e. BLS pairing check: `e(agg_pk, H(m)) == e(G1, sig)`
3. Assert `attesting_balance * 3 >= total_active_balance * 2`
4. Output: `finalized_checkpoint` (epoch + root)

**Cost**: ~700K validators x 40 Poseidon siblings = ~28M Poseidon hashes (dominant cost). ~32 BLS pairing checks. With batch Poseidon tree traversal (V2), reduces to ~1M Poseidon.

**Double-counting safety**: protocol guarantees — a validator voting twice for the same target epoch commits a slashable double vote. No in-circuit dedup needed.

## crate: `bootstrap-guest`

Guest program logic:

1. Deserialize `BootstrapWitness`
2. For each validator: verify field_chunks encode the claimed data, compute `validator_hash_tree_root`
3. Rebuild SSZ data tree bottom-up from all validator roots (~1M SHA256)
4. Verify data tree root -> state_root via list mix-in + state siblings
5. Compute all Poseidon leaves, build Poseidon tree bottom-up (~2M Poseidon)
6. Output: `poseidon_root` + `total_active_balance`

**Cost**: ~8M SHA256 + ~2M Poseidon. Must be chunked via recursive proof composition. Each chunk proves a subtree (e.g. 2^16 validators), final proof aggregates subtree roots.

## crate: `witness-gen`

Host-side Rust binary. Not compiled for Zisk.

### `beacon_api.rs`
Standard Beacon REST API client (`/eth/v2/debug/beacon/states/{id}`, `/eth/v1/beacon/states/{id}/validators`, `/eth/v1/beacon/blocks/{id}/attestations`, `/eth/v1/beacon/states/{id}/committees`).

### `poseidon_tree.rs`
Full Poseidon Merkle tree in memory (2^40 capacity, ~1M populated leaves). Supports:
- `build(validators, epoch)` — initial construction (~4M Poseidon hashes on host)
- `update_leaf(index, new_leaf) -> old_siblings` — returns siblings BEFORE update, then mutates
- `get_siblings(index) -> siblings` — for finality proof reads
- `root() -> [u8; 32]`
- `save/load` via bincode file for persistence across runs

### `state_diff.rs`
- Fetch two beacon states, extract validator registries
- Compare field-by-field to find mutations (~200 per epoch from churn + balance updates)
- Build full SSZ data trees on host (depth 40, ~1M validators), extract Merkle siblings per mutation
- Extract state_root -> validators proof (BeaconState top-level tree, field index 11)

### `attestation_collector.rs`
- Scan blocks in the finalized epoch for attestations targeting the finalized checkpoint
- Resolve committee assignments (committee_bits + aggregation_bits -> global validator indices)
- For each attesting validator, extract Poseidon proof from host tree
- Group by `AttestationData` (same signing root -> aggregate)

### CLI (`main.rs`)
```
zkasper-witness-gen bootstrap --beacon-url <URL> --slot <SLOT>
zkasper-witness-gen epoch-diff --beacon-url <URL> --slot1 <S1> --slot2 <S2>
zkasper-witness-gen finality --beacon-url <URL> --epoch <E>
zkasper-witness-gen run --beacon-url <URL>   # continuous mode
```

Outputs: `input.bin` (bincode-serialized witness) for the corresponding guest program.

## accumulator commitment

To minimize on-chain storage, the contract stores a single `accumulatorCommitment = poseidon(poseidon_root, total_active_balance)` instead of two separate values. The circuits compute this commitment internally:

- **Bootstrap** outputs: `(accumulator_commitment, state_root)`
- **EpochDiff** outputs: `(new_accumulator_commitment, state_root_1, state_root_2)`
- **Finality** outputs: `(accumulator_commitment, finalized_block_root)` — no epoch, the block root alone identifies what was finalized

Poseidon is used (not SHA-256) because the contract never recomputes the commitment — it only stores and compares. The circuits already use Poseidon everywhere.

## crate: `onchain-verifier`

`ZkasperVerifier.sol`:
- Stores: `accumulatorCommitment`, `latestStateRoot`, `latestFinalizedBlockRoot`, `initialized`
- `bootstrap(proof, publicOutputs)` — one-time init, extracts commitment + state_root
- `submitEpochDiff(proof, publicOutputs)` — verify proof, verify state_root_1 matches stored, update commitment + state_root
- `submitFinality(proof, publicOutputs)` — verify proof, verify commitment matches stored, update finalized block root
- `isFinalized(blockRoot) -> bool` — query

Verifier interface depends on Zisk's proof format (likely Groth16/FFLONK wrapper). Placeholder `IZiskVerifier.verify(proof, publicOutputs)`.

## implementation order

1. **Scaffold**: workspace Cargo.toml, all crate stubs, PLAN.md
2. **`common/merkle.rs`**: generic Merkle verify/compute root
3. **`common/ssz.rs`**: sha256_pair, validator_hash_tree_root, list_hash_tree_root, field verification
4. **`common/poseidon.rs`**: poseidon_leaf, poseidon_pair, Poseidon Merkle ops
5. **`common/types.rs`**: all witness structs with serde derives
6. **`epoch-diff-guest/main.rs`**: Proof 1 circuit logic
7. **`witness-gen/beacon_api.rs`**: beacon node client
8. **`witness-gen/poseidon_tree.rs`**: host-side tree
9. **`witness-gen/state_diff.rs`**: SSZ tree building + diffing
10. **`witness-gen/witness_epoch_diff.rs`**: assemble epoch diff witness
11. **`common/bls.rs`**: BLS verification (depends on Zisk pairing support)
12. **`finality-guest/main.rs`**: Proof 2 circuit logic
13. **`witness-gen/attestation_collector.rs`**: attestation fetching + committee resolution
14. **`witness-gen/witness_finality.rs`**: assemble finality witness
15. **`bootstrap-guest/main.rs`**: bootstrap circuit
16. **`witness-gen/witness_bootstrap.rs`**: bootstrap witness assembly
17. **`onchain-verifier/ZkasperVerifier.sol`**: Solidity contract

## proposed architecture: incremental slot-level proving

### motivation

The monolithic finality proof is expensive — it must verify BLS signatures for ~660K validators and a Poseidon multi-proof for all of them in one circuit. By breaking it into per-slot proofs, we get:

- **Incremental proving**: Start proving as blocks arrive, don't wait for 2/3
- **Parallelism**: Each slot proof is independent, can be proven concurrently
- **Smaller circuits**: Each slot proof covers one block's attestations (~10-20 attestations, ~10-50K validators)
- **Natural recursive composition**: Aggregate slot proofs into justification, justifications into finalization

### proof hierarchy

```
                      ┌─────────────────────┐
                      │  Finalization Proof  │
                      │                      │
                      │  Verifies:           │
                      │  - justification_N   │
                      │  - justification_N-1 │
                      └──────────┬───────────┘
                           ┌─────┴─────┐
                           │           │
                ┌──────────▼──┐  ┌─────▼──────────┐
                │ Justif. N-1 │  │ Justif. N       │
                │ (previous)  │  │ (new)           │
                │             │  │                 │
                │ Aggregates  │  │ Aggregates      │
                │ slot proofs │  │ slot proofs     │
                │ until ≥2/3  │  │ until ≥2/3      │
                └─────────────┘  └────────┬────────┘
                                    ┌─────┴─────┐
                          ┌─────────▼──┐  ┌─────▼─────────┐
                          │ Slot Proof │  │ Slot Proof    │  ...
                          │ slot S     │  │ slot S+1      │
                          │            │  │               │
                          │ BLS verify │  │ BLS verify    │
                          │ + Poseidon │  │ + Poseidon    │
                          │ multi-proof│  │ multi-proof   │
                          └────────────┘  └───────────────┘
```

### 1. Slot proof (per-block)

Produced for each block as it arrives. Proves: "these attestations in block B at slot S are valid and contribute X balance toward target checkpoint (epoch, root)."

**Circuit inputs (public)**:
- `accumulator_commitment` — binds to the current validator set
- `target_epoch`, `target_root` — the checkpoint being voted for
- `signing_domain` — domain for BLS verification

**Circuit outputs (public)**:
- `attesting_balance` — sum of unique validator balances in this block's attestations
- `unique_validator_bitmap_commitment` — commitment to which validators attested (for dedup across slots)

**Circuit logic**:
1. For each attestation in the block:
   - Verify BLS aggregate signature over `signing_root(attestation_data_root, signing_domain)`
   - Verify each validator's `(pubkey, balance)` via Poseidon multi-proof against `poseidon_root`
2. Sum unique attesting balances
3. Commit to the set of validator indices (for dedup in aggregation)

**Witness**: attestations from one block + Poseidon multi-proof for that block's validators

### 2. Justification proof (aggregation)

Aggregates slot proofs until attesting balance ≥ 2/3 of total. This is a recursive proof that verifies N slot proofs.

**Circuit inputs (public)**:
- `accumulator_commitment`
- `target_epoch`, `target_root`
- `total_active_balance`

**Circuit outputs (public)**:
- `justified` = true (asserted by the 2/3 check)

**Circuit logic**:
1. Recursively verify each slot proof
2. Deduplicate validators across slots (using bitmap commitments)
3. Sum unique attesting balance across all slots
4. Assert `attesting_balance * 3 >= total_active_balance * 2`

**Cross-slot balance deduplication**: A validator may attest in multiple blocks (included in different slots). Its balance must only be counted once toward the 2/3 threshold across all slot proofs for the same target checkpoint. This is a critical correctness requirement.

**Approach — witness-generator dedup with in-circuit uniqueness check**:
The witness generator tracks which validators have already been counted across earlier slots (via a running `seen_validators` set). For each slot witness, each validator carries a `count_balance` flag — `true` only for its first occurrence globally. The circuit enforces correctness by:
1. Within each slot proof: all validators with `count_balance=true` must have strictly increasing indices (no intra-slot duplicates)
2. Each slot proof outputs a **sorted list commitment** of its `count_balance=true` validator indices
3. At the justification level: merge the sorted lists from all slot proofs and verify the merged list is strictly increasing (no cross-slot duplicates)

This avoids expensive bitmaps or running accumulators inside the circuit. The witness generator does the heavy lifting; the circuit only verifies a sorted-merge property.

**Alternative approaches considered**:
- **Bitmap**: Commit to a bitfield of size `num_validators`. Each slot proof sets bits. Merge via OR. Count set bits × balance. Expensive in-circuit (~2M bits).
- **Running accumulator**: Each slot proof takes the previous slot's "seen set" as input, adds its validators, outputs updated set. Sequential — kills parallelism.
- **No dedup (protocol guarantees)**: Double-voting for same target is a slashable offense, so duplicates shouldn't exist in honest blocks. But we can't assume honest proposers — must enforce in-circuit.

### 3. Finalization proof

Casper FFG rule: epoch E is finalized when both E and E+1 are justified (with E+1's target being a descendant of E's target).

**Circuit inputs (public)**:
- `accumulator_commitment`
- `finalized_epoch`, `finalized_root`

**Circuit logic**:
1. Verify `justification_proof_N` (for epoch E+1)
2. Verify `justification_proof_N_minus_1` (for epoch E)
3. Assert both target epochs are consecutive
4. Output `finalized_root` = epoch E's target root

**Key optimization**: The next finalization proof for epoch E+1 reuses `justification_proof_N` as the "previous" justification. Only one new justification proof needs to be produced per epoch.

```
Finalization of epoch E:
  = justify(E) + justify(E+1)

Finalization of epoch E+1:
  = justify(E+1)  ← already have this!
  + justify(E+2)  ← only this is new
```

### proof chain summary

```
Time ───────────────────────────────────────────────────►

Bootstrap ──► EpochDiff ──► EpochDiff ──► ...
   │              │              │
   ▼              ▼              ▼
 acc_0          acc_1          acc_2        (accumulator commitments)
   │              │              │
   ▼              ▼              ▼
 SlotProofs    SlotProofs    SlotProofs     (per-block, as blocks arrive)
   │              │              │
   ▼              ▼              ▼
 Justify(E)   Justify(E+1)  Justify(E+2)   (aggregate when ≥2/3)
       \          / \          /
        ▼        ▼   ▼       ▼
      Finalize(E)   Finalize(E+1)          (pair consecutive justifications)
```

### what changes from current code

The current `finality-guest` does everything in one monolithic proof. To implement the slot-level architecture:

1. **Split `finality-guest` into `slot-proof-guest`**: Verifies attestations from one block. Much smaller circuit.

2. **New `justification-guest`**: Recursively verifies slot proofs, deduplicates validators, checks 2/3. This is the recursive aggregation layer.

3. **New `finalization-guest`**: Verifies two justification proofs for consecutive epochs. Lightweight — just two recursive proof verifications + epoch check.

4. **`attestation_collector`**: Instead of collecting all attestations at once, produce one witness per slot. The early-stopping logic moves to the justification level.

5. **`witness_finality`**: Splits into `witness_slot_proof` (one per block) and `witness_justification` (aggregates slot proofs).

## implementation plan

### step 1: new types in `crates/common/src/types.rs`

```rust
pub struct SlotProofOutput {
    pub accumulator_commitment: [u8; 32],
    pub target_epoch: u64,
    pub target_root: [u8; 32],
    pub attesting_balance: u64,
    pub counted_validators_commitment: [u8; 32],
    pub num_counted_validators: u64,
}

pub struct SlotProofWitness {
    pub accumulator_commitment: [u8; 32],
    pub target_epoch: u64,
    pub target_root: [u8; 32],
    pub signing_domain: [u8; 32],
    pub poseidon_root: [u8; 32],
    pub total_active_balance: u64,
    pub attestations: Vec<AttestationWitness>,
    pub poseidon_multi_proof: MerkleMultiProof,
}

pub struct JustificationWitness {
    pub accumulator_commitment: [u8; 32],
    pub target_epoch: u64,
    pub target_root: [u8; 32],
    pub total_active_balance: u64,
    pub slot_proof_outputs: Vec<SlotProofOutput>,
    pub slot_proof_proofs: Vec<Vec<u8>>,
    pub counted_indices_per_slot: Vec<Vec<u64>>,
}

pub struct JustificationOutput {
    pub accumulator_commitment: [u8; 32],
    pub target_epoch: u64,
    pub target_root: [u8; 32],
    pub justified: bool,
}

pub struct FinalizationWitness {
    pub accumulator_commitment: [u8; 32],
    pub justification_outputs: [JustificationOutput; 2],
    pub justification_proofs: [Vec<u8>; 2],
}
```

### step 2: counted validators commitment in `crates/common/src/poseidon.rs`

`counted_validators_commitment(sorted_indices) -> [u8; 32]` — Poseidon hash chain: `fold(indices, |acc, idx| poseidon_pair(acc, pad32(idx)))` starting from `pad32(count)`.

### step 3: new crate `crates/slot-proof-guest/`

`verify_slot_proof(witness) -> SlotProofOutput`:
1. Verify accumulator_commitment = poseidon(poseidon_root, total_active_balance)
2. Per attestation: collect validators, enforce strictly increasing, accumulate counted balance
3. Sort multi_proof_leaves by index, verify no duplicates
4. Verify Poseidon multi-proof against poseidon_root
5. BLS verify each attestation
6. Compute counted_validators_commitment
7. Return SlotProofOutput (**no 2/3 check** — justification's job)

### step 4: new crate `crates/justification-guest/`

`verify_justification(witness) -> JustificationOutput`:
1. Per slot proof: `ziskos::verify_proof()`, assert matching accumulator/target/domain, re-hash indices → verify commitment, accumulate balance
2. Cross-slot dedup: merge sorted per-slot indices, verify globally strictly increasing
3. Assert `attesting_balance * 3 >= total_active_balance * 2`

### step 5: new crate `crates/finalization-guest/`

`verify_finalization(witness) -> (epoch, root)`:
1. Verify two justification proofs (recursive)
2. Assert same accumulator_commitment, consecutive epochs
3. Output `(finalized_epoch, finalized_root)`

### step 6: refactor `crates/witness-gen/src/attestation_collector.rs`

Add `collect_per_slot_for_checkpoint()` — groups by block slot, cross-slot dedup, no early stopping.

### step 7–8: new witness builders

- `witness_slot_proof.rs`: `build_per_slot()` → per-slot Poseidon multi-proofs
- `witness_justification.rs`: `build()` → assembles from slot proof outputs

### step 9: update CLI, step 10: tests

### files to create

- `crates/slot-proof-guest/{Cargo.toml,src/lib.rs,src/main.rs}`
- `crates/justification-guest/{Cargo.toml,src/lib.rs,src/main.rs}`
- `crates/finalization-guest/{Cargo.toml,src/lib.rs,src/main.rs}`
- `crates/witness-gen/src/{witness_slot_proof.rs,witness_justification.rs}`

### files to modify

- `Cargo.toml` — add 3 new workspace members
- `crates/common/src/types.rs` — add new types
- `crates/common/src/poseidon.rs` — add counted_validators_commitment
- `crates/witness-gen/src/attestation_collector.rs` — add collect_per_slot_for_checkpoint
- `crates/witness-gen/src/{lib.rs,main.rs}` — new modules + CLI subcommands
- `crates/witness-gen/tests/integration_tests.rs` — slot proof + justification tests

## completed work

- [x] BLS aggregate signature verification (blst crate, cfg-gated)
- [x] Fetch JSON attestation/committee data from beacon API
- [x] Upload finality test data to GitHub release
- [x] SSZ state extraction helpers (genesis_validators_root, fork_version)
- [x] SszFileApi extended for attestations + committees
- [x] Poseidon multi-proof (verify + build)
- [x] Attestation collector with dedup + early stopping at 2/3
- [x] Finality guest verifier (monolithic, passing with real mainnet data)
- [x] Separate POSEIDON_TREE_DEPTH (22) from SSZ VALIDATORS_TREE_DEPTH (40)
- [x] End-to-end test: 66 attestations, 657K validators, 68.5% balance, BLS verified
- [x] Incremental slot-level proving architecture (steps 1-8, 10)
  - slot-proof-guest, justification-guest, finalization-guest crates
  - counted_validators_commitment (Poseidon hash chain for cross-slot dedup)
  - verify_proof stub in common/recursion.rs (no-op, replaced by ziskos::verify_proof on Zisk)
  - collect_per_slot_for_checkpoint in attestation_collector
  - witness_slot_proof.rs and witness_justification.rs builders
  - Integration tests: justification round-trip, finalization round-trip, dedup rejection, full pipeline
- [x] Attestation target soundness fix: circuits recompute `attestation_data_root` from raw `AttestationData` fields and assert `target_epoch`/`target_root` match the claimed checkpoint (both slot-proof-guest and finality-guest)
- [x] Removed `signing_domain` from `SlotProofOutput` (private to slot proof, not a public output)

## CI / testing

CI must test the full end-to-end pipeline with real Zisk proofs and verification:

1. **Native tests** (`cargo test --workspace --features bls`): unit tests + e2e test running guest logic natively
2. **Witness generation smoke test**: `gen-test-witness` for all proof types (bootstrap, epoch-diff, slot-proof, justification, finalization)
3. **Zisk proof pipeline**: for each proof type, run the full `scripts/test_zisk_proof.sh` flow:
   - Generate witness (`gen-test-witness`)
   - Build guest ELF for RISC-V (`cargo-zisk build`)
   - Execute in Zisk emulator (`ziskemu`)
   - ROM setup (`cargo-zisk rom-setup`)
   - Generate proof (`cargo-zisk prove`)
   - Verify proof (`cargo-zisk verify`)
4. **Forge unit tests** (available now): deploy `ZkasperVerifier.sol` with mock verifiers, test
   contract logic (state transitions, access control, event emission)
5. **On-chain verification with real proofs** (blocked on Zisk SNARK wrapper):
   - `cargo-zisk prove -f` wraps STARK proof into a final SNARK (FFLONK/Groth16)
   - Zisk team needs to ship a Solidity verifier contract that implements `IZiskVerifier`
   - Once available: deploy real verifier, feed proof bytes + public outputs, assert on-chain
   - Pipeline: gen witness → build ELF → prove -f → export verifier.sol → forge test
   - **Status**: `cargo-zisk prove -f` flag exists but no public docs on Solidity verifier
     generation yet. The `stark-recurser` repo (Circom) and `pil-fflonk` handle the
     recursion pipeline but don't export a verifier contract. Ask Jordi.

Requires: `ziskup` (Zisk toolchain installer), `foundry` (forge/cast).

## open questions for Jordi / Zisk team — resolved

All of the blocking ones were answered by code landing upstream. Recorded here
with the version each arrived in, because they arrive in different releases and
zkasper needs all of them.

1. **Poseidon precompile** — shipped. `syscall_poseidon2` (Poseidon2 over
   Goldilocks, width 16) since **v0.16.0**, joined by `syscall_poseidon1` in
   v1.0.0-alpha. The accumulator was moved off BN254 Poseidon onto it; measured
   3,117 per node against 50,746 for an SSZ node.
2. **BLS12-381 pairing** — shipped. zisklib carries the full tower
   (`miller_loop`, `final_exp`, `fp2/fp6/fp12`, `pairing`), backed by an
   `arith384_mod` precompile, plus `hash_to_curve` and `bls.rs` from
   **v1.0.0-alpha**. zisklib's own `bls_verify_bls12_381` uses the Basic-scheme
   DST, so zkasper composes the primitives directly to get Ethereum's
   proof-of-possession ciphersuite.
3. **Recursive proof composition** — shipped. `verify_zisk_proof` since
   **v0.18.0**. The proof blob also exposes the child's program verification key
   and public values, which is what lets an aggregator bind *which* proof it is
   verifying and not just that it verifies.
4. **Public inputs vs outputs** — `set_output` became `pub(crate)`; guests now
   commit a byte stream through `ziskos::io::commit_slice`, packed into 64 u32
   public slots (256 bytes). Layout of a serialized proof, in u64 words:
   `[minimal][n_publics][program_vk(4)][publics(64)][proof..][vadcop_vk(4)]`.
5. **`arith256_mod` generality** — moot. The accumulator no longer needs a
   256-bit modular multiply; BLS uses `arith384_mod`.
6. **Max cycle count** — the real constraint turned out to be the per-proof cost
   floor of 293,601,280, roughly one pairing check. Small proofs are mostly
   overhead, which argues for batching rather than for splitting.
7. **Hash-to-G2** — `hash_to_curve_g2_bls12_381`, measured at 18,594,420.
8. **Zisk version** — v1.0.0-alpha. Nothing earlier has all three of poseidon2,
   recursion and hash-to-curve.

Still open:

9. **Solidity verifier** — how to get an `IZiskVerifier` implementation and what
   proof format it expects on chain.
10. **Proving time and memory** — the cost model here comes from the emulator.
    Actual prover wall-clock and RAM for a slot proof at mainnet scale are
    unmeasured; that needs the proving key and real hardware.

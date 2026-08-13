# zkasper

Based on the [beacon chain finality proof research](https://github.com/dapplion/research/blob/main/beacon_chain_finality_proof.md).

ZK proof of Ethereum beacon chain finality for trustless bridges, targeting the [Zisk](https://github.com/0xPolygonHermez/zisk) zkVM.

## Overview

zkasper proves that an Ethereum Casper FFG checkpoint has been finalized, without requiring the verifier to process the full beacon chain. It works in five stages:

1. **Bootstrap** — one-time, builds the accumulator tree from a trusted beacon state.

2. **Epoch Diff** — tracks how the validator set changes between consecutive
   epochs, keeping the accumulator in sync with the SSZ validator registry. Each
   proof covers ~200 mutations (churn plus balance updates) and outputs the new
   accumulator root and total active balance.

3. **Slot Proof** — one per block slot. Checks that slot's attestations against
   the accumulator and verifies every signature in a single multi-pairing.

4. **Justification** — folds a slot's proofs recursively, dedupes attesters
   across slots, and checks the 2/3 threshold.

5. **Finalization** — pairs two consecutive justifications.

Stages 3 to 5 compose through `verify_zisk_proof`, so slot proofs can be produced
independently and in parallel.

## Architecture

```
crates/
  common/              # shared types, SSZ, accumulator, Merkle, BLS, recursion
  bootstrap-guest/     # Zisk guest: one-time tree construction
  epoch-diff-guest/    # Zisk guest: validator set diff
  slot-proof-guest/    # Zisk guest: one slot's attestations
  justification-guest/ # Zisk guest: folds slot proofs, checks 2/3
  finalization-guest/  # Zisk guest: pairs two justifications
  bench-guest/         # Zisk guest: precompile cost probe
  witness-gen/         # host-side witness generator (beacon API, tree management)
  onchain-verifier/    # Solidity verifier contract
```

### Why a second tree?

The beacon chain stores validators in an SSZ Merkle tree of depth 40, hashed with
SHA-256. zkasper maintains a parallel tree of depth 22 keyed the same way, hashed
with Poseidon2 over Goldilocks: `H(pubkey, active_effective_balance)`.

Both hashes are Zisk precompiles, so the question is what the second tree actually
buys. Measured: an accumulator node costs 3,117 against 50,746 for an SSZ node,
and the tree is 22 deep instead of 40 — about **30x** less work per membership
path. See [BENCHMARKS.md](BENCHMARKS.md).

`syscall_poseidon2` runs the same permutation in software on native targets, so
the host tree and the in-circuit tree agree by construction rather than by a
second implementation that has to be kept in sync.

## Building

```sh
cargo build            # host build; circuit logic runs natively for tests
cargo test --release
```

Every guest also builds for the real target. `ziskos` compiles on the host too —
each syscall falls back to a software implementation — so the circuits are the
same code in both places:

```sh
cargo-zisk build --release -p zkasper-slot-proof-guest
ziskemu -e target/elf/riscv64ima-zisk-zkvm-elf/release/zkasper-slot-proof-guest -i input.bin -X
```

## Witness Generator Usage

The witness generator talks to a standard Ethereum beacon node and produces binary witness files that can be fed to the guest programs.

### Prerequisites

- A beacon node with REST API enabled (e.g., Lighthouse, Lodestar, Prysm)
- The beacon node URL (e.g., `http://localhost:5052`)

### Commands

**Bootstrap** — one-time accumulator tree construction from a beacon state:

```sh
cargo run -p zkasper-witness-gen -- --beacon-url http://localhost:5052 bootstrap 3200
```

This fetches all validators at slot 3200, builds the accumulator tree, saves state to `zkasper.db`, and writes `bootstrap_input.bin`.

**Epoch Diff** — generate proof witness for validator set changes between two epoch boundaries:

```sh
cargo run -p zkasper-witness-gen -- --beacon-url http://localhost:5052 epoch-diff 3200 3232
```

Loads the saved tree, computes mutations between the two states, updates the tree, and writes `epoch_diff_input.bin`.

### Options

- `--beacon-url` (or `BEACON_API_URL` env) — beacon node REST URL
- `--db-path` — persistent state file (default: `zkasper.db`)
- `--output-dir` — directory for witness files (default: `.`)

### Typical workflow

```
bootstrap <slot>  →  epoch-diff <slot> <slot+32>  →  epoch-diff ...
                                                        ↓
                          slot proofs  →  justification  →  finalization
```

Each epoch-diff advances the accumulator by one epoch. Slot proofs can be
generated as soon as a slot's attestations are available, and folded into a
justification once the epoch completes.

## Status

- [x] Core library (SSZ, accumulator, Merkle, types)
- [x] Bootstrap, epoch-diff, slot-proof, justification and finalization circuits
- [x] Poseidon2-Goldilocks accumulator on `syscall_poseidon2`
- [x] SSZ hashing on `syscall_sha256_f`
- [x] BLS12-381 aggregate signature verification via zisklib, batched into one
      multi-pairing per slot
- [x] Recursive composition via `verify_zisk_proof`, with child program and
      public outputs bound
- [x] Host-side accumulator tree with incremental updates
- [x] Witness generator (beacon API, state diffing, attestation collection, DB persistence)
- [x] Measured cost model ([BENCHMARKS.md](BENCHMARKS.md), `scripts/bench.py`)
- [x] All guests build for `riscv64ima-zisk-zkvm-elf` and run under `ziskemu`
- [ ] Store decompressed public keys in the accumulator leaf (~24% off an epoch)
- [ ] Solidity verifier integration with the Zisk proof format
- [ ] Bootstrap chunking across recursive proofs

## Requirements

Zisk **v1.0.0-alpha** or newer. Earlier releases are missing pieces zkasper
depends on: `syscall_poseidon2` arrives in v0.16.0, `zisk_verifier` (recursion)
in v0.18.0, and zisklib's `hash_to_curve` in v1.0.0-alpha.

```sh
curl -sSf https://raw.githubusercontent.com/0xPolygonHermez/zisk/main/ziskup/install.sh | bash
ziskup --cpu --nokey -y
cargo-zisk build --release -p zkasper-slot-proof-guest
```

## Design

See [PLAN.md](PLAN.md) for the implementation plan and [BENCHMARKS.md](BENCHMARKS.md) for the measured cost model.

## License

MIT

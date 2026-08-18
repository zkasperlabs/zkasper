# zkasper

zkasper proves that an Ethereum beacon chain checkpoint is finalized. A bridge
that verifies one proof does not process the beacon chain itself.

The circuits target the [Zisk](https://github.com/0xPolygonHermez/zisk) zkVM.
The design comes from the
[beacon chain finality proof research](https://github.com/dapplion/research/blob/main/beacon_chain_finality_proof.md).

## What a proof claims

A finalization proof publishes the finalized checkpoint, the beacon state root
of that checkpoint, and the accumulator commitments the attestations were opened
against. The accumulator is a second validator-set tree, hashed with Poseidon2
over Goldilocks, that costs far less to open than the SSZ registry. Its
commitments chain back through one epoch diff per epoch to a single bootstrap
state.

`T` is the moment the chain publishes enough attestations to justify a
checkpoint. `T2` is the moment a proof of it exists. `T2 - T` is the only
latency a consumer sees, and the pipeline exists to make it small. The measured
cost model puts `T2 - T` at **5.5 s on one GPU**, with one proof and one wrap
between `T` and `T2`. See [BENCHMARKS.md](BENCHMARKS.md).

## Layout

```
crates/
  common/                # shared types, SSZ, accumulator, Merkle, BLS, recursion
  bootstrap-guest/       # guest: one-time tree construction
  epoch-diff-guest/      # guest: validator set diff, one per epoch
  committee-proof-guest/ # guest: one epoch's committee aggregates
  slot-proof-guest/      # guest: one slot's attestations, by complement
  group-proof-guest/     # guest: several slots, no final exponentiation
  aggregation-guest/     # guest: folds group proofs into a running aggregate
  justification-guest/   # guest: folds slot proofs, checks the 2/3 threshold
  finalization-guest/    # guest: pairs two justifications
  stream-final-guest/    # guest: the one proof after the last attestation
  bench-guest/           # guest: precompile cost probe
  committee-bench-guest/ # guest: committee strategy probe
  witness-gen/           # host: beacon API, tree management, zkasperd, provers
  onchain-verifier/      # Solidity verifier contract
```

## Build

```sh
cargo build
cargo test --release
```

The circuits run natively on the host, because every `ziskos` syscall has a
software implementation. The same code therefore runs in the tests and in the
zkVM. To build the guest ELFs for the real target, run:

```sh
./scripts/build_guests.sh
```

## Run

`zkasperd` follows a beacon node, writes one witness per stage, and rewrites
`status.json` after every stage:

```sh
cargo run --release --bin zkasperd -- \
    --beacon-url http://localhost:5052 --mode streaming
```

`--mode streaming` proves each epoch as the attestations arrive.
`--mode batch`, the default, proves each slot and folds the epoch after the
epoch ends. `--once` catches up to the head of the chain and exits. `--chain`
selects `mainnet` or `gnosis`.

The batch pipeline carries a known soundness gap. Read
[docs/assumptions.md](docs/assumptions.md) before you secure value with it.

`--prover native`, the default, runs each guest natively and returns an empty
proof. It needs no proving hardware, and it checks every witness with the
circuit that will later prove it. For real proofs, build with the
`zisk-prover` feature and run:

```sh
cargo build --release --features zisk-prover
zkasperd --beacon-url ... --mode streaming --prover zisk --gpu
```

That puts the prover in the daemon, which only suits a single box. The
deployment runs the beacon node and `zkasperd` on a stable machine and a prover
server on the rented GPU box:

```sh
# GPU box
zkasper-prover-server --gpu --listen 0.0.0.0:9099 --mode streaming
# stable machine, no CUDA needed
zkasperd --beacon-url ... --mode streaming --prover remote --prover-addr <gpu>:9099
```

If the server goes away the daemon keeps generating witnesses, spools the ones
it could not prove, and backfills them when the server returns.

Given `--api-url`, the daemon also mirrors every stage to
[the v1 API](docs/api-v1.md) as it happens, and uploads the proof bytes of each
epoch. That is what drives the live view on zkasper.com. Publishing never holds
proving up: a batch the API will not take is spooled to `<output-dir>/spool`.

```sh
ZKASPER_API_TOKEN=... ZKASPER_COMMIT=$(git rev-parse --short HEAD) \
cargo run --release --bin zkasperd -- --beacon-url http://localhost:5052 \
    --mode streaming --api-url https://api.zkasper.com
```

The beacon node needs specific flags. Read
[docs/architecture.md](docs/architecture.md) before you point the daemon at a
node, and [RUNBOOK.md](RUNBOOK.md) to operate one.

For one step at a time, use the `zkasper-witness-gen` binary:

```sh
cargo run -p zkasper-witness-gen -- --beacon-url http://localhost:5052 bootstrap 3200
cargo run -p zkasper-witness-gen -- --beacon-url http://localhost:5052 epoch-diff 3200 3232
```

## Status

Done:

- Every stage of the pipeline, as a circuit and as a native implementation.
- Poseidon2 accumulator, SSZ hashing, and BLS multi-pairing on Zisk precompiles.
- Recursive composition, with the child program key and public outputs bound.
- Complement proving: a slot proof names the absentees of a per-epoch committee
  aggregate.
- Streaming pipeline: geometric groups, a threshold trigger, and a collapsed
  tail.
- Finalization across a real mainnet epoch boundary, on the native prover,
  including one whose first slot the chain skipped.
- A measured cost model over every stage.

Open:

- No streaming epoch has a real end-to-end proof yet. `T2 - T` is a model over
  measured per-stage times.
- Recursive verification is unmeasured. It is a model parameter that defaults to
  zero.
- The Solidity verifier is not integrated with the Zisk proof format.
- Bootstrap is one proof, and it is not chunked.

## Read next

| document | what it holds |
|---|---|
| [docs/architecture.md](docs/architecture.md) | the proofs, and the machines they run on |
| [docs/assumptions.md](docs/assumptions.md) | every trust assumption and accepted risk |
| [RUNBOOK.md](RUNBOOK.md) | how to provision, run, monitor and recover a mainnet deployment |
| [BENCHMARKS.md](BENCHMARKS.md) | every cost constant, and what measured it |
| [docs/gossip.md](docs/gossip.md) | where attestations come from, and what they cost |
| [docs/api-v1.md](docs/api-v1.md) | the public HTTP API |
| [FCR_CIRCUIT_DESIGN.md](FCR_CIRCUIT_DESIGN.md) | fast confirmation, designed and not built |

## Requirements

Zisk **v1.1.0-alpha**. The toolchain and `ziskos` must match, because
v1.1.0-alpha changed the guest linker script. A guest that is built against one
version and linked by another fails with undefined symbols.

```sh
curl -sSf https://raw.githubusercontent.com/0xPolygonHermez/zisk/main/ziskup/install.sh | bash
ziskup --version 1.1.0-alpha --cpu --nokey -y
```

## License

MIT

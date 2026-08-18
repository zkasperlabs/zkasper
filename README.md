# zkasper

Based on the [beacon chain finality proof research](https://github.com/dapplion/research/blob/main/beacon_chain_finality_proof.md).

ZK proof of Ethereum beacon chain finality for trustless bridges, targeting the [Zisk](https://github.com/0xPolygonHermez/zisk) zkVM.

## Overview

zkasper proves that an Ethereum Casper FFG checkpoint has been finalized, without requiring the verifier to process the full beacon chain. It works in six stages:

1. **Bootstrap** — one-time, builds the accumulator tree from a trusted beacon state.

2. **Epoch Diff** — tracks how the validator set changes between consecutive
   epochs, keeping the accumulator in sync with the SSZ validator registry. Each
   proof covers ~200 mutations (churn plus balance updates) and outputs the new
   accumulator root and total active balance.

3. **Committee** — one per epoch, and the reason a slot proof is cheap. Sums
   each slot's committee out of the accumulator into a `(public key, effective
   balance)` pair, so that a slot can be proven by naming the validators that
   did *not* attest.

4. **Slot Proof** — one per attestation slot. Subtracts that slot's absentees
   from its committee aggregate, and verifies every signature in a single
   multi-pairing.

5. **Justification** — folds a slot's proofs recursively, checks that no slot is
   counted twice, and checks the 2/3 threshold.

6. **Finalization** — pairs two consecutive justifications, together with the
   epoch diff that carries the accumulator from the first epoch to the second.
   Effective balances are rewritten at every epoch transition, so the two
   justifications are never proved against the same accumulator; verifying the
   diff between them is what makes the pair sound. The proof publishes both
   accumulator commitments, the finalized checkpoint, and the beacon state root
   that checkpoint's block produced — which the circuit pins to the state the
   accumulator entered the finalized epoch with, so a consumer can compare the
   two directly.

Stages 4 to 6 compose through `verify_zisk_proof`, so slot proofs can be produced
independently and in parallel.

## Architecture

```
crates/
  common/              # shared types, SSZ, accumulator, Merkle, BLS, recursion
  bootstrap-guest/     # Zisk guest: one-time tree construction
  epoch-diff-guest/    # Zisk guest: validator set diff
  committee-proof-guest/ # Zisk guest: one epoch's committee aggregates
  slot-proof-guest/    # Zisk guest: one slot's attestations, by complement
  group-proof-guest/   # Zisk guest: several slots, no final exponentiation
  aggregation-guest/   # Zisk guest: folds group proofs into a running aggregate
  justification-guest/ # Zisk guest: folds slot proofs, checks 2/3
  finalization-guest/  # Zisk guest: pairs two justifications
  stream-final-guest/  # Zisk guest: the one proof after the last attestation
  bench-guest/         # Zisk guest: precompile cost probe
  witness-gen/         # host-side witness generator (beacon API, tree management)
  onchain-verifier/    # Solidity verifier contract
```

### Complement proving

A mainnet slot committee is about 30,000 validators and roughly 99.7% of them
attest. Opening a Merkle path for every attester proves the overwhelmingly
common case tens of thousands of times over; naming the ~90 absentees instead is
**167x** less accumulator work per slot, and it is what makes the marginal proof
of an epoch small. The per-epoch committee proof that pays for it costs 14.5B,
which is *less* than the 26.8B the slot proofs were spending, and it can run a
whole epoch ahead of the attestations it serves.

It works because the aggregate signature pins the absentee set exactly: the
derived aggregate public key is the committee minus whoever the witness names, so
omitting a genuine absentee, naming an attester, or naming a stranger all leave a
key that no signature closes against. The balance side is *not* pinned by the
signature, and is bound instead by the accumulator leaf — one Poseidon2 hash over
`(public key, effective balance)` together — so a committee's two totals cannot
be moved apart. `crates/common/src/committee.rs` carries the full argument,
including why the swap-or-not shuffle never has to enter a circuit.

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

### Streaming: minimising `T2 - T`

`T` is the moment the chain has published enough attestations to justify a
checkpoint; `T2` is the moment a proof of it exists. That gap is the only
latency a consumer sees, and it is not the cost of proving an epoch — it is the
cost of whatever still depends on the *last* attestation. The pipeline is built
to leave one proof there.

```
    slots 0..12      13..18   19..21  22  23   the slot that crosses 2/3
    +-----------+    +-----+  +---+  +-+ +-+   +-------------------------+
    | group     |    |group|  |grp|  |g| |g|   |  proven inline, in the  |
    | proof     |    |     |  |   |  | | | |   |  final proof itself     |
    +-----+-----+    +--+--+  +-+-+  +++ +++   +------------+------------+
          |             |       |     |   |                 |
          v             v       v     v   v                 v
    +-----------------------------------------+    +-----------------+
    |     running aggregate (folded as         |-->|   final proof   |--> finalization
    |     each group finishes)                 |    +-----------------+
    +-----------------------------------------+       ^ one final exponentiation
                                                        for the whole epoch
```

Four things make that work, and `crates/witness-gen/src/streaming.rs` implements
the schedule:

- **The Miller loop is split from the final exponentiation.** A group proof
  computes its Miller loops and publishes a commitment to the Fp12 accumulator;
  it asserts *nothing* about the signatures. The final proof multiplies every
  group's accumulator and runs one final exponentiation for the epoch.
- **Groups shrink geometrically** toward the threshold, so the last one is a
  single slot rather than a fixed eight.
- **The epoch stops at the threshold**, measured by accumulated weight. On the
  real mainnet epoch in the test suite that skips 31% of the aggregates.
- **The tail is collapsed**: one proof verifies the aggregate, does the marginal
  slot inline, settles every signature, checks 2/3, and emits the finalization —
  instead of four proofs in series.

Scheduled against a real mainnet epoch — 430529, 2,212,730 validators — on
measured RTX 5090 times, `T2 - T` is **9.1s on one card**. Six proofs run in the
epoch and only one of them is after the last attestation: 9.0s of final proof and
0.2s of wrap, three quarters of which is the measured 7.18s floor every proof
pays whatever it computes. Against that, fixed groups of eight enumerating every
attester is 311s.

The threshold is what decides whether that number is 9.1s or 25.6s. Epoch 430529
crosses 2/3 inside its slot 21, at 68.52% of the stake — 1.85 points of headroom
— and a slot carries about 3.1%, so any threshold from 66% to 68% ends the epoch
there and anything from 69% up waits a whole extra slot:

```
 margin     T2-T   slots    balance  over 2/3
    67%     9.1s      22     68.52%     1.85%
    68%     9.1s      22     68.52%     1.85%
    69%    25.6s      23     71.63%     4.97%
    70%    25.6s      23     71.63%     4.97%
    75%    45.1s      25     77.78%    11.12%
```

The default is 2/3 exactly — the circuit's own rule and no margin on top. There
used to be one because a slot's contribution was an estimate that deduplication
across slots could shrink; `slots_mask` puts a validator in exactly one slot and
`marginal_balance` is committee balance minus absentee balance, so it is exact
and a margin can only ever waste a proof, never make an unsound one. What guards
the thin headroom is not margin but detection: a checkpoint that reorgs out is a
retry, never a publication (`crates/witness-gen/src/orchestrator.rs`).

Those are seconds, not cost units, and that is deliberate: measured throughput
on the campaign's own guests spans 18M to 246M Zisk cost units per second, so no
single units-per-second constant describes this prover. `scripts/time_model.py`
and `ProverModel` in `crates/witness-gen/src/streaming.rs` predict wall-clock
directly, with a rate per work class. The warm path is the product — a cold
`cargo-zisk` invocation adds **13.5s** of startup per proof, which is why
`crates/witness-gen/src/prover.rs` requires a long-running prover. See
[BENCHMARKS.md](BENCHMARKS.md).

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

## Continuous mode — `zkasperd`

The subcommands above each do one step. `zkasperd` runs the whole thing as a
service: it bootstraps from the node's finalized checkpoint, then follows the
chain, writing witnesses and a status manifest as it goes.

```sh
cargo run --release --bin zkasperd -- --beacon-url http://localhost:5052 \
    --db-path zkasperd.db --output-dir zkasper-out
```

Per epoch it runs one epoch diff to advance the accumulator and one committee
proof to sum that epoch's committees, then streams slot proofs as attestations
arrive and fires the justification the moment the counted balance crosses 2/3,
around slot 22 of a mainnet epoch rather than at the epoch boundary. Nothing past
that point is proven. A finalization follows whenever two consecutive epochs
justify.

### Publishing to the public API

Given `--api-url`, the daemon mirrors every stage to
[the v1 API](docs/api-v1.md) as it happens — a stage starting, a stage finishing
with its measured duration, the 2/3 threshold crossing, the final proof landing —
and uploads the epoch's proof bytes. That is what drives the live view on
zkasper.com; it is a mirror, and the daemon remains the source of truth.

```sh
ZKASPER_API_TOKEN=... ZKASPER_COMMIT=$(git rev-parse --short HEAD) \
cargo run --release --bin zkasperd -- --beacon-url http://localhost:5052 \
    --mode streaming --api-url https://api.zkasper.com
```

`ZKASPER_COMMIT` is compiled in and published with every proof, so a verifier
knows which tree to rebuild the guest from. Publishing cannot hold proving up:
events go through a bounded queue, and anything the API will not take is spooled
to `<output-dir>/spool` and sent when it answers again — across a restart too.
`status.json` reports what that has cost under `publish`, and an outage long
enough to overflow the spool shows up there as `dropped` rather than as silence.

### Beacon node requirements

`--mode streaming` follows attestations on the node's event stream,
`/eth/v1/events?topics=attestation,single_attestation,chain_reorg`, and this is
an operational dependency rather than an optimisation:

- **The node must subscribe to every attestation subnet**, because unaggregated
  attestations are the primary source and a partial subnet view is a partial feed —
  `--subscribe-all-subnets` on Lighthouse, `--subscribe-all-subnets` on Prysm and
  Teku, `--subscribeAllSubnets` on Lodestar, `--subscribe-all-subnets` on Nimbus.
  A default node only joins the subnets its own validators need plus a rotating
  backbone, so its `single_attestation` topic is a *partial* view of gossip. The
  `attestation` topic carries aggregates, which travel a global topic and are
  complete on any node; unaggregated attestations arrive a third of a slot
  earlier, and only a fully subscribed node sees all of them.
- **`/eth/v2/debug/beacon/states/{id}` must be enabled.** Bootstrap reads the
  whole `BeaconState` as SSZ from it. Hosted providers usually disable it,
  because it is a several-hundred-megabyte response.
- **`/eth/v1/beacon/states/{id}/committees` is trusted for the shuffle.** Nothing
  in the host or the circuit recomputes it; the committee proof only needs the
  buckets to be disjoint and to cover what it opens. A node that lies produces
  buckets that are disjoint but wrong, and the signatures then fail to verify —
  so a dishonest node costs liveness, not soundness.

`--no-gossip` falls back to reading attestations out of blocks. That is a slot
behind the chain by construction and is there for a node that will not serve the
event stream; the stream is also the source blocks repair after an outage, which
the daemon does automatically and reports in `status.json` under `gossip`.

### Where attestations come from, and what it costs

The daemon builds its own aggregates. It subscribes to unaggregated gossip,
groups by `AttestationData` root, sums the signatures natively on the host and
hands the circuit **one aggregate per distinct message**. Network aggregates are
a backstop, taken only where the singles left a hole.

Three reasons, in the order they matter:

- **Coverage is a cost.** A network aggregator publishes the best cover it has
  seen; an attester missing from it becomes a named absentee in the complement
  proof at 1.79 ms each. Singles let the daemon find those validators itself.
  Measured on epoch 430529, this is real but small: an attester that the first
  block to carry its slot missed — a lower bound on what one aggregate pool
  misses — is 11 validators on the slot 2/3 crosses in (20 ms), 236 across the
  epoch, and 87 on the worst slot (156 ms). Worth having, and two orders of
  magnitude less than the four seconds below.
- **Four seconds.** Unaggregated attestations are published a third of a slot in;
  aggregates two thirds. Since the trigger fires when the arrival burst drains,
  that is four seconds off `T2`.
- **Minimality by construction.** A single names one validator, so a running sum
  over singles is disjoint with no cover to choose. A slot's proving cost is
  dominated by distinct messages — about 51.8M cost units for another message
  against 53K for another absentee — so one aggregate per message is the shape
  worth having.

Disjointness at the seam is proved, not assumed: summing a validator's signature
twice still *verifies* (`sig + sig_v` against `2·pk_v + rest`), so nothing
downstream would catch a double count. The collector seeds the merge with its own
summed singles and takes a network aggregate only when its signers are disjoint
from everything already counted, which in practice means only for a committee the
singles feed missed entirely.

#### Measured cost, per mainnet slot of 30,030 unaggregated attestations

| | wire | daemon CPU | per attestation |
|---|---|---|---|
| JSON frames over SSE | 18.45 MB | 0.121 s | 4.0 us |
| socket to inbox, end to end | 18.45 MB | 0.204 s | 6.8 us |
| the same as fixed 240-byte SSZ | 7.21 MB | 0.00016 s | 5.3 ns |
| summing the signatures (G2) | — | 0.678 s | 22.6 us |

Reproduce with `cargo test --release -p zkasper-witness-gen throughput -- --ignored
--nocapture`. Ingest and summing together are **0.88 s of one core per slot, 7.3%
of a 12 s slot**, and both parallelise. The daemon is not the bottleneck, and
note what the table says about where the cost is: SSZ would remove 0.12 s of the
0.88 s, while the signature arithmetic — which SSZ does not touch — is 77% of it.

#### The node is the bottleneck, and it takes one flag

Lighthouse holds each SSE topic in a `tokio::sync::broadcast` ring of
`--http-sse-capacity-multiplier` x 16 messages. The default multiplier is 1, so
the `single_attestation` topic buffers **sixteen** messages against a slot's
thirty thousand. A consumer that falls behind gets `Lagged(n)`, which the node
renders as an SSE *comment* — `error - dropped n messages` — while the
attestations themselves are gone. A client that ignores comments loses
attestations and never learns it did.

So:

- Run the node with **`--http-sse-capacity-multiplier 2000`** (32,000 messages,
  a whole slot). 64 would absorb ordinary millisecond jitter at 30,000 events a
  second; 2,000 makes loss essentially impossible for about 24 MB of node memory.
- zkasperd counts those comments and publishes them as `gossip.dropped` in
  `status.json`, and treats each as a gap to repair from blocks. **Anything but
  zero there means the node is misconfigured**, not that the daemon is unlucky.

#### What a forked node should expose

Stock Lighthouse is workable with the flag above, so a fork is an optimisation
rather than a precondition. In increasing order of what it removes:

1. **SSZ event frames.** Length-prefixed fixed-size records on the same event
   stream: 7.21 MB a slot instead of 18.45 MB, and decoding becomes free
   (5.3 ns against 4.0 us). Removes 0.12 s of the daemon's 0.88 s.
2. **Pre-grouped, pre-summed attestations.** This is the one worth building. The
   node already computes the attestation data root during gossip validation and
   already holds the signatures, so it can emit, per slot and per distinct
   `AttestationData`, a running `(data, aggregate signature, participation
   bitfield)` snapshot at a fixed cadence — 100 ms is finer than the daemon's
   trigger interval. Epoch 430529 averages 2.8 distinct messages a slot, so that
   is three events and about two kilobytes a slot instead of 30,030 events and
   18 MB, and it removes the whole 0.88 s. It also removes the merge seam
   outright: each snapshot replaces the daemon's running total for that message
   wholesale, so there is no union to prove disjoint.
   The cadence matters as much as the content — a single end-of-slot emission
   would destroy the incremental convergence the trigger reads its arrival rate
   from.
3. **A unix socket or shared-memory ring**, if HTTP framing ever shows up in a
   profile. Nothing measured here says it does.

Embedding `lighthouse_network` and subscribing to the subnets directly is the
option not to take. Every source above delivers attestations the node has already
*gossip-validated*; raw libp2p makes that validation ours, and getting it wrong
lets a peer feed us signatures over arbitrary data. The circuit still rejects a
bad signature, so this is liveness and denial of service rather than soundness —
but it is a large amount of consensus code to own for a cost that is already
7.3% of a core.

All of these sit behind `AttestationSource` in
`crates/witness-gen/src/gossip.rs`, which is a `drain`, a reorg flag, a gap flag
and some counters. Swapping the transport does not touch the pipeline.

Output:

```
zkasper-out/
  status.json              # accumulator, checkpoints, per-stage and per-epoch timings
  epoch-000123456/
    epoch_diff.bin
    committee.bin
    slot_proof_<slot>.bin  # --mode batch
    justification.bin
    finalization.bin
    group_<n>.bin          # --mode streaming
    aggregate_<n>.bin
    stream_final.bin
```

`--once` catches up to the node's head and exits. `--bootstrap-slot` picks a
different starting state. `--signing-domain` overrides the domain otherwise
derived from the node's fork and genesis.

Proving is behind the `Prover` trait in `crates/witness-gen/src/prover.rs` —
witness in, `(public output, proof)` out — and there are two implementations.
`--prover native`, the default, runs each guest's logic natively and returns an
empty proof, so every witness written has been checked by the same circuit that
will later prove it, and no proving hardware is needed. `--prover zisk` produces
real proofs from one embedded `zisk-sdk` client that is initialised once and kept
warm for the life of the process; add `--gpu` to prove on a GPU. It is behind a
cargo feature because it pulls in the whole Zisk proving stack:

```sh
./scripts/build_guests.sh
cargo build --release --features zisk-prover
zkasperd --beacon-url ... --mode streaming --prover zisk --gpu
```

`--mode streaming` proves the epoch as attestations arrive — a group per slot,
folded into a running aggregate, closed by one proof over the attestation that
crossed the threshold — and records the measured `T2 - T` per epoch in
`status.json` under `recent_latencies`. `--mode batch`, the default, proves each
slot and folds the epoch once it is over.

The trigger is `--threshold-numerator`/`--threshold-denominator`, 2/3 by default:
the circuit's own rule and no margin on top, because `slots_mask` makes a slot's
contribution exact rather than an estimate that could shrink. A higher setting
only ever costs latency — weight arrives a committee at a time, about 3.1% of the
stake, so a margin that pushes the crossing into the next slot costs a whole
slot. What the daemon does *not* do is fire on the instant the threshold is
crossed: a slot proof opens the validators that did not attest, so every
attestation still in flight is an extra accumulator leaf at 1.79 ms. It keeps
waiting while arrivals run above 558 validators a second — the rate at which one
more second of waiting pays for itself — and fires the interval they do not, up
to `--max-trigger-wait-millis`. `--trigger-interval-millis` sets how often that
is re-evaluated, and so the resolution of the firing instant.

Restarts are safe. The accumulator is a chain, so `crates/witness-gen/src/store.rs`
writes atomically, checksums what it writes, rehashes the tree on load and
compares it against the recorded root, and refuses any epoch diff that is not
exactly one epoch forward.

## Status

- [x] Core library (SSZ, accumulator, Merkle, types)
- [x] Bootstrap, epoch-diff, committee, slot-proof, justification and
      finalization circuits
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
- [x] Accumulator leaf commits the decompressed public key (28.4% off a mainnet epoch)
- [x] Finalization across a real epoch boundary, with the epoch diff linking the
      two accumulators verified inside the proof
- [x] Streaming proof pipeline: Miller loops split from the final
      exponentiation, geometric groups, threshold trigger, collapsed tail
      (`T2 - T` 6.1x shorter, measured on epoch 430529)
- [x] Complement proving: slot proofs name absentees against a per-epoch
      committee aggregate, 167x less accumulator work per slot and an epoch
      47.9% cheaper overall
- [ ] Finalizing an epoch whose first slot was empty. The accumulator is built
      from the state at the epoch boundary, and the finalized header only names
      that state when a block sits on the boundary slot. Covering the empty case
      needs the boundary state root proved out of the finalized state's
      `state_roots` list.
- [ ] Splitting the committee proof across validator index ranges. Bucket sums
      add and a validator lands in one range, so a fold that adds aggregates is
      all it needs. No longer urgent: at 169 s against a 384 s epoch the proof
      fits whole, and every extra chunk is an extra stage floor.
- [ ] Projective or batched-inversion G1 aggregation
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

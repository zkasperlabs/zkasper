# Architecture

This document has two halves. The first half is the proofs: what each guest
proves, what feeds what, and why each piece sits where it does. The second half
is the deployment: which machine runs which part, and why.

Every number here is Zisk v1.1.0-alpha on an RTX 5090 unless the text says
otherwise. [BENCHMARKS.md](../BENCHMARKS.md) holds the measurements.
[assumptions.md](assumptions.md) holds what the proofs trust.

---

# Part 1 — the proofs

`T` is the moment the chain has published enough attestations to justify a
target checkpoint. `T2` is the moment a wrapped proof of it exists. `T2 - T` is
the only latency a consumer sees. The pipeline exists to make it small, and it
does that by proving before `T` everything that is known before `T`.

## The stages

| stage | proves | runs |
|---|---|---|
| epoch diff | the accumulator moves from epoch E-1 to epoch E | once per epoch |
| committee proof | each slot bucket of epoch E sums to one public key and one balance | once per epoch, an epoch ahead |
| group proof | some slots of an epoch, as Miller loops that nothing has closed yet | as the slots arrive |
| aggregation | a running aggregate absorbs a group proof | as groups finish |
| stream final | the epoch justifies, and the epoch before it finalizes | once, after `T` |
| slot proof | one slot attested, signatures included | batch pipeline only |
| justification | folded slot proofs cross 2/3 | batch pipeline only |
| finalization | two consecutive justifications pair | batch pipeline only |

The batch pipeline proves the same claim as the streaming pipeline. It proves
each slot, then folds the epoch after the epoch ends. It is simple and it is
slow. The streaming pipeline is the one that makes `T2 - T` small.

## What feeds what

```
  init point ──► accumulator (configuration, checked at start, not proved)
      │
      ▼
  epoch-diff (E-1 -> E) ─────────┐  the fold that opens the epoch verifies it,
      │                          │  so it never touches the critical path
      ▼                          │
  committee proof (for E) ───────┤  one per epoch, one bucket per slot
      │  committee_root          │
      ▼                          │
  group proof  slots 0..19 ──────┤
  group proof  slots 20, 21 ─────┤
      │                          │
      │  (folds, when there is   │
      │   time to spare)         │
      ▼                          ▼
  ══════════════ T ═══════════════════════════
      │
      ▼
  stream-final  ── absorbs late groups as child proofs
      │            proves the crossing slot inline
      │            runs the epoch's ONE final exponentiation
      │            verifies 2/3 and the previous justification
      ▼
  wrap (0.048 s)
      │
      ▼
  T2 ── postable
```

The stages compose through `verify_zisk_proof`. A parent binds the verification
key of the child program and the public bytes the child committed. A parent
therefore proves which proof it verified, and not only that it verified one.

## The group proof proves a conditional claim

A group proof opens accumulator paths for the absentees of each slot it covers.
It aggregates the public keys and folds the signatures into one Miller
accumulator. It does not run the final exponentiation, so it asserts nothing
about the signatures on its own.

The claim has one condition and two parts. If the product of every Miller
accumulator exponentiates to 1, then these validators are the committees of
these slots, and this is their attesting balance.

**The final proof discharges that condition.** It verifies the running
aggregate, proves the crossing slot inline, runs the epoch's one final
exponentiation, verifies the 2/3 threshold, and emits the finalization. One
circuit does five jobs, which saves four stage floors and four prover
invocations.

A fold extends a running aggregate. Every term is associative: balances add,
Fp12 values multiply, and slot masks union. The cost of a fold therefore scales
with what it absorbs and never with what it already holds. When the schedule
cannot fold a group in time, the final proof absorbs that group directly, as one
recursion instead of a whole stage.

## Why each piece sits where it does

**The committee proof has an epoch of lead time.** A RANDAO mix from the end of
epoch E-2 fixes the committees of epoch E. The proof for the next epoch
therefore runs in the slack of this one. It is throughput work, and it never
touches `T2`.

**Complement proving makes a slot proof small.** A mainnet slot committee is
about 30,000 validators and about 99.7% of them attest. The committee proof
publishes one `(summed public key, summed effective balance)` pair per slot. A
slot proof subtracts the validators that did not attest, which is about 90 of
them. That is 167x less accumulator work per slot. The aggregate signature pins
the absentee set exactly: a wrong name leaves an aggregate public key that no
signature closes against.

**The accumulator is a second tree because the SSZ registry is expensive to
open.** The beacon chain stores validators in an SSZ tree of depth 40, hashed
with SHA-256. zkasper keeps a parallel tree of depth 22, hashed with Poseidon2
over Goldilocks, whose leaf is `H(public key, active effective balance)`. An
accumulator node costs 7,462 against 36,207 for an SSZ node, and the tree is
half as deep.

**The Miller accumulator travels as witness, not as public output.** An Fp12
value is 576 bytes and the public budget is 256 bytes. Each proof therefore
publishes a Poseidon2 commitment to it, and the host hands the value to the
parent. A host that gets that wrong produces a proof that fails, not a proof
that lies.

**One stage floor sits between `T` and `T2`, never two.** A stage floor is
3.640 s, which no amount of cost-unit work buys back. The hard wall under
`T2 - T` is one floor, one final exponentiation, and two Miller loops.
`MillerLoop(sig, -g2)` takes the signature as an input, so it cannot run before
the signature exists.

## The threshold trigger

The daemon fires the final proof when the accumulated attesting balance crosses
the threshold. The default is 2/3 exactly, which is the rule the circuit
enforces. A margin above 2/3 can only cost latency. Weight arrives one committee
at a time, which is about 3.1% of the stake. A margin that pushes the crossing
into the next slot therefore costs a whole slot.

The daemon does not fire on the instant the threshold crosses. A slot proof
opens the validators that did not attest, so every attestation still in flight
is one more accumulator leaf. The trigger keeps waiting while the arrival rate
pays for the wait, and it fires at the first interval that does not, up to
`--max-trigger-wait-millis`.

The epoch stops at the threshold. On mainnet epoch 430529 that skips 31% of the
epoch aggregates, and the crossing happens inside slot 21 at 68.52% of the
stake.

A checkpoint that reorgs out of the chain is a retry and never a publication.
The daemon re-resolves the checkpoint root when the node reports a reorg.

---

# Part 2 — where the parts run

## Two machines

```
   stable machine                         GPU machine
   ┌──────────────────────────┐          ┌──────────────────────┐
   │ beacon node              │          │ prover server        │
   │   all attestation subnets│          │   one process        │
   │ zkasperd                 │  witness │   one EmbeddedClient │
   │   witness generation ────┼─────────►│   one GPU            │
   │   schedule, triggers     │◄─────────┤                      │
   │   status.json            │  proof   └──────────────────────┘
   └───────────┬──────────────┘
               │ proof bytes, epoch index
               ▼
   object storage + public API  ──►  the site and any consumer
```

The stable machine runs the beacon node and `zkasperd`. The GPU machine runs a
prover server and nothing else. [RUNBOOK.md](../RUNBOOK.md) is the operational
version of this half: how to provision, install, start, monitor and recover a
mainnet deployment.

## The GPU machine runs a prover and nothing else

`zisk_sdk` decides this. An `EmbeddedClient` pays for the proving key, the
Vadcop setups and the device buffers once, in `build()`. It then serves proofs
for the life of the process. A second client in the same process panics with
"Only one instance is allowed per process". The flag is never cleared, so a
client cannot be dropped and rebuilt. One process therefore holds the GPU, and
that process must live as long as the service.

A cold start costs 5.80 s, against a 3.640 s stage floor. A prover that restarts
per proof spends more time on startup than on proving.

The daemon reaches the prover through the `Prover` trait: witness in,
`(public output, proof)` out, every method on `&self`. `RemoteProver` is that
trait over a socket, and `zkasper-prover-server` is the process on the far side
holding the one client. The daemon needs no CUDA to drive it — measured
2026-08-18, a client built without `--features zisk-prover` proved a group and a
slot proof on an RTX 5090 through the server and accepted both with
`verify_child`.

The client runs the guest logic natively and asks the server only for the
cryptography, so the outputs the accumulator advances on never come off the
wire, and a proof that comes back is checked against the key the handshake
reported. One connection, length-prefixed bincode frames, a shared token.

**When the server disappears the daemon keeps going.** The witness is spooled to
disk and the call returns the empty proof a witness-only run returns, so the
epoch is published without a proof rather than not published at all. The
verification keys were cached at the handshake, so the witness builders keep
binding them. The next call reconnects, and a background thread proves the
backlog in the slack between epochs. `crates/witness-gen/src/remote_prover.rs`
has the detail.

**The split is affordable because the critical-path witness is small.**
Complement proving shrank the witness of the proof after `T` to **2,671 bytes**.
The only large witness is the committee proof at about **115 MB**, and that
proof has a full epoch of lead time.

Proofman serializes proof generation on one mutex, so one process proves one
proof at a time. Concurrency needs more processes, and a warm GPU prover sizes
its buffers to the free memory of the GPU, so more processes need more GPUs.

Provision the GPU machine with 150 GB of disk. The proving key reaches 105 GB
after the first setup, and `~/.zisk/cache` reaches 13 GB for four ELFs.

## Do not run a beacon node on a rented GPU machine

Rented GPU instances are ephemeral and are usually behind NAT. A node that
serves this pipeline must subscribe to every attestation subnet, and peering for
`--subscribe-all-subnets` is what an ephemeral NAT-ed instance is worst at. Run
the node on the stable machine, and send witnesses over the network instead.

## What the beacon node must serve

- **Every attestation subnet.** Unaggregated attestations are the primary
  source, and a node only sees the subnets it joins. Use
  `--subscribe-all-subnets` on Lighthouse, Prysm, Teku and Nimbus, or
  `--subscribeAllSubnets` on Lodestar. A default node gives a partial view of
  gossip.
- **A large SSE buffer.** Lighthouse holds each event topic in a ring of
  `--http-sse-capacity-multiplier` x 16 messages, and the default multiplier is
  1. A ring of sixteen messages against 30,000 attestations a slot loses
  attestations, and the node reports the loss only as an SSE comment. Run
  Lighthouse with
  `--http-sse-capacity-multiplier 2000`. That is a whole slot of messages for
  about 24 MB of node memory. `zkasperd` counts the comments and publishes them
  as `gossip.dropped`. Anything but zero there means the node is misconfigured.
- **`/eth/v2/debug/beacon/states/{id}`.** Every epoch diff reads the whole
  `BeaconState` as SSZ from it, and so does the boundary anchor a finalization
  opens out of the justified checkpoint's `state_roots`. It is a continuous
  dependency, not a one-off. Hosted providers usually disable it, because the
  response is several hundred megabytes — 335 MB on mainnet, measured. Startup
  itself does not need it: the init point carries the branch from its state root
  to the validators field, so a fresh run walks the registry and nothing else.
- **`/eth/v1/events?topics=attestation,single_attestation,chain_reorg`.** This
  is the streaming source. `--no-gossip` falls back to reading attestations out
  of blocks, which is a slot behind the chain by construction.
- **`/eth/v1/beacon/states/{id}/committees`.** Nothing recomputes the shuffle.
  A node that lies here costs liveness and not soundness. Read
  [assumptions.md](assumptions.md) before you trust a node with it.

[gossip.md](gossip.md) holds the measured cost of the attestation feed and the
case for a forked node.

## Publishing

`zkasperd` writes one directory per epoch and rewrites `status.json` after every
stage:

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

`crates/witness-gen/src/publish.rs` posts every stage to the public API as it
happens. The daemon is the source of truth and the API is a mirror of it, so a
slow or unreachable API never holds a proof up. Events go into a bounded queue,
and a batch that cannot be posted is spooled to disk and drained later.

The API keeps the epoch index in a Durable Object with SQLite storage. Proof
bytes land in the same store today, and the storage abstraction moves them to
R2 object storage as soon as the R2 binding is enabled. The site and every
other consumer read that API, which stores what the daemon posted and never
recomputes it. The contract is in [api-v1.md](api-v1.md).

## Where the accumulator starts

`zkasperd` does not prove its own starting accumulator. It is given one, as an
init point: a JSON tuple naming the epoch, the beacon state root the registry
was read from, the accumulator root, the commitment, the total active balance
and the branch from the state root down to the `validators` field. On a fresh
run the daemon checks the tuple binds itself, walks the registry at that epoch,
and refuses to start unless everything it rebuilds matches. `zkasper-init-point`
takes one from a beacon node, so a third party can regenerate a deployment's and
compare. See [assumptions.md](assumptions.md) for what this trusts and what it
does not, and `crates/witness-gen/src/init_point.rs` for the code.

This replaced a bootstrap proof that took about two minutes over a 2.3M-validator
state. That mattered operationally rather than cryptographically: the state a
run starts from is the oldest one a checkpoint-synced node still serves, so a
two-minute startup routinely lost its own state to the node's advancing split
and crashlooped. Startup is now a registry walk with no proving and no 335 MB
state download.

## Restart safety

The accumulator is a chain, so a corrupt or skipped step must not survive a
restart. The store writes atomically, checksums what it writes, rehashes the
tree on load, and compares the result against the recorded root. It refuses any
epoch diff that is not exactly one epoch forward.

If the node has thrown away a state the run still needs, the daemon stops and
says so rather than starting a new accumulator over the top of the old one.
Recovering means taking a fresh init point and publishing it, because the
accumulator chain genuinely breaks at that epoch and a consumer has to be able
to see that it did.

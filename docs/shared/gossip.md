# Attestation ingest

Both proofs read the same feed. This page is the transport, and it belongs to
neither product: the finality proof takes target votes out of it and the fast
confirmation rule would take head votes out of it. The measurements below were
taken against the finality pipeline, which is the only one that runs.

The daemon builds its own aggregates. It subscribes to unaggregated gossip and
groups the attestations by `AttestationData` root. It sums the signatures
natively on the host, and hands the circuit one aggregate per distinct message. Network
aggregates are a backstop, taken only where the singles left a hole.

This document holds the measurements behind that choice.
[../finality/architecture.md](../finality/architecture.md) holds the operational
requirements it puts on the beacon node.

## Why the daemon sums its own

**Coverage is a cost.** A network aggregator publishes the best cover it has
seen. An attester that is missing from that cover becomes a named absentee in
the complement proof, and every named absentee makes the proof longer. Singles
let the daemon find those validators itself. Measured on mainnet epoch 430529,
the gap is real and small. The first block to carry a slot missed 11 attesters
on the slot that crosses 2/3. It missed 236 across the epoch, and 87 on the
worst slot. Those counts are a lower bound on what one aggregate pool misses.

**Four seconds.** A node publishes unaggregated attestations a third of a slot
in, and aggregates two thirds of a slot in. The trigger fires when the arrival
burst drains, so the earlier source takes four seconds off `T2`.

**Minimality by construction.** A single attestation names one validator, so a
running sum over singles is disjoint and there is no cover to choose. A slot
costs about 51.8M cost units for another distinct message against 53K for
another absentee, so one aggregate per message is the shape worth having.

## Disjointness at the seam is proven, not assumed

Summing the signature of one validator twice still verifies: `sig + sig_v`
closes against `2·pk_v + rest`. Nothing downstream catches a double count. The
collector therefore seeds the merge with its own summed singles. It takes a
network aggregate only when the signers of that aggregate are disjoint from
everything already counted. In practice that happens only for a committee that
the singles feed missed entirely.

## What the feed costs

Per mainnet slot of 30,030 unaggregated attestations:

| | wire | daemon CPU | per attestation |
|---|---|---|---|
| JSON frames over SSE | 18.45 MB | 0.121 s | 4.0 us |
| socket to inbox, end to end | 18.45 MB | 0.204 s | 6.8 us |
| the same as fixed 240-byte SSZ | 7.21 MB | 0.00016 s | 5.3 ns |
| summing the signatures (G2) | — | 0.678 s | 22.6 us |

Reproduce the table with:

```sh
cargo test --release -p zkasper-witness-gen throughput -- --ignored --nocapture
```

Ingest and summing together are 0.88 s of one core per slot, which is 7.3% of a
12 s slot, and both parallelise. The daemon is not the bottleneck. Note where
the cost sits: an SSZ wire format removes 0.12 s of the 0.88 s, and the
signature arithmetic that SSZ does not touch is 77% of it.

## The node is the bottleneck, and it takes one flag

Lighthouse holds each SSE topic in a `tokio::sync::broadcast` ring of
`--http-sse-capacity-multiplier` x 16 messages. The default multiplier is 1, so
the `single_attestation` topic buffers sixteen messages against the thirty
thousand of a slot. A consumer that falls behind gets `Lagged(n)`, which the
node renders as an SSE comment — `error - dropped n messages` — while the
attestations themselves are gone. A client that ignores comments loses
attestations and never learns that it did.

Run the node with `--http-sse-capacity-multiplier 2000`. That is 32,000
messages, a whole slot, for about 24 MB of node memory. 64 absorbs ordinary
millisecond jitter at 30,000 events a second, and 2,000 makes loss essentially
impossible. `zkasperd` counts the comments and publishes them as
`gossip.dropped` in `status.json`, and it repairs each gap from blocks.

## What a forked node can expose

Stock Lighthouse with the flag above works, so a fork is an optimisation and not
a precondition. The options, in increasing order of what they remove:

1. **SSZ event frames.** Length-prefixed fixed-size records on the same event
   stream: 7.21 MB a slot instead of 18.45 MB, and decoding becomes free
   (5.3 ns against 4.0 us). This removes 0.12 s of the 0.88 s.
2. **Pre-grouped, pre-summed attestations.** This is the one worth building. The
   node already computes the attestation data root during gossip validation and
   already holds the signatures. It can therefore emit, per slot and per
   distinct `AttestationData`, a running
   `(data, aggregate signature, participation bitfield)` snapshot at a fixed
   cadence. 100 ms is finer than the trigger interval of the daemon. Epoch
   430529 averages 2.8 distinct messages a slot, so that is three events and
   about two kilobytes a slot instead of 30,030 events and 18 MB. It removes the
   whole 0.88 s, and it removes the merge seam: each snapshot replaces the
   running total of the daemon for that message wholesale, so there is no union
   left to prove disjoint. The cadence matters as much as the content. A single
   emission at the end of a slot destroys the incremental convergence that the
   trigger reads its arrival rate from.
3. **A unix socket or a shared-memory ring**, if HTTP framing ever appears in a
   profile. Nothing measured here says that it does.

**Do not embed `lighthouse_network` and subscribe to the subnets directly.**
Every source above delivers attestations that the node has already
gossip-validated. Raw libp2p makes that validation ours, and a mistake in it
lets a peer feed us signatures over arbitrary data. The circuit still rejects a
bad signature, so this is liveness and denial of service rather than soundness.
It is still a large amount of consensus code to own, for a cost that is already
7.3% of one core.

## The seam in the code

All of these sit behind `AttestationSource` in
`crates/witness-gen/src/gossip.rs`, which is a `drain`, a reorg flag, a gap flag
and some counters. Swapping the transport does not touch the pipeline.

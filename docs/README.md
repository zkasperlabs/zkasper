# zkasper documentation

zkasper builds **two proofs**, and they are two products. They have different
threat models, different thresholds and different circuits, and reading a
conclusion from one into the other has already produced wrong answers. The
documentation is split so that cannot happen quietly.

| | [finality](finality/) | [fcr](fcr/) |
|---|---|---|
| claim | in each of two consecutive epochs, at least 2/3 of the active effective balance attested to the target checkpoint | at one slot, head votes above an adversary-aware threshold all descend from one block |
| latency | ~13 min (2 epochs) | ~12 s (1 slot) |
| threshold | 2/3 of active effective balance | the specification's own adversary-aware bound, unmodified, evaluated by the verifier |
| committee proof | yes, one per epoch, produced an epoch ahead | **yes, and it needs the shuffle proven** — its denominator is a bucket |
| status | runs against mainnet | batch proof built (`crates/fcr-proof-guest`), no GPU run, no witness generation |

## The pages

| page | what it holds |
|---|---|
| [finality/assumptions.md](finality/assumptions.md) | what a finalization proof trusts, and the risks accepted in it |
| [finality/architecture.md](finality/architecture.md) | the finality stages, what feeds what, and the machines |
| [finality/api-v1.md](finality/api-v1.md) | the public HTTP API, which serves finality proofs |
| [fcr/assumptions.md](fcr/assumptions.md) | what a fast confirmation proof would trust |
| [fcr/architecture.md](fcr/architecture.md) | the FCR circuit design |
| [shared/assumptions.md](shared/assumptions.md) | the accumulator, the BLS arithmetic, the prover and the wrap — what both rest on |
| [shared/gossip.md](shared/gossip.md) | the attestation feed both would read, and what it costs |

Read a product's `assumptions.md` **and** `shared/assumptions.md`. Neither is
complete on its own, and the shared page exists so that the accumulator and the
BLS arithmetic are stated once rather than kept in two copies that drift apart.

## Where things went

This tree replaces one mixed assumptions page, one architecture page, and an FCR
design document at the repository root. Every old path still resolves: each one
now holds a pointer to the page that took it over.

Two of those moves are worth the sentence they cost. **The API is
finality's** because every path in it is indexed by epoch and every public input
it publishes is a finality claim; an FCR confirmation is indexed by block root
and slot and would need endpoints of its own. **The attestation feed is
shared** because it is transport: finality takes target votes out of it and FCR
would take head votes out of it, and nothing in the measurements depends on
which.

## Elsewhere in the repository

| page | what it holds |
|---|---|
| [../RUNBOOK.md](../RUNBOOK.md) | how to provision, run, monitor and recover a mainnet deployment |
| [../BENCHMARKS.md](../BENCHMARKS.md) | every cost constant, and what measured it |
| [../monitoring/README.md](../monitoring/README.md) | the metrics the daemon serves, and what pages on them |

- [shared/committee-and-shuffle.md](shared/committee-and-shuffle.md) - one proof per epoch establishes the committee assignment and the per-slot sums, an epoch ahead. Settled design.

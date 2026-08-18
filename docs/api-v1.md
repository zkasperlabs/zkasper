# zkasper public API, v1

The daemon proves. The API stores what the daemon says and serves it back. It
never recomputes a proof, never re-derives a timing, and never infers that
something was finalized: every number below was measured by `zkasperd` and
posted to `/v1/ingest`. A field that is absent is a field the daemon did not
report, not a zero.

Base URL: `https://api.zkasper.com` (also reachable at
`https://zkasper-api.lune-gift.workers.dev`).

```
GET  /v1/status              daemon state, head slot, last finalized, current epoch progress
GET  /v1/epochs?limit=50     recent proven epochs, newest first
GET  /v1/epochs/{epoch}      one epoch: every stage with timings, T2-T, proof location
GET  /v1/proofs/{epoch}      the wrapped proof bytes
GET  /v1/live                SSE stream of stage events as they happen
POST /v1/ingest              authenticated, from zkasperd
```

## Conventions

- JSON, UTF-8. Every response carries `access-control-allow-origin: *`.
- Byte strings are `0x`-prefixed lowercase hex, of fixed width.
- `u64` values that can exceed 2^53 — balances, verification keys — are strings.
  Epochs, slots and millisecond durations stay numbers.
- Times ending `_unix_millis` are integers, milliseconds since the Unix epoch, on
  the daemon's clock. `updated_unix` is seconds, and matches the daemon's own
  `status.json`.
- Durations ending `_millis` are integers measured by the daemon.
- Errors: `{"error": "not_found", "message": "..."}` with a 4xx/5xx status.
- Unknown query parameters are ignored. Unknown JSON fields may appear at any
  time; a client must not break on them.

## Shared objects

### `checkpoint`

```json
{ "epoch": 469367, "root": "0x8f...c1" }
```

### `accumulator`

The validator-set accumulator the proofs are bound to.

```json
{
  "epoch": 469368,
  "root": "0x2c...9a",
  "commitment": "0x71...04",
  "chain_digest": "0xab...7e",
  "total_active_balance": "34212000000000000",
  "num_validators": 1081226
}
```

`chain_digest` is the running hash over every `(epoch, acc_root)` since
bootstrap. Two daemons that followed the same chain agree on it; one that missed
an epoch does not.

### `stage`

One proof stage that ran. `millis` is the whole stage including witness
generation; `prove_millis` and `wrap_millis` are the part the prover charged for
and are absent on a witness-only run.

```json
{
  "stage": "group",
  "epoch": 469368,
  "slot": null,
  "index": 3,
  "started_unix_millis": 1755525123456,
  "finished_unix_millis": 1755525130636,
  "millis": 7180,
  "prove_millis": 7010,
  "wrap_millis": 160,
  "witness": { "path": "epoch-000469368/group_12.bin", "bytes": 728 },
  "proof_bytes": 262144
}
```

`stage` is one of `bootstrap`, `epoch_diff`, `committee`, `slot_proof`,
`justification`, `finalization`, `group`, `aggregate`, `stream_final` — the
daemon's own names, unchanged. `index` orders repeats of the same stage inside an
epoch (group 0, group 1, …) and is `null` for stages that run once.

### `latency`

The measured `T2 - T`: `T` is when the daemon held the attestation that carried
the epoch over the threshold, `T2` is when a proof of it existed. Everything else
the pipeline does happens before `T`.

```json
{
  "epoch": 469368,
  "threshold_unix_millis": 1755525130000,
  "fired_unix_millis": 1755525131200,
  "proof_unix_millis": 1755525140400,
  "t2_minus_t_millis": 10400,
  "wait_millis": 1200,
  "tail": 1,
  "tail_named": 14,
  "folded_groups": 6,
  "late_groups": 0
}
```

`wait_millis` is the part of `t2_minus_t_millis` that was the trigger holding
back rather than the prover working. `late_groups` above zero says the daemon was
behind the chain.

### `proof`

One epoch has one published proof: the last one, which recursively verifies
every proof under it. Group and aggregate proofs are not served — the final proof
already contains their verification, so a third party needs only this one.

```json
{
  "stage": "stream_final",
  "available": true,
  "bytes": 262144,
  "words": 32768,
  "sha256": "0x44...f0",
  "program": "zkasper-stream-final-guest",
  "program_vk": "0x9d...12",
  "public_bytes": "0x01...00",
  "url": "/v1/proofs/469368"
}
```

- `program_vk` — 32 bytes: the guest program's 4-word verification key, words in
  little-endian order. A proof of any other program has a different key.
- `public_bytes` — the exact byte string the circuit committed, as
  `PublicWriter` laid it out. The proof carries the same bytes; these are
  published so a verifier can compare without parsing the proof.
- `available: false` with `bytes: 0` means the run produced no proof bytes —
  which is what `--prover native` does. Every timing is still real.

### `public_inputs`

The decoded form of `public_bytes` for a `stream_final` proof. This is the claim.

```json
{
  "accumulator_commitment": "0x71...04",
  "next_accumulator_commitment": "0x88...2b",
  "finalized_epoch": 469367,
  "finalized_root": "0x8f...c1",
  "finalized_state_root": "0x3d...aa",
  "justified_epoch": 469368,
  "justified_root": "0x2e...5c"
}
```

For a `finalization` proof (the batch pipeline, which runs for the first epoch
after a bootstrap) the fields are `accumulator_commitment`, `finalized_epoch`,
`finalized_root`, `finalized_state_root`.

### `verify`

Everything a third party needs to check the epoch without trusting this API.
See "Verifying a proof" at the end.

```json
{
  "stage": "stream_final",
  "program": "zkasper-stream-final-guest",
  "program_vk": "0x9d...12",
  "elf_sha256": "0x2a...b7",
  "zisk_version": "v1.1.0-alpha",
  "zkasper_commit": "e4afd4c",
  "chain": "mainnet",
  "public_bytes": "0x01...00",
  "public_inputs": { "...": "as above" },
  "proof_url": "/v1/proofs/469368"
}
```

### `posting`

One finalization proof, verified on another chain. The daemon proves; something
else submits, and reports back. Every field is what the submitter measured from
the transaction receipt, forwarded unchanged.

```json
{
  "chain": "solana-mainnet-beta",
  "program": "Cuarryex9DFpVm6HNdCFvpS3EEeArSuTXDMNTk9hpKja",
  "epoch": 469367,
  "finalized_root": "0x8f...c1",
  "signature": "4Jr...oGF",
  "slot": 351019776,
  "compute_units": 99150,
  "fee_lamports": 5000,
  "rent_lamports": 2867520,
  "lamports_spent": 2872520,
  "status": "confirmed",
  "explorer": "https://explorer.solana.com/tx/4Jr...oGF",
  "unix_millis": 1755525141900
}
```

- `chain` is the chain it was posted **to**, not the one the proof is about:
  `solana-mainnet-beta`, `solana-devnet`, `solana-testnet` or `solana-localnet`.
  It is derived from the cluster's genesis hash, so a posting cannot claim a
  chain it did not land on.
- `epoch` and `finalized_root` are the Ethereum checkpoint the proof finalized,
  and match the `public_inputs` of the epoch with the same number.
- `slot` is the Solana slot the transaction landed in.
- `fee_lamports` is the transaction fee. `rent_lamports` is what the submitter
  left behind as the rent-exempt balance of the two accounts the program creates
  per finalization, which is the larger number and is not refundable — the
  program has no instruction that closes an account. `lamports_spent` is both,
  and is what the submission actually cost.
- `status` is `confirmed` or `failed`, as the submitter observed it.

## `GET /v1/status`

Where the daemon is, now. Polled by anything that cannot hold an SSE connection;
everything here also arrives on `/v1/live` as a `status` event.

```json
{
  "version": 1,
  "chain": "mainnet",
  "prover": "zisk (embedded, warm)",
  "pipeline": "streaming",
  "updated_unix": 1755525140,
  "head_slot": 15019776,
  "bootstrap_epoch": 469300,
  "accumulator": { "...": "accumulator" },
  "justified_through": 469368,
  "last_justified": { "...": "checkpoint" },
  "last_finalized": { "...": "checkpoint" },
  "node_finalized": { "...": "checkpoint" },
  "genesis_validators_root": "0x4b36...fe95",
  "prover_usd_per_hour": 0.51,
  "gossip": { "attestations": 4210233, "reconnects": 0, "dropped": 0 },
  "recent_stages": [ { "...": "stage" } ],
  "recent_latencies": [ { "...": "latency" } ],
  "postings": [ { "...": "posting" } ],
  "current_epoch": {
    "epoch": 469369,
    "target_root": "0x2e...5c",
    "opened_unix_millis": 1755525140000,
    "state": "collecting",
    "attesting_balance": "14100000000000000",
    "total_active_balance": "34212000000000000",
    "attesting_pct": 41.2,
    "threshold_pct": 66.67,
    "folded_groups": 5,
    "slots_held": 12,
    "finalizes_epoch": 469368
  },
  "service": {
    "received_unix_millis": 1755525140812,
    "age_millis": 812,
    "stale": false,
    "seq": 918233,
    "epochs_indexed": 240,
    "proofs_stored": 239,
    "proof_bytes_stored": "62914560"
  }
}
```

- `last_finalized` is what **this daemon proved**. `node_finalized` is what the
  beacon node it follows believes, for comparison. They should track; a gap is
  the daemon being behind, never the chain being wrong.
- `current_epoch` is `null` between epochs. `state` is `collecting` (below the
  threshold), `firing` (threshold crossed, final proof running) or `catching_up`
  (the epoch opened already past the threshold, so there is no honest `T` to
  report).
- `postings` is the recent postings, oldest last, and is **absent** when nothing
  is submitting these proofs to a chain. It is not a claim the daemon makes: the
  daemon forwards what a submitter told it. An epoch with a proof and no posting
  was proven and not submitted, which is the normal state of a run with no
  submitter attached.
- `service.stale` is true when nothing has arrived from the daemon for 120 s.
  The dashboard should say so rather than show a frozen number as live.
- Cache: `public, max-age=2`.

## `GET /v1/epochs`

Recent epochs, newest first.

Query: `limit` (default 50, max 200), `before` (return epochs strictly below this
number, for paging), `status` (`proven`, `proving`, `abandoned`).

```json
{
  "chain": "mainnet",
  "count": 50,
  "next_before": 469318,
  "epochs": [
    {
      "epoch": 469368,
      "target_root": "0x2e...5c",
      "status": "proven",
      "pipeline": "streaming",
      "prover": "zisk (embedded, warm)",
      "opened_unix_millis": 1755524756000,
      "closed_unix_millis": 1755525140400,
      "justified": { "...": "checkpoint" },
      "finalized": { "...": "checkpoint" },
      "latency": { "...": "latency" },
      "stage_count": 14,
      "prove_millis_total": 41234,
      "wrap_millis_total": 402,
      "prover_millis_total": 41636,
      "proof": { "...": "proof" }
    }
  ]
}
```

`status`:
- `proving` — open, no final proof yet. `latency`, `finalized` and `proof` are null.
- `proven` — a final proof exists.
- `abandoned` — the chain never justified the checkpoint, or it reorged out from
  under the daemon. `abandoned_reason` says which.

The first epoch of a run is `proven` with `finalized: null` and a `proof` whose
stage is `justification`. It has nothing before it to finalize — a bootstrap has
no previous justification to pair with — so a justification is the only proof it
will ever have. Every epoch after it is closed by `stream_final`.

`next_before` is null when there is no older page. Cache: `public, max-age=5`.

## `GET /v1/epochs/{epoch}`

One epoch, with every stage that ran.

```json
{
  "epoch": 469368,
  "target_root": "0x2e...5c",
  "status": "proven",
  "pipeline": "streaming",
  "prover": "zisk (embedded, warm)",
  "chain": "mainnet",
  "opened_unix_millis": 1755524756000,
  "closed_unix_millis": 1755525140400,
  "justified": { "...": "checkpoint" },
  "finalized": { "...": "checkpoint" },
  "finalizes_epoch": 469367,
  "accumulator": { "...": "accumulator" },
  "latency": { "...": "latency" },
  "stages": [ { "...": "stage" } ],
  "stage_count": 14,
  "prove_millis_total": 41234,
  "wrap_millis_total": 402,
  "prover_millis_total": 41636,
  "wall_millis_total": 384000,
  "proof": { "...": "proof" },
  "public_inputs": { "...": "public_inputs" },
  "verify": { "...": "verify" }
}
```

`stages` is ordered by `started_unix_millis`. 404 for an epoch this daemon never
opened. Cache: `public, max-age=5` while `proving`, `public, max-age=86400`
once `proven` or `abandoned`.

### What an epoch cost

`prover_millis_total` is the prover time an epoch bought: `prove_millis_total`
for the proofs and `wrap_millis_total` for the compressions after them. Every
stage carries its own two numbers, so `stages` says where the time went — on
mainnet almost all of it is the committee proof, which is why that stage is
given a whole epoch of lead time and is the one worth optimising.

Multiply by `prover_usd_per_hour` from `/v1/status` for what the epoch cost the
deployment that produced it, or by your own rate for what it would cost you.
The two are published apart deliberately: an hourly rate is a fact about a
rental contract rather than about the pipeline, it changes without the pipeline
changing, and a price baked in here could not be recomputed against anything
else. Nothing in the daemon or the API multiplies them.

`prover_usd_per_hour` is absent when the operator did not say what the hardware
costs, and the milliseconds are zero on a `--prover native` run, which proves
nothing.

## `GET /v1/proofs/{epoch}`

The proof bytes, exactly as the prover produced them: the serialized Zisk
proof's `u64` words, little-endian, 8 bytes each, no header, no framing.
`content-length` is always a multiple of 8.

```
content-type: application/octet-stream
content-length: 262144
etag: "0x44...f0"
cache-control: public, max-age=31536000, immutable
x-zkasper-epoch: 469368
x-zkasper-stage: stream_final
x-zkasper-program-vk: 0x9d...12
x-zkasper-public-bytes: 0x01...00
x-zkasper-sha256: 0x44...f0
```

`HEAD` returns the same headers with no body. 404 with a JSON body when the epoch
has no proof bytes, including every epoch of a `--prover native` run.

## `GET /v1/live`

Server-sent events. One connection carries the whole pipeline; a dashboard should
never need to poll.

```
content-type: text/event-stream
cache-control: no-store
```

Each event is `id:` (a monotonic `seq`), `event:` (the type) and `data:` (JSON).
Reconnect with `Last-Event-ID`, or `GET /v1/live?since=<seq>`, and the server
replays everything after that `seq` that is still in its buffer (the last 5,000
events, about six hours) before going live. `?replay=0` skips the replay.
A `: keepalive` comment is sent every 15 s.

Every `data` object carries `seq` and `unix_millis`.

| event | when | payload |
| --- | --- | --- |
| `hello` | on connect | `{seq, unix_millis, status}` — the whole `/v1/status` body, so a dashboard renders before its first poll |
| `status` | every daemon tick, at most every 5 s | `{seq, unix_millis, status}` |
| `epoch.opened` | the daemon starts an epoch | `{seq, unix_millis, epoch, target_root, finalizes_epoch, total_active_balance, accumulator}` |
| `epoch.progress` | while collecting, at most every 4 s | `{seq, unix_millis, epoch, attesting_balance, total_active_balance, attesting_pct, threshold_pct, folded_groups, slots_held, head_slot}` |
| `stage.started` | a proof starts | `{seq, unix_millis, epoch, stage, slot, index}` |
| `stage.finished` | a proof lands | `{seq, unix_millis, epoch, stage, slot, index, millis, prove_millis, wrap_millis, witness, proof_bytes}` |
| `threshold.crossed` | `T` | `{seq, unix_millis, epoch, threshold_unix_millis, attesting_balance, total_active_balance, attesting_pct}` |
| `threshold.fired` | the trigger fires | `{seq, unix_millis, epoch, fired_unix_millis, wait_millis, tail, tail_named, late_groups}` |
| `proof.landed` | `T2` | `{seq, unix_millis, epoch, proof, public_inputs, latency}` |
| `posting.landed` | a proof is verified on another chain | `{seq, unix_millis, epoch, posting}` |
| `epoch.closed` | epoch finished | `{seq, unix_millis, epoch, summary}` — `summary` is the `/v1/epochs` entry |
| `epoch.abandoned` | epoch given up | `{seq, unix_millis, epoch, reason}` |

Rendering a proof being built needs nothing else: `epoch.opened` draws the row,
`stage.started` opens a bar, `stage.finished` closes it with its measured
duration, `epoch.progress` moves the weight toward 2/3, `threshold.crossed`
marks `T`, and `proof.landed` marks `T2` and gives you `t2_minus_t_millis`.

An event type a client does not know must be ignored. New types will be added.

## `POST /v1/ingest`

`Authorization: Bearer <token>`. 401 without it. This is the only write path and
only `zkasperd` holds the token.

```json
{
  "daemon": {
    "id": "zkasperd-gpu-1",
    "chain": "mainnet",
    "prover": "zisk (embedded, warm)",
    "pipeline": "streaming",
    "version": "0.1.0",
    "commit": "e4afd4c",
    "zisk_version": "v1.1.0-alpha"
  },
  "events": [ { "type": "stage.finished", "seq": 918234, "unix_millis": 1755525130636, "...": "" } ],
  "status": { "...": "the /v1/status body, or null" }
}
```

Every event carries a daemon-assigned `seq` that never repeats and never goes
backwards, so the server can store with `INSERT OR IGNORE` and a replayed batch
costs nothing. Response:

```json
{ "ok": true, "accepted": 12, "duplicates": 0, "last_seq": 918245 }
```

### `POST /v1/ingest/proof/{epoch}`

The proof bytes, `content-type: application/octet-stream`, same layout as
`GET /v1/proofs/{epoch}` serves. Headers `x-zkasper-stage`,
`x-zkasper-program-vk`, `x-zkasper-public-bytes`, `x-zkasper-sha256`. The server
checks the SHA-256 before storing and returns
`{ "ok": true, "bytes": 262144, "sha256": "0x...", "stored": "r2" }`.

### `GET /v1/ingest/cursor`

Authenticated. `{ "last_seq": 918245, "last_epoch": 469368, "missing_proofs": [469361] }`
— what the daemon backfills against after an outage.

## Verifying a proof

Nothing here has to be taken on trust. To check that epoch `E` was finalized:

1. `GET /v1/epochs/E` and read `verify`.
2. `GET /v1/proofs/E` — the proof words.
3. Build the guest yourself: `git checkout <verify.zkasper_commit>`, then
   `./scripts/build_guests.sh <verify.program>` with Zisk
   `verify.zisk_version`. Its verification key must equal `verify.program_vk`.
   That is what binds the proof to this circuit rather than to any circuit.
4. Check the proof: `zkasper_common::recursion::verify_child(&words,
   &program_vk, &public_bytes)`. It checks the key the proof commits to, the
   public bytes it commits to, that nothing was smuggled into the unused public
   words, and then the STARK itself.
5. Check the claim against the chain: `public_inputs.finalized_root` is the block
   root of epoch `public_inputs.finalized_epoch`'s checkpoint, and
   `finalized_state_root` is that block's state root. Ask any beacon node.
6. Check the accumulator: `public_inputs.accumulator_commitment` is the
   validator set the attestations were opened against. It chains back to
   bootstrap through the epoch diffs, and `/v1/status`'s
   `accumulator.chain_digest` is the running hash of that chain — recompute it
   from the epoch list and compare.

Steps 1-5 need nothing from zkasper but the bytes this API serves. Step 6 is what
makes a *series* of proofs a chain rather than a pile.

## Storage, retention, and what a month costs

**One Durable Object with SQLite storage** holds the epoch index, the stage
events and the live fan-out; **R2** holds the proof bytes. D1 would be the
textbook choice for the index, but the daemon is a single writer and the SSE
fan-out wants a single object anyway, and putting both in one object removes a
round trip. The account's API token can create neither a D1 database nor a KV
namespace, and R2 is not enabled on the account at all — see "What is not
enabled yet" — so today the proof bytes fall back to a chunked blob table inside
the same object. Switching to R2 is a binding in `api/wrangler.jsonc` and a
redeploy; nothing else changes.

### What is kept

| what | where | how long |
| --- | --- | --- |
| one proof per epoch | R2 (blob table until R2 is enabled) | forever; it is the product |
| epoch summary, latency, public inputs | SQLite | forever |
| stage rows | SQLite | 90 days, then only the summary survives |
| event log for SSE replay | SQLite ring buffer | last 5,000 events, about six hours |
| status snapshot | SQLite, one row, overwritten | latest only |

Group and aggregate proofs are deliberately not stored. The final proof of an
epoch recursively verifies every proof beneath it, so keeping them would be
keeping the same claim several times over.

### A month of mainnet

6,750 epochs. Per epoch the daemon writes about 126 rows — 43 stage events, 45
progress updates at the 6 s floor, 38 status snapshots at the 10 s floor — posted
in batches of up to a second's worth.

| resource | a month of mainnet | free tier | fits |
| --- | --- | --- | --- |
| Worker and DO requests | ~23,000 / day of ingest, plus readers | 100,000 / day each | yes, with ~77,000 / day left for the dashboard |
| SQLite rows written | ~28,000 / day | 100,000 / day | yes |
| SQLite rows read | dominated by readers | 5,000,000 / day | yes |
| proof bytes at 256 KB each | 1.7 GB | R2 10 GB-month | yes |
| proof bytes at 1 MB each | 6.6 GB | R2 10 GB-month | yes |
| the same in the SQLite fallback | 1.7 GB / 6.6 GB | 5 GB total | only under about 700 KB a proof |
| R2 writes | 6,750 Class A | 1,000,000 / month | yes |
| egress | whatever the dashboard pulls | free on R2 | yes |

**A proof's size is not measured yet.** The pipeline has never run against a real
prover for a month, and `--prover native` produces no bytes at all. The API
records `bytes` on every proof, so the real number exists on day one of the GPU
month; the table is why it does not change the answer unless a proof turns out to
be several megabytes. Beyond the free tier R2 is $0.015 per GB-month, so a whole
year of mainnet at 1 MB a proof is 79 GB, or $1.04 a month.

**Where it does not fit.** `/v1/live` is the one thing that can push this off the
free plan. A Durable Object is billed for wall-clock time while it is active, and
an open SSE connection keeps it active: 13,000 GB-s a day against 128 MB is 28
hours of active time, so **one** continuously connected viewer is about 85% of
the daily allowance. Further concurrent viewers are free — they share the object
— but a day with someone watching around the clock will graze the limit, and a
burst will exceed it. The fix is the $5/month Workers Paid plan, which also lifts
requests to 10 million a month. Nothing else here needs it.

### What is not enabled yet

Two things need a human in the Cloudflare dashboard. Neither blocks the daemon or
the dashboard.

1. **R2 is not enabled on the account.** Its S3 endpoint does not complete a TLS
   handshake, and the API refuses bucket calls with "Please enable R2 through the
   Cloudflare Dashboard". Enabling it is free. Then create a bucket
   `zkasper-proofs` — its own bucket, not the `lune.gift` one, even though both
   zones sit in the same account — add the `PROOFS` binding to
   `api/wrangler.jsonc`, and redeploy.
2. **The API token cannot create D1, KV or R2 resources.** It can deploy Workers
   and Durable Objects, which is why the design uses those. A token with
   `D1:Edit`, `Workers R2 Storage:Edit` and `Workers KV Storage:Edit` would widen
   the options; nothing currently needs it.

## Changes since this document was first published

The contract above is what the dashboard should build against. These are the
points where the running implementation is more specific than the first draft, or
differs from it. Nothing here renames or removes a field.

1. **`hello`'s `id:` and `data.seq` are the resume anchor, not the head**, when
   the client connected with `?since=` or `Last-Event-ID`. Anchoring on the head
   would let a disconnect mid-replay skip the replayed range silently. Without
   replay it is the head, as before.
2. **A `status` SSE event is synthesized** when an ingest batch carries a status
   but no `status`-typed event — which is the normal case, because the daemon
   attaches its manifest to a batch rather than sending it as an event. Deduped
   on `updated_unix`, so a replayed spool emits nothing extra.
3. **`/v1/status` before anything has ever been ingested is `200`**, with
   `chain`, `prover` and `pipeline` null and
   `service: {received_unix_millis: null, stale: true}`. Read that as "no daemon
   yet", not "daemon frozen".
4. **`/v1/proofs/{epoch}` can return `410 gone`** when inline bytes were evicted
   under the fallback store's cap. `404` still means the epoch never had bytes,
   which includes every epoch of a `--prover native` run.
5. **`verify` and `verify.elf_sha256` may be null.** The daemon sends
   `elf_sha256` inside the `proof` object; it is null under `--prover native`,
   which has no ELF, and populated under `--prover zisk`.
6. **`epoch.closed`'s `summary` is shallow-merged** into `proof`,
   `public_inputs`, `verify`, `latency` and `accumulator` rather than replacing
   them, so a richer value an earlier `proof.landed` carried survives.
7. **Derived server-side only when the daemon did not send them**, never
   overriding: `stage_count`, `prove_millis_total`, `prover_millis_total`,
   `wall_millis_total`,
   `next_before`, `service.*`, `current_epoch.attesting_pct` (computed on the
   u64 strings, so it carries more decimals than the example) and `proof.url`.
8. **`abandoned_reason` is omitted rather than null** when the epoch was not
   abandoned.
9. **`current_epoch.state` is `collecting` or `firing`.** There is no
   `catching_up`: the daemon cannot honestly tell a catch-up from a live follow
   at that point, and it reports no latency for such an epoch instead.
10. **`epoch.opened` also carries `chain`, `pipeline`, `prover` and
    `opened_unix_millis`**, so an epoch row is complete from its first event.
11. **Added endpoints:** `GET /v1/health` (and `/health`), and
    `POST /v1/ingest/reset` behind the same bearer token, which drops and
    recreates every table. The stream sequence counter deliberately survives a
    reset, so a connected client's `Last-Event-ID` never points into the future.
12. **Error codes beyond `not_found`:** `405 method_not_allowed`,
    `413 too_large`, `400 sha256_mismatch`, `400 bad_request` (a proof whose
    length is not a multiple of 8), `503 too_many_streams` (more than 200
    concurrent SSE readers), `401 unauthorized`.
13. **`access-control-allow-methods` is `GET, HEAD, OPTIONS`.** The write path is
    deliberately not reachable from a browser.
14. **`postings` and `posting.landed` carry proofs that reached another chain.**
    Both are absent until something submits. The API stores and fans them out
    without interpreting them; the only field it reads is `epoch`.
15. **Balances are strings everywhere, including in `status.json` on disk.**
    Mainnet's total active balance in gwei passed 2^53 long ago, so a JSON reader
    that parses it as a double rounds it. A u64 sent as a JSON number would be
    corrupted before the API ever saw it.

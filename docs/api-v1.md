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
  "gossip": { "attestations": 4210233, "reconnects": 0, "dropped": 0 },
  "recent_stages": [ { "...": "stage" } ],
  "recent_latencies": [ { "...": "latency" } ],
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
  "wall_millis_total": 384000,
  "proof": { "...": "proof" },
  "public_inputs": { "...": "public_inputs" },
  "verify": { "...": "verify" }
}
```

`stages` is ordered by `started_unix_millis`. 404 for an epoch this daemon never
opened. Cache: `public, max-age=5` while `proving`, `public, max-age=86400`
once `proven` or `abandoned`.

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

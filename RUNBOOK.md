# Running zkasperd against mainnet

How to provision, install, start, run, monitor and recover a continuous mainnet
finality-proving deployment.

Every number here is labelled MEASURED (with where and when) or MODELLED.
`scripts/gpu_bench.sh` is the companion document for the proving box; this one
covers the daemon and the chain it follows.

## State of play, 2026-08-18

Written from a live mainnet run on this machine: Lighthouse v8.2.1 checkpoint-
synced with a mock execution layer, `zkasperd --mode streaming --prover native`.

**Works.** Starting from a real 2.34M-validator state; all-subnets gossip at
28,033 attestations a slot with zero drops; the singles-first collector; the
schedule; the 2/3 trigger; reorg handling; the status manifest; restart recovery.
The three arrival-timing assumptions the design rests on are confirmed (§8).

**The warm prover now works on a GPU.** On 2026-08-18 a rented RTX 5090 built
`--features zisk-prover` under CUDA 12.9.1, produced real group and slot proofs
that `verify_child` accepted, and proved again with no re-initialisation. A
daemon with no CUDA drove the same prover over the network through
`zkasper-prover-server`, and kept running when the server was killed. The
per-stage times are in [BENCHMARKS.md](BENCHMARKS.md); nothing in §8 below is a
proving measurement, because §8 is the `--prover native` run.

**Does not work yet, in order of how much it matters.**

1. **The trigger's rate rule can fire on a quiet 200 ms window** in the middle of
   the burst. Two of the three steady-state epochs fired at 924 ms and 1,355 ms
   of wait, nowhere near the cap, with 8,159 and 6,822 attesters still in flight.
   Raising the cap does not reach those two (§8).

**Fixed during the run**: a slot could be proved twice; an empty boundary wedged
the epoch diff; a 404 was reported as a parse error; a pruned bootstrap state
wedged startup. See §8 and §6.

**Fixed since**: bootstrap is gone. The daemon starts from a trusted init point —
see [docs/assumptions.md](docs/assumptions.md) — which deletes the two-minute
startup and the whole "bootstrap epoch pruned" failure mode with it.

**Fixed after it**: an empty epoch boundary slot no longer ends the run — the
boundary state root is proven out of the justified checkpoint's `state_roots`
rather than read off a header that does not exist — and the trigger cap is
10,000 ms, above the range in which waiting still pays (§8).

## Contents

1. [Topology, and why the beacon node is not on the GPU box](#1-topology)
2. [The beacon node](#2-the-beacon-node)
3. [Installing and starting the node](#3-installing-and-starting-the-node)
4. [Starting and running the daemon](#4-starting-and-running-the-daemon)
5. [Monitoring: what to alert on](#5-monitoring-what-to-alert-on)
6. [Recovery](#6-recovery)
7. [Provisioning and cost](#7-provisioning-and-cost)
8. [Measured baseline](#8-measured-baseline)

---

## 1. Topology

Three components, and the split between them is not arbitrary.

```
  this machine (long-lived)                    rented GPU box (per run)
  ┌────────────────────────────────┐           ┌──────────────────────┐
  │ execution client or mock EL    │           │ prover server        │
  │        ↕ engine API :8551      │           │  one EmbeddedClient  │
  │ lighthouse bn  :5052           │           │  held for its life   │
  │        ↕ beacon API + SSE      │           └──────────────────────┘
  │ zkasperd                       │  witnesses  ▲                    │
  │  → status.json, witnesses      │─────────────┘   proofs ──────────┘
  └────────────────────────────────┘
```

**Put the beacon node with the daemon, never on the rented box.** Four reasons,
in the order they bite:

- The SSE stream is **1.47 MB/s, 3.8 TB/month** (MODELLED from the measured
  28,033 events/slot at ~630 B on the wire). Across the internet you pay egress
  on that; over loopback it is free.
- A rented instance is ephemeral. An interruption costs a re-sync of a component
  that takes hours to build and is not what you are renting the card for.
- Rented GPU boxes are usually behind NAT with restricted inbound, which is the
  worst case for `--subscribe-all-subnets` peering.
- You would pay GPU-instance rates to store a beacon database.

**The witnesses are small enough that the split is free.** A group-proof witness
is 728 bytes and a stream-final witness is 2,671 bytes (MEASURED, BENCHMARKS.md),
against a 5.5 s critical path. The one large witness is the committee proof at
~115 MB, and it has a full epoch of lead time.

---

## 2. The beacon node

### 2.1 Three hard requirements

zkasperd needs more from a node than a validator does. All three must hold.

| # | Requirement | Why |
|---|---|---|
| 1 | `--subscribe-all-subnets` | The `single_attestation` topic only carries subnets the node joined. A default node joins **2 of 64** (`SUBNETS_PER_NODE: 2`), so its feed is 3.1% of gossip. |
| 2 | `--http-sse-capacity-multiplier` **20000** | Lighthouse buffers each SSE topic in a broadcast ring of `multiplier × 16`. The default multiplier is 1, so **16 messages** against a slot's 28,130. 2000 gives 32,000 — only **1.1 slots** of headroom, so one stalled slot drops attestations. **20000 gives 320,000, about 11 slots, for roughly 128 MB of ring.** Overshoot deliberately: the ring is cheap and a drop is silent and unrecoverable. |
| 3 | `/eth/v2/debug/beacon/states/{id}` enabled | **Every epoch diff** reads the whole `BeaconState` from it, and so does the boundary anchor a finalization opens. It is a continuous dependency, not a one-off. Startup does not need it: the init point carries its own branch to the `validators` field. |
| 4 | `--epochs-per-migration` **16** | How far back the node still *has* the states requirement 3 serves. At the default of 1 this node served state only **64 to 95 slots back** (MEASURED 2026-08-18), two or three epochs, and a daemon that spends longer than that on one epoch asks for a state that has been migrated to the freezer and gets a 404. **It buys less than it looks like it should, and it is not steady:** it batches the migration rather than pinning states, so retention sawtooths between ~2 epochs just after one runs and ~16 just before. Probed at one instant it was 96 to 127 slots; twenty minutes later a state 229 slots back still read. Do not size anything against a single probe. |

**The window oscillates, so a long startup tax fails intermittently.**
`--epochs-per-migration 16` does not hold sixteen epochs of state at all times:
it batches the migration, so retention sawtooths between about two epochs just
after a migration and about sixteen just before one. Probed at one instant on
2026-08-19 it was **96 to 127 slots**; twenty minutes later the daemon read a
state **229 slots** back without complaint.

That is what made the old startup tax fail *intermittently* rather than always.
A first epoch that took 22 minutes — a justification recursively verifying all
22 slot proofs at **1,224 s**, measured twice — survived when it began early in
the migration cycle and died when it began late, with
`the node no longer serves the state epoch N needs`. Folding that justification
a few slot proofs at a time removes the tax, and with it the dependence on when
a run happens to start.

**Requirement 4 is what a real prover makes binding.** A witness-only daemon
never falls two epochs behind, so the default window is invisible. With proofs,
the first epoch of every run goes through the batch path, and that epoch used to
cost **1,452 s against a 384 s epoch** — of which one justification, verifying
every slot proof of the epoch in a single circuit, was 1,224 s (MEASURED
2026-08-18, mainnet epoch 469424). A run started about 20 minutes behind the
chain and spent the next 20 catching up. That is far longer than the default
window, so the daemon fell behind its own startup, 404ed, and crashlooped — 74
restarts in an hour.

**That epoch is about 320 s now** (MODELLED over measured parts; the recursion
and committee terms are measured at mainnet scale). Slots are proven in groups
of eleven and folded into a justification chain, so the epoch's ~22 slots are
two children rather than twenty-two — and a child is 53.087 s, which is the term
the whole tax was made of. See BENCHMARKS.md.

**Requirement 4 stands anyway**, because 320 s of proving still runs a run's
first epoch close to a whole epoch behind, and because a restart mid-epoch
re-proves from the epoch's first slot. Sixteen epochs of hot states is about
1.7 hours of slack, which absorbs it with room. The window only widens for
states finalized *after* the node restarts; states already migrated stay
migrated. A daemon whose chain depends on one of them can no longer skip forward
on its own — it stops, and recovery is a fresh init point (§6).

**The daemon no longer reads a boundary state at the moment it needs it.** The
registry and the committee assignment at an epoch's first slot are the only two
node responses that stop being servable, and both are now taken while the epoch
is young and held in `zkasperd.db.boundaries/` beside the store until the
accumulator has moved past them. What used to be two reads of the same state, up
to twenty minutes apart, with the second one racing the migration, is one read at
the earliest moment the boundary exists. Requirement 4 buys slack for the rest of
the pipeline; it is no longer what keeps the epoch diff alive.

**Subscribe to `single_attestation`, not `attestation`.** Since Electra,
Lighthouse emits `EventKind::SingleAttestation` for unaggregated attestations and
`EventKind::Attestation` only for aggregates. Mainnet is on Fulu
(`current_version 0x06000000`, fork epoch 411392, MEASURED 2026-08-18), so
`topics=attestation` gives you 83 aggregates a slot and none of the singles.
The daemon already subscribes to both plus `chain_reorg`; this matters when you
are testing an endpoint by hand.

**Do not add `--import-all-attestations`.** The Lighthouse validator-monitoring
docs pair it with `--subscribe-all-subnets`, but it does nothing for us: the SSE
event fires inside gossip *verification*, before the `should_import` gate. The
flag only makes the node apply all 28,130 attestations a slot to fork choice and
the aggregation pool, for no extra events.

### 2.2 No hosted provider can meet requirement 1

Tested empirically on 2026-08-18 by reading each node's `attnets` ENR bitfield
from `/eth/v1/node/identity` and by counting distinct `committee_index` values on
the live stream. On mainnet `committees_per_slot == ATTESTATION_SUBNET_COUNT == 64`,
so `committee_index` *is* the subnet id and the two methods agree.

| Provider | Events | Debug state | Subnets | Verdict |
|---|---|---|---|---|
| QuickNode | yes | yes, 335 MB in 3.5 s | **2/64**, 877/slot | fails req. 1 |
| PublicNode / Allnodes | **501** | 501 on v2 | 2/64 | fails 1 and 2 |
| ChainSafe Lodestar public | yes | 403 | 2/64 | fails 1 and 3 |
| Nimbus team public | singles only | yes | 64/64 but 41.5% delivered | fails 2 |
| Checkpointz endpoints (×8) | **404** | finalized only | n/a | fails 1 and 2 |
| Infura / MetaMask | Beacon API withdrawn 2022 | — | — | fails |

The failure is silent and that is the dangerous part. QuickNode's stream is
clean, well formed, drops nothing — and is missing 97% of the data, because the
loss is subscription rather than channel capacity. Nothing in the response says
so.

Contrary to expectation, **the debug state endpoint is the easy requirement** and
subnet coverage is the binding one. Nobody sells all-subnets because nobody asks
for it; both QuickNode and PublicNode run PeerDAS supernodes with
`custody_group_count: 128` for blob serving and still sit on 2 attestation
subnets.

**Conclusion: run your own node.** A hosted provider is usable only as a source
for an init point or as an aggregate-only fallback, and costs you the four
seconds that unaggregated attestations buy.

### 2.3 A mock execution layer is sufficient

Post-merge Lighthouse refuses to start without `--execution-endpoint`. Syncing a
real execution client is 8+ hours and ~1 TB, and we do not need one: **the daemon
reads attestations, and an attestation is a real BLS signature over real data
whether or not the execution payload underneath it has been validated.**

A mock Engine API server that answers `engine_newPayloadV1..V4` and
`engine_forkchoiceUpdatedV1..V3` with `VALID` is enough. Use the one at
`/mnt/ssd/lh-byhead-A/mock_el.py`; it ignores JWT and takes its mode from a
sibling `el_mode` file.

**What this costs, precisely.** The node cannot tell you whether an execution
payload is valid, so it will follow a chain whose payloads are invalid. Fork
choice still runs on attestations, so the head it picks is the head the
*attesting validators* picked. Since zkasper proves "this much stake attested to
this checkpoint" and never "this block executed correctly", the proofs are
unaffected. What you lose is the node's ability to reject an
execution-invalid chain that the network is about to reorg out — a risk that
lasts as long as the reorg does, and that the daemon already handles by
discarding proofs of checkpoints that reorg away.

With the mock answering `VALID`, the node reports `is_optimistic: false`
(MEASURED) because it believes it has a validating EL. That field is therefore
**not** a usable health signal in this topology.

---

## 3. Installing and starting the node

### Step 1 — Check for an existing binary before building one

A Lighthouse release build takes a long time. Several worktrees share one target
directory.

```sh
ls -la /root/.openclaw/workspace/.lighthouse-target/release/lighthouse
```

If it exists, use it. Confirm it has both flags:

```sh
LH=/root/.openclaw/workspace/.lighthouse-target/release/lighthouse
$LH --version
$LH bn --help | grep -E "subscribe-all-subnets|http-sse-capacity-multiplier"
```

If it does not exist, build with
`CARGO_TARGET_DIR=/root/.openclaw/workspace/.lighthouse-target cargo build --release --bin lighthouse`.

### Step 2 — Lay out the run directory on /mnt/ssd

`/` has run out of disk twice. Everything generated goes on `/mnt/ssd`.

```sh
mkdir -p /mnt/ssd/zkasper-run/datadir
cd /mnt/ssd/zkasper-run
cp /mnt/ssd/lh-byhead-A/mock_el.py .
openssl rand -hex 32 > jwt.hex
echo valid > el_mode
echo 0 > el_delay_ms
```

### Step 3 — Start the mock execution layer

```sh
cd /mnt/ssd/zkasper-run
setsid nohup python3 mock_el.py > mock_el.log 2>&1 < /dev/null &
```

Confirm before going on. If this does not answer, Lighthouse will not start:

```sh
curl -s -X POST -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
  http://127.0.0.1:8551
```

Expect `{"jsonrpc": "2.0", "id": 1, "result": "0x1"}`.

### Step 4 — Start the beacon node

`--disable-deposit-contract-sync` does not exist in Lighthouse v8.2.1. Do not
copy it from older runbooks; the node exits with code 2.

```sh
cat > /mnt/ssd/zkasper-run/run_bn.sh <<'EOF'
#!/bin/bash
exec /root/.openclaw/workspace/.lighthouse-target/release/lighthouse bn \
  --network mainnet \
  --datadir /mnt/ssd/zkasper-run/datadir \
  --checkpoint-sync-url https://mainnet.checkpoint.sigp.io \
  --execution-endpoint http://127.0.0.1:8551 \
  --execution-jwt /mnt/ssd/zkasper-run/jwt.hex \
  --http --http-address 127.0.0.1 --http-port 5052 \
  --subscribe-all-subnets \
  --http-sse-capacity-multiplier 2000 \
  --target-peers 100 \
  --disable-upnp \
  --logfile-debug-level info
EOF
chmod +x /mnt/ssd/zkasper-run/run_bn.sh
cd /mnt/ssd/zkasper-run
setsid nohup ./run_bn.sh > bn.log 2>&1 < /dev/null &
```

Checkpoint sync reaches head in about **2 minutes** (MEASURED 2026-08-18:
started 16:16:52, `sync_distance: 0` before 16:18:53).

### Step 5 — Verify all three requirements before starting the daemon

Do not skip this. Each failure below is one that produces a running daemon and
wrong data rather than an error.

```sh
# at head?
curl -s http://127.0.0.1:5052/eth/v1/node/syncing

# requirement 3: debug state served, and how big and how slow
curl -s -o /dev/null -w "code=%{http_code} bytes=%{size_download} time=%{time_total}s\n" \
  -H 'Accept: application/octet-stream' \
  http://127.0.0.1:5052/eth/v2/debug/beacon/states/head

# requirements 1 and 2: count a slot's singles
timeout 30 curl -s -N -H 'Accept: text/event-stream' \
  'http://127.0.0.1:5052/eth/v1/events?topics=single_attestation' \
  | grep -c '^data:'
```

Pass conditions:

- `is_syncing: false` and `sync_distance: 0`.
- Debug state returns **200** and a few hundred MB. 335 MB in 0.34 s on
  loopback (MEASURED).
- The 30-second count is **50,000–60,000**, i.e. ~28,000 a slot. If it is around
  1,700 (~880 a slot) the node is on 2 subnets and `--subscribe-all-subnets` did
  not take effect.

Always send `Accept: application/octet-stream` to the debug endpoint. The JSON
encoding of the same state is 959 MB against 335 MB SSZ.

---

## 4. Starting and running the daemon

### Step 6 — Build the daemon

For a witness-only run, which is everything except the cryptography:

```sh
cd /root/.openclaw/workspace/zkasper
cargo build --release --bin zkasperd
```

For real proofs the proving stack goes on the GPU box, not here. Build
`--features zisk-prover` **there**, and read the CUDA matrix in
`scripts/gpu_bench.sh` first — that build needs CUDA 12.9 or newer, and it was
confirmed against `nvidia/cuda:12.9.1-devel-ubuntu24.04` on 2026-08-18.

```sh
# on the GPU box, after ziskup --gpu --provingkey.
# Stop any prover server first -- see below.
pkill -f zkasper-prover-server
./scripts/bake_child_vks.sh
cargo build --release --features zisk-prover --bin zkasper-prover-server
ZKASPER_PROVER_TOKEN=<secret> ./target/release/zkasper-prover-server \
  --gpu --listen 0.0.0.0:9099 --mode streaming
```

The token is sent in the clear, so bind the server to a private interface or an
SSH tunnel — `ssh -N -L 9099:127.0.0.1:9099 <gpu-box>` is enough. Then point the
daemon at it:

```sh
cargo build --release --bin zkasperd     # no CUDA needed here
ZKASPER_PROVER_TOKEN=<secret> ./target/release/zkasperd \
  --prover remote --prover-addr 127.0.0.1:9099 ...
```

`bake_child_vks.sh` rather than `build_guests.sh`: a guest verifies its children
against keys it was compiled with, and that script is what derives them from the
ELFs and writes them back. It takes a ROM setup per guest, which is the same cost
the server pays at startup anyway. Skip it and the guests hold all-zero child
keys, which no program has, so every recursion fails — and the client says so at
the handshake rather than several minutes into an epoch, because
`child_vks::check` compares the server's keys against the constants the daemon
was built with. Commit the four `crates/*/src/child_vks.rs` files it writes
alongside the ELFs they describe.

**Stop the prover server before rebaking a box that is already serving.** A warm
prover holds tens of gigabytes for the life of the process, and `cargo-zisk`
building eight guests wants the rest; on a 251 GB box the OOM killer took four
guest builds while the script kept going and wrote the keys it had. The result
is a half-baked set that looks built. It surfaces at the next daemon start as
`the guests were built before the epoch_diff program had a key` — which is the
right message, but it is a rebuild away from the box, so save yourself the
round trip. Nothing in the bake needs the GPU.

`--stages group,slot_proof` starts a server for part of a pipeline; each guest
costs a ROM setup and gigabytes of `~/.zisk/cache`, so do not set up nine when
the run needs two. `--mode streaming` sets up **eight**, not five: the first
epoch of a run has nothing before it to finalize, so it goes through the batch
path — slot proofs and a justification — before the streaming path takes over.
Build all eight guests. There is no ninth: the bootstrap guest is gone, and with
it the stage that used to sit in front of every pipeline.

Only for a single-box run does the prover go in the daemon: add
`--features zisk-prover` here and use `--prover zisk`.

Tell the daemon what the card costs, so every epoch it publishes can be priced:

```sh
  --prover-usd-per-hour 0.51
```

It is published as given and nothing multiplies by it. The daemon measures
prover milliseconds per epoch and publishes those separately, because an hourly
rate is a fact about a rental contract rather than about the pipeline. See
[docs/api-v1.md](docs/api-v1.md#what-an-epoch-cost).

### Step 7 — Take the init point

The daemon does not prove its own starting accumulator. It is given one, and
refuses to start without it on a fresh run:

```sh
cargo build --release --bin zkasper-init-point
./target/release/zkasper-init-point \
  --beacon-url http://127.0.0.1:5052 \
  --chain mainnet \
  --out /mnt/ssd/zkasper-run/init-point.json
```

With no `--slot` it takes the node's current finalized checkpoint, which is where
a run should start. The file is small enough to read:

```json
{
  "chain": "mainnet",
  "epoch": 469300,
  "state_root": "0x...",
  "num_validators": 2338764,
  "total_active_balance": 42233196000000000,
  "acc_root": "0x...",
  "accumulator_commitment": "0x...",
  "state_to_validators_siblings": ["0x...", "0x...", "0x...", "0x...", "0x...", "0x..."]
}
```

**Publish it with the run.** It is the declared root of trust, and the only way a
consumer can check it is to regenerate it: `zkasper-init-point --slot <epoch*32>`
against any node that still holds that state, then `diff`. See
[docs/assumptions.md](docs/assumptions.md).

Confirm the node still holds the state the file names — the daemon walks that
registry on its first breath:

```sh
curl -s -o /dev/null -w "%{http_code}\n" \
  http://127.0.0.1:5052/eth/v1/beacon/states/<epoch*32>/fork
```

If it is not 200, take the init point again at the new finalized checkpoint.

### Step 7b — Know that the node's state window slides

A checkpoint-synced Lighthouse serves states from its **split slot** — the
finalized checkpoint — forward. The split advances every finalization, so the
window is only about two epochs wide and it moves. Nothing older than the current
finalized checkpoint is served, and `--archive` is not the answer (it also turns
on genesis backfill and a week of reconstruction for 418 GiB).

**This used to be the main startup hazard and no longer is.** Bootstrap took
about two minutes over a 2.3M-validator state and then needed that same state
again on its first tick, so one that landed shortly before a finalization lost
the state underneath itself and failed with:

```
Error: fetch validators for the target epoch
Caused by: .../states/15020064/validators returned 404 Not Found:
           {"code":404,"message":"NOT_FOUND: beacon state at slot 15020064"}
```

Startup is now a registry walk at the init point's epoch, with no proving and no
335 MB state download, so the window it has to fit inside is seconds rather than
minutes. Take the init point and start the daemon in the same breath and the race
is not close.

If it is lost anyway, the daemon takes an init point of its own at the node's
finalized checkpoint and starts there, writing the tuple to
`<db-path minus .db>.init-point.json` and saying so twice at ERROR. It only does
this before anything has been chained — which is the whole of what this branch
is, since there is no store yet — so nothing is broken by it. **Publish that
file**: it is the tuple a consumer checks the run against, and it is not the one
you generated.

After startup the window no longer decides anything: every boundary a stage will
need is taken while its epoch is young and held beside the store. A daemon asked
for a boundary it never took still stops rather than starting a second
accumulator over the top of the first — see §6.

### Step 8 — Run the daemon under a supervisor

**zkasperd has no error handling in its main loop.** `run()` propagates every
error to `main`, so any transient beacon-node failure ends the process. Nothing
on disk is damaged when that happens — the store is written atomically and
advances one epoch at a time — so the recovery is always "start it again". A
supervisor is not optional.

```sh
cat > /mnt/ssd/zkasper-run/run_zkasperd.sh <<'EOF'
#!/bin/bash
cd /root/.openclaw/workspace/zkasper || exit 1
RUN=/mnt/ssd/zkasper-run
mkdir -p "$RUN/out"
n=0
fails=0
while true; do
  n=$((n + 1))
  echo "=== zkasperd start #$n at $(date -Is) ===" >> "$RUN/zkasperd.log"
  ./target/release/zkasperd \
    --beacon-url http://127.0.0.1:5052 \
    --db-path "$RUN/zkasperd.db" \
    --output-dir "$RUN/out" \
    --init-point "$RUN/init-point.json" \
    --chain mainnet \
    --mode streaming \
    >> "$RUN/zkasperd.log" 2>&1
  rc=$?
  echo "=== zkasperd exited rc=$rc at $(date -Is) ===" >> "$RUN/zkasperd.log"

  # The supervisor does not delete the store on its own any more. It used to,
  # because a pruned bootstrap epoch could only be escaped by bootstrapping
  # again — and that silently broke the accumulator chain, which is the one
  # thing a consumer cannot detect for themselves. A run that cannot continue
  # now stops here, and §6 says what to do about it.
  if [ "$rc" -eq 0 ]; then fails=0; else fails=$((fails + 1)); fi
  if [ "$fails" -ge 5 ]; then
    echo "=== $fails consecutive failures; stopping at $(date -Is)." \
         "Read the log, then RUNBOOK §6 ===" >> "$RUN/zkasperd.log"
    exit 1
  fi

  sleep 5
done
EOF
chmod +x /mnt/ssd/zkasper-run/run_zkasperd.sh
cd /mnt/ssd/zkasper-run
setsid nohup ./run_zkasperd.sh > supervisor.log 2>&1 < /dev/null &
```

Under systemd this is `Restart=always` with `RestartSec=5`.

### Step 9 — Confirm the start

Starting is a registry walk: no proving, and no state download. Watch for:

```
started from a trusted init point epoch=469300 num_validators=2338764
  total_active_balance=42233196000000000 acc_root=0x... state_root=0x...
following attestation gossip
```

If the daemon exits instead, read the message: it names the field that
disagreed — the validator count, the total active balance, the accumulator root
it rebuilt, or the state root the branch opened to. Any of those means the init
point does not describe the registry at that epoch, and the run must not start.

**The first epoch of a run uses the batch pipeline, not the streaming one, and
this is expected.** The streaming path needs an epoch diff on record and a
justification for the previous epoch, and at the init point neither exists. You
will see `slot_proof` and `justification` stages for that epoch and no
`recent_latencies` entry. From the next epoch on you get `group`, `aggregate` and
`stream_final`, and a measured `T2 - T`.

### Step 10 — Capture the latency data off the box

`recent_latencies` holds **16 epochs** and `recent_stages` holds **64 stages**,
both in memory only. They are lost on restart and they roll over in about 51
minutes. A run whose data lives only in `status.json` has no data.

Poll and append. Once a minute is enough for a 12 s slot and a 384 s epoch:

```sh
cat > /mnt/ssd/zkasper-run/scrape.sh <<'EOF'
#!/bin/bash
# Append every new epoch latency to a file the instance cannot take with it.
OUT=/mnt/ssd/zkasper-run/latencies.jsonl
touch "$OUT"
while true; do
  python3 - "$OUT" <<'PY'
import json, sys, os
out = sys.argv[1]
try:
    d = json.load(open('/mnt/ssd/zkasper-run/out/status.json'))
except Exception:
    raise SystemExit
seen = set()
if os.path.exists(out):
    for line in open(out):
        try: seen.add(json.loads(line)['epoch'])
        except Exception: pass
with open(out, 'a') as f:
    for l in d.get('recent_latencies', []):
        if l['epoch'] not in seen:
            f.write(json.dumps(l) + '\n')
PY
  sleep 60
done
EOF
chmod +x /mnt/ssd/zkasper-run/scrape.sh
setsid nohup /mnt/ssd/zkasper-run/scrape.sh > /dev/null 2>&1 < /dev/null &
```

---

## 5. Monitoring: what to alert on

There are two ways to read this daemon, and they answer different questions.

**Prometheus, for the trend and the page.** `zkasperd` serves `/metrics` itself
on `127.0.0.1:9464`. Every duration is a histogram taken from a `tracing` span —
`T2 - T`, each proof's duration, the witness half of it, what the prover charged,
and how far each proof's start slipped from the schedule — so the distribution
over hundreds of epochs is readable rather than the last value. Proof size and
proof cost are histograms too, labelled by stage, because 92% of an epoch's bill
is one stage. The box ships it all to Grafana Cloud, which evaluates the same
alert rules off-box — a rule about this machine being alive cannot be evaluated
on this machine. Set it up with `monitoring/install.sh`; the metrics and the
alerts are listed in [monitoring/README.md](monitoring/README.md).

Two things there are worth knowing before reading anything else. Liveness is
`zkasper_heartbeat_timestamp_seconds`, written once a second by a task of its
own, and **not** the manifest — a committee proof legitimately holds a tick for
over two minutes, so a manifest-based liveness alert fires on a healthy daemon.
And a restart is a failure to debug rather than an event to absorb:
`changes(process_start_time_seconds[1h]) > 2` pages.

**The manifest, for right now.** Everything below is read from
`<output_dir>/status.json`. The daemon rewrites it
after every stage, which during a streaming epoch is about **5 times a second**.
Each rewrite is a temp file, an fsync, a rename and a directory fsync — keep the
output directory on local disk, not on network storage.

### Page immediately

| Signal | Condition | Meaning |
|---|---|---|
| `updated_unix` | older than 120 s | The daemon is dead or wedged. Nothing else in the file can be trusted. |
| `gossip.dropped` | `> 0` | **The node's SSE buffer is too small.** Raise `--http-sse-capacity-multiplier`. This is a node misconfiguration, never bad luck, and every drop costs an epoch its live-gossip sourcing. |
| restart rate | more than 2 per hour | The supervisor is masking a real fault. Read the log. |
| `head_slot` | more than 4 slots behind the node | The daemon is not keeping up with the chain. |

### Investigate the same day

| Signal | Condition | Meaning |
|---|---|---|
| `recent_latencies[].late_groups` | `> 0` | The daemon fell behind: attestations arrived that had not been folded when the trigger fired. It is a throughput symptom, not a correctness one. Currently 0 or 1 by construction. **Expected on the first streaming epoch of a run, or after a restart**, which opens mid-epoch and so folds nothing before the trigger — read it together with `folded_groups`, and only treat it as real when `folded_groups` is also non-zero. |
| `gossip.reconnects` | rising | The node or the network is unstable. Epochs around each reconnect were sourced from blocks, so their `T2 - T` is not representative — exclude them from any latency claim. |
| `gossip` | **absent** | The daemon is reading blocks instead of gossip and is a slot behind by construction. Either `--no-gossip` is set or the pipeline is `batch`. |
| `recent_latencies[].t2_minus_t_millis` | drifting up | Compare against the baseline in §8. |
| `"synthetic state root"` in the log | any | The node stopped serving the debug endpoint and the epoch diff is anchored on a fabricated state root. Treat every epoch after the first such line as void. |

### Do not page on these

They are handled, they log a warning, and they resolve themselves:

- `gossip gap; repairing this epoch from blocks`
- `the checkpoint reorged out; reopening the epoch`
- `the checkpoint reorged out while the final proof ran; discarding it`
- `checkpoint never reached the 2/3 threshold; giving up on this epoch` — once.
  Repeatedly means the node is not answering
  `/eth/v2/beacon/blocks/{id}/attestations`, whose errors are swallowed
  silently and produce no other symptom.
- `no state to read the fork version from; taking head's`

### The health check

`scripts/health.py` applies every threshold above and prints one line per check.
It exits 0 when clear, 1 when something needs action and 2 when the manifest
cannot be read, so it drives an alert directly.

```sh
./scripts/health.py /mnt/ssd/zkasper-run/out/status.json
```

```
      updated 0 s ago
      accumulator epoch 469375
      justified through 469374
      gossip 358402 attestations, 0 reconnects, 0 dropped
      T2-T over 3 epochs: min 1177 median 5007 max 5118 ms
OK
```

The counters are monotonic since process start and reset on restart, so a
climbing `reconnects` only shows up by diffing scrapes. Store what step 10
appends and read the trend from there.

---

## 6. Recovery

### What a restart costs

Persisted to `--db-path`, written whole and atomically twice an epoch: the
accumulator tree, the cursor, the audit chain digest, and the last epoch diff,
justification and stream-final records with their proofs.

Held **only in memory**, and therefore lost: the running aggregate and its folded
group proofs, this epoch's committee proof, all gossip collected for this epoch,
the `T` timestamp, and the whole of `recent_stages` and `recent_latencies`.

So **a restart mid-epoch costs exactly one epoch**, which the daemon redoes from
blocks rather than from live gossip — meaning the redone epoch is a slot behind
and reports no `T2 - T` at all. The accumulator chain never regresses or
double-applies; `StoreState::advance` rejects anything that is not exactly
`cursor_epoch + 1`.

**Recommendation: accept this and do not persist the aggregate.** One epoch is
384 seconds and the loss is bounded, self-healing and already correct. The
serialized aggregate would be small (an `AggregateOutput` is ~216 bytes, the
Miller accumulator 576 bytes, plus one proof) but resuming an epoch needs the
committee proof and the whole `SlotStream` of running BLS sums as well, and that
is a new persistence format and a new class of bug on the critical path. The
cheaper mitigation is to restart *between* epochs whenever the restart is
voluntary.

### Failure table

| Symptom | Cause | Action |
|---|---|---|
| `Error: fetch chain head` | Node unreachable | Restart node, then daemon. Nothing is damaged. |
| `could not take this epoch's boundary` (warning) | The node had already migrated a boundary the daemon tried to take ahead of time | None. It is a warning by design: the stage that needs one and has none is what fails, and it says so separately. Repeated for the *same* epoch every tick means the run is behind the node's window. |
| `... returned 404 Not Found: NOT_FOUND: beacon state at slot N` | The node no longer holds a state the daemon never took | The daemon takes every boundary it needs while the epoch is inside the node's window and holds it in `zkasperd.db.boundaries/`, so this is a run pointed at an epoch it was never up to see — a store moved without that directory, or a stall longer than the cache reaches. Not resumable: restart from a new init point (§ below). |
| `missing current_version` / `missing data array` | Old binary. Fixed: the client now reports the status and body. | Rebuild. |
| `store at ... is damaged; delete it and start again from an init point` | Truncation or checksum failure | Not recoverable in place. Restart from a new init point (§ below); note that `acc_chain_digest` restarts and will not match a peer that never lost theirs. |
| `store ... holds a X accumulator, but this run is configured for Y` | Wrong `--db-path` or `--chain` | Point at the right file. |
| `store format version N, expected M` | Format bump, no migration exists | Restart from a new init point (§ below). |
| `the ... circuit rejected the witness` | An unprovable witness | Real bug. Keep the epoch directory under `out/epoch-*` — it is the reproduction. |
| `the ... proof does not verify against its own program key and outputs` | Prover, ELF or proving-key mismatch | Not a chain problem. Check the ELF against the proving key. |
| `fetch header at slot N` / `NOT_FOUND: beacon block at slot N`, repeating forever | **The epoch boundary slot was skipped.** Fixed — the epoch diff now reads the state root from `/eth/v1/beacon/states/{slot}/root`, which is defined for a skipped slot, instead of from a block header, which is not. On a build before that fix the daemon crash-loops permanently, because the slot will never gain a block. | Rebuild. To get moving without one, take a fresh init point past the skipped boundary. |
| Wedged, repeating the same epoch | The node cannot serve that epoch's state | Restart from a new init point (§ below). |
| `accumulator_commitment ... does not bind acc_root ... and total_active_balance ...` | The init point's three accumulator fields disagree | The file is wrong or was edited. Take it again with `zkasper-init-point`; do not patch it by hand. |
| `init point claims ... but the state at slot N ...` | The init point does not describe the registry at its own epoch | Wrong slot, wrong chain, or a file from another deployment. Take it again against this node. |
| `no accumulator state file and no init point` | A fresh run with no `--init-point` | Step 7. |

### Restarting from a new init point

**This breaks the accumulator chain**, and the break is visible: `init_epoch`
moves, and `acc_chain_digest` restarts and will not match a peer that never lost
theirs. Do it only when the table above says to, and publish the new init point
alongside the old one — a consumer applying the rule in
[docs/assumptions.md](docs/assumptions.md) needs to know where one chain ended
and the next began.

```sh
pkill -f run_zkasperd.sh; pkill -f 'target/release/zkasperd'
cd /mnt/ssd/zkasper-run
rm -f zkasperd.db && rm -rf zkasperd.db.boundaries out
# then step 7 to take a fresh init point, and step 8 to start again
```

### Testing that recovery works

Worth doing deliberately once, and cheap:

```sh
pkill -f 'target/release/zkasperd'   # supervisor restarts it in 5 s
```

Expect `loaded verified accumulator state epoch=N`, then `resuming epoch=N`, then
the epoch redone with no `recent_latencies` entry for it.

---

## 7. Provisioning and cost

### The daemon and node together, measured on this machine

| Resource | Measured | Notes |
|---|---|---|
| zkasperd RSS | **4.7–7.9 GB**, 6.9 GB at rest | Dominated by the accumulator tree over 2.34M validator records. Sampled once a minute for 42 minutes: it sawtooths — it peaks while the epoch diff and committee proof run and falls back after — with **no upward trend**. That is evidence against a fast leak, not proof of stability over a day; nobody has watched it for hours yet. |
| lighthouse RSS | **5.9–7.0 GB** | With `--subscribe-all-subnets` and multiplier 2000. Flat over the same window. |
| Node datadir | **947 MB** after 15 minutes | Checkpoint-synced, backfill running. Budget 450+ GB for a month with default `--hierarchy-exponents`. |
| `zkasperd.db` | **343 MB** | Rewritten whole twice an epoch. |
| `zkasperd.db.boundaries/` | **~300 MB per epoch held**, four at a time | The validator registry and committees at each epoch boundary the run is holding, one file per boundary. Written once per epoch and pruned as the accumulator passes them, so it does not grow. Delete it only with the store: without it a resumed run needs states the node may have migrated. |
| `out/` | **110–120 MB per epoch** | Witness files, of which `committee.bin` is 113 MB. At 225 epochs a day that is **~26 GB/day, ~780 GB/month** — larger than the beacon database. Prune or ship them; nothing re-reads a closed epoch's directory. |
| SSE ingest | 28,033 events/slot | ~1.47 MB/s sustained, 3.8 TB/month if it crosses a network. |

Machine: 8 cores, 32 GB RAM and 1 TB is the floor for daemon + node with a mock
EL. With a real execution client, 64 GB and 2 TB.

### If you buy a dedicated node

Priced 2026-08-16/17, USD, excluding VAT. Hetzner repriced on 2026-06-15 — any
older quote is wrong.

| Provider | SKU | Specs | USD/mo | Setup |
|---|---|---|---|---|
| netcup | RS 8000 G12 | 16 ded. cores, 64 GB, 2 TB NVMe | **~70** | ? — VPS, verify traffic policy |
| OVH | RISE-2 + 64 GB + 2×1.92 TB | 8c/16t, 64 GB ECC, 1 Gbps unmetered | **141** | 80, waived on 12-mo prepay |
| **Hetzner** | **AX102-1-LTD** | 16c/32t, 128 GB ECC, 2×1.92 TB NVMe, unmetered | **187** | 39 |
| Vultr | vbm-8c-132gb-v2 | 8c/16t, 128 GB, 2×1.92 TB, 10 TB | 350 | 0 |
| AWS | i4i.2xlarge on-demand | 8 vCPU, 64 GiB, 1.875 TB NVMe | **501 + ~230 egress = 731** | 0 |
| GCP | n2-standard-8 + 2.25 TB local SSD | 8 vCPU, 32 GiB | **~776** | 0 |

**Hetzner AX102-1-LTD at $187 is the pick.** OVH RISE-2 at $141 if you prepay a
year. On AWS or GCP the egress alone exceeds the entire European bare-metal bill.

Two traps that cost a run rather than money:

- **Network-attached block storage will not sync an execution client.** Hetzner
  Cloud volumes measure ~7,500 IOPS against ~39,600 on local NVMe. Snap sync ends
  in state healing, which has no progress bar and must outpace chain growth; on
  capped IOPS it never finishes. Local NVMe only.
- **The 1 TB cliff.** Hetzner's entry AX line ships 2×512 GB. That fits
  Lighthouse plus Erigon 3 with little margin and does not fit Lighthouse plus
  Geth at all.

### The proving box

Rented per run, holding nothing but the prover.

| Instance | Measured price |
|---|---|
| RTX 5090 on-demand, vast.ai | **$0.336–0.53/hr**, cheapest $0.336 (MEASURED 2026-08-18, 43 offers) |
| RTX 5090 interruptible, vast.ai | **$0.20–0.28/hr**, i.e. 55–60% of on-demand |
| Storage | $0.13–0.53 per GB-month; 250 GB for a day is $1.1–4.4 |

Sizing from `scripts/gpu_bench.sh`: **150 GB disk** (the proving key reaches
~105 GB after setup, plus ~13 GB of `~/.zisk/cache` for four ELFs), 32 GB RAM,
driver ≥ 525.60.13. For the from-source `--features zisk-prover` build add the
cargo target directory and take **250 GB**.

- **One day, on-demand:** $8.06–12.72 for the card, plus ~$1–4 storage.
- **One day, interruptible:** $4.80–6.72.
- **One month, on-demand:** $242–382. **Interruptible:** $144–202.

**What an interruption costs.** The card is stateless in this topology: the
daemon and its store are elsewhere. An interruption costs the in-flight epoch —
the same one epoch a daemon restart costs — plus the prover's setup on the
replacement box, which is the expensive part: **~16 min** for apt, rustup and the
3.2 GB proving key, plus **~4.6 min** for the first ELF's one-time constant-tree
regeneration and ~14 s for each ELF after. Call it **25 minutes to a warm prover**,
about 4 epochs.

**On money, interruptible wins easily.** Take the midpoints: $0.43/hr on-demand
against $0.24/hr interruptible, and 0.42 hr of paid-but-unproductive setup per
interruption. Running H hours with N interruptions costs `0.24(H + 0.42N)`
against `0.43H`, so interruptible is cheaper while `N < 1.9H` — about two
interruptions an hour. No real interruption rate comes close, so **buy
interruptible.**

**The cost that matters is coverage, not dollars.** Each interruption is ~25
minutes with no prover, which is **4 epochs of a day's 225, or 1.8%**. Ten
interruptions in a day would still be under 20% of epochs missed and would save
$4.60. Decide on how many epochs you need proven, not on the hourly rate.

The daemon survives an interruption without doing anything: it holds the store,
it keeps generating witnesses, and it is the prover connection that fails. That
is what `--prover remote` buys, and it was measured on 2026-08-18: the server
was killed mid-run, the client kept its outputs and spooled the witness, the
server came back and the backfill proved it. **Replacing the box costs ~15 s to
a warm prover** once its proving key and ROM setups exist — `EmbeddedClient`
build 14.8 s, ROM setup 37–48 ms per guest — so the 25 minutes above is the cost
of provisioning a *new* box, not of restarting a server on the same one.

---

## 8. Measured baseline

Everything in this section was measured on 2026-08-18 against mainnet, on this
machine, with `--prover native`. Chain: Fulu, epoch 469371–469373, head slot
~15,019,970. Beacon node: Lighthouse v8.2.1 with the flags in §3, mock EL.

### Gossip arrival curve

**This is the measurement the scheduler's assumptions rest on, and it is the
first time they have been checked against real traffic.** 113 steady-state slots
(15,019,900–15,020,013), 23 minutes, after discarding the partial slots at each
end. Times are milliseconds into the attestation's own slot.

| topic | per slot | p05 | p25 | **p50** | p75 | p90 | p95 | p99 |
|---|---|---|---|---|---|---|---|---|
| `single_attestation` | **28,044** | 2,115 | 3,165 | **4,365** | 5,560 | 6,841 | 7,695 | 9,675 |
| `attestation` (aggregates) | **85** | 8,017 | 8,072 | **8,099** | 8,130 | 8,184 | 8,305 | 9,142 |

**All three design assumptions hold.**

| Assumption | Assumed | Measured |
|---|---|---|
| Singles land about a third into the slot | 0.333 (4,000 ms) | **0.364** (4,365 ms) |
| Aggregates land about two thirds in | 0.667 (8,000 ms) | **0.675** (8,099 ms) |
| Singles buy four seconds over aggregates | 4,000 ms | **3,734 ms** |

Cumulative share of a slot's singles in hand:

| ms into slot | 2,000 | 3,000 | 4,000 | 5,000 | 6,000 | 7,000 | 8,000 |
|---|---|---|---|---|---|---|---|
| share | 3.4% | 21.6% | 42.6% | **64.3%** | 81.9% | 91.1% | 96.2% |

The burst drains — last arrival before a gap of more than 500 ms — at a median
of **7,326 ms** into the slot (p25 6,412, p75 8,330, p90 9,819). The old
`--max-trigger-wait-millis 6000` expired before the burst had finished draining
on a typical slot; the section below is how the default became 10,000.

Note how tight the aggregate distribution is: p05 to p95 spans 288 ms against
5,580 ms for the singles. Aggregates are published on a schedule; singles arrive
as validators produce them. That is also why the singles median moves by ~100 ms
between samples while the aggregate median moves by ~10 ms.

Per-slot counts are steady: min 27,841, median 28,053, max 28,071.

### The trigger cap is binding, and it binds against the design's own rule

The daemon does not fire the instant 2/3 is crossed. Every attestation still in
flight is one fewer named absentee in the final proof, so one more second of
waiting pays for itself while arrivals exceed break-even. That rule is capped by
`--max-trigger-wait-millis`, default 6,000.

**The break-even is 651 validators a second, not 558.** It is not a constant of
its own — `ProverModel::per_named_s()` derives it from two measured ones, and the
derivation is the authority:

| | per_validator_s | acc_node_s x 22 | per named leaf | break-even |
|---|---|---|---|---|
| Zisk v1.0.0-alpha | 834.7 us | 43.5 us | 1.79 ms | 558/s |
| **Zisk v1.1.0-alpha** | 834.7 us | **31.9 us** | **1.5365 ms** | **651/s** |

`acc_node_s` was re-measured at 31.9 us on v1.1.0-alpha and the model carries
that value; 1.79 ms and 558/s are the v1.0.0-alpha pair, left behind in prose
that the re-measurement did not reach. Every "at 1.79 ms" in an older revision of
this document is 14% too high. `waiting_pays_exactly_while_arrivals_outrun_the_per_leaf_price`
asserts the derived figure, so the code has been right throughout.

The measured arrival rate — 168 slots where the capture was complete, singles and
aggregates together — crosses 651/s between **8,000 and 9,000 ms** into the slot:

| ms into slot | 4–5 k | 5–6 k | 6–7 k | 7–8 k | **8–9 k** | 9–10 k | 10–11 k |
|---|---|---|---|---|---|---|---|
| arrivals/s | 5,984 | 4,858 | 2,538 | 1,423 | **652** | 313 | 215 |

Both constants land in that same bucket, so the correction does not move the cap.
The cap was wrong for its own reasons, and **it is now 10,000 ms**. The
arithmetic:

- Waiting pays while arrivals exceed break-even, which the table above puts
  between **8,000 and 9,000 ms** into the slot.
- The burst drains at a median of 7,326 ms and a **p90 of 9,819 ms**.
- Both are measured from the start of the slot. The cap is measured from the
  **threshold crossing**, which lands anywhere in it: back out the crossing from
  the three steady-state epochs below — `tail_named` against the cumulative
  share of a slot's singles — and it fell at about 4.4 s into the filling slot
  twice and at the slot boundary once. Reaching 9,000 ms into the slot therefore
  needs a wait of ~4.6 s in the first case and ~9 s in the second.
- One slot is 12,000 ms, and past that the slot being waited for is no longer the
  one filling.

**10,000 ms** is the smallest round number above the p90 drain and below a slot.
At it the cap should never bind: the rate rule fires first, 8–9 s into the slot,
where 96.2% of the slot's singles are in hand. Expect **`tail_named` of order
1,000** — 3.8% of a 28,044-validator slot — against the 4,999 to 8,159 measured
at 6,000 ms. That is ~1.5 s of absentee opening in place of 7.7 to 12.5 s, for at
most ~3.6 s more waiting, and usually none.

Replaying the rule that replaced it against 23 measured epochs bears the cap out:
caps of 6, 10 and 20 s all give the identical firing instant, and only a cap of
4 s changes it. The cap does not decide anything any more.

A cap that never binds in normal operation is the right shape for it. It is a
backstop against a source that trickles for ever, and it should not be what
decides when the epoch closes.

Under `--prover native` none of this shows up in `T2 - T`. **On a GPU it would
dominate the critical path**, which is why it is worth the change before a GPU
run rather than after one.

**The cap is not the whole story, and the other half is the rate rule itself.**
The section below is the answer, from a run that did stay up for hours.

This was only visible because the arrival curve and `tail_named` were measured
together.

### A slot's gossip is two arrivals, and the rate rule stopped between them

The rule was: keep waiting while the last 200 ms removed more than 130 leaves.
Over **23 steady-state epochs** it fired at a median of **6,248 ms into the
filling slot** and left a median **`tail_named` of 6,563** — 10.1 s of absentee
opening. Not one epoch reached the cap.

It stops early for two reasons, and 200 ms of resolution is only the smaller one.

**A slot's unaggregated attestations arrive in a burst with holes in it.** Twelve
of the 23 epochs fired while later windows in the same slot were still above
break-even; the worst, 469391, fired **3,908 ms** into the slot with **14,538**
attesters still to come, on a dip between the block-triggered arrivals and the
4-second attestation deadline.

**And the aggregates are a second arrival entirely.** Averaged over the 168
complete-capture slots, per 200 ms window:

| ms into slot | 6,000 | 6,600 | 7,200 | 7,800 | **8,000** | 8,400 | 9,000 |
|---|---|---|---|---|---|---|---|
| singles | 675 | 419 | 327 | 229 | 151 | 111 | 70 |
| aggregate events | 0 | 0 | 0 | 2.1 | **72** | 1.4 | 0.5 |

Aggregates land in one 200 ms piece at 8,000 ms and are worth far more than their
count: on the five epochs the daemon happened to fire after them, they removed
**3,635 to 4,494 validators** the singles never delivered — 5.6 to 6.9 s of
proving. Seventeen of the 23 epochs fired **before the first aggregate for their
slot arrived**, and paid for it.

So the failure is structural, not statistical. The rule reads a rate off the last
interval and treats a quiet interval as the slot being finished, and between the
two arrivals there is a silence that means nothing of the kind. **A longer window
or more hysteresis moves which silence it stops in; it does not stop it stopping
in one.** Replayed against the same 23 epochs' arrivals, 20 tick phases apiece:

| rule | median fire, ms into slot | mean `tail_named` | mean `wait + tail x 1.5365 ms` |
|---|---|---|---|
| **measured, as it ran** | 6,248 | 5,347 | **9.93 s** |
| 200 ms window (the rule, replayed) | 6,132 | 5,427 | 9.80 s |
| 1,000 ms evaluation window | 7,231 | 4,744 | 9.56 s |
| 2,000 ms evaluation window | 7,621 | 4,365 | 9.51 s |
| hysteresis, 5 windows | 7,845 | 4,119 | 9.29 s |
| hysteresis, 10 windows | 10,228 | 2,780 | 8.64 s |
| hysteresis, 15 windows | 11,266 | 2,156 | 8.88 s |
| in-flight floor, 1,000 | 13,426 | 2,218 | 10.33 s |
| in-flight floor, 2,500 | 9,403 | 2,375 | 9.17 s |
| in-flight floor, 5,000 | 8,466 | 2,556 | 7.04 s |
| **hold until the aggregates have been and gone** | **8,672** | **2,160** | **6.86 s** |
| fire at a fixed 8,400 ms (reference) | 8,400 | 2,149 | 6.66 s |
| per-epoch hindsight optimum (reference) | — | — | 6.56 s |

The replay reproduces the measured baseline to 1.5% on the mean tail and 1.3% on
the objective, which is what makes the other rows worth reading.

**Every rate-only rule is beaten by the same 2 s of silence.** It has to observe
that silence to know the singles are done, and if it waits long enough to survive
it, it also pays it again after the aggregates land. Hysteresis at 10 windows is
the best of them and is still 1.8 s short. **An in-flight floor** is not a rate
rule and gets much closer, but only at 5,000 — a value that happens to sit
between the 6,300 still in flight before the aggregate burst and the 2,150 after
it, on this node, on this run. At 2,500 it is 2.1 s worse and at 1,000 it is
3.5 s worse. It is a fitted constant with no meaning on another chain, another
committee size, or a node with different subnet coverage, so it is rejected
despite the number.

**The rule the daemon now runs** keeps waiting while either the last interval
paid for itself, **or** the aggregate half of the slot's gossip has not yet been
and gone — which it reads off the gossip, as "no aggregate for this slot yet, or
one arrived in the last interval", and not off a clock. The hold is not free, so
it is taken only while what is still in flight could pay for the silence so far
at the same 1.5365 ms a leaf. A slot that has already converged fires instead of
waiting for aggregates that cannot be worth much, and a slot with nothing in
flight fires on the instant.

It costs **2.1 s more waiting** (mean 1,465 → 3,545 ms) and buys back **3,267
leaves, 5.0 s of proving**, for **2.9 s** net off `T2 - T`.
`--max-trigger-wait-millis` and `--trigger-interval-millis` both stop mattering:
6, 10 and 20 s of cap give the same answer, and 100, 200 and 400 ms of interval
are within 0.3 s of each other.

**What this is not.** Twenty-three epochs from one afternoon, on one node, tuned
and replayed against themselves. The replay's aggregate yield is calibrated from
five epochs. The prediction is `tail_named` **~2,200 mean, ~2,500 median, ~3,800
p90**, and what would falsify it is a run of a hundred-odd epochs *not* used to
choose the rule, reporting `tail_named` and `wait_millis` per epoch: the tail
distribution should sit where the table says, the cap should still never bind,
and `late_groups` should stay 0 — a wait 1.9 s longer leaves that much less of
the slot before the frontier moves. A second node, with different subnet
coverage, is the other half of it: the rule's premise is that aggregates are the
second arrival, and a node that sees every single would have less to gain.

### Volume cross-check

`/eth/v1/beacon/states/head/committees` reports 64 committees and 28,130
attesting validators per slot at slot 15,019,864. The stream delivered 28,033 a
slot — **99.7%**. The node is not dropping and the subscription is complete.

For contrast, QuickNode's public endpoint delivers 877/slot: **3.1%**.

### Stage costs

| Stage | Measured |
|---|---|
| epoch_diff | 33,378 ms and 25,046 ms |
| committee | 27,649 ms |
| group | 4,812 ms |
| stream_final | 90 ms |
| slot_proof (batch path) | 71–159 ms |
| justification | 2 ms |

These are witness generation only; `--prover native` adds no cryptography. The
epoch diff and the committee proof together are about 60 s of a 384 s epoch, both
off the critical path.

### Measured `T2 - T`

| epoch | `T2-T` ms | `wait` ms | `tail_named` | `folded_groups` | `late_groups` | shape |
|---|---|---|---|---|---|---|
| 469372 | 5,007 | 4,919 | 110 | 0 | 1 | catch-up |
| 469373 | 5,118 | 4,964 | 93 | 0 | 1 | catch-up |
| 469374 | 1,177 | 1,095 | 75 | 2 | 0 | catch-up |
| **469375** | **6,961** | **6,378** | **4,999** | **16** | **0** | **steady state** |
| 469376 | 5,707 | 5,565 | 80 | 0 | 1 | catch-up |
| 469379 | 8,027 | 7,835 | 111 | 0 | 1 | catch-up |
| 469380 | 4,276 | 4,204 | 89 | 0 | 1 | catch-up |
| **469381** | **1,642** | **1,355** | **6,822** | **21** | **0** | **steady state** |
| **469382** | **1,230** | **924** | **8,159** | **20** | **0** | **steady state** |

**Only 469375, 469381 and 469382 are steady-state epochs** — the only three the
daemon followed from near their first slot, folding a group per slot as gossip
closed it, 16/21/20 in total. Every other row is an epoch opened already in
progress at the start of a run or after a restart, which folds nothing before the trigger
and so reports `folded_groups = 0` and `late_groups = 1`. Those rows say what a
catch-up costs, not what the pipeline costs. **Do not quote them as a
steady-state result.** Three epochs are not a distribution either; what follows
is what three epochs can support.

- **`late_groups = 0` on all three steady-state epochs, and 1 on every catch-up.**
  The alert is meaningful and the daemon keeps up with the chain once it is on
  it.
- **`wait_millis` is 82–92% of `T2 - T`.** Under `--prover native` the prover is
  not on the critical path; the trigger holding for in-flight attestations is. A
  GPU run will report a similar `T2 - T` for an entirely different reason, so
  these are a baseline for the *trigger*, not for proving.
- **`tail_named` is the number that will hurt on a GPU, and it is two orders of
  magnitude larger in steady state**: 4,999 / 6,822 / 8,159, against 75–111 on
  every catch-up. At 1.5365 ms per named leaf that is **7.7 s, 10.5 s and 12.5 s
  of proving** on the critical path, against a `T2 - T` of 1.2–7.0 s today. On a
  GPU it does not add to the critical path — it becomes it, dwarfing the 3.640 s
  stage floor and the ~0.87 s of BLS, and the modelled `T2 - T` of 5.5 s does not
  survive it. The correction is configuration rather than circuit work: see the
  trigger section above. The fixture epoch's tail of ~113 is small by
  construction — a replay has the whole epoch available at once — and is not a
  steady-state number.
- **Waiting longer does buy fewer absentees, and the three epochs show it in the
  predicted direction:**

  | `wait_millis` | 924 | 1,355 | 6,378 |
  |---|---|---|---|
  | `tail_named` | 8,159 | 6,822 | 4,999 |
  | that costs, at 1.5365 ms | 12.5 s | 10.5 s | 7.7 s |

  Monotonic, and it is the mechanism the trigger exists to exploit. It is three
  points from three different epochs with different arrival patterns, so treat it
  as a direction rather than a slope. Note that even the longest wait observed —
  6,378 ms, which hit the old 6,000 ms cap — still left 7.7 s of proving, and
  that the burst does not drain until a median of 7,326 ms. **The old cap sat
  below the useful range at every point measured**, which is why it is now
  10,000 ms.

The catch-up rows are not noise, incidentally — they are what every epoch after
a restart looks like, and §6 explains why restarts happen.

#### The longer run: 23 steady-state epochs

A later run stayed up for 23 consecutive steady-state epochs, 469381–469403, all
with `late_groups = 0` and 18–22 folded groups. It is what the trigger section
above is argued from. Waiting still buys absentees, and with 23 points the
relationship is a distribution rather than a direction:

| fired, ms into the filling slot | < 6,000 | 6,000–7,000 | 7,000–8,000 | > 8,000 |
|---|---|---|---|---|
| epochs | 9 | 4 | 5 | 5 |
| median `tail_named` | 7,334 | 7,814 | 1,197 | 1,310 |

| | median | mean | min | max |
|---|---|---|---|---|
| `wait_millis` | 1,192 | 1,715 | 239 | 4,761 |
| fired, ms into slot | 6,248 | — | 3,908 | 8,684 |
| `tail_named` | 6,563 | 5,347 | 603 | 14,538 |
| that costs, at 1.5365 ms | 10.1 s | 8.2 s | 0.9 s | 22.3 s |

The cap did not bind on any of the 23. What ended every one of them was the rate
rule, and the trigger section above is what was wrong with it.

### Two bugs the run found

Both were only visible against real mainnet traffic, and both are fixed and
pushed. They are recorded because they say what a readiness run is for.

1. **A slot could be proved twice.** `SlotStream::forget` dropped a slot's
   collected attestations but did not stop later ones re-creating it, despite its
   doc comment saying it did. Attestations for a slot keep arriving for several
   slots after it closes, so the slot came back, was taken a second time, and the
   aggregation circuit correctly rejected the epoch with `group proof 0 counts a
   slot that was already counted`. The daemon died. Observed once in the first
   four epochs. Fixed by remembering forgotten slots and dropping later arrivals
   for them — which also fixes the gossip-gap repair path, where a rescan would
   have re-ingested already-proved slots.

2. **An empty epoch boundary slot wedged the daemon permanently.** The epoch diff
   verified its parsed state against the block header at the boundary slot. Slot
   15,020,032 had no block, `/eth/v1/beacon/headers/15020032` returned 404, and
   the daemon crash-looped — the slot will never gain a block, so the supervisor
   restarting it forever made no difference. About 1% of slots are missed on
   mainnet, so this is roughly one epoch in a hundred, or **two to three times a
   day**. Fixed by reading the state root from `/eth/v1/beacon/states/{slot}/root`,
   which is defined for every slot.

   Verified live rather than in a test: the run was restarted at epoch
   469375 so that its first epoch diff was the one over slot 15,020,032, and it
   logged `accumulator advanced ... millis=23128` where the previous build had
   logged nothing but `Error: build epoch diff witness` on a five-second loop.

### The blocker the run found, and how it was closed

**An empty epoch boundary slot used to stop the streaming pipeline,
permanently.** Fixing the epoch diff (bug 2 above) moved the failure one stage
later rather than removing it. Two epochs on, the final proof for the *next*
epoch rejected:

```
stream_final circuit rejected the witness: assertion `left == right` failed:
the finalized epoch's accumulator was built from a different state than its
block produced
```

Observed 26 times in a row on epoch 469377, which finalizes 469376, whose first
slot 15,020,032 has no block. The supervisor restarting the daemon did not help,
because the slot will never gain a block. About 1% of mainnet slots are missed,
so an epoch boundary is empty roughly once in a hundred epochs — **two to three
times a day, and about eighty times a month.** Each one ended the run.

**The fix.** The circuit no longer reads the boundary state root off the
finalized block's header. A checkpoint root is the last block at or *before* the
epoch's first slot, so an empty first slot leaves the boundary state with no
header naming it. What does name it is the next state that passes the slot:
`state_roots[n % 8192]` is the state at the end of slot `n`, and
`block_roots[n % 8192]` is the last block at or before it. Both are defined for a
skipped slot.

Both are opened out of the **justified checkpoint's** state, which is the one
state after the boundary the proof already trusts — 2/3 of the stake signed its
root as their target, which is the same assumption the rest of the system rests
on. Opening the checkpoint root as well as the state root is what keeps the pair
together: without it the finalized root would come from one chain and the state
root from another.

The anchor is not weakened by this. It still names the state the accumulator was
built from, and it now names the *right* one when the boundary is empty, where
before it named a state the accumulator never used or — correctly — refused to
prove at all.

Verified against the real chain rather than only in a fixture: the state at slot
13,776,928 carries eight empty epoch boundaries in its 8192 slots of history, and
`cargo test --release --test ssz_file_tests -- --ignored` opens one of them
(13,776,864) through the circuit. The same test checks that
`state_roots[13,776,608 % 8192]` is the state root of the state this repository
ships separately, which pins the semantics against two independent files.

The two bugs above, and this blocker, are the reason a day-long run needed
rehearsing rather than launching: nothing in a fixture-backed test suite produced
a skipped epoch boundary, and now something does.

### Health at the end of the window

`gossip: {attestations: 478454, reconnects: 0, dropped: 0}` over ~12 minutes.
**Zero drops with `--http-sse-capacity-multiplier 2000`**, which is the setting
validated. Consider 3000 (48,000 messages, 1.7 slots of headroom) for margin as
the validator set grows; the cost is about 90 MB of node memory.

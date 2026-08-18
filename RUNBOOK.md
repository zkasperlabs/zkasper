# Running zkasperd against mainnet

How to provision, install, bootstrap, run, monitor and recover a continuous
mainnet finality-proving deployment.

Every number here is labelled MEASURED (with where and when) or MODELLED.
`scripts/gpu_bench.sh` is the companion document for the proving box; this one
covers the daemon and the chain it follows.

## Contents

1. [Topology, and why the beacon node is not on the GPU box](#1-topology)
2. [The beacon node](#2-the-beacon-node)
3. [Installing and starting the node](#3-installing-and-starting-the-node)
4. [Bootstrapping and running the daemon](#4-bootstrapping-and-running-the-daemon)
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
| 2 | `--http-sse-capacity-multiplier` ≥ 2000 | Lighthouse buffers each SSE topic in a broadcast ring of `multiplier × 16`. The default multiplier is 1, so **16 messages** against a slot's 28,130. |
| 3 | `/eth/v2/debug/beacon/states/{id}` enabled | Bootstrap reads the whole `BeaconState` from it, and **so does every epoch diff** — it is a continuous dependency, not a one-off. |

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

**Conclusion: run your own node.** A hosted provider is usable only as a
bootstrap source or as an aggregate-only fallback, and costs you the four seconds
that unaggregated attestations buy.

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

## 4. Bootstrapping and running the daemon

### Step 6 — Build the daemon

For a witness-only run, which is everything except the cryptography:

```sh
cd /root/.openclaw/workspace/zkasper
cargo build --release --bin zkasperd
```

For real proofs add `--features zisk-prover`, and read the CUDA matrix in
`scripts/gpu_bench.sh` first — **that build needs CUDA 12.9 or newer.**

### Step 7 — Check the node still holds the state you will bootstrap from

A checkpoint-synced Lighthouse serves states from its split slot (the finalized
checkpoint) forward. Its own sync anchor stops being served once finalization
moves past it. If you bootstrap from a slot on the wrong side of that line, the
daemon bootstraps successfully and then **wedges on the next epoch** because it
cannot re-read that state.

```sh
curl -s http://127.0.0.1:5052/eth/v1/beacon/states/head/finality_checkpoints \
  | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; \
      e=int(d['finalized']['epoch']); print('finalized epoch', e, 'slot', e*32)"
```

Then confirm that slot answers:

```sh
curl -s -o /dev/null -w "%{http_code}\n" \
  http://127.0.0.1:5052/eth/v1/beacon/states/<slot>/fork
```

If it is not 200, wait for the next finalization and repeat. Leave
`--bootstrap-slot` unset so the daemon takes the node's current finalized
checkpoint.

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
while true; do
  n=$((n + 1))
  echo "=== zkasperd start #$n at $(date -Is) ===" >> "$RUN/zkasperd.log"
  ./target/release/zkasperd \
    --beacon-url http://127.0.0.1:5052 \
    --db-path "$RUN/zkasperd.db" \
    --output-dir "$RUN/out" \
    --chain mainnet \
    --mode streaming \
    >> "$RUN/zkasperd.log" 2>&1
  echo "=== zkasperd exited rc=$? at $(date -Is) ===" >> "$RUN/zkasperd.log"
  sleep 5
done
EOF
chmod +x /mnt/ssd/zkasper-run/run_zkasperd.sh
cd /mnt/ssd/zkasper-run
setsid nohup ./run_zkasperd.sh > supervisor.log 2>&1 < /dev/null &
```

Under systemd this is `Restart=always` with `RestartSec=5`.

### Step 9 — Confirm the bootstrap

Bootstrap takes about **2 minutes** on mainnet (MEASURED 128,164 ms for
2,338,364 validator records). Watch for:

```
bootstrap complete num_validators=2338364 total_active_balance=42233196000000000
bootstrapped ... millis=128164
following attestation gossip
```

**The first epoch after bootstrap runs the batch pipeline, not the streaming
one, and this is expected.** The streaming path needs an epoch diff on record and
a justification for the previous epoch, and after a bootstrap neither exists. You
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

Everything below is read from `<output_dir>/status.json`. The daemon rewrites it
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
| `recent_latencies[].late_groups` | `> 0` | The daemon fell behind: attestations arrived that had not been folded when the trigger fired. It is a throughput symptom, not a correctness one. Currently 0 or 1 by construction. |
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
| `... returned 404 Not Found: NOT_FOUND: beacon state at slot N` | The node no longer holds that state | If it is the bootstrap epoch, delete the store and re-bootstrap (§ below). Otherwise wait one epoch. |
| `missing current_version` / `missing data array` | Old binary. Fixed: the client now reports the status and body. | Rebuild. |
| `store at ... is damaged; delete it to re-bootstrap` | Truncation or checksum failure | Not recoverable in place. Delete and re-bootstrap; note that `acc_chain_digest` restarts and will not match a peer that never lost theirs. |
| `store ... holds a X accumulator, but this run is configured for Y` | Wrong `--db-path` or `--chain` | Point at the right file. |
| `store format version N, expected M` | Format bump, no migration exists | Delete and re-bootstrap. |
| `the ... circuit rejected the witness` | An unprovable witness | Real bug. Keep the epoch directory under `out/epoch-*` — it is the reproduction. |
| `the ... proof does not verify against its own program key and outputs` | Prover, ELF or proving-key mismatch | Not a chain problem. Check the ELF against the proving key. |
| Wedged, repeating the same epoch | The node cannot serve that epoch's state | Re-bootstrap. |

### Re-bootstrapping

Destroys the accumulator chain since the last bootstrap. Do it only when the
table above says to.

```sh
pkill -f run_zkasperd.sh; pkill -f 'target/release/zkasperd'
cd /mnt/ssd/zkasper-run
rm -f zkasperd.db && rm -rf out
# repeat step 7 to confirm the node holds the finalized state, then step 8
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
| zkasperd RSS | **7.9 GB** | Dominated by the accumulator tree over 2.34M validator records. |
| lighthouse RSS | **5.8 GB** | With `--subscribe-all-subnets` and multiplier 2000. |
| Node datadir | **947 MB** after 15 minutes | Checkpoint-synced, backfill running. Budget 450+ GB for a month with default `--hierarchy-exponents`. |
| `zkasperd.db` | **343 MB** | Rewritten whole twice an epoch. |
| `out/` | **110 MB per epoch** | Witness files. **7.7 GB/day, 232 GB/month.** Prune or ship them. |
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
about 4 epochs. At 55–60% of on-demand you break even on one interruption per
~11 hours, so interruptible is the better buy for a day and a close call for a
month.

---

## 8. Measured baseline

Everything in this section was measured on 2026-08-18 against mainnet, on this
machine, with `--prover native`. Chain: Fulu, epoch 469371–469373, head slot
~15,019,970. Beacon node: Lighthouse v8.2.1 with the flags in §3, mock EL.

### Gossip arrival curve

**This is the measurement the scheduler's assumptions rest on, and it is the
first time they have been checked against real traffic.** 1,771,307 events over
79 slots; 67 steady-state slots (15,019,900–15,019,966) after discarding partial
ones at each end. Times are milliseconds into the attestation's own slot.

| topic | per slot | p05 | p10 | p25 | **p50** | p75 | p90 | p95 | p99 |
|---|---|---|---|---|---|---|---|---|---|
| `single_attestation` | **28,033** | 2,104 | 2,385 | 3,105 | **4,254** | 5,432 | 6,654 | 7,526 | 9,170 |
| `attestation` (aggregates) | **83** | 8,014 | 8,049 | 8,074 | **8,107** | 8,134 | 8,171 | 8,264 | 8,609 |

**All three design assumptions hold.**

| Assumption | Assumed | Measured |
|---|---|---|
| Singles land about a third into the slot | 0.333 (4,000 ms) | **0.354** (4,254 ms) |
| Aggregates land about two thirds in | 0.667 (8,000 ms) | **0.676** (8,107 ms) |
| Singles buy four seconds over aggregates | 4,000 ms | **3,853 ms** |

Cumulative share of a slot's singles in hand:

| ms into slot | 2,000 | 3,000 | 4,000 | 5,000 | 6,000 | 7,000 | 8,000 | 9,000 |
|---|---|---|---|---|---|---|---|---|
| share | 3.5% | 22.7% | 44.9% | **66.8%** | 84.0% | 92.2% | 96.9% | 98.9% |

The burst drains — last arrival before a gap of more than 500 ms — at a median
of **7,445 ms** into the slot (p25 6,520, p75 8,016). The default
`--max-trigger-wait-millis 6000` therefore expires slightly before the burst
finishes draining on a typical slot, which is what the two `late_groups = 1`
observations below reflect.

Note how tight the aggregate distribution is: p05 to p95 spans 250 ms, against
5,400 ms for the singles. Aggregates are published on a schedule; singles arrive
as validators produce them.

### Volume cross-check

`/eth/v1/beacon/states/head/committees` reports 64 committees and 28,130
attesting validators per slot at slot 15,019,864. The stream delivered 28,033 a
slot — **99.7%**. The node is not dropping and the subscription is complete.

For contrast, QuickNode's public endpoint delivers 877/slot: **3.1%**.

### Stage costs

| Stage | Measured |
|---|---|
| bootstrap | 128,164 ms, 2,338,364 validator records, 42,233,196 ETH active |
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

| epoch | `t2_minus_t_millis` | `wait_millis` | `tail_named` | `tail` | `folded_groups` | `late_groups` |
|---|---|---|---|---|---|---|
| 469372 | **5,007** | 4,919 | 110 | 1 | 0 | 1 |
| 469373 | **5,118** | 4,964 | 93 | 1 | 0 | 1 |

Read these carefully: **`wait_millis` is 98% of `T2 - T`.** The prover is not on
the critical path here — the trigger deliberately holding for in-flight
attestations is. That is the design working, but it also means these two numbers
say almost nothing about proving cost, and a GPU run will report a very similar
`T2 - T` for a completely different reason.

`folded_groups = 0` with `late_groups = 1` on both epochs says no group proof was
folded before the trigger fired. These are the first two streaming epochs after a
bootstrap, so the daemon opened them already in progress; this is the shape a
catch-up produces, not steady state. Do not quote them as a steady-state result
until a run has produced epochs it followed from their first slot.

### Health at the end of the window

`gossip: {attestations: 478454, reconnects: 0, dropped: 0}` over ~12 minutes.
**Zero drops with `--http-sse-capacity-multiplier 2000`**, which is the setting
validated. Consider 3000 (48,000 messages, 1.7 slots of headroom) for margin as
the validator set grows; the cost is about 90 MB of node memory.

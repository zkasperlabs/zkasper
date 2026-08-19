# Monitoring

`zkasperd` serves Prometheus metrics itself, on `/metrics`. Nothing here parses
`status.json` and re-emits it; the manifest is a separate contract, for the API
and the dashboard, and it keeps its millisecond fields.

```
zkasperd :9464/metrics ─┐
                        ├─ prometheus (this box) ─ remote_write ─► Grafana Cloud
node_exporter :9100 ────┘        rules                                 rules
        ▲                                                          notifications
        └─ vast_exporter.py (cron) → textfile collector
```

Two things are worth understanding about that shape.

**The rules are evaluated twice, on purpose.** Locally, so an operator can read
them from a shell with no account; and in Grafana Cloud, because a rule that
says "this machine has stopped answering" cannot be evaluated on that machine.

**It pushes.** This box has no inbound access, so nothing external can scrape
it. `remote_write` is the standard answer, and it is why Grafana Cloud is the
service rather than anything that wants to reach in.

## Install

```sh
sudo apt-get install prometheus prometheus-node-exporter
sudo ./monitoring/install.sh          # scrape targets, rules, the GPU cron
sudo ./monitoring/grafana_cloud.sh    # once the account exists
```

`install.sh` is idempotent and keeps any `remote_write` block already there.

**One box, two daemons.** `--metrics-addr` defaults to `127.0.0.1:9464` and a
second daemon will fail to bind it and crash-loop — loudly, which is right, but
only if you know to expect it. Give the second one `--metrics-addr
127.0.0.1:9465` and uncomment its target in `prometheus.yml`.

## What `/metrics` exposes

Namespaced `zkasper_`, in base units, with `_total` on every counter and a
histogram wherever the distribution is the point.

### Is it alive, and is it advancing

| Metric | |
|---|---|
| `zkasper_heartbeat_timestamp_seconds` | Written once a second by a task of its own. **Alert on this first**: it is the only thing that separates a wedged process from a busy one. |
| `zkasper_manifest_updated_timestamp_seconds` | When the last tick finished. Stops when the *pipeline* stops — which a committee proof legitimately does for over two minutes, so this needs a much longer threshold than the heartbeat. |
| `process_start_time_seconds` | Uptime, and — via `changes(...[1h])` — the restart count. A restart is a failure to debug, not an event to absorb: it costs the epoch in flight, its committee proof and the gossip collected for it. |
| `zkasper_accumulator_epoch` | Epoch the accumulator represents. |
| `zkasper_head_slot` | Head slot, as the node last reported it. |
| `zkasper_justified_epoch`, `zkasper_finalized_epoch` | What this daemon has proven. |
| `zkasper_node_finalized_epoch` | What the node thinks, to compare against. |
| `zkasper_validators`, `zkasper_total_active_balance_gwei` | What the accumulator commits to. |
| `zkasper_build_info` | Always 1. Version, commit and Zisk release as labels, so a change in any other series can be told apart from a deploy. |

### The gossip feed

| Metric | |
|---|---|
| `zkasper_gossip_reconnects_total` | Each one is a hole gossip did not deliver and blocks had to repair. |
| `zkasper_gossip_attestations_total` | Delivered. |

### The product

| Metric | |
|---|---|
| `zkasper_t2_minus_t_seconds{follow}` | From holding the attestation that crossed 2/3 to holding a proof of it. **A histogram, because the distribution over hundreds of epochs is the whole point** — a gauge of the last epoch is exactly what a point-in-time check already gives. **Read `follow="live"`**: see below. |
| `zkasper_trigger_wait_seconds` | The part of that which was the trigger holding back rather than the prover working. |
| `zkasper_tail_named` | Absentees the final proof opened inline. What makes `T2 − T` large, and what moves when the trigger rule is retuned. Read against `trigger_wait`: the wait is only paying for itself if this falls. |
| `zkasper_groups_folded_total` | Groups folded before the threshold, the shape the design aims at. |

### Where the time goes

Every one of these is a histogram labelled by stage. None is a gauge holding the
last value — that is the question `scripts/monitor.py` already answers from a
shell, and it is exactly the shape that makes a distribution unrecoverable.

| Metric | |
|---|---|
| `zkasper_proof_start_delay_seconds{stage}` | **Actual start minus the start the schedule expected.** The scheduler prices a proof as startable once the slots it covers have arrived; this is how far off that the daemon actually was. Negative buckets are deliberate — a proof that ran early is information, and clamping at zero throws it away. This replaced a count of groups that missed the fold, which said something was wrong without saying how badly or where. |
| `zkasper_proof_duration_seconds{stage}` | How long making one proof took, witness generation included. |
| `zkasper_proof_busy_seconds{stage}` | The part of that not spent awaiting the node or the prover. |
| `zkasper_witness_duration_seconds{stage}` | The witness half on its own, so a slow witness build is told from a slow prover. |
| `zkasper_witness_busy_seconds{stage}` | The same, minus the beacon-node round trips. |
| `zkasper_prove_duration_seconds{stage}` | What the prover charged. The only source when the prover is on another machine. |
| `zkasper_wrap_duration_seconds{stage}` | What compressing it charged. |
| `zkasper_verify_duration_seconds{stage}` | **Checking a proof: pure Rust, no GPU, no proving key.** See below. |

Four bucket ladders, because one cannot serve a 2 ms fold and a 132 s committee
proof at the same resolution: a wide work ladder, a narrow one for the wrap, a
very fine one for verification, and one with negative edges for the start delay.

The duration families come from spans and nothing else. Every stage runs inside
`#[instrument(name = "stage", fields(stage = …))]` and every witness build inside
`#[instrument(name = "witness", …)]`; `tracing_subscriber`'s `fmt` layer logs
each span's `time.busy`/`time.idle` when it closes and `metrics::StageMetrics`
records the same measurement as a histogram. One instrumentation, two consumers;
no stopwatch beside it.

`stage` is one of nine values and nothing else — the layer maps the field
through `Stage::from_str` and drops what it does not recognise, which is the
cardinality guard. Epoch numbers are span fields for the log, never labels.

### What a proof costs, and what it weighs

| Metric | |
|---|---|
| `zkasper_proof_size_bytes{stage}` | Proof size. A wrapped proof measured 249 KB once, from one stage on one card; a histogram is what turns that one sample into a distribution. |
| `zkasper_proof_cost_usd{stage}` | Prover seconds for that stage, priced at the rate below. **Labelled by stage because 92% of an epoch's bill is the committee proof** — an unlabelled total hides the only interesting thing about it. |
| `zkasper_epoch_cost_usd` | The whole epoch. This is the number the project quotes: $0.0203 measured, at $0.51/hr. |
| `zkasper_epoch_prover_seconds` | The prover time that price is built from. |
| `zkasper_prover_usd_per_hour` | The rate itself, so a reader can price the seconds at *their* rate rather than take this deployment's. |

The API stores the same thing without multiplying: `/v1/epochs/{epoch}` carries
`prover_millis_total` and each stage's `prove_millis`, `wrap_millis` and
`proof_bytes`, and `/v1/status` carries `prover_usd_per_hour`. That is
deliberate — an hourly rate is a fact about a rental contract, not about the
pipeline — so the stored record keeps the two factors and the metrics do the
arithmetic.

### How long does it take to verify a proof?

`zkasper_verify_duration_seconds{stage}`, and it is the number a light-client
integrator asks for first. `zkasper_common::recursion::verify_child` runs the
Zisk STARK verifier in pure Rust with no GPU and no proving key, and that
property is the entire reason verifying a zkasper proof inside Helios is
possible. The tests assert it returns true; nothing had ever timed it.

The instrumentation lives in `crates/witness-gen/src/verify.rs` rather than in
`zkasper-common`, because that crate is compiled into every guest where
`tracing` has no business. The daemon checks each epoch's own final proof
*after* `T2` has been stamped, so what this measures can never inflate the
latency the project quotes.

It records nothing on a witness-only run — an empty proof is not a verification
— so the histogram stays empty until a real proof exists to time.

### Why the latency is split by `follow`

The first epoch of a run, or the first after a restart, is opened mid-flight. It folds
nothing before the trigger, so its final proof carries the whole epoch inline —
the first one this pipeline measured took **185 s against a steady-state 1.2 to
7 s**. Mixed into one histogram those samples move every quantile and cannot be
separated again afterwards.

So `follow="live"` is an epoch with at least one group folded before the
threshold, which is the manifest's own rule for when a latency is real, and
`follow="catchup"` is everything else. Quote the first; watch the second for
getting worse. The same label is on `zkasper_trigger_wait_seconds` and
`zkasper_tail_named`, because they are read against it.

This split exists because the metric found it. The histogram's first live sample
was a catch-up that landed in `+Inf`, which is also why the ladder now runs to
five minutes rather than thirty seconds.

### What is on disk

`zkasper_retained_epochs` and `zkasper_output_bytes`, read at the moment the
retention bound is applied rather than on a timer, because that is the one point
the directory is walked anyway.

### Publishing

`zkasper_publish_posted_total`, `_spooled_total`, `_dropped_total`, and
`zkasper_publish_pending`. `pending` climbing is the API being unreachable,
which the daemon rides out; `dropped` climbing is the outage having outlasted
the spool, which is the only case that leaves a hole in the published record.

### The process

`process_resident_memory_bytes`, `process_cpu_seconds_total` and the rest of the
standard set, from `metrics-process`. Unprefixed, because they are the standard
names.

## What is deliberately not in the daemon

The rented GPU count, the burn rate and the remaining credit. `zkasperd` does
not rent anything and cannot see the account — but the deciding argument is the
failure being watched for: **a card that is running while no daemon is.** An
exporter for that inside the daemon would go quiet at exactly the moment it
mattered. So `vast_exporter.py` is a separate process with a separate lifetime,
polled by cron into node_exporter's textfile collector, which is the standard
shape for a periodic poll of a third-party API. Because node_exporter publishes
`node_textfile_mtime_seconds` for the file, the exporter's own silence is
alertable too.

## The alerts

In `alerts.yml`. Page-worthy:

| Alert | |
|---|---|
| `ZkasperDaemonStale` | No heartbeat in two minutes. |
| `ZkasperPipelineStalled` | Breathing, but no tick in ten minutes. |
| `ZkasperDaemonDown` | `/metrics` not answering for two minutes — eight scrapes, because one failed scrape is not an outage. |
| `ZkasperRestarting` | More than two restarts in an hour. |
| `ZkasperEpochNotAdvancing` | Alive, not progressing, for half an hour. An epoch is 6.4 minutes. |
| `ZkasperGossipDropped` | Any increase at all. |
| `ZkasperGpuIdle` | A card running with no proof reaching the daemon for half an hour. It measures work arriving *here*, so a card rented for a benchmark trips it — deliberately, because an unattended benchmark card is the same bill. |
| `ZkasperCreditLow` | Less than a day of credit at the current burn. |

Warnings, which is where a single late epoch belongs:

`ZkasperProofsStartingLate` (p90 start delay over a slot, for a quarter of an
hour), `ZkasperGossipFlapping`, `ZkasperPublishDropped`,
`ZkasperVastExporterStale`.

**One of these was wrong, and the alert firing is how we found out.**
`ZkasperDaemonStale` originally watched the manifest, which is only rewritten
when a tick finishes — and a committee proof holds a tick for over two minutes
by design. It fired on a perfectly healthy daemon within twenty minutes of being
armed. The heartbeat exists because of that, and the split between "the process
is breathing" and "the pipeline is moving" is the thing the incident taught.

```sh
promtool check rules monitoring/alerts.yml
curl -s localhost:9090/api/v1/alerts | jq '.data.alerts[] | {alertname:.labels.alertname, state}'
```

## This is not a replacement for `scripts/monitor.py`

`monitor.py` answers "is it broken right now" from a shell, over the whole
service — the daemon, the card, the API, the site — and needs no
infrastructure. `health.py` does the same from the manifest alone. This
directory answers "what has it been doing for the last fortnight, and wake me
when it stops". Different questions.

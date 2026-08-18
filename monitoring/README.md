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

## What `/metrics` exposes

Namespaced `zkasper_`, in base units, with `_total` on every counter and a
histogram wherever the distribution is the point.

### Is it alive, and is it advancing

| Metric | |
|---|---|
| `zkasper_manifest_updated_timestamp_seconds` | When the last tick finished. **Alert on this first**: every other number is meaningless if it has stopped moving. |
| `zkasper_accumulator_epoch` | Epoch the accumulator represents. |
| `zkasper_head_slot` | Head slot, as the node last reported it. |
| `zkasper_justified_epoch`, `zkasper_finalized_epoch` | What this daemon has proven. |
| `zkasper_node_finalized_epoch` | What the node thinks, to compare against. |
| `zkasper_validators`, `zkasper_total_active_balance_gwei` | What the accumulator commits to. |
| `zkasper_build_info` | Always 1. Version, commit and Zisk release as labels, so a change in any other series can be told apart from a deploy. |

### The gossip feed

| Metric | |
|---|---|
| `zkasper_gossip_dropped_total` | The node threw attestation events away because its own SSE channel overflowed. **The nastiest failure here**: the epoch is quietly short of weight and it looks exactly like a slow chain. It never self-heals — raise `--http-sse-capacity-multiplier` on the node. |
| `zkasper_gossip_reconnects_total` | Each one is a hole gossip did not deliver and blocks had to repair. |
| `zkasper_gossip_attestations_total` | Delivered. |

### The product

| Metric | |
|---|---|
| `zkasper_t2_minus_t_seconds` | From holding the attestation that crossed 2/3 to holding a proof of it. **A histogram, because the distribution over hundreds of epochs is the whole point** — a gauge of the last epoch is exactly what a point-in-time check already gives. |
| `zkasper_trigger_wait_seconds` | The part of that which was the trigger holding back rather than the prover working. |
| `zkasper_tail_named` | Absentees the final proof opened inline. What makes `T2 − T` large, and what moves when the trigger rule is retuned. Read against `trigger_wait`: the wait is only paying for itself if this falls. |
| `zkasper_groups_late_total` | Groups the final proof had to verify itself. Not page-worthy for one epoch — that marks a catch-up — but a run of them says the rule is too patient. |
| `zkasper_groups_folded_total` | Groups folded before the threshold, the shape the design aims at. |

### Where the time goes

| Metric | |
|---|---|
| `zkasper_stage_duration_seconds{stage}` | Wall-clock, from the stage's `tracing` span. |
| `zkasper_stage_busy_seconds{stage}` | The part of it the span was entered. The difference is what the stage spent awaiting the node or the prover. |
| `zkasper_prove_duration_seconds{stage}` | What the prover charged. The only source when the prover is on another machine. |
| `zkasper_wrap_duration_seconds{stage}` | What compressing it charged. |
| `zkasper_proof_bytes_total{stage}` | Zero on a witness-only run. |

The two `stage_*` families come from the spans and nothing else. Every stage in
the orchestrator runs inside `#[instrument(name = "stage", fields(stage = …))]`,
`tracing_subscriber`'s `fmt` layer logs each one's `time.busy`/`time.idle` when
it closes, and `metrics::StageMetrics` records the same measurement as a
histogram. One instrumentation, two consumers; no stopwatch beside it.

`stage` is one of nine values and nothing else — the layer maps the field
through `Stage::from_str` and drops what it does not recognise, which is the
cardinality guard. Epoch numbers are span fields for the log, never labels.

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
| `ZkasperDaemonStale` | No tick in two minutes. |
| `ZkasperDaemonDown` | `/metrics` not answering for two minutes — eight scrapes, because one failed scrape is not an outage. |
| `ZkasperEpochNotAdvancing` | Alive, not progressing, for half an hour. An epoch is 6.4 minutes. |
| `ZkasperGossipDropped` | Any increase at all. |
| `ZkasperGpuIdle` | A card running with no proof coming back for half an hour. |
| `ZkasperCreditLow` | Less than a day of credit at the current burn. |

Warnings, which is where a single late epoch belongs:

`ZkasperFallingBehind` (more than five late groups in an hour),
`ZkasperGossipFlapping`, `ZkasperPublishDropped`,
`ZkasperVastExporterStale`.

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

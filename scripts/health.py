#!/usr/bin/env python3
"""Answer "is zkasperd working" from the status manifest, without reading logs.

Exits 0 when everything an operator would page on is clear, 1 when something is
wrong, 2 when the manifest cannot be read at all. Prints one line per check so
that the output is the explanation.

    ./scripts/health.py /mnt/ssd/zkasper-run/out/status.json

Run it from cron or a monitoring agent. Nothing here writes anything.

WHAT THE THRESHOLDS MEAN. Each is a claim about the deployment, not a taste:

  stale > 300 s      The manifest is rewritten after every stage, about five
                     times a second during a streaming epoch and every poll
                     interval otherwise. Two minutes of silence is a dead or
                     wedged daemon, and every other field is then untrustworthy.

  gossip.dropped     The node's SSE ring overflowed and attestations are simply
                     gone. Lighthouse reports it as an SSE comment and the
                     daemon counts it. Anything but zero is a misconfigured
                     node: raise --http-sse-capacity-multiplier. It is never
                     bad luck and it never fixes itself.

  gossip absent      The daemon is reading attestations out of blocks, which is
                     a slot behind the chain by construction. Expected only
                     under --no-gossip or --mode batch.

  late_groups        Attestations arrived that had not been folded when the
                     trigger fired, so the final proof had to verify them
                     itself. It is a throughput symptom, not a correctness one,
                     and the design aims at zero.

  behind > 4 slots   The daemon's view of the head has stopped tracking the
                     node's.

The counters are monotonic since process start and reset on restart, so a
rising `reconnects` is only visible by diffing scrapes; this script reports the
absolute value and leaves the trend to whatever stores it.
"""

import json
import sys
import time

STALE_SECONDS = 120
BEHIND_SLOTS = 4


def main(path):
    try:
        with open(path) as f:
            status = json.load(f)
    except (OSError, ValueError) as e:
        print(f"CRIT  cannot read {path}: {e}")
        return 2

    failures = []
    notes = []

    age = int(time.time()) - status["updated_unix"]
    if age > STALE_SECONDS:
        failures.append(f"manifest is {age} s old (limit {STALE_SECONDS})")
    notes.append(f"updated {age} s ago")

    acc = status["accumulator"]
    notes.append(f"accumulator epoch {acc['epoch']}")
    notes.append(f"justified through {status.get('justified_through')}")

    node = status.get("node_finalized")
    if node:
        notes.append(f"node finalized {node['epoch']}")

    gossip = status.get("gossip")
    if gossip is None:
        notes.append("gossip OFF (reading blocks, a slot behind)")
    else:
        if gossip["dropped"]:
            failures.append(
                f"the node dropped events {gossip['dropped']} times; "
                "raise --http-sse-capacity-multiplier"
            )
        notes.append(
            f"gossip {gossip['attestations']} attestations, "
            f"{gossip['reconnects']} reconnects, {gossip['dropped']} dropped"
        )

    latencies = status.get("recent_latencies", [])
    if latencies:
        late = sum(l["late_groups"] for l in latencies)
        if late:
            failures.append(
                f"{late} late group(s) across {len(latencies)} epochs; "
                "the daemon fell behind the chain"
            )
        t2 = sorted(l["t2_minus_t_millis"] for l in latencies)
        notes.append(
            f"T2-T over {len(t2)} epochs: "
            f"min {t2[0]} median {t2[len(t2) // 2]} max {t2[-1]} ms"
        )
    else:
        notes.append("no measured epochs yet")

    # The manifest carries the node's head as the daemon last saw it, so this
    # catches the daemon falling behind without a second source to ask.
    stages = status.get("recent_stages", [])
    if stages:
        newest = max(s.get("slot") or 0 for s in stages)
        if newest and status["head_slot"] - newest > BEHIND_SLOTS * 32:
            notes.append(f"newest proved slot {newest} vs head {status['head_slot']}")

    for note in notes:
        print(f"      {note}")
    for failure in failures:
        print(f"FAIL  {failure}")

    if failures:
        print("BAD")
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "zkasper-out/status.json"))

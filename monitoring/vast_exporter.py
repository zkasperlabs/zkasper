#!/usr/bin/env python3
"""What the GPU account is renting and what it is costing, as Prometheus text.

Deliberately not part of zkasperd. The daemon does not rent anything, cannot
see the account, and — this is the point — the failure being watched for is a
card that is running while no daemon is. An exporter for that inside the daemon
would go quiet at exactly the moment it was needed.

So it is a separate process with a separate lifetime: a cron job that polls the
provider and writes into node_exporter's textfile collector, which is the
standard shape for "a periodic poll of a third-party API". node_exporter
publishes `node_textfile_mtime_seconds` for the file, so an exporter that stops
running is itself alertable.

    ./monitoring/vast_exporter.py                    # write the default path
    ./monitoring/vast_exporter.py --stdout           # look at it first

Read-only. It rents nothing, destroys nothing and spends nothing.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

VAST_KEY_FILE = "/root/.openclaw/workspace/.vast-api"
DEFAULT_OUT = "/var/lib/prometheus/node-exporter/zkasper_vast.prom"
TIMEOUT_S = 45


def vast(key, *args):
    """One vastai call, as parsed JSON."""
    out = subprocess.run(
        ["vastai", *args, "--raw"],
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
        env={**os.environ, "VAST_API_KEY": key},
    )
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip() or f"vastai {args[0]} failed")
    return json.loads(out.stdout) if out.stdout.strip() else []


def collect():
    """Instances and credit, or an exception."""
    key = re.search(r"[a-f0-9]{64}", Path(VAST_KEY_FILE).read_text()).group(0)
    instances = vast(key, "show", "instances")
    credit = vast(key, "show", "user").get("credit", 0.0)
    return instances, float(credit)


def render(instances, credit, ok, error=""):
    """The exposition.

    Every series is written on every successful run, including the zeroes: a
    gauge that only appears when it is non-zero cannot be alerted on for being
    zero, and "nothing is rented" is the state we most want to confirm. Each
    family is written as one block, because the text format is parsed a family
    at a time and interleaving them is how a collector starts rejecting a file.
    """
    out = [
        family(
            "zkasper_vast_scrape_success",
            "Whether the last poll of the provider worked.",
            [("", 1 if ok else 0)],
        ),
    ]
    if not ok:
        # A failed poll must not look like an account with nothing rented, so
        # every other gauge is left out rather than written as zero. The
        # staleness alert is what covers a run of failures.
        out.append(f"# poll failed: {error}\n")
        return "".join(out)

    by_status = {}
    for instance in instances:
        status = instance.get("actual_status") or "unknown"
        by_status[status] = by_status.get(status, 0) + 1
    out.append(
        family(
            "zkasper_vast_instances",
            "Rented instances, by the status the provider reports.",
            [(f'{{status="{s}"}}', n) for s, n in sorted(by_status.items())],
        )
    )
    out.append(
        family(
            "zkasper_vast_instances_running",
            "Rented instances that are running and therefore billing.",
            [("", sum(1 for i in instances if i.get("actual_status") == "running"))],
        )
    )
    out.append(
        family(
            "zkasper_vast_burn_usd_per_hour",
            "What every rented instance costs per hour, together.",
            [("", round(sum(float(i.get("dph_total") or 0) for i in instances), 4))],
        )
    )
    out.append(
        family(
            "zkasper_vast_credit_usd",
            "Credit left on the account.",
            [("", round(credit, 4))],
        )
    )
    return "".join(out)


def family(name, help_text, samples):
    """One metric family: its documentation, then its samples."""
    lines = [f"# HELP {name} {help_text}", f"# TYPE {name} gauge"]
    lines += [f"{name}{labels} {value}" for labels, value in samples]
    return "\n".join(lines) + "\n"


def write_atomic(path, text):
    """node_exporter reads the directory while this writes, so the file has to
    appear whole or not at all."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".prom.tmp")
    tmp.write_text(text)
    os.replace(tmp, path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--stdout", action="store_true", help="print instead of writing")
    args = ap.parse_args()

    try:
        instances, credit = collect()
        text = render(instances, credit, ok=True)
        failed = False
    except Exception as e:
        text = render([], 0.0, ok=False, error=str(e).replace("\n", " ")[:200])
        failed = True

    if args.stdout:
        sys.stdout.write(text)
    else:
        write_atomic(args.out, text)
    if failed:
        print(f"{time.strftime('%FT%T')} vast poll failed", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

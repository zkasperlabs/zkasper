#!/usr/bin/env python3
"""Extract per-phase timings from cargo-zisk prove/wrap logs.

cargo-zisk brackets each phase with `>>> NAME` and `<<< NAME (Nms)`. Wall-clock
around the process therefore splits into phases plus whatever is left, and that
remainder is what a persistent prover would save: process start, library load
and GPU allocation.

Usage:
    python3 scripts/parse_prove_logs.py <logdir> [--tsv out.tsv]
"""
import argparse
import os
import re
import sys

PHASE = re.compile(r"<<< ([A-Z0-9_]+) \((\d+)ms\)")
# The prover's own end-to-end figure for the proof itself, excluding the
# process start and the GPU allocation that INITIALIZING_PROOFMAN covers.
GENERATED = re.compile(r"Proof generated in ([0-9.]+)s")
# The prover prints its own total for the proof itself.
TOTAL = re.compile(r"<<< (GENERATE_VADCOP_PROOF|GENERATE_VADCOP_FINAL_PROOF|"
                   r"GENERATE_VADCOP_FINAL_COMPRESSED_PROOF|PROVE) \((\d+)ms\)")


def phases(path):
    out = {}
    with open(path, errors="replace") as f:
        for line in f:
            m = PHASE.search(line)
            if m:
                out.setdefault(m.group(1), []).append(int(m.group(2)) / 1000.0)
                continue
            g = GENERATED.search(line)
            if g:
                out.setdefault("PROOF_GENERATED", []).append(float(g.group(1)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logdir")
    ap.add_argument("--tsv")
    args = ap.parse_args()

    rows = []
    for name in sorted(os.listdir(args.logdir)):
        if not name.endswith(".log"):
            continue
        p = phases(os.path.join(args.logdir, name))
        if not p:
            continue
        rows.append((name, p))

    seen = set()
    for _, p in rows:
        seen.update(p)
    order = sorted(seen)

    out = sys.stdout
    if args.tsv:
        out = open(args.tsv, "w")
    print("log\t" + "\t".join(order), file=out)
    for name, p in rows:
        print(name + "\t" + "\t".join(f"{sum(p[k]):.3f}" if k in p else ""
                                      for k in order), file=out)
    if args.tsv:
        out.close()
        print(f"wrote {args.tsv} ({len(rows)} logs, {len(order)} phases)")


if __name__ == "__main__":
    main()
